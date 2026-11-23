//! What must be true before the first request is served.
//!
//! Configuration is validated once, loudly, at start — not lazily on the first request that trips
//! over it. A server that starts and then refuses everything reports the failure in the wrong place:
//! far from the setting that caused it, and only to whoever happens to be watching the logs.

use crate::*;

/// Checks the configuration at startup and REFUSES to run when it contradicts itself.
///
/// The reason is specific: a security control switched off silently by a typo is worse than no
/// control at all, because the operator believes they have it. A misconfiguration matrix surfaced
/// three such cases: an unreadable HMAC key file made the audit quietly fall back to plain SHA-256;
/// `MCP_RATE_RPM=-5` silently disabled rate limiting; an unparsable `JWT_PUBKEY_PEM` produced a
/// server with "working" auth that nobody could ever authenticate against.
/// Asks the database whether redaction is actually enforced, instead of trusting our own filtering.
///
/// Three adversarial rounds got past the syntactic checks, each time through a shape nobody had
/// listed: a row cast to text, a qualified wildcard, a column name assembled from `chr(112)`, a
/// positional alias list. Enumerating shapes is a race the SQL language wins. So the server stops
/// asserting and goes and looks: for every configured database it reports which tables still let the
/// connected role read a redacted column, with the statement that fixes it. `MCP_REDACT_REQUIRE_REVOKE=1`
/// turns that report into a refusal to run — which is the only way this setting becomes a guarantee.
///
/// It runs in the background: connecting at startup would trade a lazy, diagnosable first connection
/// for a server that will not start when the database is briefly unavailable.
pub(crate) fn spawn_redaction_verification() {
    if !validate::redaction_configured() {
        return;
    }
    let strict = std::env::var("MCP_REDACT_REQUIRE_REVOKE").is_ok_and(|v| v == "1" || v == "true");
    // Strict means "no query is answered until the database has been seen to enforce this". The flag
    // is raised BEFORE the thread starts, so there is no window in which requests run unchecked, and
    // it is lowered only by a verification that actually ran. It used to be the other way round: the
    // check ran in the background, so even a successful one let queries through first.
    if strict {
        REDACTION_PENDING.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    std::thread::spawn(move || {
        let mut told = false;
        loop {
            match verify_redaction_once() {
                Verdict::Verified => {
                    eprintln!(
                        "MCP_REDACT_COLUMNS: verified against the database — the connected role cannot read \
                         those columns anywhere. Redaction is enforced by PostgreSQL, not only by this server."
                    );
                    REDACTION_PENDING.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
                Verdict::Unknown(n) => {
                    // A catalog query that FAILS says nothing about the privileges. It used to be
                    // skipped, which left "nothing exposed" and printed "verified" for a database that
                    // had not been reached at all.
                    if !told {
                        told = true;
                        eprintln!(
                            "MCP_REDACT_COLUMNS: could NOT verify against the database ({} database(s) \
                             unreachable or the catalog query failed). Redaction is NOT confirmed; retrying.{}",
                            n,
                            if strict { " Serving is blocked until it is (MCP_REDACT_REQUIRE_REVOKE=1)." } else { "" }
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                Verdict::Exposed(exposed) => {
                    eprintln!(
                        "WARNING: MCP_REDACT_COLUMNS is NOT enforced by the database. The role can still read these \
                         columns, so masking is cosmetic against a caller who writes SQL. Run:"
                    );
                    for line in &exposed {
                        eprintln!("{}", line);
                    }
                    if strict {
                        eprintln!(
                            "MCP_REDACT_REQUIRE_REVOKE=1 — refusing to serve until those privileges are revoked."
                        );
                        std::process::exit(2);
                    }
                    eprintln!(
                        "  -- note: with column-level grants PostgreSQL refuses `SELECT *` on that table, so \
                         callers must name columns; describe_table lists them and marks the redacted one."
                    );
                    eprintln!(
                        "(set MCP_REDACT_REQUIRE_REVOKE=1 to make this fatal instead of advisory)"
                    );
                    return;
                }
            }
        }
    });
}

/// Raised while `MCP_REDACT_REQUIRE_REVOKE=1` is waiting for a database verdict.
static REDACTION_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn redaction_unverified() -> bool {
    REDACTION_PENDING.load(std::sync::atomic::Ordering::SeqCst)
}

enum Verdict {
    Verified,
    /// How many databases could not be asked.
    Unknown(usize),
    Exposed(Vec<String>),
}

fn verify_redaction_once() -> Verdict {
    // Per table, not per column: the fix has to be a table-level REVOKE followed by a GRANT of the
    // columns that stay. A bare `REVOKE SELECT (password) ON staff` is silently a no-op while the
    // role holds SELECT on the whole table — this server printed exactly that advice until an
    // end-to-end test followed it and the value came straight back.
    //
    // Names come back already quoted by the database (`quote_ident`): this text is meant to be pasted
    // into a superuser's psql, and a table called `x"; DROP ...` must not turn the fix into the attack.
    const SQL: &str =
        "SELECT quote_ident(current_user) AS role, quote_ident(n.nspname) AS schema, \
                quote_ident(c.relname) AS rel, \
                array_to_string(array_agg(quote_ident(a.attname) ORDER BY a.attnum) \
                                FILTER (WHERE lower(a.attname) = ANY($1)), ', ') AS exposed, \
                array_to_string(array_agg(quote_ident(a.attname) ORDER BY a.attnum) \
                                FILTER (WHERE lower(a.attname) <> ALL($1)), ', ') AS keep \
         FROM pg_attribute a \
         JOIN pg_class c ON c.oid = a.attrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE a.attnum > 0 AND NOT a.attisdropped \
           AND c.relkind IN ('r', 'p', 'v', 'm', 'f') \
           AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
           AND has_column_privilege(c.oid, a.attnum, 'SELECT') \
         GROUP BY 1, 2, 3 \
         HAVING count(*) FILTER (WHERE lower(a.attname) = ANY($1)) > 0 \
         ORDER BY 2, 3 LIMIT 50";
    let pats: Vec<String> = validate::redacted_column_list();
    let mut exposed: Vec<String> = Vec::new();
    let mut failed = 0usize;
    for name in configured_databases() {
        let Ok(v) = query_catalog(SQL, &[&pats], Some(&name)) else {
            failed += 1;
            continue;
        };
        let empty = vec![];
        for row in v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty) {
            let get = |k: &str| {
                row.get(k)
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let (role, schema, rel) = (get("role"), get("schema"), get("rel"));
            let keep = get("keep");
            // Everything inside a `--` comment goes through `comment_safe`: a newline in a table name
            // would otherwise end the comment and start a statement of the attacker's choosing.
            exposed.push(format!(
                "  -- {}.{} in database {} exposes: {}\n  REVOKE SELECT ON {}.{} FROM {};\n  GRANT SELECT ({}) ON {}.{} TO {};",
                setup_sql::comment_safe(&schema), setup_sql::comment_safe(&rel),
                setup_sql::comment_safe(&name), setup_sql::comment_safe(&get("exposed")),
                schema, rel, role,
                if keep.is_empty() { "/* no other readable columns — do not re-grant */".into() } else { keep },
                schema, rel, role
            ));
        }
    }
    if !exposed.is_empty() {
        Verdict::Exposed(exposed)
    } else if failed > 0 {
        Verdict::Unknown(failed)
    } else {
        Verdict::Verified
    }
}

/// Every environment variable this server reads. One list, so that a typo cannot pass for a setting.
///
/// `MCP_REDACT_COLUMN=ssn` — singular, one letter short — would otherwise start the server with
/// redaction silently switched off, and nothing anywhere would say so. A configuration mistake that
/// turns a protection off must be louder than one that turns it on, and the only way to be loud
/// about a misspelling is to know every correct spelling.
///
/// `MCP_X_*` is reserved for whoever needs their own variables in the same environment (another MCP
/// server in the same compose file, say) and is never rejected. That reservation only helps people
/// who have read this file, which is why `classify_unknown` also has to cope with programs that
/// never will — see the note there.
pub(crate) const KNOWN_VARS: &[&str] = &[
    "DATABASE_URL",
    "JWT_AUD",
    "JWT_ISS",
    "JWT_PUBKEY_PEM",
    "MCP_ADDR",
    "MCP_ALLOWED_HOSTS",
    "MCP_ALLOWED_ORIGINS",
    "MCP_ALLOW_ANONYMOUS_NETWORK",
    "MCP_ALLOW_EXCESSIVE_ROLE",
    "MCP_ALLOW_FUNCTIONS",
    "MCP_ALLOW_CATALOG",
    "MCP_ALLOW_PLAINTEXT_DB",
    "MCP_ALLOW_SCHEMAS",
    "MCP_PROTOCOL_PREVIEW",
    "MCP_ALLOW_TABLES",
    "MCP_AUDIT_HMAC_KEY",
    "MCP_AUDIT_HMAC_KEYS_OLD",
    "MCP_AUDIT_HMAC_KEY_FILE",
    "MCP_AUDIT_LOG",
    "MCP_AUTH_SERVERS",
    "MCP_BEARER_TOKEN",
    "MCP_DATABASE_URLS",
    "MCP_FUZZ_VERBOSE",
    "MCP_MAX_CONNECTIONS",
    "MCP_MAX_CONNECTIONS_PER_IP",
    "MCP_CONN_TIMEOUT_SECS",
    "MCP_MAX_COST",
    "MCP_MAX_INFLIGHT_PER_CLIENT",
    "MCP_METRICS_TOKEN",
    "MCP_PASSWORD_FILE",
    "MCP_CLIENT_ID",
    "MCP_PUBLIC_URL",
    "MCP_RATE_BURST",
    "MCP_RATE_RPM",
    "MCP_RATE_RPM_STDIO",
    "MCP_REDACT_COLUMNS",
    "MCP_REDACT_REQUIRE_REVOKE",
    "MCP_RESERVED_AUTH_SLOTS",
    "MCP_SEARCH_PATH",
    "MCP_SERVER_LABEL",
    "MCP_SHOW_PARTITIONS",
    "MCP_SSLROOTCERT",
    "MCP_STATEMENT_TIMEOUT",
    "MCP_STRUCTURED_CONTENT",
    "MCP_TRUST_PROXY",
];

/// Levenshtein distance, for turning "unknown variable" into "did you mean".
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Prefixes belonging to programs that legitimately share this process's environment.
///
/// `mcp-proxy` is the stdio bridge that Glama, Smithery and every other catalogue puts in front of
/// a server in order to inspect it; it exports `MCP_PROXY_DEBUG`. Until 0.1.6 that one variable was
/// enough to make this server exit 2 before it read a single request, which meant it could not be
/// listed anywhere at all. Found on 2026-08-15 by the first host that ever tried.
const FOREIGN_PREFIXES: &[&str] = &["MCP_X_", "MCP_PROXY_"];

/// Splits unknown `MCP_*` names into the ones that are ours-misspelled and the ones that are not
/// ours at all: `(fatal, ignored)`.
///
/// The distinction is the whole point. `MCP_REDACT_COLUMN` — singular, one letter short — is a
/// misspelling of a protection, and starting with redaction silently off is exactly the outcome
/// this check exists to prevent, so it still refuses to start. `MCP_PROXY_DEBUG` resembles nothing
/// we define; it was set by a program that has never heard of us, and refusing to start because
/// somebody else's variable exists is our bug, not their misconfiguration.
///
/// Takes the names rather than reading the environment so it can be tested without setting a
/// process-global variable — a parallel test that mutates the environment is a test that fails on
/// somebody else's schedule, which this suite has already paid for once.
fn classify_unknown(names: impl Iterator<Item = String>) -> (Vec<String>, Vec<String>) {
    let (mut fatal, mut ignored) = (Vec::new(), Vec::new());
    let candidates = names.filter(|k| {
        k.starts_with("MCP_")
            && !FOREIGN_PREFIXES.iter().any(|p| k.starts_with(p))
            && !KNOWN_VARS.contains(&k.as_str())
    });
    for k in candidates {
        match KNOWN_VARS
            .iter()
            .map(|known| (edit_distance(&k, known), *known))
            .min()
        {
            Some((d, known)) if d <= 3 => {
                fatal.push(format!("unknown setting {}: did you mean {}?", k, known))
            }
            _ => ignored.push(k),
        }
    }
    (fatal, ignored)
}

fn unknown_vars() -> (Vec<String>, Vec<String>) {
    classify_unknown(std::env::vars().map(|(k, _)| k))
}

/// Variables whose value must never reach the log — recorded as a fingerprint so a rotation is
/// visible without the secret ever being written down.
const SECRET_VARS: &[&str] = &[
    "MCP_BEARER_TOKEN",
    "MCP_METRICS_TOKEN",
    "MCP_AUDIT_HMAC_KEY",
    "MCP_AUDIT_HMAC_KEYS_OLD",
];

/// The settings the server is actually running with, rendered for the audit log.
///
/// A chain that begins at the first query can say what happened but never under what configuration,
/// and "was the rate limit on at the time?" is exactly the question an incident asks. Connection strings lose their password; secrets become fingerprints; the whole
/// thing is hashed into `config_fp`, which an operator can pin and compare across restarts.
fn config_snapshot() -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for name in KNOWN_VARS {
        let Ok(raw) = std::env::var(name) else {
            continue;
        };
        let rendered = if SECRET_VARS.contains(name) {
            format!(
                "sha256:{}",
                &hmac_sha256_hex(b"mcp-config-fingerprint".to_vec(), raw.as_bytes())[..8]
            )
        } else if raw.contains("://") || raw.to_ascii_lowercase().contains("password") {
            // The test for a connection string was "does it contain ://", which is one of the two
            // spellings libpq accepts and this server supports. The other, `host=… password=… `,
            // went into the audit log verbatim.
            strip_password(&raw, *name == "MCP_DATABASE_URLS")
        } else if raw.len() > 120 {
            format!("<{} bytes>", raw.len())
        } else {
            raw
        };
        out.insert((*name).to_string(), Value::String(rendered));
    }
    out
}

/// Removes the password from a connection string, keeping the shape an operator recognises.
///
/// Two parsers instead of cutting on characters, because both spellings libpq accepts have more
/// edge cases than a substring test can hold: a URL password may contain an unencoded `@` and can
/// also arrive as `?password=` or `?sslpassword=` in any letter case; the keyword form allows spaces
/// around `=` and quoted values with spaces. Each of those went into the audit log in clear text.
/// `;` separates connection strings only in `MCP_DATABASE_URLS` (`multi`); in `DATABASE_URL` it is
/// an ordinary character of a password and splitting there left the rest of the password behind.
/// Where the masker and the driver could disagree, the masker hides more, never less.
pub(crate) fn strip_password(url: &str, multi: bool) -> String {
    // The driver reads the URL form only after these two prefixes; anything else is the keyword
    // form, even with a `://` inside a password.
    let one = |part: &str| {
        let t = part.trim_start();
        if t.starts_with("postgres://") || t.starts_with("postgresql://") {
            strip_url_password(part)
        } else {
            strip_keyword_password(part)
        }
    };
    if !multi {
        return one(url);
    }
    split_unquoted(url, ';')
        .iter()
        .map(|part| match part.split_once('=') {
            // `name=url`, the way the pool reads it (db.rs)
            Some((name, rest)) if !name.contains("://") => format!("{name}={}", one(rest)),
            _ => one(part),
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Parameter names libpq and the driver know. A pair with any other name is hidden with its value:
/// it is not something either would connect with, and the most likely source of a name nobody
/// knows is a password that contained `&` or a space and spilled into the next pair.
const CONN_KEYS: &[&str] = &[
    "host",
    "hostaddr",
    "port",
    "user",
    "dbname",
    "options",
    "application_name",
    "fallback_application_name",
    "client_encoding",
    "connect_timeout",
    "tcp_user_timeout",
    "keepalives",
    "keepalives_idle",
    "keepalives_interval",
    "keepalives_retries",
    "sslmode",
    "sslnegotiation",
    "sslcert",
    "sslkey",
    "sslrootcert",
    "sslcrl",
    "sslcrldir",
    "sslsni",
    "sslcompression",
    "requiressl",
    "ssl_min_protocol_version",
    "ssl_max_protocol_version",
    "gssencmode",
    "krbsrvname",
    "gsslib",
    "gssdelegation",
    "require_auth",
    "channel_binding",
    "target_session_attrs",
    "load_balance_hosts",
    "service",
    "passfile",
    "replication",
];

fn is_conn_key(k: &str) -> bool {
    CONN_KEYS.contains(&k)
}

fn is_secret_key(k: &str) -> bool {
    k.to_ascii_lowercase().contains("password")
}

/// The driver percent-decodes parameter names (`?pass%77ord=` is `password`), so the comparison
/// has to look at the decoded text. Invalid UTF-8 decodes lossily, which only widens the match.
fn percent_decoded(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits on `sep` outside single quotes (libpq quoting, `\'` escapes a quote).
fn split_unquoted(s: &str, sep: char) -> Vec<&str> {
    let (mut out, mut start, mut quoted, mut esc) = (Vec::new(), 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if esc => esc = false,
            '\\' if quoted => esc = true,
            '\'' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// `scheme://user:pw@host/db?password=x`. The driver (tokio-postgres, like libpq) takes the
/// credentials up to the FIRST `@` anywhere in the rest of the string, without stopping at `/`,
/// `?` or `#`, so a password such as `Zm9v/YmFy` connects fine. Cutting the authority at `/`
/// left that password in the log. The string is therefore read twice, splitting the credentials at
/// the first `@` (what the driver does) and at the last one (an `@` inside the password), and
/// whatever either reading calls secret is hidden. Hiding more than the driver uses is the safe
/// direction; hiding less is the bug this replaces.
fn strip_url_password(part: &str) -> String {
    let Some(s) = part.find("://") else {
        return part.to_string();
    };
    let head = &part[..s + 3];
    let rest = &part[s + 3..];
    let mut hidden: Vec<(usize, usize)> = Vec::new();
    let ats = [None, rest.find('@'), rest.rfind('@')];
    for at in ats {
        // The reading without credentials only matters for the query when there is an `@`.
        let query_only = at.is_none() && ats[1].is_some();
        hide_in_url(rest, at, query_only, &mut hidden);
    }
    hidden.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (from, to) in hidden {
        match merged.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => merged.push((from, to)),
        }
    }
    let mut out = String::from(head);
    let mut pos = 0;
    for (from, to) in merged {
        out.push_str(&rest[pos..from]);
        out.push_str("***");
        pos = to;
    }
    out.push_str(&rest[pos..]);
    out
}

/// Marks the secret byte ranges of `rest` (the URL after `scheme://`) under one reading of where
/// the credentials end.
fn hide_in_url(rest: &str, at: Option<usize>, query_only: bool, hidden: &mut Vec<(usize, usize)>) {
    let syntax = ['/', '?', '#', '&', '=', '@'];
    let tail_start = match at {
        Some(at) => {
            let creds = &rest[..at];
            match creds.find(':') {
                // A "user" that holds URL syntax is the driver's sloppy reading of something
                // else (`h/db?password=x&a=b@c`): it is not a name an operator needs.
                Some(c)
                    if !creds[..c].contains(syntax)
                        && !is_secret_key(&percent_decoded(&creds[..c])) =>
                {
                    hidden.push((c + 1, at))
                }
                None if !creds.contains(syntax) && !is_secret_key(&percent_decoded(creds)) => {}
                _ => hidden.push((0, at)),
            }
            at + 1
        }
        None => 0,
    };
    let tail = &rest[tail_start..];
    let (hostpath, query) = match tail.find('?') {
        Some(q) => (&tail[..q], Some((tail_start + q + 1, &tail[q + 1..]))),
        None => (tail, None),
    };
    let authority_end = hostpath.find('/').unwrap_or(hostpath.len());
    // Without an `@` a `user:password` pair reads as `host:port`; a port that is not a number is
    // not a port, so it is hidden rather than guessed at.
    let mut off = tail_start;
    for chunk in hostpath[..authority_end].split(',') {
        if query_only {
            break;
        }
        let port = if chunk.starts_with('[') {
            chunk.find("]:").map(|i| i + 2)
        } else {
            chunk.find(':').map(|i| i + 1)
        };
        if let Some(i) = port {
            if !chunk[i..].bytes().all(|c| c.is_ascii_digit()) {
                hidden.push((off + i, off + chunk.len()));
            }
        }
        off += chunk.len() + 1;
    }
    if !query_only && is_secret_key(&percent_decoded(&hostpath[authority_end..])) {
        hidden.push((tail_start + authority_end, tail_start + hostpath.len()));
    }
    let Some((mut off, query)) = query else {
        return;
    };
    for kv in query.split('&') {
        let decoded = percent_decoded(kv);
        let key = kv.split_once('=').map(|(k, _)| k);
        let plain_key = key.is_some_and(|k| {
            let k = percent_decoded(k);
            is_conn_key(&k)
                || k.eq_ignore_ascii_case("password")
                || k.eq_ignore_ascii_case("sslpassword")
        });
        match key {
            // a known name keeps its name; a secret one loses its value
            Some(k) if plain_key && is_secret_key(&decoded) => {
                hidden.push((off + k.len() + 1, off + kv.len()))
            }
            Some(_) if plain_key => {}
            // anything else, including a name that carries more than a name (`password%3Dx`), goes
            _ if kv.is_empty() => {}
            _ => hidden.push((off, off + kv.len())),
        }
        off += kv.len() + 1;
    }
}

/// `key = value key2='quoted value'`: libpq's tokenizer, so `password = x` and `password='a b'`
/// are both caught. Keeps every other pair as written. A word that is not a `key=value` pair is
/// hidden (libpq rejects it, and it is most often the second half of an unquoted password with a
/// space). A password value with a backslash or an unterminated quote hides everything after it:
/// that is where two tokenizers can disagree about where the value ends.
fn strip_keyword_password(part: &str) -> String {
    let b: Vec<char> = part.chars().collect();
    let (mut i, mut pairs) = (0, Vec::new());
    while i < b.len() {
        while i < b.len() && b[i].is_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        while i < b.len() && b[i] != '=' && !b[i].is_whitespace() {
            i += 1;
        }
        let key: String = b[start..i].iter().collect();
        let mut j = i;
        while j < b.len() && b[j].is_whitespace() {
            j += 1;
        }
        if j >= b.len() || b[j] != '=' {
            // not a key=value pair: libpq refuses it, and it may be a piece of a password
            pairs.push(("***".to_string(), "***".to_string()));
            continue;
        }
        j += 1;
        while j < b.len() && b[j].is_whitespace() {
            j += 1;
        }
        let value_start = j;
        let mut unsure = false;
        if j < b.len() && b[j] == '\'' {
            j += 1;
            while j < b.len() && b[j] != '\'' {
                if b[j] == '\\' {
                    unsure = true;
                    j += 1;
                }
                j += 1;
            }
            unsure |= j >= b.len();
            j += 1;
        } else {
            while j < b.len() && !b[j].is_whitespace() {
                if b[j] == '\\' {
                    unsure = true;
                    j += 1;
                }
                j += 1;
            }
        }
        i = j.min(b.len());
        if is_secret_key(&key) {
            pairs.push((key.clone(), format!("{key}=***")));
            if unsure || part_of(&b, value_start, i).contains('\'') {
                if i < b.len() {
                    pairs.push(("***".to_string(), "***".to_string()));
                }
                break;
            }
        } else if is_conn_key(&key) {
            pairs.push((key, part_of(&b, start, i)));
        } else {
            pairs.push(("***".to_string(), "***".to_string()));
        }
    }
    pairs
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join(" ")
}

fn part_of(b: &[char], from: usize, to: usize) -> String {
    b[from..to].iter().collect()
}

/// Opens the chain with what this process is, before it serves anything.
pub(crate) fn audit_startup(transport: &str) {
    let snapshot = config_snapshot();
    let canonical = serde_json::to_string(&snapshot).unwrap_or_default();
    let mut extra = serde_json::Map::new();
    extra.insert("version".into(), json!(env!("CARGO_PKG_VERSION")));
    extra.insert("transport".into(), json!(transport));
    extra.insert(
        "config_fp".into(),
        json!(&hmac_sha256_hex(b"mcp-config-fingerprint".to_vec(), canonical.as_bytes())[..16]),
    );
    extra.insert("config".into(), Value::Object(snapshot));
    if let Some(a) = audit_log::startup_anomaly() {
        extra.insert("chain_anomaly".into(), json!(a));
    }
    audit_extra("server", "startup", None, extra);
}

pub(crate) fn preflight_config() {
    let mut fatal: Vec<String> = Vec::new();

    // A switch that used to do something and now does nothing is a lie an operator keeps believing.
    // `MCP_PROTOCOL_PREVIEW` gated `2026-07-28` until upstream cut the revision; it is the default
    // now. The variable stays recognised so an existing config line is not reported as a typo, and
    // says so once at startup rather than sitting there looking meaningful.
    if crate::protocol::preview_switch_still_set() {
        eprintln!(
            "MCP_PROTOCOL_PREVIEW is set and no longer does anything: 2026-07-28 was released \
             upstream and is now the default revision. You can remove the variable."
        );
    }

    // numbers: a typo must not silently change a threshold or switch a limit off
    for (var, allow_zero) in [
        ("MCP_RATE_RPM", true),
        ("MCP_RATE_BURST", true),
        ("MCP_MAX_INFLIGHT_PER_CLIENT", true),
        ("MCP_MAX_COST", false),
        ("MCP_MAX_CONNECTIONS", false),
        ("MCP_MAX_CONNECTIONS_PER_IP", false),
        ("MCP_CONN_TIMEOUT_SECS", false),
    ] {
        if let Ok(v) = std::env::var(var) {
            // These three are read as whole numbers; "1e3" or "2.5" would pass a float check and
            // then silently fall back to the default.
            let whole = matches!(
                var,
                "MCP_MAX_CONNECTIONS" | "MCP_MAX_CONNECTIONS_PER_IP" | "MCP_CONN_TIMEOUT_SECS"
            );
            if whole
                && v.trim().parse::<u64>().is_err()
                && v.trim().parse::<f64>().is_ok_and(|n| n > 0.0)
            {
                fatal.push(format!("{} must be a whole number ({:?})", var, v));
                continue;
            }
            match v.trim().parse::<f64>() {
                Ok(n) if n < 0.0 => fatal.push(format!("{} is negative ({})", var, v)),
                Ok(n) if n == 0.0 && !allow_zero => {
                    fatal.push(format!("{}=0 would reject every query", var))
                }
                Ok(_) => {}
                Err(_) => fatal.push(format!("{} is not a number ({:?})", var, v)),
            }
        }
    }

    // audit HMAC key: configured but unreadable = a silent downgrade to weaker protection
    if let Ok(p) = std::env::var("MCP_AUDIT_HMAC_KEY_FILE") {
        match std::fs::read(&p) {
            // Trimmed like `audit_key` trims it: a file holding only "\n" passed the length check
            // and then became NO key, the silent downgrade this check exists to prevent.
            Ok(b) if b.iter().all(|c| matches!(c, b'\n' | b'\r')) => {
                fatal.push(format!("MCP_AUDIT_HMAC_KEY_FILE {} is empty", p))
            }
            Ok(_) => {}
            Err(e) => fatal.push(format!("MCP_AUDIT_HMAC_KEY_FILE {}: {}", p, e)),
        }
    }

    // JWT public key: unparsable = auth nobody can get through
    if std::env::var("JWT_PUBKEY_PEM").map(|v| !v.trim().is_empty()) == Ok(true) {
        match jwt_pubkey_pem() {
            None => fatal.push(
                "JWT_PUBKEY_PEM is set but is neither PEM text nor a readable file path"
                    .to_string(),
            ),
            Some(pem) => {
                if jsonwebtoken::DecodingKey::from_rsa_pem(&pem).is_err() {
                    fatal.push(
                        "JWT_PUBKEY_PEM is not a valid RSA public key in PEM format".to_string(),
                    );
                }
            }
        }
        // Audience and issuer are what stop a token minted by the same provider FOR A DIFFERENT
        // APPLICATION from working here — the confused-deputy shape. `validate_token` already
        // refuses every request when they are unset, so there was never a fail-open; but the
        // refusal arrived at the first call rather than at startup, which made this the only
        // misconfiguration in the server that let the process come up and then reject everything.
        // A G4 round called it a critical bypass. It was not one. It was an inconsistency, and an
        // operator staring at a server that answers nothing deserves the same treatment as one who
        // mistyped a timeout: told before it starts.
        for var in ["JWT_AUD", "JWT_ISS"] {
            if std::env::var(var).map(|v| v.trim().is_empty()) != Ok(false) {
                fatal.push(format!(
                    "{} is required when JWT_PUBKEY_PEM is set — without it a token issued by the \
                     same provider for another application would be accepted here",
                    var
                ));
            }
        }
    }

    // Statement timeout must be a value PostgreSQL accepts; a typo would otherwise surface as a
    // failed query much later, or (worse) be silently ignored.
    if let Ok(v) = std::env::var("MCP_STATEMENT_TIMEOUT") {
        let ok = !v.trim().is_empty()
            && v.trim()
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_alphabetic() || c == ' ');
        if !ok {
            fatal.push(format!(
                "MCP_STATEMENT_TIMEOUT is not a PostgreSQL interval: {:?}",
                v
            ));
        }
    }
    if let Ok(p) = std::env::var("MCP_PASSWORD_FILE") {
        if let Err(e) = std::fs::read_to_string(&p) {
            fatal.push(format!("MCP_PASSWORD_FILE {}: {}", p, e));
        }
    }
    // TLS CA: better to learn at startup than on the first query
    if std::env::var("MCP_SSLROOTCERT").is_ok() {
        if let Err(e) = build_tls() {
            fatal.push(e);
        }
    }

    // Honest about what redaction is. It refuses references and masks values, and the panel that
    // spent an afternoon on it got past the first version fourteen different ways — the last of them
    // by asking for the column under a name the check could not match. Name-based filtering cannot
    // be a boundary against the full SQL language; the boundary is a privilege the role does not have.
    if std::env::var("MCP_BEARER_TOKEN").is_ok_and(|t| !t.trim().is_empty())
        && std::env::var("JWT_PUBKEY_PEM").is_ok_and(|t| !t.trim().is_empty())
    {
        eprintln!(
            "NOTE: MCP_BEARER_TOKEN is ignored because OAuth is configured — a valid JWT is required. \
             Accepting the shared token as an alternative would give its holder full scope and leave \
             the audit without an identity. Remove one of the two."
        );
    }

    // The listen address decides which start-up policy applies, so an unparsable one cannot be
    // discovered later — it would mean guessing whether we are exposed.
    if let Ok(v) = std::env::var("MCP_ADDR") {
        if v.trim().parse::<std::net::SocketAddr>().is_err() {
            fatal.push(format!(
                "MCP_ADDR is not an address:port ({:?}) — e.g. 127.0.0.1:8080 or 0.0.0.0:8080",
                v
            ));
        }
    }

    // An audit file we cannot write is an audit that does not exist, discovered at the moment it was
    // supposed to record something. We open it now, in the mode we will use.
    if let Ok(p) = std::env::var("MCP_AUDIT_LOG") {
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
        {
            fatal.push(format!("MCP_AUDIT_LOG {} cannot be written: {}", p, e));
        }
    }

    // Plaintext to a database on another machine sends every query and every row across the network
    // in the clear, and nothing in the protocol would tell you. Loopback is exempt: there is no wire.
    for (var, value) in [
        ("DATABASE_URL", std::env::var("DATABASE_URL").ok()),
        ("MCP_DATABASE_URLS", std::env::var("MCP_DATABASE_URLS").ok()),
    ] {
        let Some(spec) = value else { continue };
        for part in spec.split(';').filter(|s| !s.trim().is_empty()) {
            // `name=url` only when the part before `=` is a name. A connection string contains its
            // own `=` (in `?sslmode=…`), so splitting on the first one turned the whole URL into the
            // word "disable" and this check silently inspected nothing.
            let url = match part.split_once('=') {
                Some((name, rest)) if !name.contains("://") => rest,
                _ => part,
            };
            if !url.contains("sslmode=disable") {
                continue;
            }
            // The same notion of "somebody untrusted could sit on this wire" that decides the TLS
            // default, and for the same reason. Judging this one by loopback while the default judged
            // by network left the strictness inverted against the information: an operator on a
            // container network who said NOTHING got plaintext silently, and the one who wrote
            // `sslmode=disable` — the same wire, the same risk, stated out loud — was refused at
            // start-up. Punishing the more explicit of two identical deployments teaches people to be
            // vaguer, which is the opposite of what this gate is for.
            let untrusted = !db_on_trusted_network(url);
            if untrusted
                && !std::env::var("MCP_ALLOW_PLAINTEXT_DB").is_ok_and(|v| v == "i-accept-the-risk")
            {
                fatal.push(format!(
                    "{} disables TLS to a database reachable over a network outside this machine: \
                     every query and every row would cross it in the clear. Use sslmode=verify-full, \
                     or set MCP_ALLOW_PLAINTEXT_DB=i-accept-the-risk",
                    var
                ));
            }
        }
    }

    // A metrics token equal to the bearer token is not a second credential; it hands whoever scrapes
    // metrics the ability to query the database.
    if let (Ok(m), Ok(b)) = (
        std::env::var("MCP_METRICS_TOKEN"),
        std::env::var("MCP_BEARER_TOKEN"),
    ) {
        if !m.trim().is_empty() && m == b {
            fatal.push(
                "MCP_METRICS_TOKEN is the same string as MCP_BEARER_TOKEN — a scraper would hold a \
                 credential that can also read the database"
                    .to_string(),
            );
        }
    }

    // A short shared token is a guessing target twice over: on the wire, and through the audit log,
    // which records an 8-hex fingerprint of it (`bearer:<fp>`) computed with a key anyone can read in
    // the source, so a weak token can be tested offline against any copy of the log. Warn rather than
    // refuse: existing deployments keep working, and the operator is told what the number costs.
    for var in ["MCP_BEARER_TOKEN", "MCP_METRICS_TOKEN"] {
        if let Ok(t) = std::env::var(var) {
            if !t.trim().is_empty() && t.trim().len() < 24 {
                eprintln!(
                    "WARNING: {} is {} characters. Use at least 24 random ones (`openssl rand -base64 32`): \
                     a short token is easy to guess, and its fingerprint appears in the audit log.",
                    var,
                    t.trim().len()
                );
            }
        }
    }

    // Booleans and small integers: a value nobody parses is a setting nobody applied.
    for var in [
        "MCP_TRUST_PROXY",
        "MCP_SHOW_PARTITIONS",
        "MCP_STRUCTURED_CONTENT",
    ] {
        if let Ok(v) = std::env::var(var) {
            if !matches!(v.trim(), "0" | "1" | "true" | "false" | "") {
                fatal.push(format!(
                    "{} must be 0, 1, true or false — {:?} would be read as false",
                    var, v
                ));
            }
        }
    }
    if let Ok(v) = std::env::var("MCP_RESERVED_AUTH_SLOTS") {
        if v.trim().parse::<u32>().is_err() {
            fatal.push(format!(
                "MCP_RESERVED_AUTH_SLOTS is not a whole number ({:?}) — it used to fall back to a \
                 default without saying so",
                v
            ));
        }
    }

    // search_path becomes an identifier list in a SET statement. Quotes were being stripped, which
    // silently pointed queries at a different schema than the one that was asked for.
    if let Ok(v) = std::env::var("MCP_SEARCH_PATH") {
        for part in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if !part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                fatal.push(format!(
                    "MCP_SEARCH_PATH contains {:?}, which is not a plain schema name",
                    part
                ));
            }
        }
    }

    // The public URL goes into OAuth discovery metadata, where a client follows it.
    if let Ok(v) = std::env::var("MCP_PUBLIC_URL") {
        if !v.trim().is_empty() && !v.starts_with("https://") && !v.starts_with("http://localhost")
        {
            fatal.push(format!(
                "MCP_PUBLIC_URL must be an https:// URL (or http://localhost for development): {:?}",
                v
            ));
        }
    }

    let (misspelled, foreign) = unknown_vars();
    fatal.extend(misspelled);

    // Said out loud rather than swallowed: if one of these was meant for us, the operator is
    // watching a setting do nothing, and the only clue they will get is this line.
    for k in &foreign {
        eprintln!(
            "NOTE: {} is not a setting of this server and is being ignored. \
             If you meant one of ours it is spelled differently; if it belongs to another program \
             sharing this environment, nothing is wrong.",
            k
        );
    }

    if !fatal.is_empty() {
        eprintln!("CONFIGURATION ERROR — the server will not start:");
        for f in &fatal {
            eprintln!("  - {}", f);
        }
        eprintln!("Fix the above and restart (to disable a limit deliberately, set it to 0).");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn no_spelling_of_a_connection_string_leaves_a_password_in_the_log() {
        // Seven shapes found by the 0.1.12 audit; each put SEKRET into the audit record.
        for url in [
            "postgres://u:SEKRET@127.0.0.1:1/db",
            "postgres://u@127.0.0.1:1/db?password=SEKRET",
            "postgres://u:pa@SEKRET@127.0.0.1:1/db",
            "host=127.0.0.1 port=1 user=u password='a SEKRET' dbname=db",
            "host=127.0.0.1 port=1 user=u password = SEKRET dbname=db",
            "postgres://u@127.0.0.1:1/db?sslpassword=SEKRET",
            "postgres://u:x@127.0.0.1:1/db?PassWord=SEKRET",
            "a=host=h password=SEKRET;b=postgres://u:p@h/d",
            "host=h password='a;SEKRET' user=u",
            "postgres://u:SEKRET@h/d?sslmode=require&password=SEKRET#x",
        ] {
            let out = strip_password(url, url.starts_with("a="));
            assert!(!out.contains("SEKRET"), "{url} -> {out}");
        }
    }

    /// The 37 spellings of the 0.1.12 review (`/tmp/rev0112/pw/cases.txt`): slash, `?`, `#` and `;`
    /// inside a URL password, `;` in a keyword password, percent-encoded parameter names, and the
    /// shapes the driver reads differently from a URL parser.
    const REVIEW_CASES: &[&str] = &[
        "postgres://u:SEKRET@127.0.0.1:1/db",
        "postgres://u:SE@KRET@127.0.0.1:1/db",
        "postgres://u:SE%40KRET@127.0.0.1:1/db",
        "postgres://u:SE:KRET@127.0.0.1:1/db",
        "postgres://u:SE;KRET@127.0.0.1:1/db",
        "postgres://u:SE/KRET@127.0.0.1:1/db",
        "postgres://u:SE?KRET@127.0.0.1:1/db",
        "postgres://u:SE#KRET@127.0.0.1:1/db",
        "postgres://u:SE'KRET@127.0.0.1:1/db",
        "postgres://127.0.0.1:1/db?password=SEKRET",
        "postgres://127.0.0.1:1/db?PASSWORD=SEKRET",
        "postgres://127.0.0.1:1/db?sslpassword=SEKRET",
        "postgres://127.0.0.1:1/db?user=u&password=SEKRET&x=1",
        "postgres://127.0.0.1:1/db?password=SE;KRET",
        "postgres://127.0.0.1:1/db?pass%77ord=SEKRET",
        "postgres://127.0.0.1:1/db?password%3DSEKRET",
        "postgres://127.0.0.1:1/db?x=1?password=SEKRET",
        "postgres://127.0.0.1:1/db#x?password=SEKRET",
        "postgres://u:SEKRET@[::1]:1/db",
        "postgres://[::1]:1/db?password=SEKRET",
        "postgresql://u:SEKRET@127.0.0.1:1",
        "postgres://u:SEKRET@127.0.0.1:1?password=SEKRET2",
        "host=127.0.0.1 port=1 password=SEKRET",
        "host=127.0.0.1 port=1 password = SEKRET",
        "host=127.0.0.1 port=1 password='SE KRET'",
        r"host=127.0.0.1 port=1 password='SE\'KRET'",
        r"host=127.0.0.1 port=1 password='SE\\' user=SEKRET",
        r"host=127.0.0.1 port=1 password=SE\ KRET",
        "host=127.0.0.1\tport=1\tpassword=SEKRET",
        "host=127.0.0.1 port=1 password=SE;KRET",
        "host=127.0.0.1 port=1 password='SE;KRET'",
        "host=127.0.0.1 port=1 password=SE'KRET",
        "host=127.0.0.1 port=1 password='SEKRET",
        "host=127.0.0.1 port=1 password=",
        "host=127.0.0.1 port=1 sslpassword=SEKRET",
        "host=127.0.0.1 port=1 PassWord=SEKRET",
        "password=SEKRET host=127.0.0.1",
    ];

    #[test]
    fn every_spelling_from_the_review_is_masked() {
        for url in REVIEW_CASES {
            let out = strip_password(url, false);
            assert!(!out.contains("KRET"), "{url} -> {out}");
        }
        // `;` splits only the multi-connection variable, and each half is masked there too.
        let multi = strip_password(
            "prod=postgres://u:SEKRET@h/d;dev=host=h password=SE;KRET",
            true,
        );
        assert!(!multi.contains("KRET"), "{multi}");
        assert_eq!(
            strip_password("prod=postgres://u:p@h1/d;dev=postgres://v:q@h2/e", true),
            "prod=postgres://u:***@h1/d;dev=postgres://v:***@h2/e"
        );
        // An ordinary URL keeps everything but the password.
        assert_eq!(
            strip_password(
                "postgres://app:Zm9v/YmFy+cXV4@db:5432/shop?sslmode=require",
                false
            ),
            "postgres://app:***@db:5432/shop?sslmode=require"
        );
    }

    /// Whatever the driver itself accepts must lose the password the driver would use. Passwords
    /// are built from the characters that broke the earlier maskers, around a marker that must
    /// never survive.
    #[test]
    fn what_the_driver_accepts_loses_the_password_the_driver_reads() {
        let alphabet: Vec<char> = "/?#@:;&='\\ %+,[]aZ09".chars().collect();
        let mut seed: u64 = 0x2026_1124;
        let mut next = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let shapes: &[fn(&str) -> String] = &[
            |p| format!("postgres://u:{p}@127.0.0.1:1/db"),
            |p| format!("postgresql://u:{p}@[::1]:1/db?sslmode=disable"),
            |p| format!("postgres://u@127.0.0.1:1/db?password={p}"),
            |p| format!("postgres://127.0.0.1:1/db?x=1&PassWord={p}&y=2"),
            |p| format!("host=127.0.0.1 port=1 password={p}"),
            |p| format!("host=127.0.0.1 password='{p}' user=u"),
            |p| format!("password = {p} host=h"),
        ];
        let mut accepted = 0;
        for _ in 0..20_000 {
            let mut pw = String::new();
            for _ in 0..next(5) {
                pw.push(alphabet[next(alphabet.len())]);
            }
            pw.push_str("KRET");
            for _ in 0..next(5) {
                pw.push(alphabet[next(alphabet.len())]);
            }
            let s = shapes[next(shapes.len())](&pw);
            let out = strip_password(&s, false);
            if let Ok(cfg) = s.parse::<postgres::Config>() {
                if let Some(real) = cfg.get_password() {
                    let real = String::from_utf8_lossy(real);
                    if real.len() >= 4 {
                        accepted += 1;
                        assert!(
                            !out.contains(real.as_ref()),
                            "{s} -> {out} (password {real})"
                        );
                    }
                }
            }
            assert!(!out.contains("KRET"), "{s} -> {out}");
        }
        assert!(
            accepted > 1000,
            "only {accepted} strings were accepted by the driver"
        );
    }

    #[test]
    fn stripping_a_password_keeps_the_parts_an_operator_needs() {
        assert_eq!(
            strip_password(
                "postgres://app:SEKRET@db.example.com:5432/shop?sslmode=require",
                false
            ),
            "postgres://app:***@db.example.com:5432/shop?sslmode=require"
        );
        assert_eq!(
            strip_password("postgres://u:pa@SEKRET@h/d", false),
            "postgres://u:***@h/d"
        );
        assert_eq!(
            strip_password("host=h port=5432 user=u password = SEKRET dbname=d", false),
            "host=h port=5432 user=u password=*** dbname=d"
        );
    }
    use super::*;

    fn classify(names: &[&str]) -> (Vec<String>, Vec<String>) {
        classify_unknown(names.iter().map(|s| s.to_string()))
    }

    #[test]
    fn a_misspelled_protection_still_refuses_to_start() {
        // The reason this check exists at all: one letter short and redaction is off, silently.
        let (fatal, ignored) = classify(&["MCP_REDACT_COLUMN"]);
        assert_eq!(ignored, Vec::<String>::new());
        assert_eq!(fatal.len(), 1);
        assert!(
            fatal[0].contains("did you mean MCP_REDACT_COLUMNS?"),
            "{:?}",
            fatal
        );
    }

    #[test]
    fn mcp_proxy_debug_does_not_stop_the_server() {
        // 0.1.5 exited 2 on this, which made the server impossible to list in any catalogue.
        let (fatal, ignored) = classify(&["MCP_PROXY_DEBUG"]);
        assert_eq!(fatal, Vec::<String>::new());
        assert_eq!(
            ignored,
            Vec::<String>::new(),
            "a known foreign prefix is not even worth a note"
        );
    }

    #[test]
    fn an_unrelated_mcp_variable_is_noted_but_not_fatal() {
        let (fatal, ignored) = classify(&["MCP_SOMEBODY_ELSES_GATEWAY_FLAG"]);
        assert_eq!(fatal, Vec::<String>::new());
        assert_eq!(ignored, vec!["MCP_SOMEBODY_ELSES_GATEWAY_FLAG".to_string()]);
    }

    #[test]
    fn the_reserved_prefix_and_known_settings_are_untouched() {
        let (fatal, ignored) =
            classify(&["MCP_X_ANYTHING", "MCP_MAX_COST", "DATABASE_URL", "PATH"]);
        assert_eq!(fatal, Vec::<String>::new());
        assert_eq!(ignored, Vec::<String>::new());
    }

    #[test]
    fn both_kinds_are_reported_separately_in_one_pass() {
        let (fatal, ignored) = classify(&[
            "MCP_RATE_RPMM",
            "MCP_PROXY_DEBUG",
            "MCP_WHATEVER_ELSE_ENTIRELY",
        ]);
        assert_eq!(fatal.len(), 1, "only the near miss is fatal: {:?}", fatal);
        assert!(fatal[0].contains("MCP_RATE_RPMM"));
        assert_eq!(ignored, vec!["MCP_WHATEVER_ELSE_ENTIRELY".to_string()]);
    }
}
