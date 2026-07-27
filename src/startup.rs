//! Split out of `main.rs`, which had grown to 2572 lines holding the entry point, the
//! configuration gate, both transports, authorisation and the tool dispatcher at once. The
//! code below is UNCHANGED — this was a move, so that the diff reads as "the same thing,
//! somewhere else" on the most security-sensitive file in the project.

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
    std::thread::spawn(move || {
        // Per table, not per column: the fix has to be a table-level REVOKE followed by a GRANT of the
        // columns that stay. A bare `REVOKE SELECT (password) ON staff` is silently a no-op while the
        // role holds SELECT on the whole table — this server printed exactly that advice until an
        // end-to-end test followed it and the value came straight back.
        const SQL: &str = "SELECT current_user AS role, n.nspname AS schema, c.relname AS rel, \
                    array_to_string(array_agg(a.attname ORDER BY a.attnum) \
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
        for name in configured_databases() {
            let Ok(v) = query_catalog(SQL, &[&pats], Some(&name)) else {
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
                exposed.push(format!(
                    "  -- {}.{} in database {} exposes: {}\n  REVOKE SELECT ON {}.{} FROM {};\n  GRANT SELECT ({}) ON {}.{} TO {};",
                    schema, rel, name, get("exposed"),
                    schema, rel, role,
                    if keep.is_empty() { "/* no other readable columns — do not re-grant */".into() } else { keep },
                    schema, rel, role
                ));
            }
        }
        if exposed.is_empty() {
            eprintln!(
                "MCP_REDACT_COLUMNS: verified against the database — the connected role cannot read \
                 those columns anywhere. Redaction is enforced by PostgreSQL, not only by this server."
            );
            return;
        }
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
        eprintln!("(set MCP_REDACT_REQUIRE_REVOKE=1 to make this fatal instead of advisory)");
    });
}

/// Every environment variable this server reads. One list, so that a typo cannot pass for a setting.
///
/// `MCP_REDACT_COLUMN=ssn` — singular, one letter short — used to start the server with redaction
/// silently switched off, and nothing anywhere would say so. A configuration mistake that turns a
/// protection off must be louder than one that turns it on, and the only way to be loud about a
/// misspelling is to know every correct spelling.
///
/// `MCP_X_*` is reserved for whoever needs their own variables in the same environment (another MCP
/// server in the same compose file, say) and is never rejected.
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

fn unknown_vars() -> Vec<String> {
    std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("MCP_") && !k.starts_with("MCP_X_"))
        .filter(|k| !KNOWN_VARS.contains(&k.as_str()))
        .map(|k| {
            match KNOWN_VARS
                .iter()
                .map(|known| (edit_distance(&k, known), *known))
                .min()
            {
                Some((d, known)) if d <= 3 => {
                    format!("unknown setting {}: did you mean {}?", k, known)
                }
                _ => format!("unknown setting {} (no similar name exists)", k),
            }
        })
        .collect()
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
/// The chain used to begin at the first query, so it could say what happened but never under what
/// configuration — and "was the rate limit on when this happened?" is exactly the question an
/// incident asks. Connection strings lose their password; secrets become fingerprints; the whole
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
        } else if raw.contains("://") || raw.contains("password=") {
            // The test for a connection string was "does it contain ://", which is one of the two
            // spellings libpq accepts and this server supports. The other, `host=… password=… `,
            // went into the audit log verbatim.
            strip_password(&raw)
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
fn strip_password(url: &str) -> String {
    // libpq accepts two spellings and this server supports both. Only the URL form was being
    // redacted, so `host=... password=secret dbname=...` went into the audit log — and into whatever
    // collects it — in clear text, under a comment promising the opposite.
    if !url.contains("://") && url.contains("password=") {
        let mut out = String::with_capacity(url.len());
        for (i, tok) in url.split_whitespace().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            match tok.split_once('=') {
                Some((k, _)) if k.eq_ignore_ascii_case("password") => out.push_str("password=***"),
                _ => out.push_str(tok),
            }
        }
        return out;
    }
    let mut out = String::with_capacity(url.len());
    for part in url.split(';') {
        if !out.is_empty() {
            out.push(';');
        }
        match (part.find("://"), part.find('@')) {
            (Some(s), Some(at)) if at > s => {
                let creds = &part[s + 3..at];
                let user = creds.split(':').next().unwrap_or("");
                out.push_str(&part[..s + 3]);
                out.push_str(user);
                out.push_str(":***");
                out.push_str(&part[at..]);
            }
            _ => out.push_str(part),
        }
    }
    out
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
    audit_extra("server", "startup", None, extra);
}

pub(crate) fn preflight_config() {
    let mut fatal: Vec<String> = Vec::new();

    // numbers: a typo must not silently change a threshold or switch a limit off
    for (var, allow_zero) in [
        ("MCP_RATE_RPM", true),
        ("MCP_RATE_BURST", true),
        ("MCP_MAX_INFLIGHT_PER_CLIENT", true),
        ("MCP_MAX_COST", false),
    ] {
        if let Ok(v) = std::env::var(var) {
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
            Ok(b) if b.is_empty() => fatal.push(format!("MCP_AUDIT_HMAC_KEY_FILE {} is empty", p)),
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
            let remote = !(url.contains("@localhost")
                || url.contains("@127.0.0.1")
                || url.contains("@[::1]"));
            if remote
                && !std::env::var("MCP_ALLOW_PLAINTEXT_DB").is_ok_and(|v| v == "i-accept-the-risk")
            {
                fatal.push(format!(
                    "{} disables TLS to a host that is not loopback: every query and every row \
                     would cross the network in the clear. Use sslmode=verify-full, or set \
                     MCP_ALLOW_PLAINTEXT_DB=i-accept-the-risk",
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

    fatal.extend(unknown_vars());

    if !fatal.is_empty() {
        eprintln!("CONFIGURATION ERROR — the server will not start:");
        for f in &fatal {
            eprintln!("  - {}", f);
        }
        eprintln!("Fix the above and restart (to disable a limit deliberately, set it to 0).");
        std::process::exit(2);
    }
}
