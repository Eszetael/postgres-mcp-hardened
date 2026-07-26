//! # postgres-mcp-hardened
//!
//! A secure, read-only PostgreSQL MCP (Model Context Protocol) server — a hardened
//! alternative to the deprecated `@modelcontextprotocol/server-postgres`.
//!
//! Read-only is enforced twice (AST validation via `sqlparser` + `default_transaction_read_only`),
//! with statement timeouts, an `EXPLAIN` cost guard, prompt-injection-aware output, structured
//! non-leaking errors, optional OAuth 2.1, and a tamper-evident audit log. Streamable HTTP + stdio.
//!
//! See the README for configuration and the security model.

use serde_json::{json, Value};
mod audit_log;
#[allow(dead_code)]
mod auth;
mod db;
mod fuzz;
mod http;
mod tools;

// Everything the modules share lives behind one crate-root prelude, so each module needs a single
// `use crate::*;` rather than a shifting list of paths.
pub(crate) use audit_log::*;
pub(crate) use db::*;
pub(crate) use http::*;
pub(crate) use tools::*;
mod pipeline;
mod posture;
mod protocol;
mod ratelimit;
mod setup_sql;
mod surface;
mod validate;

use axum::routing::get;
use axum::{
    extract::{ConnectInfo, Json, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

// --- Session state (simple, in memory) ---
#[derive(Clone, Default)]
pub(crate) struct AppState {
    /// value = last use (seconds since process start). The map MUST have a cap and a TTL:
    /// `initialize` is unauthenticated by design, so without one anybody could inflate it
    /// without bound — the very defence already present in the rate limiter.
    sessions: Arc<tokio::sync::RwLock<std::collections::HashMap<String, u64>>>,
}

/// How many sessions we keep, and for how long while idle.
pub(crate) const MAX_SESSIONS: usize = 10_000;
pub(crate) const SESSION_IDLE_SECS: u64 = 3_600;

pub(crate) static PROC_START: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);
pub(crate) fn uptime_secs() -> u64 {
    PROC_START.elapsed().as_secs()
}

// --- MAIN ENTRY POINT ---
#[tokio::main]
pub(crate) async fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Dev/CI: run one statement through the validator and exit.
    if let Some(pos) = args.iter().position(|a| a == "--validate") {
        let sql = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
        match validate::validate_readonly(sql) {
            Ok(()) => println!("ALLOW"),
            Err(e) => println!("REJECT: {}", e),
        }
        return;
    }
    // Dev/CI/auto-research: deterministyczny fuzz walidatora (bez bazy, bez LLM).
    // `--fuzz [iterations] [seed]`; exits 1 when an invariant breaks (suitable as a CI gate).
    if let Some(pos) = args.iter().position(|a| a == "--fuzz") {
        let iters: u64 = args
            .get(pos + 1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(200_000);
        let seed: u64 = args
            .get(pos + 2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0x5EED_1234);
        let r = fuzz::run(iters, seed);
        println!(
            "fuzz: {} iteracji, seed {}, najwolniejsza walidacja {} ms",
            r.iters, r.seed, r.slowest_ms
        );
        if r.slowest_ms > 0 {
            println!("  slowest input: {}", r.slowest_input);
        }
        if r.findings.is_empty() {
            println!("RESULT: 0 invariant violations");
            return;
        }
        println!("RESULT: {} VIOLATIONS", r.findings.len());
        for f in &r.findings {
            println!("- [{}] {}\n    {}", f.kind, f.input, f.detail);
        }
        std::process::exit(1);
    }
    // Dev: show the TEXT that would actually reach the database (canonical AST + enforced LIMIT).
    // We validate one thing and execute another — this command lets harnesses compare the two.
    // Generates the least-privilege role to connect as. Prints; never executes — see setup_sql.rs.
    if args.iter().any(|a| a == "--print-setup-sql") {
        // On the blocking pool: the PostgreSQL driver is synchronous, and blocking on a runtime
        // thread panics. Same reason as the start-up check.
        let a = args.clone();
        let rc = tokio::task::spawn_blocking(move || setup_sql::run(&a))
            .await
            .unwrap_or(2);
        std::process::exit(rc);
    }
    if let Some(pos) = args.iter().position(|a| a == "--canon") {
        let sql = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
        match validate::enforce_limit(sql, 1000) {
            Ok(c) => println!("{}", c),
            Err(e) => println!("ERR: {}", e),
        }
        return;
    }
    /// Write a line of command-line output, and treat a closed pipe as the end of the job.
    ///
    /// `println!` panics when stdout goes away, which is what every other Unix tool treats as "the
    /// reader has seen enough". `--verify-audit … | head` printed a Rust panic and a non-zero status
    /// on a log long enough to race — it looked like the verification had failed when it had not.
    /// Every other write error is still real and still reported.
    fn say(line: String) {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        match out
            .write_all(line.as_bytes())
            .and_then(|_| out.write_all(b"\n"))
            .and_then(|_| out.flush())
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
            Err(e) => {
                eprintln!("cannot write to stdout: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Audit chain verification. "Tamper-evident" without a tool to check it is a slogan, not a
    // control — the user must be able to confirm the log was not touched THEMSELVES, using the same
    // code that wrote it (rather than guessing our key ordering).
    if let Some(pos) = args.iter().position(|a| a == "--verify-audit") {
        let path = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
        let expect = args
            .iter()
            .position(|a| a == "--expect-last")
            .and_then(|p| args.get(p + 1))
            .map(|s| s.as_str());
        match verify_audit_file(path, expect) {
            Ok((summary, _last)) => {
                say(format!(
                    "OK ({}): {}",
                    if audit_key().is_some() {
                        "HMAC-SHA256"
                    } else {
                        "SHA-256, unkeyed"
                    },
                    summary
                ));
            }
            Err(e) => {
                say(format!("TAMPERED: {}", e));
                std::process::exit(1);
            }
        }
        return;
    }
    // Configuration is checked BEFORE we serve anyone — see `preflight_config`.
    preflight_config();
    let stdio = args.contains(&"--stdio".to_string());
    let transport = if stdio { "stdio" } else { "http" };
    audit_startup(transport);
    // Before the listener exists: a server that would refuse to serve should never have accepted a
    // connection in the first place. On the blocking pool, because the PostgreSQL driver is
    // synchronous and blocking inside a runtime thread panics.
    {
        let addr = listen_addr();
        let t = transport.to_string();
        tokio::task::spawn_blocking(move || {
            posture::enforce_start_policy(&t, &addr);
        })
        .await
        .expect("start policy check");
    }
    // In the background, deliberately. The chain should record what the server was ALLOWED to do,
    // not only what it was configured with — but that means querying the database, and doing it
    // before the listener binds meant a database that was slow, unreachable or refusing a
    // certificate held the whole process before it could answer /health. Found by the TLS test,
    // which hung here long before it could test anything about TLS.
    std::thread::spawn(posture::audit_posture);
    spawn_redaction_verification();
    if stdio {
        // stdio: run the synchronous loop on a blocking task so the runtime stays free
        tokio::task::spawn_blocking(run_stdio).await.unwrap();
    } else {
        run_http().await;
    }
}

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

// --- STDIO TRANSPORT (stara logika main, bez zmian) ---
pub(crate) fn run_stdio() {
    use std::io::{self, BufRead, Write};
    // One key for the whole session: stdio has a single peer by construction, so the limiter measures
    // this client rather than pretending to distinguish several.
    let caller_key = pipeline::stdio_caller();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    // Buffer: JSON-RPC does not require a message to fit on one line — a pretty-printed request is
    // perfectly valid, yet reading line by line discarded it silently together with its `id`, so the
    // client waited forever. We accumulate until the text parses.
    const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;
    let mut buf = String::new();
    let emit = |resp: Value, stdout: &mut io::Stdout| {
        let out = serde_json::to_string(&resp).unwrap_or_default();
        let _ = writeln!(stdout, "{}", out);
        let _ = stdout.flush();
    };
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if buf.is_empty() && line.trim().is_empty() {
            continue;
        }
        buf.push_str(&line);
        buf.push('\n');
        if buf.len() > MAX_MSG_BYTES {
            buf.clear();
            emit(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"message too large"}}),
                &mut stdout,
            );
            continue;
        }
        let req: Value = match serde_json::from_str(&buf) {
            Ok(v) => {
                buf.clear();
                v
            }
            // incomplete JSON → take another line; a real syntax error → SAY SO
            Err(e) if e.is_eof() => continue,
            Err(e) => {
                buf.clear();
                emit(
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {}", e)}}),
                    &mut stdout,
                );
                continue;
            }
        };
        // Batch (an array) was removed from the MCP 2025-06-18 specification. We reject it with an ERROR,
        // not with silence — `Value::Array::get("id")` returned None, so a batch carrying real `id`s was
        // treated as a notification and the client waited forever.
        if req.is_array() {
            emit(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"JSON-RPC batching is not supported in MCP 2025-06-18 — send one request per message"}}),
                &mut stdout,
            );
            continue;
        }
        // A NOTIFICATION is an object without `id`. JSON-RPC forbids answering it.
        if req.is_object() && req.get("id").is_none() {
            continue;
        }
        // The same gates HTTP applies. Before this, the transport most people actually use had none
        // of them, and every record in the audit named the caller "-".
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let _scope = audit_log::set_caller(Some(pipeline::stdio_caller()));
        let mut resp = match pipeline::gate(&caller_key, "stdio") {
            Ok(guards) => {
                let r = handle_request(&req);
                drop(guards);
                r
            }
            Err(rej) => pipeline::rejection_response(&rej, id.clone()),
        };
        resp["jsonrpc"] = serde_json::Value::String("2.0".into());
        resp["id"] = id;
        emit(resp, &mut stdout);
    }
}

// --- HTTP TRANSPORT ---
pub(crate) async fn run_http() {
    let addr = std::env::var("MCP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let state = AppState::default();

    let app = Router::new()
        .route("/mcp", post(mcp_handler).delete(delete_session_handler))
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_handler),
        )
        .route(
            "/.well-known/mcp/server-card.json",
            get(server_card_handler),
        )
        .with_state(state);

    let listener = TcpListener::bind(&addr).await.unwrap();
    eprintln!("MCP HTTP listening on http://{}", addr);
    // ConnectInfo: the rate limiter needs the peer address (headers are client-controlled, so untrusted).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

/// `DELETE /mcp` — explicit session termination (Streamable HTTP). Without it a client had no way
/// to clean up and the entry lingered until the TTL expired; the specification provides for this.
pub(crate) async fn delete_session_handler(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // This endpoint takes a WRITE lock on the session map — the same lock every request carrying an
    // `Mcp-Session-Id` needs. Without a rate limit it could be used to choke normal traffic.
    if let Err(msg) = http::check_origin(&headers, &listen_addr()) {
        METRICS.denied_origin.fetch_add(1, Ordering::Relaxed);
        audit("http", "denied_origin", None);
        return (StatusCode::FORBIDDEN, msg).into_response();
    }
    let key = ratelimit::client_key(
        &peer.ip().to_string(),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    );
    if !ratelimit::allow(&key) {
        METRICS.denied_rate.fetch_add(1, Ordering::Relaxed);
        audit("http", "denied_rate", None);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    // Session teardown is a state change, so it goes through the same gate as everything else on
    // this surface. It used to be reachable without a token: anyone who saw a session id (a log, a
    // proxy, a crash report) could end that client's session on an otherwise authenticated server.
    if let Err((code, msg, _)) = enforce_auth(&headers, &json!({"method": "session/delete"})) {
        METRICS.denied_auth.fetch_add(1, Ordering::Relaxed);
        audit("http", "denied_auth", None);
        return (
            StatusCode::from_u16(code).unwrap_or(StatusCode::UNAUTHORIZED),
            msg,
        )
            .into_response();
    }
    match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(sid) => {
            if state.sessions.write().await.remove(sid).is_some() {
                (StatusCode::NO_CONTENT, "").into_response()
            } else {
                (StatusCode::NOT_FOUND, "unknown session").into_response()
            }
        }
        None => (StatusCode::BAD_REQUEST, "missing Mcp-Session-Id").into_response(),
    }
}

// --- HANDLER /mcp (STREAMABLE HTTP) ---
/// The address the server was told to listen on, for checks that depend on exposure.
pub(crate) fn listen_addr() -> String {
    std::env::var("MCP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

pub(crate) async fn mcp_handler(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    METRICS.requests.fetch_add(1, Ordering::Relaxed);
    // Before anything else, including the rate limit: a browser page must not be able to reach this
    // server at all, so it should not even be able to consume the rate-limit budget.
    if let Err(msg) = http::check_origin(&headers, &listen_addr()) {
        METRICS.denied_origin.fetch_add(1, Ordering::Relaxed);
        audit("http", "denied_origin", None);
        return (StatusCode::FORBIDDEN, msg).into_response();
    }
    if let Some(why) = posture::serving_blocked() {
        let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
            "error": { "code": -32000, "message": why } });
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
    }
    // Rate limit BEFORE auth: verifying an RS256 signature costs CPU, so a flood of junk tokens must
    // bounce earlier. DB_SEM caps concurrency; this caps rate.
    let key = ratelimit::client_key(
        &peer.ip().to_string(),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    );
    if let Err(rej) = pipeline::gate_rate(&key, "http") {
        let body =
            pipeline::rejection_response(&rej, req.get("id").cloned().unwrap_or(Value::Null));
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Retry-After", HeaderValue::from_static("1"));
        return (StatusCode::TOO_MANY_REQUESTS, hdrs, Json(body)).into_response();
    }
    // An unknown `Mcp-Session-Id` must get a 404 so the client knows to initialize again
    // (Streamable HTTP). The server used to accept ANY invented id and echo it back.
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        let mut known = state.sessions.write().await;
        match known.get_mut(sid) {
            Some(last) => *last = uptime_secs(), // refresh so an active session does not expire
            None => {
                let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": -32001, "message": "unknown or expired session — reinitialize" } });
                return (StatusCode::NOT_FOUND, HeaderMap::new(), Json(body)).into_response();
            }
        }
    }
    // Second DoS gate: how many of this client requests are IN FLIGHT. Rate limiting is not enough
    // when a single query runs until `statement_timeout` — without this one client took the whole pool.
    // Once the database pool is busy we tighten the per-client cap to 1 — an attacker then needs as
    // many addresses as there are slots, instead of four times fewer.
    let slot = match pipeline::gate_in_flight(&key, "http") {
        Ok(g) => g,
        Err(rej) => {
            let body =
                pipeline::rejection_response(&rej, req.get("id").cloned().unwrap_or(Value::Null));
            let mut hdrs = HeaderMap::new();
            hdrs.insert("Retry-After", HeaderValue::from_static("1"));
            return (StatusCode::SERVICE_UNAVAILABLE, hdrs, Json(body)).into_response();
        }
    };
    // OAuth 2.1: egzekwuj token+scope (aktywne gdy JWT_PUBKEY_PEM ustawiony); initialize/tools/list pomijane.
    let caller = match enforce_auth(&headers, &req) {
        Ok(c) => c,
        Err((status, msg, tenant)) => {
            METRICS.denied_auth.fetch_add(1, Ordering::Relaxed);
            {
                // `denied_scope` (we know WHO) vs `denied_auth` (identity unknown: bad or missing signature).
                let decision = if tenant.is_some() {
                    "denied_scope"
                } else {
                    "denied_auth"
                };
                let _who = set_caller(tenant.clone());
                audit("http", decision, None);
            }
            let code = if status == 401 { -32001 } else { -32003 };
            let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null), "error": { "code": code, "message": msg } });
            let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
            let mut hdrs = HeaderMap::new();
            if status == 401 {
                // RFC 9728: a 401 must point at the protected-resource metadata so the client — and registry
                // scanners — can start OAuth discovery. Without a base URL we degrade to a bare "Bearer".
                let base = std::env::var("MCP_PUBLIC_URL").unwrap_or_default();
                let wa = if base.is_empty() {
                    "Bearer".to_string()
                } else {
                    format!(
                        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                        base.trim_end_matches('/')
                    )
                };
                if let Ok(hv) = HeaderValue::from_str(&wa) {
                    hdrs.insert("WWW-Authenticate", hv);
                }
            }
            return (sc, hdrs, Json(body)).into_response();
        }
    };
    // Batch: removed from the MCP 2025-06-18 spec. An explicit error instead of 202 "accepted"
    // (the client used to wait for responses that never came).
    if req.is_array() {
        let body = json!({ "jsonrpc": "2.0", "id": Value::Null,
            "error": { "code": -32600, "message": "JSON-RPC batching is not supported in MCP 2025-06-18 — send one request per message" } });
        return (StatusCode::BAD_REQUEST, HeaderMap::new(), Json(body)).into_response();
    }
    // Slots reserved for AUTHENTICATED traffic: a flood from anonymous addresses must not push out a
    // client holding a valid token. This works regardless of IP, so it cannot be defeated by buying
    // more addresses. With OAuth unconfigured the reservation is disabled.
    if caller.is_none() && AUTH_CONFIG.is_some() {
        let reserved: usize = std::env::var("MCP_RESERVED_AUTH_SLOTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or((MAX_DB_CONNS as usize) / 4);
        if DB_SEM.available_permits() <= reserved {
            let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32000, "message": "server busy — remaining capacity is reserved for authenticated clients" } });
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                HeaderMap::new(),
                Json(body),
            )
                .into_response();
        }
    }
    // 1. NIE MA "id" → to notyfikacja → 202 Accepted, bez body
    if req.is_object() && req.get("id").is_none() {
        // optionally: handle_request(&req) could be called here fire-and-forget
        return (
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            Json(serde_json::Value::Null),
        )
            .into_response();
    }

    // 2. Run the business logic on a BLOCKING thread — sync-postgres uses block_on internally,
    //    a z async-workera axum to panikuje („runtime within runtime"). spawn_blocking to izoluje.
    // Concurrency gate: excess parallel work gets a fast 503 "busy" instead of blocking the pool.
    // OWNERSHIP of the permit and the slot moves to the thread that ACTUALLY runs the query.
    //
    // Previously both guards lived in the HTTP future: when a client disconnected mid-request, axum
    // dropped the future, the guards were released — and `spawn_blocking` kept running the query,
    // because it is NOT cancellable. The server claimed free slots while the database ground through
    // orphaned work: 12 requests aborted after 0.2s left 4 backends busy, and the next request got a
    // 200 in 5 ms. Repeating that in a loop drained the whole pool from a single connection.
    // Now release happens only when the work finishes.
    let permit = match pipeline::gate_pool("http") {
        Ok(p) => p,
        Err(rej) => {
            let body =
                pipeline::rejection_response(&rej, req.get("id").cloned().unwrap_or(Value::Null));
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                HeaderMap::new(),
                Json(body),
            )
                .into_response();
        }
    };

    let req_logic = req.clone();
    // The negotiated revision has to be read on the thread that runs the logic: `spawn_blocking`
    // moves the work to another thread and thread-local state does not follow it.
    // Always Some: an HTTP request must not inherit the revision another client negotiated. A
    // client that sends no header is, in practice, an older client.
    // The draft carries the version in the body's `_meta`; earlier revisions use the header. Read
    // both here, because the header agreement check below needs to know which contract applies
    // before the request reaches the thread that runs it.
    let body_params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    let rev_for_request = protocol::rev_from_meta(&body_params).unwrap_or_else(|| {
        headers
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok())
            .and_then(protocol::Rev::parse)
            .unwrap_or(protocol::Rev::V20250618)
    });
    let wire_rev = Some(rev_for_request);

    // `Mcp-Method`/`Mcp-Name` must agree with the body from 2026-07-28. A proxy that routed or
    // authorised on the header while we executed the body would be deciding about a different
    // request than the one that runs — refusing the mismatch is what makes the header safe to
    // trust. The refusal is audited: it is a security event, not a parse hiccup.
    let body_method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if let Err((code, msg)) = protocol::check_header_agreement(
        rev_for_request,
        body_method,
        protocol::body_target_name(body_method, &body_params).as_deref(),
        headers.get("mcp-method").and_then(|v| v.to_str().ok()),
        headers.get("mcp-name").and_then(|v| v.to_str().ok()),
    ) {
        let _who = set_caller(caller);
        audit("http/header_mismatch", "refused", Some(&msg));
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": code, "message": msg }
            })),
        )
            .into_response();
    }
    let mut resp = tokio::task::spawn_blocking(move || {
        let _permit = permit; // released when the WORK ends, not when the client disconnects
        let _slot = slot;
        let _who = set_caller(caller); // identity visible to the audit on this thread
        let _rev = protocol::set_request_rev(wire_rev);
        handle_request(&req_logic)
    })
    .await
    .unwrap_or_else(|_| json!({ "error": { "code": -32603, "message": "internal task error" } }));

    // 3. Fill in the JSON-RPC fields
    resp["jsonrpc"] = serde_json::Value::String("2.0".into());
    resp["id"] = req["id"].clone();

    // 4. Session ID handling
    let mut resp_headers = HeaderMap::new();
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // initialize without a session id → issue a new one
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let final_session_id = if method == "initialize" && session_id.is_none() {
        let new_id = Uuid::new_v4().to_string();
        let now = uptime_secs();
        let mut s = state.sessions.write().await;
        if s.len() >= MAX_SESSIONS {
            s.retain(|_, last| now.saturating_sub(*last) < SESSION_IDLE_SECS);
            if s.len() >= MAX_SESSIONS {
                s.clear(); // still full = someone is inflating it; start clean rather than grow
            }
        }
        s.insert(new_id.clone(), now);
        new_id
    } else {
        session_id.unwrap_or_default()
    };

    if !final_session_id.is_empty() {
        resp_headers.insert(
            "mcp-session-id",
            HeaderValue::from_str(&final_session_id).unwrap(),
        );
    }

    (StatusCode::OK, resp_headers, Json(resp)).into_response()
}

// ── warstwa PG (slice 4): synchroniczny klient postgres + pool ──
use once_cell::sync::Lazy;
use postgres::Row;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

pub struct AuthConfig {
    pub pubkey: Vec<u8>,
    pub aud: String,
    pub iss: String,
}

/// Reads `JWT_PUBKEY_PEM` as either the PEM text itself or a path to a `.pem` file.
///
/// Both spellings occur in the wild — a Kubernetes secret mounts a file, a `.env` inlines the text —
/// and `MCP_SSLROOTCERT` already accepts a path, so accepting only one here was a trap that cost a
/// startup failure with a message that looked like a corrupt key.
pub(crate) fn jwt_pubkey_pem() -> Option<Vec<u8>> {
    let raw = std::env::var("JWT_PUBKEY_PEM").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("-----BEGIN") {
        return Some(raw.as_bytes().to_vec());
    }
    std::fs::read(raw).ok()
}

pub(crate) static AUTH_CONFIG: Lazy<Option<AuthConfig>> = Lazy::new(|| {
    let pem = jwt_pubkey_pem()?;
    Some(AuthConfig {
        pubkey: pem,
        aud: std::env::var("JWT_AUD").unwrap_or_default(),
        iss: std::env::var("JWT_ISS").unwrap_or_default(),
    })
});

/// Compares two secrets without revealing the length of the expected one.
///
/// The previous version short-circuited on `len() != len()`, which answers "how long is the token"
/// to anyone who can time it, and then compared only over that length. Hashing both sides first makes
/// every comparison the same fixed width regardless of what was supplied.
pub(crate) fn secret_eq(given: &str, expected: &str) -> bool {
    let key = SECRET_CMP_KEY.clone();
    let a = hmac_sha256_hex(key.clone(), given.as_bytes());
    let b = hmac_sha256_hex(key, expected.as_bytes());
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
        && a.len() == b.len()
}

/// A per-process key, so the digests compared above cannot be precomputed off-line.
static SECRET_CMP_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut k = Vec::with_capacity(32);
    k.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    k.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    k
});

/// The scope a tool call needs. Running SQL is a different privilege from reading the schema, and
/// `security_posture` deliberately sits with the read tools: an operator investigating a deployment
/// should not need the scope that lets them query it.
pub(crate) fn required_scope(tool: &str) -> &'static str {
    match tool {
        "query" | "explain_query" => "mcp:query",
        _ => "mcp:read",
    }
}

/// `mcp:admin` stands in for any scope. Kept as its own function so the rule is one line to read and
/// one line to test, rather than a condition buried in a long authorisation path.
pub(crate) fn scope_satisfied(ctx: &auth::AuthContext, needed: &str) -> bool {
    ctx.has_scope(needed) || ctx.has_scope("mcp:admin")
}

pub(crate) fn enforce_auth(
    headers: &HeaderMap,
    req: &Value,
) -> Result<Option<String>, (u16, String, Option<String>)> {
    // A shared bearer token: the simplest possible protection for people who do not run an identity
    // provider. Both alternatives have an open request for exactly this. Checked before OAuth so a
    // deployment can use either, and compared in constant time.
    // The shared token is the mechanism for deployments WITHOUT an identity provider. When OAuth is
    // configured it is ignored, and deliberately so: accepting it as an alternative let any holder of
    // the shared secret act with full scope while the audit recorded no identity at all. A caller
    // could opt out of being identified by presenting the shared token instead of their JWT — the
    // exact opposite of what the log exists for. Preflight says so at startup when both are set.
    // The one method that stays reachable without credentials, in BOTH modes. The specification
    // tells clients to call `server/discover` as a backwards-compatibility probe before they know
    // anything about the server — including whether it wants a token. It answers what we are and
    // which revisions we speak, and nothing about the database. What it must NOT answer to an
    // anonymous caller is the security posture; `handle_server_discover` decides that separately.
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method == "server/discover" {
        return Ok(None);
    }

    if AUTH_CONFIG.is_none() {
        if let Some(expected) = std::env::var("MCP_BEARER_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
        {
            let given = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            if !secret_eq(given, &expected) {
                return Err((401, "invalid or missing bearer token".into(), None));
            }
            // An identity, not a dash. A shared token names no person, but it does name a
            // credential — and when one is rotated or leaks, the log has to be able to say which
            // requests used it. The fingerprint never reveals the token itself.
            return Ok(Some(format!(
                "bearer:{}",
                &hmac_sha256_hex(b"mcp-bearer-fingerprint".to_vec(), expected.as_bytes())[..8]
            )));
        }
    }

    let cfg = match &*AUTH_CONFIG {
        Some(c) => c,
        None => return Ok(None),
    };

    // `initialize` and `tools/list` used to be exempt HERE and nowhere else, so the same door was
    // shut with a shared token and open with OAuth. An operator moving from one to the other had no
    // way of seeing that the tool inventory had just become anonymous. Whether those methods are
    // worth protecting is arguable; a policy that depends on which auth mechanism you picked is not.

    // Fail-closed: auth enabled (a pubkey is set) but JWT_AUD/JWT_ISS empty means a broken config.
    // Without this, validate_token skipped the audience check and accepted ANY token signed with the key.
    //. Wymuszamy skonfigurowany audience+issuer zamiast cichego fail-open.
    if cfg.aud.is_empty() || cfg.iss.is_empty() {
        return Err((
            500,
            "server auth misconfigured: JWT_AUD and JWT_ISS are required when auth is enabled"
                .into(),
            None,
        ));
    }

    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => return Err((401, "missing bearer token".into(), None)),
    };

    let ctx = auth::validate_token(token, &cfg.pubkey, &cfg.aud, &cfg.iss)
        .map_err(|e| (401u16, e, None))?;

    // Scope was checked for `tools/call` only. `resources/read` returns table and column names,
    // which the threat model calls reconnaissance in as many words — and a token deliberately issued
    // with no scope at all could read every schema in the database. Both are data; both need a
    // scope. Methods that reveal nothing about the database (initialize, tools/list, ping) need a
    // valid token, which they now have, but no particular right.
    let scoped = match method {
        "tools/call" => Some(required_scope(
            req.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )),
        "resources/read" | "resources/list" | "resources/templates/list" => Some("mcp:read"),
        _ => None,
    };
    if let Some(needed) = scoped {
        if !scope_satisfied(&ctx, needed) {
            // The identity IS known (the token is valid, only the scope is missing) — it must reach the audit,
            // because this is the insider/escalation case, exactly what the log exists to catch.
            return Err((
                403,
                format!("insufficient scope: {} required", needed),
                Some(ctx.tenant.clone()),
            ));
        }
    }

    Ok(Some(ctx.tenant))
}

use axum::http::header::CONTENT_TYPE;
/// Reverse-DNS namespace for `_meta` keys that are ours rather than the specification's.
pub(crate) const PRIVATE_NS: &str = "io.github.eszetael.postgres-mcp-hardened";

pub(crate) fn handle_request(req: &Value) -> Value {
    // Walidacja wersji JSON-RPC
    if req.get("jsonrpc") != Some(&json!("2.0")) {
        return json!({ "error": { "code": -32600, "message": "Invalid Request: jsonrpc must be 2.0" } });
    }

    let method = match req.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return json!({ "error": { "code": -32600, "message": "Invalid Request: missing method" } })
        }
    };

    let params = req.get("params").cloned().unwrap_or(json!({}));

    // From 2026-07-28 the version is not agreed once at the start — it rides on every request, so
    // it has to be read here, before anything decides what shape the answer takes.
    if let Some(err) = protocol::unsupported_version_error(&params) {
        return err;
    }
    let _meta_rev = protocol::rev_from_meta(&params).map(|r| protocol::set_request_rev(Some(r)));
    let rev = protocol::current();

    let resp = match method {
        "initialize" => handle_initialize(&params),
        // Required from 2026-07-28, and answered under every revision: a client may call it as a
        // backwards-compatibility probe, which only works if old servers answer it too.
        "server/discover" => handle_server_discover(),
        "tools/list" => handle_tools_list(),
        // SEP-1303: from 2025-11-25 a tool's refusal belongs in the result, so the model reads the
        // reason and rewrites the query, instead of the client seeing a broken call. The audit
        // record was already written by the code that refused — reshaping happens after, never
        // instead.
        "tools/call" => {
            protocol::shape_tool_result(handle_tools_call(&params), protocol::current())
        }
        // `ping` is part of MCP utilities — clients use it as a keepalive. The answer is an empty object;
        // not handling it made us look like a server that does not know the protocol.
        "ping" => json!({ "result": {} }),
        // Resources: the deprecated server we replace exposed every table schema as a resource.
        // Without them we are not a "drop-in" replacement — a client browsing the schema through resources
        // would lose that capability. Ours carry MORE: comments, primary keys and foreign keys.
        "resources/list" => handle_resources_list(),
        "resources/read" => handle_resources_read(&params),
        _ => {
            json!({ "error": { "code": -32601, "message": format!("Method not found: {}", method) } })
        }
    };
    // Applied once, at the edge, so no handler has to know which revision it is answering.
    protocol::decorate_result(resp, rev, method, &server_label())
}

/// What we are, which revisions we speak, and how safely we are connected.
///
/// The draft made this the first thing a client may ask, replacing the handshake. That makes it the
/// right place for the posture: a client can learn that this server is connected as a superuser
/// before it sends a single query — and, because it arrives as protocol data rather than prose, it
/// can act on it instead of hoping a model read the instructions.
pub(crate) fn handle_server_discover() -> Value {
    // The posture is genuinely useful here — a client can see it is talking to a superuser
    // connection before it sends a query. But this is the one method that answers without
    // credentials, so on a server that wants credentials it would be telling anyone who asks how
    // badly configured we are. When auth is on, the posture is available through the
    // `security_posture` tool, which requires a token and a scope. When auth is off there is
    // nobody to hide it from, and the whole point is that the agent tells the operator.
    let auth_on = AUTH_CONFIG.is_some()
        || std::env::var("MCP_BEARER_TOKEN").is_ok_and(|t| !t.trim().is_empty());
    let meta = if auth_on {
        json!({ format!("{}/postureAvailable", PRIVATE_NS): "call the security_posture tool with a token" })
    } else {
        // Namespaced under our own reverse-DNS: the specification reserves io.modelcontextprotocol/*
        json!({ format!("{}/securityPosture", PRIVATE_NS): posture::report(None) })
    };
    json!({
        "result": {
            "protocolVersions": protocol::Rev::supported(),
            "serverInfo": {
                "name": server_label(),
                "version": "0.1.0",
                "description": "Read-only PostgreSQL for AI agents, with the read-only part enforced before the database sees the statement."
            },
            "capabilities": { "tools": {}, "resources": {} },
            "instructions": posture::instructions(),
            "_meta": meta
        }
    })
}

pub(crate) fn handle_initialize(params: &Value) -> Value {
    // Answer with a revision we can actually speak: the client's if we implement it, ours otherwise.
    // The version used to be a constant, which meant we announced 2025-06-18 to a client that had
    // asked for something newer and could have had the better error contract.
    let rev = protocol::negotiate_initialize(params);
    json!({
        "result": {
            "protocolVersion": rev.as_str(),
            // MCP_SERVER_LABEL lets an operator running several instances tell them apart in the
            // client UI ("postgres-mcp-hardened (production)") instead of seeing identical entries.
            // The one channel that reaches the person, through the agent, on a transport where
            // stderr is invisible. Kept to a few sentences: a wall of text here is ignored.
            "instructions": posture::instructions(),
            "serverInfo": {
                "name": server_label(),
                "version": "0.1.0",
                // `description` on Implementation, from 2025-11-25: a client listing several
                // servers can say what each one is without the user opening its documentation.
                "description": "Read-only PostgreSQL for AI agents, with the read-only part enforced before the database sees the statement."
            },
            "capabilities": { "tools": {}, "resources": {} }
        }
    })
}

pub(crate) fn handle_tools_list() -> Value {
    // Descriptions are written for the caller that actually reads them — a model choosing between
    // eight tools with no other context. Each says what the tool answers, what it costs, and where
    // it will disappoint: a cap that applies silently, a column that is null unless someone wrote a
    // COMMENT, an extension that has to be installed. An agent told the limit in advance does not
    // have to discover it by mistaking a truncated page for the whole table.
    let tools = vec![
        tool_def(
            "query",
            "Run SQL (read-only)",
            "Run a read-only SQL query and return rows. Writes, DDL and administrative functions are refused before the statement reaches the database. \
             At most 1000 rows come back unless you pass `limit` (server maximum 10000); `truncated: true` in the response means there is more data — \
             page through it with `offset`, and give the query an ORDER BY when you do, or the rows you get on page two depend on the planner's mood.",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "a single read-only statement: SELECT, WITH, VALUES, EXPLAIN or SHOW (write `SELECT * FROM t`, not `TABLE t`)" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 1000, "description": "maximum rows to return; larger values are capped at 10000 and the response says so" },
                    "offset": { "type": "integer", "minimum": 0, "maximum": 1000000000, "default": 0, "description": "rows to skip, for paging; pair it with ORDER BY for stable pages" }
                },
                "required": ["sql"]
            })
        ),
        tool_def(
            "list_schemas",
            "List schemas",
            "List the schemas in the database, excluding PostgreSQL's own catalogs. Start here when you do not know the layout yet.",
            json!({"type": "object", "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }}),
        ),
        tool_def(
            "list_tables",
            "List tables in a schema",
            "List tables, views and materialized views in one schema, with their comments. Only objects the connected role may read are shown.",
            json!({
                "type": "object",
                "properties": { "schema": { "type": "string" }, "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } },
                "required": ["schema"]
            })
        ),
        tool_def(
            "describe_table",
            "Describe a table",
            "Column names, types, nullability, defaults and primary key for one table, plus each column's comment. \
             `description` is null unless somebody ran COMMENT ON — that means undocumented, not unused, so do not infer a column is dead from it.",
            json!({
                "type": "object",
                "properties": { "schema": { "type": "string" }, "table": { "type": "string" }, "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } },
                "required": ["schema", "table"]
            })
        ),
        tool_def(
            "explain_query",
            "Explain one query",
            "Why THIS statement is slow: the PostgreSQL execution plan for a query you provide. With analyze=true it actually runs the query and reports \
             measured timings and buffer usage (still read-only, still rolled back). Use it on a specific statement; use top_queries to find out which statement to look at.",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string" },
                    "analyze": { "type": "boolean", "default": false, "description": "run the query and report real timings instead of estimates" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                },
                "required": ["sql"]
            })
        ),
        tool_def(
            "database_health",
            "Health snapshot",
            "One snapshot of the things an operator would otherwise assemble by hand: cache hit ratio, connections, long-running statements and abandoned \
             transactions, vacuum backlog, invalid indexes, sequences near their ceiling, replication lag. Scoped to the current database; anything the \
             connected role cannot read is reported as unavailable rather than left out.",
            json!({
                "type": "object",
                "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }
            })
        ),
        tool_def(
            "top_queries",
            "Slowest statements server-wide",
            "WHICH statements cost the most, ranked by total execution time across the whole server. Requires the pg_stat_statements extension; if it is \
             missing the answer says how to enable it. Take the statement you find here to explain_query for the plan.",
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                }
            })
        ),
        tool_def(
            "security_posture",
            "What this server can and cannot do",
            "What this deployment is actually able to do to your database, asked of PostgreSQL rather than \
             assumed: whether the connected role can write, bypass row-level security or reach server files; \
             whether the transport is authenticated; whether the audit chain is keyed; whether the connection \
             is encrypted. Returns a grade and, for anything wrong, the command that fixes it. Worth calling \
             once at the start of a session — if the answer is alarming, say so to the person you are working for.",
            json!({
                "type": "object",
                "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }
            })
        ),
        tool_def(
            "analyze_indexes",
            "Index findings",
            "Indexes nobody uses, genuine duplicates, and tables scanned sequentially often enough that an index would likely pay off. Counters come from \
             pg_stat_*, which reset with the server — read them after real traffic, not after a restart. Primary-key and unique indexes are excluded from \
             the unused list on purpose: they earn their keep by enforcing a constraint.",
            json!({
                "type": "object",
                "properties": {
                    "schema": { "type": "string", "default": "public" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                }
            })
        ),
    ];
    json!({ "result": { "tools": tools } })
}

/// Why an agent needs this: without a plan it guesses why a query is slow, and its guesses are
/// confident and usually wrong. `analyze` actually executes the statement — safe here because the
/// statement is validated read-only first and runs inside the transaction we always roll back.
pub(crate) fn handle_explain_query(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let sql = match args.get("sql").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_content(-32602, "missing 'sql'".into()),
    };
    if let Err(e) = validate::validate_readonly(sql) {
        audit("explain_query", "denied_validation", Some(sql));
        return err_content(-32602, e.to_string());
    }
    let analyze = args
        .get("analyze")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // With `analyze` the statement REALLY RUNS, and this path had none of the protections the query
    // tool applies: no cost guard, no row limit, no byte ceiling. `EXPLAIN (ANALYZE) SELECT` over a
    // cross join executed for the whole statement_timeout and returned whatever it produced —
    // a denial of service and a way round the cost guard, available to any caller. Planning alone
    // (`analyze: false`) is cheap and needs neither: running the guard there would double the work
    // for no gain, since the guard is itself an EXPLAIN.
    let inner = if analyze {
        let capped = match validate::enforce_limit(sql, MAX_LIMIT) {
            Ok(s) => s,
            Err(e) => {
                audit("explain_query", "denied_validation", Some(sql));
                return err_content(-32602, e.to_string());
            }
        };
        if is_row_query(&capped) {
            let max_cost: f64 = std::env::var("MCP_MAX_COST")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_000_000.0);
            match cost_guard(&capped, max_cost, db) {
                Ok(()) => {}
                Err(CostErr::TooExpensive(e)) => {
                    audit("explain_query", "denied_cost", Some(sql));
                    METRICS.denied_cost.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32001, e);
                }
                Err(CostErr::OutsideSurface(e)) => {
                    audit("explain_query", "denied_surface", Some(sql));
                    METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32602, e);
                }
                Err(CostErr::QueryError(e)) => {
                    audit("explain_query", "error", Some(sql));
                    METRICS.errors.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32000, e);
                }
            }
        }
        capped
    } else {
        sql.to_string()
    };
    let opts = if analyze {
        "FORMAT JSON, ANALYZE true, BUFFERS true"
    } else {
        "FORMAT JSON"
    };
    let stmt = format!("EXPLAIN ({}) {}", opts, inner);
    match query_catalog(&stmt, &[], db) {
        Ok(mut v) => {
            audit("explain_query", "allowed", Some(sql));
            attach_plan_summary(&mut v);
            ok_content(&v)
        }
        Err(e) => {
            audit("explain_query", "error", Some(sql));
            err_content(-32000, e)
        }
    }
}

/// A few lines of conclusion in front of the plan.
///
/// A plan for a ten-row query is eleven kilobytes of JSON across seventeen nodes, every one carrying
/// `Local Dirtied Blocks: 0`. The caller asked why the statement is slow; handing back the raw tree
/// makes that their problem, and for an agent it is also several thousand tokens per call. The tree
/// stays — this only says which node cost the most and where the planner's estimate was furthest
/// from reality, because a bad estimate is the usual reason a plan is wrong at all.
fn attach_plan_summary(v: &mut Value) {
    let Some(plan) = v
        .get("rows")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.as_object())
        .and_then(|o| o.values().next())
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .cloned()
    else {
        return;
    };
    let root = match plan.get("Plan") {
        Some(p) => p.clone(),
        None => return,
    };

    let mut slowest: Option<(String, f64)> = None;
    let mut worst_estimate: Option<(String, f64, f64)> = None;
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        let label = node
            .get("Relation Name")
            .and_then(|r| r.as_str())
            .map(|r| {
                format!(
                    "{} on {}",
                    node.get("Node Type")
                        .and_then(|n| n.as_str())
                        .unwrap_or("?"),
                    r
                )
            })
            .unwrap_or_else(|| {
                node.get("Node Type")
                    .and_then(|n| n.as_str())
                    .unwrap_or("?")
                    .to_string()
            });

        // Self time, not inclusive time: an inclusive figure always names the root and tells nobody
        // anything.
        if let Some(total) = node.get("Actual Total Time").and_then(|t| t.as_f64()) {
            let children: f64 = node
                .get("Plans")
                .and_then(|p| p.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.get("Actual Total Time").and_then(|t| t.as_f64()))
                        .sum()
                })
                .unwrap_or(0.0);
            let self_ms = (total - children).max(0.0);
            if slowest.as_ref().is_none_or(|(_, s)| self_ms > *s) {
                slowest = Some((label.clone(), self_ms));
            }
        }
        if let (Some(est), Some(act)) = (
            node.get("Plan Rows").and_then(|r| r.as_f64()),
            node.get("Actual Rows").and_then(|r| r.as_f64()),
        ) {
            let off = (est.max(1.0) / act.max(1.0)).max(act.max(1.0) / est.max(1.0));
            if worst_estimate.as_ref().is_none_or(|(_, e, a)| {
                off > (e.max(1.0) / a.max(1.0)).max(a.max(1.0) / e.max(1.0))
            }) {
                worst_estimate = Some((label, est, act));
            }
        }
        if let Some(children) = node.get("Plans").and_then(|p| p.as_array()) {
            stack.extend(children.iter().cloned());
        }
    }

    let mut summary = serde_json::Map::new();
    for (field, key) in [
        ("execution_ms", "Execution Time"),
        ("planning_ms", "Planning Time"),
    ] {
        if let Some(t) = plan.get(key).and_then(|t| t.as_f64()) {
            summary.insert(field.into(), json!((t * 100.0).round() / 100.0));
        }
    }
    if let Some((label, ms)) = slowest {
        summary.insert(
            "most_time_in".into(),
            json!({ "node": label, "self_ms": (ms * 100.0).round() / 100.0 }),
        );
    }
    if let Some((label, est, act)) = worst_estimate {
        let off = (est.max(1.0) / act.max(1.0)).max(act.max(1.0) / est.max(1.0));
        summary.insert(
            "worst_row_estimate".into(),
            json!({ "node": label, "estimated": est, "actual": act, "off_by": (off * 10.0).round() / 10.0 }),
        );
        if off >= 10.0 {
            summary.insert(
                "note".into(),
                json!("the planner's row estimate is off by an order of magnitude here — usually stale \
                       or missing statistics; run ANALYZE on the tables involved and read the plan again"),
            );
        }
    }
    if !summary.is_empty() {
        v["summary"] = Value::Object(summary);
    }
}

/// A health snapshot an operator would otherwise assemble by hand from half a dozen catalog views.
/// Every check degrades gracefully: a role that cannot read a view yields a note, not a failure.
pub(crate) fn handle_database_health(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    // Every query here is scoped to the CURRENT DATABASE and filtered by the caller's table
    // privileges. Both were missing and both produced confident nonsense: `pg_stat_activity` spans
    // the whole cluster, so a fresh database with two connections reported nineteen; and the catalog
    // views happily describe tables the role cannot read, so a restricted role could enumerate
    // index and table names it has no access to.
    const CHECKS: &[(&str, &str)] = &[
        (
            "cache_hit_ratio",
            "SELECT round(100.0 * (t.hit + x.hit) / NULLIF(t.hit + t.read + x.hit + x.read, 0), 2) AS pct_from_cache, \
                    t.hit + t.read + x.hit + x.read AS blocks_sampled, \
                    round(100.0 * t.hit / NULLIF(t.hit + t.read, 0), 2) AS pct_tables, \
                    round(100.0 * x.hit / NULLIF(x.hit + x.read, 0), 2) AS pct_indexes, \
                    CASE WHEN COALESCE(t.hit + t.read + x.hit + x.read, 0) = 0 \
                         THEN 'no I/O recorded yet — statistics reset with the server' END AS note \
             FROM (SELECT COALESCE(sum(heap_blks_hit), 0) AS hit, COALESCE(sum(heap_blks_read), 0) AS read \
                     FROM pg_statio_user_tables WHERE has_table_privilege(relid, 'SELECT')) t, \
                  (SELECT COALESCE(sum(idx_blks_hit), 0) AS hit, COALESCE(sum(idx_blks_read), 0) AS read \
                     FROM pg_statio_user_indexes WHERE has_table_privilege(relid, 'SELECT')) x",
        ),
        (
            "connections",
            "SELECT count(*) FILTER (WHERE datname = current_database()) AS in_use, \
                    count(*) AS in_use_cluster_wide, \
                    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections, \
                    count(*) FILTER (WHERE datname = current_database() AND state = 'idle in transaction') AS idle_in_transaction, \
                    count(*) FILTER (WHERE state IS NULL AND pid <> pg_backend_pid() \
                                     AND (backend_type IS NULL OR backend_type = 'client backend')) AS backends_not_visible \
             FROM pg_stat_activity",
        ),
        (
            // `longest_query_seconds` used to include sessions that are idle in transaction, where
            // query_start is when the LAST query ended — a connection abandoned for three hours was
            // reported as a three-hour running query, hiding the actual diagnosis. Split apart, the
            // idle-in-transaction figure now names the leak instead of disguising it.
            "longest_running",
            "SELECT round(EXTRACT(epoch FROM max(now() - query_start) FILTER (WHERE state = 'active'))::numeric, 1) AS longest_active_query_seconds, \
                    round(EXTRACT(epoch FROM max(now() - xact_start))::numeric, 1) AS longest_transaction_seconds, \
                    round(EXTRACT(epoch FROM max(now() - state_change) FILTER (WHERE state = 'idle in transaction'))::numeric, 1) AS longest_idle_in_transaction_seconds, \
                    CASE WHEN count(*) FILTER (WHERE state IS NULL AND pid <> pg_backend_pid() \
                                                AND (backend_type IS NULL OR backend_type = 'client backend')) > 0 \
                         THEN 'this role cannot see other backends (grant pg_read_all_stats or pg_monitor); the count \
                               includes PostgreSQL background processes, and the figures above describe only what this \
                               role can see — a zero here does NOT mean the database is idle' \
                         END AS note \
             FROM pg_stat_activity WHERE datname = current_database()",
        ),
        (
            "vacuum_backlog",
            "SELECT relname AS table_name, n_dead_tup AS dead_rows, n_live_tup AS live_rows, last_autovacuum, \
                    count(*) OVER () AS matching_total \
             FROM pg_stat_user_tables WHERE n_dead_tup > 1000 AND has_table_privilege(relid, 'SELECT') \
             ORDER BY n_dead_tup DESC LIMIT 10",
        ),
        (
            "invalid_indexes",
            "SELECT c.relname AS index_name, t.relname AS table_name \
             FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
             WHERE NOT i.indisvalid AND has_table_privilege(i.indrelid, 'SELECT')",
        ),
        (
            "sequences_near_limit",
            "SELECT schemaname || '.' || sequencename AS sequence, last_value, max_value, \
                    round(100.0 * last_value / NULLIF(max_value, 0), 2) AS pct_used, \
                    count(*) OVER () AS matching_total \
             FROM pg_sequences WHERE last_value IS NOT NULL \
               AND 100.0 * last_value / NULLIF(max_value, 0) > 50 ORDER BY 4 DESC LIMIT 10",
        ),
        (
            // Without this, a sequence at 95% of its ceiling was indistinguishable from no risk at
            // all: PostgreSQL returns last_value as NULL when the role lacks USAGE/SELECT, the filter
            // above drops the row, and an empty list reads as "nothing to worry about".
            // last_value is NULL for two unrelated reasons — no privilege, or never used. Reporting
            // both as "cannot read" sent a superuser hunting for a permission problem that did not
            // exist: a lie in the opposite direction, with instructions attached.
            "sequences_unreadable",
            "SELECT count(*) AS count, \
                    'this role cannot read these sequences (needs USAGE or SELECT); their headroom was NOT checked' AS note \
             FROM pg_sequences WHERE last_value IS NULL \
               AND NOT has_sequence_privilege(quote_ident(schemaname) || '.' || quote_ident(sequencename), 'SELECT,USAGE') \
             HAVING count(*) > 0",
        ),
        (
            // The check that was missing entirely. A database whose tables have never been analysed
            // has no planner statistics at all — the usual reason "everything looks healthy" and the
            // queries are still slow. vacuum_backlog cannot see it: n_dead_tup is 0 precisely because
            // nothing has collected statistics.
            "tables_never_analyzed",
            "SELECT relname AS table_name, n_live_tup AS estimated_rows, \
                    pg_size_pretty(pg_relation_size(relid)) AS size, \
                    count(*) OVER () AS matching_total \
             FROM pg_stat_user_tables \
             WHERE has_table_privilege(relid, 'SELECT') \
               AND last_analyze IS NULL AND last_autoanalyze IS NULL \
             ORDER BY pg_relation_size(relid) DESC LIMIT 10",
        ),
        (
            // Every counter above is meaningless without the window it was collected over.
            "statistics_window",
            "SELECT stats_reset AS counters_since, \
                    CASE WHEN stats_reset IS NULL \
                         THEN 'counters have never been reset — they cover the whole life of this database' \
                         END AS note \
             FROM pg_stat_database WHERE datname = current_database()",
        ),
        (
            "replication",
            "SELECT pg_is_in_recovery() AS is_standby, \
                    CASE WHEN pg_is_in_recovery() \
                         THEN round(EXTRACT(epoch FROM now() - pg_last_xact_replay_timestamp())::numeric, 1) \
                         END AS replay_lag_seconds",
        ),
    ];
    let mut out = serde_json::Map::new();
    for (name, sql) in CHECKS {
        match query_catalog(sql, &[], db) {
            Ok(v) => {
                out.insert(
                    (*name).to_string(),
                    v.get("rows").cloned().unwrap_or(Value::Null),
                );
            }
            // Not fatal: a least-privilege role legitimately cannot see some of these.
            Err(e) => {
                out.insert((*name).to_string(), json!({ "unavailable": e }));
            }
        }
    }
    audit("database_health", "allowed", None);
    ok_content(&Value::Object(out))
}

/// The heaviest statements, from pg_stat_statements. When the extension is absent we say so and
/// how to enable it — a missing extension is a setup fact, not an error the agent should retry.
pub(crate) fn handle_top_queries(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(50) as i64;
    let sql = format!(
        "SELECT calls, round(total_exec_time::numeric, 1) AS total_ms,                 round(mean_exec_time::numeric, 2) AS mean_ms, rows,                 left(query, 300) AS query, count(*) OVER () AS matching_total          FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT {}",
        limit
    );
    match query_catalog(&sql, &[], db) {
        Ok(v) => {
            audit("top_queries", "allowed", None);
            ok_content(&v)
        }
        Err(e) => {
            audit("top_queries", "error", None);
            // Two different setup states, two different next steps. Conflating them sent people to
            // run CREATE EXTENSION again when what they actually needed was a server restart.
            if e.contains("55000") || e.contains("must be loaded") {
                err_content(
                    -32000,
                    "pg_stat_statements is installed but not loaded — add it to shared_preload_libraries and RESTART PostgreSQL (CREATE EXTENSION alone is not enough)"
                        .into(),
                )
            } else if e.contains("does not exist") || e.contains("42P01") {
                err_content(
                    -32000,
                    "pg_stat_statements is not enabled on this server — add it to shared_preload_libraries and run CREATE EXTENSION pg_stat_statements"
                        .into(),
                )
            } else {
                err_content(-32000, e)
            }
        }
    }
}

/// Index findings that are cheap to compute and expensive to notice by hand: indexes nobody uses,
/// duplicates, and tables scanned sequentially often enough that an index would likely pay off.
pub(crate) fn handle_analyze_indexes(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let schema = args
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    // `supports_foreign_key` is the context that decides whether "unused" means "droppable".
    // idx_scan does not count the lookups a foreign-key check performs, so an index backing an FK can
    // sit at zero scans for the life of the database and still be the only thing keeping DELETE on the
    // parent table off a sequential scan. Without this the tool named indexes it was not safe to drop.
    //
    // `matching_total` exists because the list is capped at 20: a caller asking "which indexes are
    // unused" was handed 20 of 29 with nothing to indicate the rest — the same silent truncation this
    // server refuses to commit anywhere else.
    const UNUSED: &str =
        "SELECT s.relname AS table_name, s.indexrelname AS index_name, s.idx_scan AS scans, \
                pg_size_pretty(pg_relation_size(s.indexrelid)) AS size, \
                EXISTS (SELECT 1 FROM pg_constraint con \
                         WHERE con.contype = 'f' AND con.conrelid = s.relid \
                           AND con.conkey[1] = i.indkey[0]) AS supports_foreign_key, \
                count(*) OVER () AS matching_total \
         FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid \
         WHERE s.schemaname = $1 AND s.idx_scan = 0 AND NOT i.indisprimary AND NOT i.indisunique \
           AND has_table_privilege(s.relid, 'SELECT') \
         ORDER BY pg_relation_size(s.indexrelid) DESC LIMIT 20";
    // Grouping used to collapse on `indpred IS NULL`, which asks whether an index is partial but not
    // WHICH rows it covers — so `WHERE active` and `WHERE NOT active`, indexing disjoint sets, were
    // reported as duplicates. It also ignored uniqueness, so a UNIQUE index landed in a cluster with
    // ordinary ones and "drop the redundant copy" could remove the only thing enforcing uniqueness.
    // Grouping on the predicate text and on indisunique makes the claim mean what it says.
    // The grouping key has to be everything that makes two indexes interchangeable. Adding the
    // predicate was not enough: expression indexes all share indkey='0', so `lower(a)` and `upper(b)`
    // grouped together and the tool advised dropping a working index. Sort order (indoption) and
    // collation belong there for the same reason.
    //
    // Uniqueness is REPORTED, not grouped on. Grouping by it removed the most common real duplicate
    // in production — an ordinary index sitting next to an existing UNIQUE on the same column — which
    // is exactly the one worth dropping. The unique index is listed first and marked, so the answer
    // says which of the pair earns its keep instead of hiding the pair.
    const DUPLICATES: &str =
        // array_to_string, not array_agg: an array column comes back as null through the driver.
        "SELECT t.relname AS table_name, \
                array_to_string(array_agg(c.relname || CASE WHEN i.indisunique THEN ' [unique — keep this one]' ELSE '' END \
                                          ORDER BY i.indisunique DESC, c.relname), ', ') AS duplicate_indexes, \
                count(*) FILTER (WHERE i.indisunique) AS unique_in_group, \
                pg_size_pretty(sum(pg_relation_size(c.oid))) AS combined_size, count(*) OVER () AS matching_total \
         FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
              JOIN pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = $1 AND has_table_privilege(i.indrelid, 'SELECT') \
         GROUP BY t.relname, i.indrelid, i.indkey::text, i.indclass::text, i.indoption::text, \
                  i.indcollation::text, \
                  COALESCE(pg_get_expr(i.indexprs, i.indrelid), ''), \
                  COALESCE(pg_get_expr(i.indpred, i.indrelid), '') \
         HAVING count(*) > 1 ORDER BY sum(pg_relation_size(c.oid)) DESC LIMIT 20";
    const SEQ_SCANS: &str =
        "SELECT relname AS table_name, seq_scan, idx_scan, n_live_tup AS rows, \
                pg_size_pretty(pg_relation_size(relid)) AS size, count(*) OVER () AS matching_total \
         FROM pg_stat_user_tables WHERE schemaname = $1 AND seq_scan > COALESCE(idx_scan, 0) \
           AND n_live_tup > 10000 AND has_table_privilege(relid, 'SELECT') \
         ORDER BY seq_scan DESC LIMIT 10";
    if let Some(e) = schema_missing(schema, db) {
        audit("analyze_indexes", "error", None);
        return e;
    }
    let mut out = serde_json::Map::new();
    for (name, sql) in [
        ("unused_indexes", UNUSED),
        ("duplicate_indexes", DUPLICATES),
        ("tables_scanned_sequentially", SEQ_SCANS),
    ] {
        match query_catalog(sql, &[&schema], db) {
            Ok(v) => {
                out.insert(
                    name.to_string(),
                    v.get("rows").cloned().unwrap_or(Value::Null),
                );
            }
            Err(e) => {
                out.insert(name.to_string(), json!({ "unavailable": e }));
            }
        }
    }
    out.insert(
        "note".to_string(),
        Value::String(
            "Counters come from pg_stat_*, which reset with the server and start empty; read them \
             after a representative period of traffic, not straight after a restart. \
             unused_indexes deliberately omits primary-key and unique indexes: they earn their keep by \
             enforcing a constraint, so a scan count of zero does not make them removable."
                .into(),
        ),
    );
    audit("analyze_indexes", "allowed", None);
    ok_content(&Value::Object(out))
}

/// `title` is what a user sees in a client's tool list; `name` is what the model calls. Both matter:
/// agents pick tools from the description, humans approve them from the title.
///
/// The annotations are the full set from the 2025-06-18 specification rather than `readOnlyHint`
/// alone. `openWorldHint: false` because the domain is closed — the configured databases and nothing
/// else; `idempotentHint: true` because a repeated call changes nothing (the DATA may have changed
/// underneath, which is a different property and not what this hint describes).
pub(crate) fn tool_def(name: &str, title: &str, desc: &str, input_schema: Value) -> Value {
    // MCP schemas are JSON Schema 2020-12. Saying which dialect a schema is written in is not
    // decoration: a validator that guesses will guess wrong on the keywords that differ between
    // drafts, and the caller reading our schema is a machine choosing how to build the call.
    let mut input_schema = input_schema;
    if let Some(obj) = input_schema.as_object_mut() {
        obj.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
    }
    json!({
        "name": name,
        "title": title,
        "description": desc,
        "inputSchema": input_schema,
        "annotations": {
            "title": title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

pub(crate) fn handle_tools_call(params: &Value) -> Value {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({ "error": { "code": -32602, "message": "Missing tool name" } }),
    };

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "query" => handle_query_tool(&args),
        "list_schemas" => handle_list_schemas(&args),
        "list_tables" => handle_list_tables(&args),
        "describe_table" => handle_describe_table(&args),
        "explain_query" => handle_explain_query(&args),
        "database_health" => handle_database_health(&args),
        "top_queries" => handle_top_queries(&args),
        "analyze_indexes" => handle_analyze_indexes(&args),
        "security_posture" => posture::handle_security_posture(&args),
        _ => json!({ "error": { "code": -32601, "message": format!("Unknown tool: {}", name) } }),
    }
}

pub(crate) fn handle_query_tool(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let sql = match args.get("sql").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": { "code": -32602, "message": "Missing 'sql' argument" } }),
    };

    // 1. Walidacja read-only
    if let Err(e) = validate::validate_readonly(sql) {
        audit("query", "denied_validation", Some(sql));
        METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
        return json!({ "error": { "code": -32602, "message": e.to_string() } });
    }

    // 2. Limit (1000 by default). We ask the database for ONE row MORE than we return — the extra row
    //    is proof that the data was cut, so we can TELL the agent instead of quietly presenting a
    //    fragment as the whole (`returnedRows: 1000` was indistinguishable from a complete result).
    let requested_limit = args.get("limit").and_then(|v| v.as_u64());
    let limit = requested_limit.unwrap_or(1000).min(MAX_LIMIT);
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
    let final_sql = match validate::enforce_limit_offset(sql, limit.saturating_add(1), offset) {
        Ok(s) => s,
        Err(e) => return json!({ "error": { "code": -32602, "message": e.to_string() } }),
    };

    // cost guard only for queries EXPLAIN can plan (SELECT/WITH/VALUES/TABLE); EXPLAIN/SHOW are
    // skipped (you cannot EXPLAIN an EXPLAIN — statement_timeout is the backstop there).
    // EXPLAIN skips the cost guard (you cannot plan a plan), and the surface check lived inside it —
    // so `EXPLAIN VERBOSE SELECT ... FROM elsewhere` reported the table's existence, its columns, the
    // filter and the planner's row estimates, all from outside the configured surface. Row estimates
    // are an oracle: repeated with different constants they leak values, without ever running.
    if surface::active() && !is_row_query(&final_sql) {
        if let Some(inner) = validate::explained_statement(&final_sql) {
            let max_cost = f64::MAX; // the surface is the question here, not the cost
            match cost_guard(&inner, max_cost, db) {
                Ok(()) => {}
                Err(CostErr::OutsideSurface(e)) => {
                    audit("query", "denied_surface", Some(sql));
                    METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                    return json!({ "error": { "code": -32602, "message": e } });
                }
                // A plan we cannot obtain is not permission to proceed.
                Err(CostErr::QueryError(e)) | Err(CostErr::TooExpensive(e)) => {
                    audit("query", "error", Some(sql));
                    return json!({ "error": { "code": -32000, "message": e } });
                }
            }
        }
    }
    if is_row_query(&final_sql) {
        let max_cost: f64 = std::env::var("MCP_MAX_COST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000.0);
        match cost_guard(&final_sql, max_cost, db) {
            Ok(()) => {}
            Err(CostErr::TooExpensive(e)) => {
                audit("query", "denied_cost", Some(sql));
                METRICS.denied_cost.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32001, "message": e } });
            }
            Err(CostErr::OutsideSurface(e)) => {
                // Its own decision in the log: "reached somewhere it should not" is a different
                // event from "asked for too much", and an operator reviewing the chain wants to
                // tell them apart.
                audit("query", "denied_surface", Some(sql));
                METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32602, "message": e } });
            }
            Err(CostErr::QueryError(e)) => {
                // an error in the query itself (a missing column) — NOT denied_cost; an ordinary error. Audited.
                audit("query", "error", Some(sql));
                METRICS.errors.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32000, "message": e } });
            }
        }
    }
    match execute_readonly(&final_sql, db) {
        Ok(mut data) => {
            mark_truncation(&mut data, limit);
            // Say what was actually applied. A request for 50000 rows silently became 10000, and the
            // response looked identical to one that had asked for 10000 — the agent had no way to
            // tell a server cap from the end of the data.
            if requested_limit.is_some_and(|r| r > MAX_LIMIT) {
                data["requestedLimit"] = json!(requested_limit);
                data["limitNote"] = json!(format!(
                    "requested limit exceeds the server maximum of {}; {} was applied",
                    MAX_LIMIT, limit
                ));
            }
            if offset > 0 {
                data["offset"] = json!(offset);
                // The description says to add ORDER BY; the loop that pages through a table reads the
                // response, not the description. Without an ordering PostgreSQL may return the same
                // row twice across pages and never return another, and nothing in the result would
                // show it.
                if !sql.to_uppercase().contains("ORDER BY") {
                    data["pagingNote"] = json!(
                        "this query has no ORDER BY, so page boundaries are not stable — rows may \
                         repeat or be skipped between pages"
                    );
                }
            }
            audit("query", "allowed", Some(sql));
            METRICS.query_allowed.fetch_add(1, Ordering::Relaxed);
            wrap_untrusted(&data, "query")
        }
        Err(e) => {
            audit("query", "error", Some(sql));
            METRICS.errors.fetch_add(1, Ordering::Relaxed);
            json!({ "error": { "code": -32000, "message": e } })
        }
    }
}

/// Trims the result to `limit` and states plainly whether anything was cut.
///
/// The query went to the database with `LIMIT limit+1`; an extra row means there is more data. An
/// AI agent draws conclusions from what it received — "1000 rows" without a note that this is the
/// first thousand of sixteen is a quiet untruth, even when every value in it is correct.
pub(crate) fn mark_truncation(data: &mut Value, limit: u64) {
    let n = data
        .get("rows")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as u64;
    let truncated = n > limit;
    if truncated {
        if let Some(arr) = data.get_mut("rows").and_then(|r| r.as_array_mut()) {
            arr.truncate(limit as usize);
        }
        data["returnedRows"] = json!(limit);
    }
    data["truncated"] = json!(truncated);
    data["appliedLimit"] = json!(limit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A read-only token must not be able to run SQL. `explain_query` counts as running SQL because
    /// with `analyze` it really does — a distinction that would be easy to get wrong and invisible
    /// if it were.
    #[test]
    fn running_sql_needs_a_different_scope_from_reading_the_schema() {
        assert_eq!(required_scope("query"), "mcp:query");
        assert_eq!(required_scope("explain_query"), "mcp:query");
        for read_only in [
            "list_tables",
            "list_schemas",
            "describe_table",
            "security_posture",
            "database_health",
            "analyze_indexes",
            "top_queries",
            "anything_added_later",
        ] {
            assert_eq!(required_scope(read_only), "mcp:read", "{read_only}");
        }
    }

    #[test]
    fn a_reader_cannot_run_sql_and_admin_can_do_both() {
        let reader = auth::AuthContext {
            tenant: "t".into(),
            scopes: vec!["mcp:read".into()],
        };
        assert!(scope_satisfied(&reader, "mcp:read"));
        assert!(!scope_satisfied(&reader, "mcp:query"));

        let admin = auth::AuthContext {
            tenant: "t".into(),
            scopes: vec!["mcp:admin".into()],
        };
        assert!(scope_satisfied(&admin, "mcp:read"));
        assert!(scope_satisfied(&admin, "mcp:query"));

        let none = auth::AuthContext {
            tenant: "t".into(),
            scopes: vec![],
        };
        assert!(!scope_satisfied(&none, "mcp:read"));
    }

    /// Cloud connection strings (and our own documentation) use `verify-full`/`verify-ca`, which the
    /// driver does not know. Without the rewrite a new user hit "invalid connection string" on the very
    /// first step (verified against PostgreSQL with an intermediate certificate chain).
    #[test]
    fn sslmode_from_cloud_is_accepted() {
        for (input, expect) in [
            (
                "postgres://u:p@h:5432/db?sslmode=verify-full",
                "postgres://u:p@h:5432/db?sslmode=require",
            ),
            (
                "postgres://u:p@h:5432/db?sslmode=verify-ca",
                "postgres://u:p@h:5432/db?sslmode=require",
            ),
            (
                "postgres://u:p@h:5432/db?sslmode=allow",
                "postgres://u:p@h:5432/db?sslmode=prefer",
            ),
            (
                "host=h user=u sslmode=verify-full",
                "host=h user=u sslmode=require",
            ),
            (
                "postgres://u:p@h/db?sslmode=require",
                "postgres://u:p@h/db?sslmode=require",
            ),
            ("postgres://u:p@h/db", "postgres://u:p@h/db"),
        ] {
            assert_eq!(normalize_sslmode(input), expect, "input: {input}");
        }
        // after rewriting, the string MUST parse
        assert!(
            normalize_sslmode("postgres://u:p@h:5432/db?sslmode=verify-full")
                .parse::<postgres::Config>()
                .is_ok()
        );
    }

    /// `numeric` from the database must not lose digits on the way through JSON (avg(amount)
    /// 4.2006673312979002 came back as 4.2006673312979 — a quiet untruth in a number an agent reasons on).
    #[test]
    fn numeric_precision_survives_json_roundtrip() {
        let raw = r#"{"avg":4.2006673312979002,"big":12345678901234567890.123456789012345}"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            raw,
            "utrata precyzji w round-tripie JSON"
        );
    }

    /// Truncation MUST be explicit in the response (and must not overstate returnedRows).
    #[test]
    fn truncation_is_reported() {
        let mut full = json!({"returnedRows": 3, "rows": [{"a":1},{"a":2},{"a":3}]});
        mark_truncation(&mut full, 2);
        assert_eq!(full["truncated"], json!(true));
        assert_eq!(full["returnedRows"], json!(2));
        assert_eq!(full["rows"].as_array().unwrap().len(), 2);
        assert_eq!(full["appliedLimit"], json!(2));

        let mut partial = json!({"returnedRows": 2, "rows": [{"a":1},{"a":2}]});
        mark_truncation(&mut partial, 5);
        assert_eq!(partial["truncated"], json!(false));
        assert_eq!(partial["returnedRows"], json!(2));
    }

    #[test]
    fn test_initialize_returns_server_info() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let resp = handle_request(&req);
        assert!(resp.get("result").is_some());
        let result = resp["result"].as_object().unwrap();
        // A client that names no revision gets the newest we implement; one that names an older
        // revision we support gets that one back, unchanged.
        assert_eq!(result["protocolVersion"], protocol::Rev::latest().as_str());
        let older = handle_request(&json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18"}}));
        assert_eq!(older["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(result["serverInfo"]["name"], "postgres-mcp-hardened");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn test_tools_call_query_rejects_insert() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "query",
                "arguments": { "sql": "INSERT INTO users (name) VALUES ('hacker')" }
            }
        });
        // The same refusal, in whichever shape the negotiated revision calls for.
        let old = protocol::set_request_rev(Some(protocol::Rev::V20250618));
        let resp = handle_request(&req);
        assert_eq!(resp["error"]["code"], -32602);
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("read-only"),
            "the reason belongs in the message: {resp}"
        );
        drop(old);
        // From 2025-11-25 it reaches the model as a tool execution error, so it can try again
        // (SEP-1303) — the audit entry is written either way, by the code that refused.
        let new = protocol::set_request_rev(Some(protocol::Rev::V20251125));
        let resp = handle_request(&req);
        assert_eq!(resp["result"]["isError"], json!(true));
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("read-only"));
        drop(new);
    }
}
