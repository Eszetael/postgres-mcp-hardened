//! Connection pools, TLS and read-only execution against PostgreSQL.

use crate::*;
use once_cell::sync::Lazy;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub(crate) type PgTls = tokio_postgres_rustls::MakeRustlsConnect;
pub(crate) type PgPool = Pool<PostgresConnectionManager<PgTls>>;

/// Connection string: `DATABASE_URL`, or the first positional argument.
///
/// The deprecated server took the URL as `argv[2]`, so people migrating paste exactly that command
/// into their config. Accepting both means their existing invocation keeps working (issue #845 in
/// the upstream tracker asked for the environment variable; we support both rather than either).
pub(crate) fn database_url() -> Option<String> {
    // A password kept in a file (Kubernetes secret, systemd credential, .pgpass-style) rather than
    // in the client configuration: `MCP_PASSWORD_FILE` is substituted into the connection string.
    let with_password = |u: String| -> String {
        match std::env::var("MCP_PASSWORD_FILE")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
        {
            Some(pw) => {
                let pw = pw.trim_end_matches(['\n', '\r']);
                let enc: String = pw
                    .chars()
                    .map(|c| match c {
                        '@' => "%40".to_string(),
                        ':' => "%3A".to_string(),
                        '/' => "%2F".to_string(),
                        '#' => "%23".to_string(),
                        '?' => "%3F".to_string(),
                        c => c.to_string(),
                    })
                    .collect();
                if let Some(rest) = u
                    .strip_prefix("postgres://")
                    .or_else(|| u.strip_prefix("postgresql://"))
                {
                    let scheme = if u.starts_with("postgresql://") {
                        "postgresql://"
                    } else {
                        "postgres://"
                    };
                    // user[:pw]@host…  →  user:<file password>@host…
                    if let Some((userinfo, hostpart)) = rest.split_once('@') {
                        let user = userinfo.split(':').next().unwrap_or(userinfo);
                        return format!("{}{}:{}@{}", scheme, user, enc, hostpart);
                    }
                }
                u
            }
            None => u,
        }
    };
    if let Ok(u) = std::env::var("DATABASE_URL") {
        if !u.trim().is_empty() {
            return Some(with_password(u));
        }
    }
    std::env::args().skip(1).find(|a| {
        a.starts_with("postgres://") || a.starts_with("postgresql://") || a.contains("host=")
    })
}

/// The database name inside a connection string — used to label a single-database deployment.
pub(crate) fn database_name_of(url: &str) -> String {
    normalize_sslmode(url)
        .parse::<postgres::Config>()
        .ok()
        .and_then(|c| c.get_dbname().map(|s| s.to_string()))
        .unwrap_or_else(|| "postgres".to_string())
}

/// The `postgres` driver understands only `disable`/`prefer`/`require`, while libpq (and every cloud
/// console, and OUR OWN documentation) also uses `verify-ca`, `verify-full` and `allow`. Without this
/// rewrite, pasting a connection string from RDS or Supabase ended in "invalid connection string" —
/// on the very first step, for every new user.
///
/// The mapping is safe because OUR TLS connector always verifies the chain and the hostname anyway:
/// `verify-ca`/`verify-full` → `require` weakens nothing, and `allow` → `prefer` keeps the meaning
/// "use TLS if it is available".
pub(crate) fn normalize_sslmode(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    for (from, to) in [
        ("verify-full", "require"),
        ("verify-ca", "require"),
        ("allow", "prefer"),
    ] {
        let needle = format!("sslmode={}", from);
        if let Some(pos) = lower.find(&needle) {
            let mut out = String::with_capacity(url.len());
            out.push_str(&url[..pos]);
            out.push_str(&format!("sslmode={}", to));
            out.push_str(&url[pos + needle.len()..]);
            // recursion handles any further occurrence
            return normalize_sslmode(&out);
        }
    }
    url.to_string()
}

/// TLS connector for PostgreSQL. Without it the server cannot reach any hosted PostgreSQL
/// (RDS/Supabase/Neon/Render all require SSL) — and `NoTls` did not report that as an error, it
/// entered a retry loop and HUNG. Certificate verification is ALWAYS on: a "safe by default"
/// product does not ship a "trust anything" switch. A private CA (an RDS bundle, say) is supplied
/// through `MCP_SSLROOTCERT`. WHETHER TLS is used follows from `sslmode` in DATABASE_URL
/// (`disable` = no TLS, `prefer` = default, `require`/`verify-full` = mandatory).
pub(crate) fn build_tls() -> Result<PgTls, String> {
    // rustls 0.23 requires an explicit crypto provider; ring is pure Rust, no OpenSSL — which the
    // distroless image does not carry.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    // 1. the system store, if the image has one
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    // 2. bundled Mozilla roots — so it also works without a system store
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // 3. the operator's private CA (an RDS/Supabase bundle, or self-signed on an intranet).
    //    PEM parsing comes from rustls' own pki-types; the separate rustls-pemfile crate was
    //    dropped after cargo-deny flagged it unmaintained (RUSTSEC-2025-0134). Carrying fewer
    //    dependencies is the point of a security-first build, not a slogan.
    if let Ok(path) = std::env::var("MCP_SSLROOTCERT") {
        use rustls::pki_types::pem::PemObject;
        let certs = rustls::pki_types::CertificateDer::pem_file_iter(&path)
            .map_err(|e| format!("MCP_SSLROOTCERT: cannot read {}: {}", path, e))?;
        let mut added = 0usize;
        for cert in certs {
            let cert =
                cert.map_err(|e| format!("MCP_SSLROOTCERT: invalid PEM in {}: {}", path, e))?;
            roots
                .add(cert)
                .map_err(|e| format!("MCP_SSLROOTCERT: rejected certificate: {}", e))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!(
                "MCP_SSLROOTCERT: no certificates found in {}",
                path
            ));
        }
    }
    eprintln!(
        "TLS: {} trust anchors ({})",
        roots.len(),
        match std::env::var("MCP_SSLROOTCERT") {
            Ok(p) => format!("including private CA from {}", p),
            Err(_) => "system + bundled Mozilla roots".to_string(),
        }
    );
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(cfg))
}

/// Named connection pools. One server can serve several databases — the second most requested
/// feature against the deprecated server, where the connection string was a command-line argument
/// and a client config could therefore hold only one database per instance.
///
/// `MCP_DATABASE_URLS="prod=postgres://…;dev=postgres://…"` defines them; `DATABASE_URL` (or the
/// positional argument) remains the single-database form and is registered under the database name.
pub(crate) static PG_POOLS: Lazy<Result<Vec<(String, PgPool)>, String>> = Lazy::new(|| {
    let mut out: Vec<(String, PgPool)> = Vec::new();
    if let Ok(spec) = std::env::var("MCP_DATABASE_URLS") {
        for entry in spec.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let (name, url) = entry
                .split_once('=')
                .ok_or_else(|| format!("MCP_DATABASE_URLS: expected name=url, got {:?}", entry))?;
            let name = name.trim().to_string();
            if name.is_empty() {
                return Err("MCP_DATABASE_URLS: empty connection name".to_string());
            }
            out.push((name, build_pool(url.trim())?));
        }
        if out.is_empty() {
            return Err("MCP_DATABASE_URLS is set but defines no connections".to_string());
        }
        return Ok(out);
    }
    let url = database_url().ok_or_else(|| {
        "no connection string: set DATABASE_URL, MCP_DATABASE_URLS, or pass it as the first argument"
            .to_string()
    })?;
    let name = database_name_of(&url);
    out.push((name, build_pool(&url)?));
    Ok(out)
});

pub(crate) fn build_pool(url: &str) -> Result<PgPool, String> {
    let mut config = normalize_sslmode(url)
        .parse::<postgres::Config>()
        .map_err(|_| {
            "invalid connection string — if the password contains @ : / # or ?, percent-encode it \
             (@ becomes %40, : becomes %3A, / becomes %2F, # becomes %23)"
                .to_string()
        })?;
    // Without it, on a network that DROPS packets (rather than refusing connections) the worker
    // thread hangs forever and cannot be cancelled — requests pile up until the thread pool is gone.
    if config.get_connect_timeout().is_none() {
        config.connect_timeout(std::time::Duration::from_secs(10));
    }
    let mgr = PostgresConnectionManager::new(config, build_tls()?);
    // `build_unchecked` = a LAZY pool. `build()` connects eagerly up to max_size with a retry loop,
    // so a typo in the password made the server simply HANG for tens of seconds with no message.
    Ok(Pool::builder()
        .max_size(MAX_DB_CONNS)
        .min_idle(Some(0))
        .connection_timeout(std::time::Duration::from_secs(5))
        .build_unchecked(mgr))
}

/// Names of the configured databases, for checks that have to run against each of them.
pub(crate) fn configured_databases() -> Vec<String> {
    match PG_POOLS.as_ref() {
        Ok(pools) => pools.iter().map(|(k, _)| k.clone()).collect(),
        Err(_) => Vec::new(),
    }
}

/// The pool for a request. `None` picks the only configured database, or reports the choices.
pub(crate) fn pool_for(name: Option<&str>) -> Result<&'static PgPool, String> {
    let pools = PG_POOLS.as_ref().map_err(|e| e.clone())?;
    match name {
        Some(n) => pools
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, p)| p)
            .ok_or_else(|| {
                format!(
                    "unknown database {:?} — configured: {}",
                    n,
                    pools
                        .iter()
                        .map(|(k, _)| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }),
        None if pools.len() == 1 => Ok(&pools[0].1),
        None => Err(format!(
            "several databases are configured ({}) — pass \"database\" in the tool arguments",
            pools
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Names of all configured databases, in configuration order.
pub(crate) fn database_names() -> Vec<String> {
    PG_POOLS
        .as_ref()
        .map(|p| p.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default()
}

/// Upper bound on database connections and concurrent operations (pool exhaustion / DoS defence).
pub(crate) const MAX_DB_CONNS: u32 = 16;
/// Semaphore gating concurrent database work — excess gets a fast "busy" instead of blocking the pool.
pub(crate) static DB_SEM: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_DB_CONNS as usize)));

/// Why is the pool not handing out a connection? r2d2 says only "timed out" and the driver says
/// "db error" — neither tells the user what to fix. We make ONE direct connection attempt and
/// translate the cause into a hint. The CLIENT gets the error class only (no user, host or database
/// name — this is still an unauthenticated surface); the full text goes to the operator stderr.
/// The next step, named for the provider the connection string points at.
///
/// "Point MCP_SSLROOTCERT at the provider CA bundle" is correct and still leaves someone hunting
/// through a dashboard. Every managed provider that signs with a private CA puts that file in a
/// different place, and the first connection is exactly where a new user gives up.
fn provider_hint(url: &str) -> Option<&'static str> {
    let h = url.to_ascii_lowercase();
    if h.contains(".supabase.co") || h.contains(".supabase.com") {
        Some("Supabase signs its databases with its own CA: Dashboard → Project Settings → Database → \
              SSL configuration → download the certificate, then set MCP_SSLROOTCERT to that file")
    } else if h.contains(".rds.amazonaws.com") {
        Some("Amazon RDS bundle: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem")
    } else if h.contains(".ondigitalocean.com") {
        Some("DigitalOcean: download the CA certificate from the database cluster's Overview page")
    } else if h.contains("cloudsql") || h.contains(".gcp.") {
        Some("Google Cloud SQL: Connections → Security → download server-ca.pem")
    } else if h.contains(".azure.com") {
        Some(
            "Azure Database for PostgreSQL uses a public CA — if verification still fails, check \
              that the host name matches the certificate rather than supplying a bundle",
        )
    } else {
        None
    }
}

/// Supabase's direct database host resolves over IPv6 only (IPv4 is a paid add-on). On an
/// IPv4-only network the connection simply never establishes, which reads as "the server is down".
fn reachability_hint(url: &str) -> Option<&'static str> {
    let h = url.to_ascii_lowercase();
    if h.contains(".supabase.co") && h.contains("db.") {
        Some(
            "note: Supabase's direct host is IPv6-only — from an IPv4-only network use the \
              Supavisor pooler connection string (port 6543) instead",
        )
    } else {
        None
    }
}

/// Resolves the connection string behind a configured name, so diagnostics describe the connection
/// that actually failed.
///
/// Reading `DATABASE_URL` alone made every TLS diagnosis dead code under `MCP_DATABASE_URLS` — the
/// multi-database mode this server exists for. Worse, the fallback message told the operator to set
/// `DATABASE_URL` on a server that was configured correctly.
pub(crate) fn url_for(name: Option<&str>) -> Option<String> {
    if let Ok(spec) = std::env::var("MCP_DATABASE_URLS") {
        let entries: Vec<(String, String)> = spec
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|e| {
                e.split_once('=')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        return match name {
            Some(n) => entries.iter().find(|(k, _)| k == n).map(|(_, u)| u.clone()),
            None if entries.len() == 1 => Some(entries[0].1.clone()),
            None => None,
        };
    }
    database_url()
}

/// Whether the database lives on this machine.
///
/// One predicate, two callers, because they were drifting apart. Startup refuses an unencrypted
/// connection only to a database that is NOT here — the threat is somebody on the wire, and on a
/// loopback socket there is no wire. The posture grader did not know that rule and reported
/// plaintext to localhost as a finding, which capped a correctly configured local setup at B
/// forever and offered `sslmode=verify-full` as the fix — advice that breaks a local PostgreSQL
/// with no certificate. Two places judging the same fact must judge it with the same code.
pub(crate) fn db_is_local(url: &str) -> bool {
    url.contains("@localhost") || url.contains("@127.0.0.1") || url.contains("@[::1]")
}

/// The opening of every `pool_error_detail` message that means "the database never answered", as
/// opposed to "the database answered and said no".
///
/// Callers that must tell those apart match on this rather than re-deriving the distinction: an
/// unreachable database is a fact about the deployment, while a permission error is a fact about
/// the query, and the two deserve different answers.
pub(crate) const UNREACHABLE_PREFIX: &str = "cannot connect to PostgreSQL";

pub(crate) fn pool_error_detail(db: Option<&str>) -> String {
    let Some(url) = url_for(db) else {
        return "no connection string: set DATABASE_URL, MCP_DATABASE_URLS, or pass it as the first \
                argument"
            .to_string();
    };
    // the same normalisation as when building the pool — otherwise the ERROR path reports a false
    // cause ("invalid connection string") where the certificate was what actually failed.
    let mut cfg = match normalize_sslmode(&url).parse::<postgres::Config>() {
        Ok(c) => c,
        // The upstream tracker is full of "INVALID_URL" reports whose real cause is a password with
        // `@`, `:`, `/` or `#` in it. Say that outright instead of leaving the user to guess.
        Err(e) => {
            let _ = e;
            return "invalid connection string — if the password contains @ : / # or ?, percent-encode it \
                    (@ becomes %40, : becomes %3A, / becomes %2F, # becomes %23)"
                .to_string();
        }
    };
    // The pool has already waited its own timeout; this attempt only explains WHY, so keep it short.
    cfg.connect_timeout(std::time::Duration::from_secs(3));
    let tls = match build_tls() {
        Ok(t) => t,
        Err(e) => return e,
    };
    match cfg.connect(tls) {
        Ok(_) => "connection pool exhausted — too many concurrent queries".to_string(),
        Err(e) => {
            eprintln!("DB CONNECT FAILED: {}", e); // full message only to the server log
            if let Some(db) = e.as_db_error() {
                let hint = match db.code().code() {
                    "28P01" => "authentication failed — check the password in DATABASE_URL",
                    // The most common form of 28000 in the wild is "no pg_hba.conf entry ... SSL off":
                    // the server demands TLS and the client did not offer it. Say that plainly.
                    "28000" => {
                        // PostgreSQL words this differently across versions: "SSL off" in older
                        // releases, "no encryption" from 15 onwards. Match both.
                        let msg = db.message();
                        if msg.contains("SSL off") || msg.contains("no encryption") {
                            "the server requires TLS for this host/user — add ?sslmode=require to DATABASE_URL"
                        } else {
                            "connection rejected by pg_hba.conf — check the host, user and database rules"
                        }
                    }
                    "3D000" => "database does not exist",
                    "53300" => "too many connections on the server",
                    _ => "server refused the connection",
                };
                format!(
                    "cannot connect to PostgreSQL: {} [SQLSTATE {}]",
                    hint,
                    db.code().code()
                )
            } else {
                // No DbError = the transport layer. The precise cause sits in the error source
                // chain; surfacing it turns "TLS handshake failed" into an actionable sentence.
                // Two of the most-reported problems against the deprecated server were exactly
                // this: "self-signed certificate in certificate chain" and "unable to verify the
                // first certificate" — both a private CA (GCP, RDS) that nobody had supplied.
                let mut detail = e.to_string();
                detail.push(' ');
                let mut src: Option<&(dyn std::error::Error + 'static)> =
                    std::error::Error::source(&e);
                while let Some(s) = src {
                    detail.push_str(&s.to_string());
                    detail.push(' ');
                    src = std::error::Error::source(s);
                }
                let d = detail.to_ascii_lowercase();
                if d.contains("unknownissuer")
                    || d.contains("self-signed")
                    || d.contains("selfsigned")
                {
                    let base = "cannot connect to PostgreSQL: the server certificate is not signed by \
                                any CA we trust — typical of a private CA (Supabase, RDS, Cloud SQL, \
                                self-hosted). Point MCP_SSLROOTCERT at that provider CA bundle";
                    match provider_hint(&url) {
                        Some(h) => format!("{}. {}", base, h),
                        None => base.to_string(),
                    }
                } else if d.contains("notvalidforname") || d.contains("not valid for name") {
                    "cannot connect to PostgreSQL: the server certificate does not cover this host \
                     name — connect using the name in the certificate rather than an IP address"
                        .to_string()
                } else if d.contains("expired") {
                    "cannot connect to PostgreSQL: the server certificate has expired".to_string()
                } else {
                    format!(
                        "cannot connect to PostgreSQL: {} — check host, port and sslmode; \
                         for a private CA (e.g. an RDS bundle) point MCP_SSLROOTCERT at the PEM file{}",
                        e,
                        reachability_hint(&url)
                            .map(|h| format!(". {}", h))
                            .unwrap_or_default()
                    )
                }
            }
        }
    }
}

/// Column patterns whose values never leave the database: `MCP_REDACT_COLUMNS="password,ssn,card_number"`.
/// Matching is on the column name, case-insensitively; a `table.column` pattern also matches the
/// bare column, because a query may alias or join its way past the table name.
pub(crate) fn redact_patterns() -> &'static [String] {
    static P: Lazy<Vec<String>> = Lazy::new(|| {
        std::env::var("MCP_REDACT_COLUMNS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.rsplit('.').next().unwrap_or(&s).to_string())
                    .collect()
            })
            .unwrap_or_default()
    });
    &P
}

/// The column patterns redaction is configured with, for the response to declare.
///
/// An agent that receives `[redacted]` in a value can see it; an agent that receives a row where
/// the column was never selected cannot tell configuration from absence. Saying so up front is the
/// difference between a masked field and a silent one.
pub(crate) fn redacted_columns() -> Vec<String> {
    redact_patterns().to_vec()
}

/// Returns the column names actually masked in these rows.
///
/// Reporting the configured list instead was an echo of the settings, not a description of what
/// happened: a query against a table with no sensitive column still came back saying
/// `redactedColumns: ["password"]`, which reads as "something here was hidden".
pub(crate) fn redact_rows(rows: &mut [Value]) -> std::collections::BTreeSet<String> {
    let pats = redact_patterns();
    let mut masked = std::collections::BTreeSet::new();
    if pats.is_empty() {
        return masked;
    }
    for row in rows.iter_mut() {
        redact_value(row, pats, &mut masked);
    }
    masked
}

/// Masks matching keys at EVERY depth, in objects and inside arrays.
///
/// Masking only the top level was bypassable by one reformulation: `row_to_json(t)`,
/// `to_jsonb(t.*)` or `json_agg(t)` turn the whole row into a single nested value, so the column
/// name never appears at the top and never appears as an identifier the validator could refuse —
/// and `json_agg` returned every row at once. Walking the tree closes the whole class of
/// row-serialising functions, including ones PostgreSQL has not shipped yet, instead of listing
/// them one by one.
fn redact_value(v: &mut Value, pats: &[String], masked: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                if pats.iter().any(|p| p == &k.to_lowercase()) {
                    *val = Value::String("[redacted]".into());
                    masked.insert(k.clone());
                } else {
                    redact_value(val, pats, masked);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item, pats, masked);
            }
        }
        _ => {}
    }
}

pub(crate) fn col_to_json(row: &Row, i: usize) -> Value {
    // json/jsonb FIRST, deliberately.
    //
    // A G4 round called it a critical bug that `Option<String>` was tried before `Option<Value>`:
    // if a `json` column could be read as text, an EXPLAIN plan would arrive as an escaped string
    // instead of an object, and the agent would receive stringified structure. The claim is wrong —
    // `postgres-types` gates `try_get` on `FromSql::accepts`, and `String` accepts only VARCHAR,
    // TEXT, BPCHAR, NAME, UNKNOWN, citext and the ltree family; `json`/`jsonb` are not among them,
    // so the text branch errors and control reaches this one anyway.
    //
    // It is still worth reordering. The old code was correct only because of a detail two crates
    // away, invisible to anyone reading this function — and a reviewer who cannot see why something
    // is safe will eventually "fix" it. `Value` accepts json/jsonb and nothing else, so trying it
    // first cannot capture a value that belongs to another branch, and the correctness stops
    // depending on the order at all.
    if let Ok(v) = row.try_get::<_, Option<Value>>(i) {
        return v.unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<String>>(i) {
        return v.map(Value::String).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i32>>(i) {
        return v.map(|n| json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<i64>>(i) {
        return v.map(|n| json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<f64>>(i) {
        return v.map(|n| json!(n)).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<_, Option<bool>>(i) {
        return v.map(|b| json!(b)).unwrap_or(Value::Null);
    }
    Value::Null
}

/// Hard cap on result size (serialised bytes) — OOM/DoS defence against enormous values.
pub(crate) const MAX_RESULT_BYTES: usize = 8 * 1_048_576; // 8 MB
/// Hard upper bound on rows — the `limit` parameter is clamped to this value.
pub(crate) const MAX_LIMIT: u64 = 10_000;

/// A row-returning query that can be wrapped in a `(sql) t` subquery and planned with EXPLAIN.
/// SELECT/WITH/VALUES/TABLE — yes; EXPLAIN/SHOW — no (you cannot EXPLAIN an EXPLAIN).
pub(crate) fn is_row_query(sql: &str) -> bool {
    // Strip leading `(` and whitespace — `(SELECT ...)` is still a row query. Without this a leading
    // parenthesis bypassed the cost guard and routed the query down the wrong serialisation branch.
    let mut s = sql.trim_start();
    while let Some(rest) = s.strip_prefix('(') {
        s = rest.trim_start();
    }
    let up = s.to_uppercase();
    up.starts_with("SELECT")
        || up.starts_with("WITH")
        || up.starts_with("VALUES")
        || up.starts_with("TABLE")
}

pub(crate) fn execute_readonly(final_sql: &str, db: Option<&str>) -> Result<Value, String> {
    let pool = pool_for(db)?;
    let mut client = pool.get().map_err(|_| pool_error_detail(db))?;
    // Session-level defence in depth: timeouts + read-only (the database refuses a write even if the
    // validator let something through). DISCARD ALL resets pooled session state (Session Pollution).
    // It MUST be its own statement — a multi-statement batch is an implicit transaction, and
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| e.to_string())?;
    // Configurable, because a hardcoded ceiling is either too low for analytics or too high for a
    // shared database — the most requested setting against the leading alternative.
    client
        .batch_execute(&format!(
            "SET statement_timeout='{}'; SET idle_in_transaction_session_timeout='10s'; \
             SET default_transaction_read_only=on;{}",
            statement_timeout(),
            search_path_stmt()
        ))
        .map_err(|e| e.to_string())?;
    // EXPLICIT READ ONLY TRANSACTION, always finished with ROLLBACK.
    //
    // The session flag alone is not enough: in autocommit every statement commits immediately, so
    // anything that slipped past the validator stays in the database PERMANENTLY. Comparing with the
    // deprecated `@modelcontextprotocol/server-postgres` was sobering — it wraps each query in
    // `BEGIN TRANSACTION READ ONLY` and ends with `ROLLBACK`, so `pg_import_system_collations()`
    // (which writes DESPITE read-only) is undone there, while here it persisted 874 rows.
    // A third layer of defence, in the one place where we were weaker than what we replace.
    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .map_err(|e| e.to_string())?;

    let mut out: Vec<Value> = if is_row_query(final_sql) {
        // PostgreSQL serialises EVERY type to jsonb (numeric/enum/array/uuid/timestamptz/jsonb/point…).
        // Hand-written type mapping in Rust silently lost unhandled types to null — a bug found
        // na pagila (SUM(amount)→null, enum/array→null). to_jsonb(t) = jedna kolumna jsonb na wiersz.
        // STREAMING (query_raw) + an early bail on the byte budget. client.query() buffered the WHOLE
        // result in RAM BEFORE the cap could act — query_raw pulls rows in batches through a portal, so
        // nothing is materialised at once and we stop before it grows.
        use postgres::fallible_iterator::FallibleIterator;
        // A per-row SIZE cap computed IN POSTGRES: if a row exceeds the limit, PG returns a marker
        // instead of the value, so the RESULT stays bounded and the agent is told the row was
        // omitted rather than handed something truncated.
        //
        // What it costs us, measured 2026-08-09 on the RELEASE build, PostgreSQL 16, one request,
        // `VmHWM` of THIS process only (kernel high-water mark, so polling cannot miss the peak),
        // against a 64 MB INCOMPRESSIBLE cell (`STORAGE EXTERNAL`, random md5 text — `repeat('x')`
        // compresses away and would have measured nothing):
        //
        //     idle                        10 MB
        //     64 MB cell, row OMITTED     11 MB      <- bounded; the cap does its job
        //     7 MB payload, DELIVERED     57 MB      <- ~6.7x the payload
        //
        // So the omitted path does not grow with the cell, and the real characteristic is the
        // DELIVERED one: JSON text plus the parsed `Value` tree costs several times the payload,
        // which with an 8 MB cap bounds a request at roughly +55 MB. The instrument was checked
        // against a case that MUST grow (the 7 MB row) before the flat readings were believed.
        //
        // The note previously here recorded 2026-08-08 numbers — 4 MB cell 42 MB · 30 MB 128 MB ·
        // 60 MB 245 MB — claiming growth on the OMITTED path. They do not reproduce. Two candidate
        // explanations were tested and both failed: `VmPeak` is ~1.4 GB regardless of payload
        // (allocator arenas, not the value), and the PostgreSQL backend reading was unreliable.
        // What that run measured is not established, so it is not asserted here; what is asserted
        // is reproducible with the harness above. Note that 4 MB is UNDER the cap and therefore
        // was delivered, and 42 MB is exactly the amplification measured today — the only one of
        // those four numbers that is consistent with this code.
        // The trailing `::text` MATTERS: we take ready JSON TEXT from the database and parse it ourselves
        // instead of letting the driver deserialise jsonb its own way — that path lost digits from
        // `numeric` (avg(amount) 4.2006673312979002 → 4.2006673312979). Parsing the text with
        // `arbitrary_precision` preserves exactly what PostgreSQL computed.
        let wrapped = format!(
            "SELECT (CASE WHEN octet_length(_r::text) > {cap} \
             THEN to_jsonb('[row omitted: exceeds {cap}-byte limit]'::text) ELSE _r END)::text \
             FROM (SELECT to_jsonb(t) AS _r FROM ({sql}) t) _s",
            cap = MAX_RESULT_BYTES,
            sql = final_sql
        );
        // The iterator borrows `client`, so ROLLBACK cannot be issued inside the loop — we collect the
        // result or error into a variable and close the transaction once the borrow ends, on one path.
        let streamed: Result<Vec<Value>, String> = (|| {
            let mut it = client
                .query_raw(&wrapped, std::iter::empty::<&(dyn ToSql + Sync)>())
                .map_err(|e| friendly_pg_error_for(&e, Some(final_sql)))?;
            let mut acc: Vec<Value> = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = it
                .next()
                .map_err(|e| friendly_pg_error_for(&e, Some(final_sql)))?
            {
                // A jsonb deserialisation error is PROPAGATED (a silent null means lost data and a misled agent).
                let txt: Option<String> = row
                    .try_get::<_, Option<String>>(0)
                    .map_err(|_| "result serialization error".to_string())?;
                let txt = txt.unwrap_or_else(|| "null".to_string());
                bytes = bytes.saturating_add(txt.len());
                let v: Value = serde_json::from_str(&txt)
                    .map_err(|_| "result serialization error".to_string())?;
                if bytes > MAX_RESULT_BYTES {
                    return Err(format!(
                        "result too large (>{} MB) — add a tighter filter or smaller LIMIT",
                        MAX_RESULT_BYTES / 1_048_576
                    ));
                }
                acc.push(v);
            }
            Ok(acc)
        })();
        match streamed {
            Ok(a) => a,
            Err(e) => {
                let _ = client.batch_execute("ROLLBACK");
                return Err(e);
            }
        }
    } else {
        // EXPLAIN / SHOW — cannot be wrapped in a subquery; text columns, col_to_json is enough.
        // This branch has NO cost guard (you cannot EXPLAIN an EXPLAIN), so the byte cap is the only
        // defence here — `EXPLAIN VERBOSE` of a long UNION can return hundreds of KB of plan.
        let rows = client
            .query(final_sql, &[])
            .map_err(|e| friendly_pg_error_for(&e, Some(final_sql)))?;
        let mut acc: Vec<Value> = Vec::new();
        let mut bytes = 0usize;
        for row in rows.iter() {
            let mut mp = Map::new();
            for (i, col) in row.columns().iter().enumerate() {
                mp.insert(col.name().to_owned(), col_to_json(row, i));
            }
            let v = Value::Object(mp);
            bytes = bytes.saturating_add(serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0));
            if bytes > MAX_RESULT_BYTES {
                let _ = client.batch_execute("ROLLBACK");
                return Err(format!(
                    "result too large (>{} MB) — narrow the query",
                    MAX_RESULT_BYTES / 1_048_576
                ));
            }
            acc.push(v);
        }
        acc
    };
    // Redact configured columns before the data can reach the model. Defence in depth, not a
    // replacement for database permissions: it hides values an agent should never see even when
    // somebody writes `SELECT *`. Applied to query results only — column names are not secrets.
    let masked = redact_rows(&mut out);
    // ROLLBACK on EVERY exit path — including success (we never commit anything).
    let _ = client.batch_execute("ROLLBACK");
    let mut res = json!({ "returnedRows": out.len(), "rows": out });
    if !masked.is_empty() {
        res["redactedColumns"] = json!(masked.iter().collect::<Vec<_>>());
    }
    Ok(res)
}

use postgres::types::ToSql;

pub(crate) fn query_catalog(
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    db: Option<&str>,
) -> Result<Value, String> {
    let pool = pool_for(db)?;
    let mut client = pool.get().map_err(|_| pool_error_detail(db))?;
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| e.to_string())?;
    client
        .batch_execute(&format!(
            "SET statement_timeout='{}'; SET default_transaction_read_only=on;{}",
            statement_timeout(),
            search_path_stmt()
        ))
        .map_err(|e| e.to_string())?;
    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .map_err(|e| e.to_string())?;
    // Let PostgreSQL serialise the row, exactly as the query path does. Reading catalog values
    // through the driver's per-type mapping silently lost anything it did not know — a `numeric`
    // came back as null while psql showed 100.00. Wrapping is skipped for EXPLAIN, which cannot
    // live inside a subquery and already returns json.
    let wrapped;
    let (sql, wrapped_mode) = if sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
        wrapped = format!("SELECT to_jsonb(t)::text AS _r FROM ({}) t", sql);
        (wrapped.as_str(), true)
    } else {
        (sql, false)
    };
    // STREAMED, like the query path — not buffered and then measured.
    //
    // `client.query()` pulls EVERY row into a `Vec<Row>` before returning, so the byte ceiling below
    // could only ever trim the ANSWER; the PEAK was unbounded. `EXPLAIN (FORMAT JSON)` of a large
    // UNION, or a catalog scan over hundreds of thousands of relations, materialised in full inside
    // this process before anyone could object. Both paths therefore stream; a ceiling that trims the
    // answer while the peak stays unbounded protects the reader and not the server.
    //
    // `query_raw` pulls through a portal in batches, so we stop growing at the limit instead of
    // discovering we exceeded it.
    use postgres::fallible_iterator::FallibleIterator;
    let mut out: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    let mut capped = false;
    let streamed: Result<(), String> = (|| {
        let mut it = client
            .query_raw(sql, params.iter().copied())
            .map_err(|e| friendly_pg_error_for(&e, Some(sql)))?;
        while let Some(row) = it
            .next()
            .map_err(|e| friendly_pg_error_for(&e, Some(sql)))?
        {
            if bytes > MAX_RESULT_BYTES {
                capped = true;
                break;
            }
            let v = if wrapped_mode {
                let txt: Option<String> = row
                    .try_get::<_, Option<String>>(0)
                    .map_err(|_| "result serialization error".to_string())?;
                serde_json::from_str(&txt.unwrap_or_else(|| "null".into()))
                    .map_err(|_| "result serialization error".to_string())?
            } else {
                let mut obj = serde_json::Map::new();
                for i in 0..row.columns().len() {
                    let col_name = row.columns()[i].name().to_string();
                    obj.insert(col_name, col_to_json(&row, i));
                }
                Value::Object(obj)
            };
            bytes += serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0);
            out.push(v);
        }
        Ok(())
    })();
    let _ = client.batch_execute("ROLLBACK");
    streamed?;
    let mut res = json!({ "returnedRows": out.len(), "rows": out });
    if capped {
        res["truncated"] = json!(true);
        res["truncationReason"] = json!(format!(
            "result exceeded the {} MB ceiling and was cut here",
            MAX_RESULT_BYTES / 1_048_576
        ));
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction guarantee has to survive a row being serialised into a single value.
    /// `row_to_json(t)`, `to_jsonb(t.*)` and `json_agg(t)` all hide the column name from the
    /// validator and put the value one level down, where top-level masking never reached it —
    /// `json_agg` returned every row at once. Masking by key at any depth closes the class.
    #[test]
    fn redaction_reaches_nested_and_arrayed_rows() {
        // The patterns are passed in rather than read from the environment: `redact_patterns` is a
        // `Lazy` static, so a test that set the variable would pass or fail depending on which test
        // happened to touch it first.
        let pats = vec!["password".to_string(), "secret".to_string()];
        let mut rows = vec![
            json!({"row_to_json": {"id": 1, "password": "hash", "name": "ada"}}),
            json!({"json_agg": [
                {"id": 1, "password": "hash1"},
                {"id": 2, "password": "hash2", "nested": {"secret": "deep"}}
            ]}),
            json!({"id": 3, "PassWord": "case-insensitive"}),
        ];
        let mut masked = std::collections::BTreeSet::new();
        for row in rows.iter_mut() {
            redact_value(row, &pats, &mut masked);
        }
        assert_eq!(
            masked.iter().cloned().collect::<Vec<_>>(),
            vec!["PassWord", "password", "secret"],
            "the response must report the columns actually masked, at any depth"
        );
        let dump = serde_json::to_string(&rows).unwrap();
        assert!(
            !dump.contains("hash") && !dump.contains("deep") && !dump.contains("case-insensitive"),
            "a redacted value survived somewhere: {dump}"
        );
        assert_eq!(dump.matches("[redacted]").count(), 5);
        // untouched columns stay readable — redaction must not blank the whole row
        assert!(dump.contains("\"ada\"") && dump.contains("\"id\":2"));
    }
}

/// Ask the planner what a query would cost IF an index existed, without creating one.
///
/// `hypopg` registers a hypothetical index in backend memory: the planner sees it, storage never
/// does, and it disappears with the session. That is what makes this possible on a server whose
/// whole promise is that it cannot change anything — the leading alternative offers the same
/// capability, but reaches it by defaulting to a connection that can create real indexes.
///
/// The caller never supplies DDL. The index definition is assembled here from identifiers the
/// CATALOGUE confirmed exist, quoted by PostgreSQL itself via `quote_ident`, so there is no path
/// from a tool argument to arbitrary SQL. The access method comes from a fixed list.
///
/// Both plans come from ONE connection inside ONE read-only transaction, because a hypothetical
/// index belongs to the session that made it: a pooled second connection would measure a database
/// that never heard of it.
pub(crate) fn simulate_index(
    query_sql: &str,
    schema: &str,
    table: &str,
    columns: &[String],
    method: &str,
    db: Option<&str>,
) -> Result<Value, String> {
    const METHODS: &[&str] = &["btree", "hash", "gin", "gist", "spgist", "brin"];
    if !METHODS.contains(&method) {
        return Err(format!(
            "unsupported index method {method:?}; use one of: {}",
            METHODS.join(", ")
        ));
    }
    if columns.is_empty() {
        return Err("at least one column is required".into());
    }
    if columns.len() > 32 {
        return Err("an index over more than 32 columns is not something to simulate".into());
    }

    let pool = pool_for(db)?;
    let mut client = pool.get().map_err(|_| pool_error_detail(db))?;
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| e.to_string())?;
    client
        .batch_execute(&format!(
            "SET statement_timeout='{}'; SET idle_in_transaction_session_timeout='10s'; \
             SET default_transaction_read_only=on;{}",
            statement_timeout(),
            search_path_stmt()
        ))
        .map_err(|e| e.to_string())?;

    // Is the extension even here? Saying so precisely is worth more than a failure the caller has to
    // decode — the same courtesy pg_stat_statements gets.
    let has: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'hypopg')",
            &[],
        )
        .map_err(|e| e.to_string())?
        .get(0);
    if !has {
        let available: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'hypopg')",
                &[],
            )
            .map(|r| r.get(0))
            .unwrap_or(false);
        return Err(if available {
            "the hypopg extension is installed on this server but not enabled in this database — \
             run CREATE EXTENSION hypopg (needs a role that may create extensions; this server \
             cannot and should not do it for you)"
                .into()
        } else {
            "index simulation needs the hypopg extension, which is not installed on this server \
             (Debian/Ubuntu: postgresql-<version>-hypopg, then CREATE EXTENSION hypopg). Nothing \
             else in this server requires it."
                .into()
        });
    }

    // The identifiers are checked against the catalogue and quoted BY POSTGRES. A name that does not
    // exist stops here with a message naming it, rather than becoming part of a statement.
    let row = client
        .query_opt(
            "SELECT quote_ident(n.nspname), quote_ident(c.relname) \
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r','m','p')",
            &[&schema, &table],
        )
        .map_err(|e| e.to_string())?;
    let (qschema, qtable): (String, String) = match row {
        Some(r) => (r.get(0), r.get(1)),
        None => return Err(format!("no table {schema}.{table} that this role can see")),
    };

    let mut quoted_cols: Vec<String> = Vec::with_capacity(columns.len());
    for col in columns {
        let r = client
            .query_opt(
                "SELECT quote_ident(a.attname) FROM pg_attribute a \
                   JOIN pg_class c ON c.oid = a.attrelid \
                   JOIN pg_namespace n ON n.oid = c.relnamespace \
                  WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3 \
                    AND a.attnum > 0 AND NOT a.attisdropped",
                &[&schema, &table, &col],
            )
            .map_err(|e| e.to_string())?;
        match r {
            Some(r) => quoted_cols.push(r.get(0)),
            None => return Err(format!("{schema}.{table} has no column {col:?}")),
        }
    }
    let ddl = format!(
        "CREATE INDEX ON {qschema}.{qtable} USING {method} ({})",
        quoted_cols.join(", ")
    );

    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .map_err(|e| e.to_string())?;

    // Shrink the plan at the source, since we cannot measure it before it arrives (see below).
    // Parallel plans repeat a subtree once per gather worker, so a plan that is merely large becomes
    // large times N. Turning gather off costs nothing here — we want the SHAPE of the plan, not its
    // wall-clock — and it is the only lever that reduces the peak rather than reporting on it.
    let _ = client.batch_execute("SET LOCAL max_parallel_workers_per_gather = 0");

    let plan = |c: &mut postgres::Client, sql: &str| -> Result<Value, String> {
        let stmt = format!("EXPLAIN (FORMAT JSON) {sql}");
        let r = c
            .query_one(stmt.as_str(), &[])
            .map_err(|e| friendly_pg_error_for(&e, Some(sql)))?;
        // EXPLAIN (FORMAT JSON) returns a `json` column, not text. Reading it as a String panicked
        // the worker thread and surfaced as "internal task error" — a message that tells the caller
        // nothing and tells us nothing either. `try_get` so a type surprise is an error, not a panic.
        let v = r
            .try_get::<_, Value>(0)
            .map_err(|e| format!("could not read the plan: {e}"))?;
        // The same 8 MB ceiling every other result path answers to. A G4 round called this one
        // unbounded; it is not truly unbounded — the plan grows with the query, and the query is
        // already capped at MAX_SQL_LEN and killed by statement_timeout — but it was the ONE
        // endpoint from which a caller could get a response larger than the server's own limit.
        //
        // Honest about what this does and does not do: it bounds the RESPONSE, not the peak. The
        // plan is already in memory by the time we can measure it, because PostgreSQL will not let
        // you wrap EXPLAIN in a subquery and ask it to measure the result for you — the trick used
        // in `execute_readonly` is unavailable here for exactly that reason.
        let size = serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0);
        if size > MAX_RESULT_BYTES {
            return Err(format!(
                "the query plan is {} MB, over the {} MB limit — simplify the query before asking \
                 what an index would do to it",
                size / 1_048_576,
                MAX_RESULT_BYTES / 1_048_576
            ));
        }
        Ok(v)
    };

    let result = (|| -> Result<Value, String> {
        let before = plan(&mut client, query_sql)?;
        client
            .query_one(
                "SELECT indexname::text FROM hypopg_create_index($1)",
                &[&ddl],
            )
            .map_err(|e| format!("hypopg refused the index definition: {e}"))?;
        let after = plan(&mut client, query_sql)?;

        let cost =
            |p: &Value| -> Option<f64> { p.get(0)?.get("Plan")?.get("Total Cost")?.as_f64() };
        let (c0, c1) = (cost(&before), cost(&after));
        // Whether the planner actually reached for it. A cost that barely moves and an index the
        // planner ignored are different answers, and the second one is the useful one.
        let used = uses_hypothetical_index(&after);
        Ok(json!({
            "index_considered": ddl,
            "cost_without_index": c0,
            "cost_with_hypothetical_index": c1,
            "improvement_factor": match (c0, c1) {
                (Some(a), Some(b)) if b > 0.0 => Some((a / b * 100.0).round() / 100.0),
                _ => None,
            },
            "planner_switched_to_it": used,
            "plan_without_index": before,
            "plan_with_hypothetical_index": after,
            "note": "The index was never created. These are planner ESTIMATES, not measured times: \
                     a lower estimated cost is a reason to test the index, not proof that it helps."
        }))
    })();

    let _ = client.batch_execute("ROLLBACK");
    let _ = client.batch_execute("SELECT hypopg_reset()");
    result
}

/// Did the planner actually reach for the hypothetical index?
///
/// hypopg names its indexes `<oid>method_table_cols`, and that leading angle bracket distinguishes
/// "the planner chose the index we invented" from "the planner was already using a real one". The
/// first version of this searched the serialised JSON for a substring and got the answer wrong on
/// the very first test — the formatting it assumed was not the formatting serde produces. Walking
/// the structure asks the question the plan actually answers, and cannot be broken by whitespace.
fn uses_hypothetical_index(plan: &Value) -> bool {
    match plan {
        Value::Object(map) => {
            if let Some(Value::String(name)) = map.get("Index Name") {
                if name.starts_with('<') {
                    return true;
                }
            }
            map.values().any(uses_hypothetical_index)
        }
        Value::Array(items) => items.iter().any(uses_hypothetical_index),
        _ => false,
    }
}

#[cfg(test)]
mod hypo_tests {
    use super::*;

    #[test]
    fn a_hypothetical_index_is_told_apart_from_a_real_one() {
        // hypopg's own naming, nested where a plan really puts it.
        let hypo = json!([{ "Plan": { "Node Type": "Index Scan",
            "Index Name": "<13630>btree_big_id" } }]);
        assert!(uses_hypothetical_index(&hypo));
        // A plan that was already using a real index is NOT a success for the simulation.
        let real = json!([{ "Plan": { "Node Type": "Index Scan", "Index Name": "big_pkey" } }]);
        assert!(!uses_hypothetical_index(&real));
        // Nested under a parent node, which is where it lands in anything non-trivial.
        let nested = json!([{ "Plan": { "Node Type": "Nested Loop", "Plans": [
            { "Node Type": "Seq Scan" },
            { "Node Type": "Index Scan", "Index Name": "<42>btree_t_c" }] } }]);
        assert!(uses_hypothetical_index(&nested));
        let seq = json!([{ "Plan": { "Node Type": "Seq Scan", "Relation Name": "big" } }]);
        assert!(!uses_hypothetical_index(&seq));
    }
}
