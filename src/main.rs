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

use serde_json::{json, Map, Value};
#[allow(dead_code)]
mod auth;
mod fuzz;
mod ratelimit;
mod validate;

use axum::{
    extract::{ConnectInfo, Json, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

// --- Session state (simple, in memory) ---
#[derive(Clone, Default)]
struct AppState {
    /// value = last use (seconds since process start). The map MUST have a cap and a TTL:
    /// `initialize` is unauthenticated by design, so without one anybody could inflate it
    /// without bound — the very defence already present in the rate limiter.
    sessions: Arc<tokio::sync::RwLock<std::collections::HashMap<String, u64>>>,
}

/// How many sessions we keep, and for how long while idle.
const MAX_SESSIONS: usize = 10_000;
const SESSION_IDLE_SECS: u64 = 3_600;

static PROC_START: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);
fn uptime_secs() -> u64 {
    PROC_START.elapsed().as_secs()
}

// --- MAIN ENTRY POINT ---
#[tokio::main]
async fn main() {
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
    if let Some(pos) = args.iter().position(|a| a == "--canon") {
        let sql = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("");
        match validate::enforce_limit(sql, 1000) {
            Ok(c) => println!("{}", c),
            Err(e) => println!("ERR: {}", e),
        }
        return;
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
            Ok(info) => {
                println!(
                    "OK ({}): {}",
                    if audit_key().is_some() {
                        "HMAC"
                    } else {
                        "SHA-256, bez klucza"
                    },
                    info
                );
            }
            Err(e) => {
                println!("USZKODZONY: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }
    // Configuration is checked BEFORE we serve anyone — see `preflight_config`.
    preflight_config();
    if args.contains(&"--stdio".to_string()) {
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
fn preflight_config() {
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
    if let Ok(pem) = std::env::var("JWT_PUBKEY_PEM") {
        if jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).is_err() {
            fatal.push("JWT_PUBKEY_PEM is not a valid RSA public key in PEM format".to_string());
        }
    }

    // TLS CA: better to learn at startup than on the first query
    if std::env::var("MCP_SSLROOTCERT").is_ok() {
        if let Err(e) = build_tls() {
            fatal.push(e);
        }
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

// --- STDIO TRANSPORT (stara logika main, bez zmian) ---
fn run_stdio() {
    use std::io::{self, BufRead, Write};
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
        let mut resp = handle_request(&req);
        resp["jsonrpc"] = serde_json::Value::String("2.0".into());
        resp["id"] = req.get("id").cloned().unwrap_or(Value::Null);
        emit(resp, &mut stdout);
    }
}

// --- HTTP TRANSPORT ---
async fn run_http() {
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
async fn delete_session_handler(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // This endpoint takes a WRITE lock on the session map — the same lock every request carrying an
    // `Mcp-Session-Id` needs. Without a rate limit it could be used to choke normal traffic.
    let key = ratelimit::client_key(
        &peer.ip().to_string(),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    );
    if !ratelimit::allow(&key) {
        METRICS.denied_rate.fetch_add(1, Ordering::Relaxed);
        audit("http", "denied_rate", None);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
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
async fn mcp_handler(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    METRICS.requests.fetch_add(1, Ordering::Relaxed);
    // Rate limit BEFORE auth: verifying an RS256 signature costs CPU, so a flood of junk tokens must
    // bounce earlier. DB_SEM caps concurrency; this caps rate.
    let key = ratelimit::client_key(
        &peer.ip().to_string(),
        headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    );
    if !ratelimit::allow(&key) {
        METRICS.denied_rate.fetch_add(1, Ordering::Relaxed);
        // Denials MUST reach the durable, chained audit — otherwise an attempt to flood the server
        // leaves a trace only in a counter that disappears on restart.
        audit("http", "denied_rate", None);
        let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
            "error": { "code": -32000, "message": "rate limit exceeded, slow down" } });
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
    let free = DB_SEM.available_permits();
    let tight = free <= (MAX_DB_CONNS as usize) / 4;
    let effective_cap = if tight { 1 } else { ratelimit::max_in_flight() };
    let slot = match ratelimit::acquire_slot_capped(&key, effective_cap) {
        Some(g) => g,
        None => {
            let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32000, "message": "too many concurrent requests from this client" } });
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
    let permit = match DB_SEM.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            audit("http", "denied_busy", None);
            let body = json!({ "jsonrpc": "2.0", "id": req.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32000, "message": "server busy, retry shortly" } });
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                HeaderMap::new(),
                Json(body),
            )
                .into_response();
        }
    };

    let req_logic = req.clone();
    let mut resp = tokio::task::spawn_blocking(move || {
        let _permit = permit; // released when the WORK ends, not when the client disconnects
        let _slot = slot;
        let _who = set_caller(caller); // identity visible to the audit on this thread
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

type PgTls = tokio_postgres_rustls::MakeRustlsConnect;
type PgPool = Pool<PostgresConnectionManager<PgTls>>;

/// Connection string: `DATABASE_URL`, or the first positional argument.
///
/// The deprecated server took the URL as `argv[2]`, so people migrating paste exactly that command
/// into their config. Accepting both means their existing invocation keeps working (issue #845 in
/// the upstream tracker asked for the environment variable; we support both rather than either).
fn database_url() -> Option<String> {
    if let Ok(u) = std::env::var("DATABASE_URL") {
        if !u.trim().is_empty() {
            return Some(u);
        }
    }
    std::env::args().skip(1).find(|a| {
        a.starts_with("postgres://") || a.starts_with("postgresql://") || a.contains("host=")
    })
}

/// The database name inside a connection string — used to label a single-database deployment.
fn database_name_of(url: &str) -> String {
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
fn normalize_sslmode(url: &str) -> String {
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
fn build_tls() -> Result<PgTls, String> {
    // rustls 0.23 wymaga jawnego wyboru dostawcy kryptografii; ring = czysty Rust, bez OpenSSL
    // (obraz jest distroless — nie ma tam libssl).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    // 1. the system store, if the image has one
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    // 2. bundled Mozilla roots — so it also works without a system store
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // 3. prywatne CA operatora (bundle RDS/Supabase, self-signed w intranecie)
    if let Ok(path) = std::env::var("MCP_SSLROOTCERT") {
        let f = std::fs::File::open(&path)
            .map_err(|e| format!("MCP_SSLROOTCERT: cannot open {}: {}", path, e))?;
        let mut rd = std::io::BufReader::new(f);
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut rd) {
            let cert = cert.map_err(|e| format!("MCP_SSLROOTCERT: invalid PEM: {}", e))?;
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
static PG_POOLS: Lazy<Result<Vec<(String, PgPool)>, String>> = Lazy::new(|| {
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

fn build_pool(url: &str) -> Result<PgPool, String> {
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

/// The pool for a request. `None` picks the only configured database, or reports the choices.
fn pool_for(name: Option<&str>) -> Result<&'static PgPool, String> {
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
fn database_names() -> Vec<String> {
    PG_POOLS
        .as_ref()
        .map(|p| p.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default()
}

/// Upper bound on database connections and concurrent operations (pool exhaustion / DoS defence).
const MAX_DB_CONNS: u32 = 16;
/// Semaphore gating concurrent database work — excess gets a fast "busy" instead of blocking the pool.
static DB_SEM: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_DB_CONNS as usize)));

/// Why is the pool not handing out a connection? r2d2 says only "timed out" and the driver says
/// "db error" — neither tells the user what to fix. We make ONE direct connection attempt and
/// translate the cause into a hint. The CLIENT gets the error class only (no user, host or database
/// name — this is still an unauthenticated surface); the full text goes to the operator stderr.
fn pool_error_detail() -> String {
    let Some(url) = database_url() else {
        return "no connection string: set DATABASE_URL or pass it as the first argument"
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
                // brak DbError = warstwa transportu: host/port/TLS/certyfikat
                format!(
                    "cannot connect to PostgreSQL: {} — check host, port and sslmode; \
                     for a private CA (e.g. an RDS bundle) point MCP_SSLROOTCERT at the PEM file",
                    e
                )
            }
        }
    }
}

fn col_to_json(row: &Row, i: usize) -> Value {
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
const MAX_RESULT_BYTES: usize = 8 * 1_048_576; // 8 MB
/// Hard upper bound on rows — the `limit` parameter is clamped to this value.
const MAX_LIMIT: u64 = 10_000;

/// A row-returning query that can be wrapped in a `(sql) t` subquery and planned with EXPLAIN.
/// SELECT/WITH/VALUES/TABLE — yes; EXPLAIN/SHOW — no (you cannot EXPLAIN an EXPLAIN).
fn is_row_query(sql: &str) -> bool {
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

fn execute_readonly(final_sql: &str, db: Option<&str>) -> Result<Value, String> {
    let pool = pool_for(db)?;
    let mut client = pool.get().map_err(|_| pool_error_detail())?;
    // Session-level defence in depth: timeouts + read-only (the database refuses a write even if the
    // validator let something through). DISCARD ALL resets pooled session state (Session Pollution).
    // It MUST be its own statement — a multi-statement batch is an implicit transaction, and
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| e.to_string())?;
    client.batch_execute("SET statement_timeout='30s'; SET idle_in_transaction_session_timeout='10s'; SET default_transaction_read_only=on;")
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

    let out: Vec<Value> = if is_row_query(final_sql) {
        // PostgreSQL serialises EVERY type to jsonb (numeric/enum/array/uuid/timestamptz/jsonb/point…).
        // Hand-written type mapping in Rust silently lost unhandled types to null — a bug found
        // na pagila (SUM(amount)→null, enum/array→null). to_jsonb(t) = jedna kolumna jsonb na wiersz.
        // STREAMING (query_raw) + an early bail on the byte budget. client.query() buffered the WHOLE
        // result in RAM BEFORE the cap could act — query_raw pulls rows in batches through a portal, so
        // nothing is materialised at once and we stop before it grows.
        use postgres::fallible_iterator::FallibleIterator;
        // A per-row SIZE cap computed IN POSTGRES: if a row exceeds the limit, PG returns a marker instead
        // of the value — our process NEVER receives a giant cell (streaming bounds many rows, but one huge
        // row would still materialise here).
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
                .map_err(|e| friendly_pg_error(&e))?;
            let mut acc: Vec<Value> = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = it.next().map_err(|e| friendly_pg_error(&e))? {
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
            .map_err(|e| friendly_pg_error(&e))?;
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
    // ROLLBACK on EVERY exit path — including success (we never commit anything).
    let _ = client.batch_execute("ROLLBACK");
    Ok(json!({ "rowCount": out.len(), "rows": out }))
}

use postgres::types::ToSql;

fn query_catalog(
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    db: Option<&str>,
) -> Result<Value, String> {
    let pool = pool_for(db)?;
    let mut client = pool.get().map_err(|_| pool_error_detail())?;
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| e.to_string())?;
    client
        .batch_execute("SET statement_timeout='15s'; SET default_transaction_read_only=on;")
        .map_err(|e| e.to_string())?;
    client
        .batch_execute("BEGIN TRANSACTION READ ONLY")
        .map_err(|e| e.to_string())?;
    let rows = match client.query(sql, params) {
        Ok(r) => r,
        Err(e) => {
            let _ = client.batch_execute("ROLLBACK");
            return Err(friendly_pg_error(&e));
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut obj = serde_json::Map::new();
        for i in 0..row.columns().len() {
            let col_name = row.columns()[i].name().to_string();
            obj.insert(col_name, col_to_json(&row, i));
        }
        out.push(Value::Object(obj));
    }
    let _ = client.batch_execute("ROLLBACK");
    Ok(json!({ "rowCount": out.len(), "rows": out }))
}

fn ok_content(data: &Value) -> Value {
    wrap_untrusted(data, "catalog")
}

fn err_content(code: i32, msg: String) -> Value {
    json!({ "error": { "code": code, "message": msg } })
}

fn handle_list_schemas(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    match query_catalog(
        "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') AND schema_name NOT LIKE 'pg_%' ORDER BY 1",
        &[],
        db,
    ) {
        Ok(v) => { audit("list_schemas", "allowed", None); ok_content(&v) }
        Err(e) => { audit("list_schemas", "error", None); err_content(-32000, e) }
    }
}

fn handle_list_tables(args: &Value) -> Value {
    let schema = args
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    let db = args.get("database").and_then(|v| v.as_str());
    // Built on pg_class rather than information_schema, which does not list MATERIALIZED VIEWS at
    // all — a database keeping its aggregates in matviews would look half empty through this tool.
    const SQL: &str = concat!(
        "SELECT c.relname AS table_name, ",
        "       CASE c.relkind WHEN 'r' THEN 'BASE TABLE' WHEN 'p' THEN 'PARTITIONED TABLE' ",
        "                      WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ",
        "                      WHEN 'f' THEN 'FOREIGN TABLE' ELSE c.relkind::text END AS table_type, ",
        "       obj_description(c.oid) AS description ",
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace ",
        "WHERE n.nspname = $1 AND c.relkind IN ('r','p','v','m','f') ",
        "  AND has_table_privilege(c.oid, 'SELECT') AND (NOT c.relispartition OR $2) ",
        "ORDER BY c.relname"
    );
    let show_parts = show_partitions();
    match query_catalog(SQL, &[&schema, &show_parts], db) {
        Ok(v) => {
            audit("list_tables", "allowed", None);
            ok_content(&v)
        }
        Err(e) => {
            audit("list_tables", "error", None);
            err_content(-32000, e)
        }
    }
}

/// The resource list = one entry per table/view in user schemas (the system catalog is excluded).
/// Whether partition children are listed (off by default — see the query comment).
fn show_partitions() -> bool {
    std::env::var("MCP_SHOW_PARTITIONS")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

/// Server name shown to the client, optionally suffixed with `MCP_SERVER_LABEL`.
fn server_label() -> String {
    match std::env::var("MCP_SERVER_LABEL") {
        Ok(l) if !l.trim().is_empty() => format!("postgres-mcp-hardened ({})", l.trim()),
        _ => "postgres-mcp-hardened".to_string(),
    }
}

fn handle_resources_list() -> Value {
    // With several databases configured, the list spans all of them; the URI carries the database
    // name, so entries from different connections never collide.
    let names = database_names();
    if names.len() > 1 {
        let mut all: Vec<Value> = Vec::new();
        for n in &names {
            if let Some(Value::Array(items)) = resources_of(Some(n))
                .get("result")
                .and_then(|r| r.get("resources"))
                .cloned()
            {
                all.extend(items);
            }
        }
        audit("resources/list", "allowed", None);
        return json!({ "result": { "resources": all } });
    }
    resources_of(None)
}

fn resources_of(db: Option<&str>) -> Value {
    const SQL: &str = concat!(
        "SELECT n.nspname AS table_schema, c.relname AS table_name, ",
        "       CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' ",
        "                      WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' ",
        "                      WHEN 'f' THEN 'foreign table' ELSE c.relkind::text END AS table_type, ",
        "       obj_description(c.oid) AS description ",
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace ",
        "WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') ",
        "  AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' ",
        "  AND c.relkind IN ('r','p','v','m','f') AND has_table_privilege(c.oid, 'SELECT') ",
        // Partition CHILDREN are an implementation detail: a table split by month adds dozens of
        // near-identical entries and drowns the real schema. The parent is listed; set
        // MCP_SHOW_PARTITIONS=1 to see the children too.
        "  AND (NOT c.relispartition OR $1) ",
        "ORDER BY n.nspname, c.relname LIMIT 1000"
    );
    let db = db
        .map(|s| s.to_string())
        .unwrap_or_else(|| database_names().first().cloned().unwrap_or_default());
    let show_parts = show_partitions();
    match query_catalog(SQL, &[&show_parts], db.as_str().into()) {
        Ok(v) => {
            let rows = v
                .get("rows")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            let list: Vec<Value> = rows
                .iter()
                .map(|r| {
                    let s = r
                        .get("table_schema")
                        .and_then(|x| x.as_str())
                        .unwrap_or("public");
                    let t = r.get("table_name").and_then(|x| x.as_str()).unwrap_or("");
                    let kind = r
                        .get("table_type")
                        .and_then(|x| x.as_str())
                        .unwrap_or("BASE TABLE");
                    let desc = r
                        .get("description")
                        .and_then(|x| x.as_str())
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| format!("{} {}.{}", kind.to_lowercase(), s, t));
                    json!({
                        // The database name is part of the URI so two instances (production and
                        // development, say) never produce colliding resource identifiers — the most
                        // upvoted complaint about the deprecated server was exactly this ambiguity.
                        "uri": format!("postgres:///{}/{}/{}/schema", db, s, t),
                        "name": format!("{}.{}", s, t),
                        "description": desc,
                        "mimeType": "application/json"
                    })
                })
                .collect();
            audit("resources/list", "allowed", None);
            json!({ "result": { "resources": list } })
        }
        Err(e) => {
            audit("resources/list", "error", None);
            json!({ "error": { "code": -32000, "message": e } })
        }
    }
}

/// Odczyt zasobu: `postgres:///<schemat>/<tabela>/schema` → ten sam opis kolumn co `describe_table`.
fn handle_resources_read(params: &Value) -> Value {
    let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
    let rest = uri.strip_prefix("postgres:///").unwrap_or("");
    let parts: Vec<&str> = rest.split('/').collect();
    // Accept both `<db>/<schema>/<table>/schema` and the shorter `<schema>/<table>/schema`.
    let (db, schema, table) = match parts.as_slice() {
        [d, s, t, "schema"] => (Some(*d), *s, *t),
        [s, t, "schema"] => (None, *s, *t),
        _ => {
            return json!({ "error": { "code": -32602, "message":
                "unknown resource — expected postgres:///<database>/<schema>/<table>/schema" } })
        }
    };
    if schema.is_empty() || table.is_empty() {
        return json!({ "error": { "code": -32602, "message": "unknown resource — empty schema or table" } });
    }
    let mut a = json!({ "schema": schema, "table": table });
    if let Some(d) = db {
        a["database"] = Value::String(d.to_string());
    }
    let desc = handle_describe_table(&a);
    // `describe_table` returns a ready `content` block; a resource needs the `contents` shape.
    match desc
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
    {
        Some(Value::String(text)) => json!({ "result": { "contents": [{
            "uri": uri, "mimeType": "application/json", "text": text
        }]}}),
        _ => desc,
    }
}

fn handle_describe_table(args: &Value) -> Value {
    let schema = args
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    let db = args.get("database").and_then(|v| v.as_str());
    let table = match args.get("table").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return err_content(-32602, "missing 'table'".into()),
    };
    // Comments from `pg_description` + primary key + default. An agent that sees ONLY a name and a type
    // guesses what the column means (`status`, `amount`, `rental_duration`) and builds queries on that
    // guess. A schema comment is the cheapest available truth about meaning, and the primary key says
    // what to join on instead of inferring it from the name.
    const SQL: &str = concat!(
        // Built on pg_attribute/pg_class, not information_schema: the latter reports every enum,
        // domain and composite type as the useless string "USER-DEFINED", and omits materialized
        // views entirely. `format_type` gives the real name (`mood`, `addr`, `numeric(30,10)`).
        "SELECT a.attname AS column_name, ",
        "       format_type(a.atttypid, a.atttypmod) AS data_type, ",
        "       CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END AS is_nullable, ",
        "       pg_get_expr(ad.adbin, ad.adrelid) AS column_default, ",
        "       col_description(rel.oid, a.attnum) AS description, ",
        "       COALESCE(i.indisprimary, false) AS is_primary_key, ",
        // FOREIGN KEY: without it the agent guesses what to join on — and guessing from column names
        // is the most common source of quiet, convincing-looking nonsense in results.
        "       (SELECT cl2.relname || '.' || a2.attname ",
        "        FROM pg_constraint con ",
        "        JOIN pg_class cl2 ON cl2.oid = con.confrelid ",
        "        JOIN pg_attribute a2 ON a2.attrelid = con.confrelid ",
        "             AND a2.attnum = con.confkey[array_position(con.conkey, a.attnum)] ",
        "        WHERE con.contype = 'f' AND con.conrelid = rel.oid AND a.attnum = ANY (con.conkey) ",
        "        LIMIT 1) AS references_column, ",
        "       obj_description(rel.oid) AS table_description ",
        "FROM pg_class rel ",
        "JOIN pg_namespace ns ON ns.oid = rel.relnamespace ",
        "JOIN pg_attribute a ON a.attrelid = rel.oid AND a.attnum > 0 AND NOT a.attisdropped ",
        "LEFT JOIN pg_attrdef ad ON ad.adrelid = rel.oid AND ad.adnum = a.attnum ",
        "LEFT JOIN pg_index i ON i.indrelid = rel.oid AND i.indisprimary AND a.attnum = ANY (i.indkey) ",
        "WHERE ns.nspname = $1 AND rel.relname = $2 AND rel.relkind IN ('r','p','v','m','f') ",
        "  AND has_table_privilege(rel.oid, 'SELECT') ",
        "ORDER BY a.attnum"
    );
    match query_catalog(SQL, &[&schema, &table], db) {
        Ok(v) => {
            // Pusty wynik = tabela nie istnieje albo rola jej nie widzi. Bez tego agent dostaje
            // `rowCount: 0` and reads it as "a table with no columns" — a hallucination instead of an error.
            if v.get("rowCount").and_then(|n| n.as_u64()) == Some(0) {
                audit("describe_table", "error", None);
                return err_content(
                    -32000,
                    format!(
                        "table {}.{} not found or not visible to this role",
                        schema, table
                    ),
                );
            }
            audit("describe_table", "allowed", None);
            ok_content(&v)
        }
        Err(e) => {
            audit("describe_table", "error", None);
            err_content(-32000, e)
        }
    }
}

/// Cost-guard verdict — separates a genuine cost rejection from an error in the query itself
/// (a missing column, say), so the audit never confuses "denied_cost" with a SQL error.
enum CostErr {
    TooExpensive(String),
    QueryError(String),
}

fn cost_guard(sql: &str, max_cost: f64, db: Option<&str>) -> Result<(), CostErr> {
    let pool = pool_for(db).map_err(CostErr::QueryError)?;
    let mut client = pool
        .get()
        .map_err(|_| CostErr::QueryError(pool_error_detail()))?;
    client
        .batch_execute("DISCARD ALL")
        .map_err(|e| CostErr::QueryError(e.to_string()))?;
    client
        .batch_execute("SET statement_timeout='5s'; SET default_transaction_read_only=on;")
        .map_err(|e| CostErr::QueryError(e.to_string()))?;
    let row = client
        .query_one(&format!("EXPLAIN (FORMAT JSON) {}", sql), &[])
        .map_err(|e| CostErr::QueryError(friendly_pg_error(&e)))?;
    let plan: Value = row.get(0); // kolumna json: [{"Plan":{"Total Cost":..}}]
    let total = plan
        .get(0)
        .and_then(|v| v.get("Plan"))
        .and_then(|v| v.get("Total Cost"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if total > max_cost {
        Err(CostErr::TooExpensive(format!(
            "query too expensive: estimated cost {:.0} exceeds limit {:.0}",
            total, max_cost
        )))
    } else {
        Ok(())
    }
}

fn friendly_pg_error(e: &postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        let code = db.code().code();
        let msg = match code {
            "42501" => "permission denied for this object — the role lacks access",
            "42P01" => "relation does not exist — verify the table name via list_tables",
            "42703" => "column does not exist — verify columns via describe_table",
            "42601" => "SQL syntax error",
            "57014" => "statement timeout exceeded — add a LIMIT or narrow the query",
            "25006" => "read-only transaction: writes are not permitted",
            "53300" => "too many connections — try again shortly",
            _ => "database error",
        };
        format!("{} [SQLSTATE {}]", msg, code)
    } else {
        "database connection/protocol error".to_string()
    }
}

/// Usuwa niewidzialne/bidi znaki (zero-width, bidi override/isolate „Trojan Source", word-joiner, BOM),
/// which would SURVIVE JSON encoding and could smuggle instructions or reorder text for an LLM.
/// Control characters below 0x20 are already escaped by serde, so only the "invisible format" class remains.
fn strip_invisible(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            !matches!(c,
                // NOTE: U+200C (ZWNJ) and U+200D (ZWJ) are deliberately excluded — they carry meaning in
                // composed emoji (👨‍👩‍👧) and in Persian/Hindi orthography. Stripping them silently
                // altered user data. Smuggling goes through the Tags block below.
                '\u{200B}' | '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' |
                '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' |
                '\u{E0000}'..='\u{E007F}') // the Unicode Tags block — the canonical ASCII-smuggling channel
        })
        .collect()
}

/// Prevents text from "escaping" the `<mcp:tool-output>` block: every `<` becomes `\u003c`.
///
/// In JSON, `<` appears ONLY inside string literals (it is not a structural character), and
/// `\u003c` is a valid escape decoding back to `<` — so the parsed data is IDENTICAL, while the
/// raw text can never spell `</mcp:tool-output>`.
/// An earlier version inserted a bare `\` before the token name: it broke JSON (`\m` is not a legal
/// escape) and silently altered any cell containing the phrase "mcp:tool-output".
fn escape_block_breakout(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '<' {
            out.push_str("\\u003c");
        } else {
            out.push(ch);
        }
    }
    out
}

fn wrap_untrusted(data: &Value, tool: &str) -> Value {
    // Escape the delimiter so database content cannot "escape" the block or forge trusted="true".
    // Everything inside is DATA, not instructions. Plus stripping of invisible/bidi characters.
    let text = escape_block_breakout(&strip_invisible(
        &serde_json::to_string(data).unwrap_or_default(),
    ));
    let wrapped = format!(
        "<mcp:tool-output tool=\"{}\" trusted=\"false\">{}</mcp:tool-output>",
        tool, text
    );
    json!({ "result": { "content": [{ "type": "text", "text": wrapped, "annotations": { "untrustedContent": true } }] } })
}

use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Global hash chain state ---
static AUDIT_PREV: Lazy<Mutex<String>> = Lazy::new(|| {
    // Chain continuity across restarts: read the last hash from the audit file (MCP_AUDIT_LOG) so
    // tamper evidence survives a restart (resetting to GENESIS would break the chain).
    let start = std::env::var("MCP_AUDIT_LOG")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| {
            c.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(String::from)
        })
        .and_then(|last| serde_json::from_str::<Value>(&last).ok())
        .and_then(|v| v.get("hash").and_then(|h| h.as_str()).map(String::from))
        .unwrap_or_else(|| "GENESIS".into());
    Mutex::new(start)
});

/// Sequence number of the last entry — a gap reveals a deleted entry, and knowing the last number
/// makes TAIL TRUNCATION detectable (recomputing the chain alone cannot see it, because a truncated
/// log is internally consistent).
static AUDIT_SEQ: Lazy<std::sync::atomic::AtomicU64> = Lazy::new(|| {
    let last = std::env::var("MCP_AUDIT_LOG")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| {
            c.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(String::from)
        })
        .and_then(|l| serde_json::from_str::<Value>(&l).ok())
        .and_then(|v| v.get("seq").and_then(|s| s.as_u64()))
        .unwrap_or(0);
    std::sync::atomic::AtomicU64::new(last)
});

// --- SQL fingerprint (first 16 hex characters of SHA-256) ---
fn sql_fingerprint(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let result = hasher.finalize();
    // Manual hex formatting; we keep the first 16 characters (8 bytes)
    format!("{:x}", result).chars().take(16).collect()
}

// --- Main audit function ---
fn audit(tool: &str, decision: &str, sql: Option<&str>) {
    // 1. Timestamp (sekundy od epoki)
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 2. Odcisk SQL (lub pusty string)
    let sqlh = sql.map(sql_fingerprint).unwrap_or_default();

    // 3. Build the entry (without the chain fields). `caller` = `sub` from the token: without it the
    //    audit says WHAT happened but not WHO did it — with multiple tenants that is half of the
    //    accountability OWASP MCP08 asks for.
    let seq = AUDIT_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let key = audit_key();
    let mut entry = json!({
        "seq": seq,
        "ts": ts,
        "tool": tool,
        "decision": decision,
        "sql_fp": sqlh,
        "caller": current_caller().unwrap_or_else(|| "-".to_string())
    });
    // The key FINGERPRINT (never the key): lets the verifier pick the right key after a rotation.
    // Without it a legitimate rotation produced a message indistinguishable from sabotage, and the
    // operator would learn to ignore "CORRUPTED" — masking a real tamper.
    if let Some((_, fp)) = &key {
        entry["key_fp"] = Value::String(fp.clone());
    }

    // 4. Chain: HMAC-SHA256(key, prev || entry) when a key is set, otherwise plain SHA-256.
    //    THE DIFFERENCE MATTERS: plain SHA-256 detects accidental corruption and an attacker WITHOUT
    //    file access, but anyone who can write the file may delete entries and RECOMPUTE the chain from
    //    GENESIS — the result verifies as consistent. With the key held OFF the host (from a vault/KMS)
    //    that recomputation is impossible.
    let mut prev_guard = AUDIT_PREV.lock().unwrap();
    let prev_hash = prev_guard.clone();
    let entry_str = serde_json::to_string(&entry).expect("serializacja entry");
    let payload = format!("{}{}", prev_hash, entry_str);
    let current_hash = match &key {
        Some((k, _)) => hmac_sha256_hex(k.clone(), payload.as_bytes()),
        None => {
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            format!("{:x}", hasher.finalize())
        }
    };

    // 5. Extend the entry with the chain fields
    let mut full_entry = entry;
    full_entry["prev"] = Value::String(prev_hash);
    full_entry["hash"] = Value::String(current_hash.clone());

    // 6. Aktualizacja stanu globalnego
    *prev_guard = current_hash;

    // 7. Output: stderr (stream) + the durable file (MCP_AUDIT_LOG) for tamper evidence across restarts.
    let line = serde_json::to_string(&full_entry).expect("serializacja full_entry");
    eprintln!("AUDIT {}", line);
    if let Ok(path) = std::env::var("MCP_AUDIT_LOG") {
        use std::io::Write;
        // A failed write MUST be visible. Previously `if let Ok(...)` swallowed the error silently:
        // a typo in the path or an unmounted volume meant the audit was dead from the first second,
        // while the server answered normally and no counter moved.
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| writeln!(f, "{}", line));
        if let Err(e) = res {
            METRICS.audit_write_failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("AUDIT WRITE FAILED ({}): {}", path, e);
        }
    }
}

/// Walks the audit file and checks that every entry has a correct `prev` and `hash`. Returns the
/// entry count, or a description of the first mismatch (the line number is where the log was touched).
/// It uses EXACTLY the same hash function as the writer, so the verdict never depends on interpretation.
fn verify_audit_file(path: &str, expect_last: Option<&str>) -> Result<String, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;

    // Key set: the current one plus (optionally) previous ones, comma-separated. A log that survived a
    // ROTATION must verify end to end — otherwise every rotation looks like sabotage.
    let mut keys: Vec<(Vec<u8>, String)> = Vec::new();
    if let Some(k) = audit_key() {
        keys.push(k);
    }
    if let Ok(olds) = std::env::var("MCP_AUDIT_HMAC_KEYS_OLD") {
        for k in olds.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let b = k.as_bytes().to_vec();
            let fp = key_fingerprint(&b);
            keys.push((b, fp));
        }
    }

    let mut prev = "GENESIS".to_string();
    let mut prev_seq: Option<u64> = None;
    let mut n = 0usize;
    let mut rotations = 0usize;
    let mut last_fp: Option<String> = None;

    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let ln = i + 1;
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("line {}: invalid JSON: {}", ln, e))?;
        let obj = v
            .as_object()
            .ok_or_else(|| format!("line {}: not an object", ln))?;
        let got_prev = obj.get("prev").and_then(|x| x.as_str()).unwrap_or("");
        let got_hash = obj.get("hash").and_then(|x| x.as_str()).unwrap_or("");
        if got_prev != prev {
            return Err(format!(
                "line {}: chain broken — entry points at a different predecessor",
                ln
            ));
        }
        // A gap in the sequence = someone cut an entry out of the MIDDLE and recomputed the rest.
        if let Some(seq) = obj.get("seq").and_then(|s| s.as_u64()) {
            if let Some(p) = prev_seq {
                if seq != p + 1 {
                    return Err(format!(
                        "line {}: sequence gap — expected {}, found {} (entries were removed)",
                        ln,
                        p + 1,
                        seq
                    ));
                }
            }
            prev_seq = Some(seq);
        }

        let mut entry = obj.clone();
        entry.remove("prev");
        entry.remove("hash");
        let entry_str = serde_json::to_string(&Value::Object(entry))
            .map_err(|e| format!("line {}: {}", ln, e))?;
        let payload = format!("{}{}", prev, entry_str);

        let entry_fp = obj.get("key_fp").and_then(|x| x.as_str());
        let expect = match entry_fp {
            Some(fp) => {
                if last_fp.as_deref().is_some_and(|l| l != fp) {
                    rotations += 1;
                }
                last_fp = Some(fp.to_string());
                let (k, _) = keys
                    .iter()
                    .find(|(_, kfp)| kfp == fp)
                    .ok_or_else(|| format!(
                        "line {}: entry was signed with key {} which was not provided — pass it in MCP_AUDIT_HMAC_KEY or MCP_AUDIT_HMAC_KEYS_OLD",
                        ln, fp
                    ))?;
                hmac_sha256_hex(k.clone(), payload.as_bytes())
            }
            None => {
                let mut h = Sha256::new();
                h.update(payload.as_bytes());
                format!("{:x}", h.finalize())
            }
        };
        if got_hash != expect {
            return Err(format!(
                "line {}: hash mismatch — this entry was modified",
                ln
            ));
        }
        prev = got_hash.to_string();
        n += 1;
    }

    // TAIL TRUNCATION is invisible from the inside: the shortened log is self-consistent and cutting it
    // needs no key. The only defence is an anchor kept ELSEWHERE — so we return the last hash (to be
    // stored off this host) and check it whenever the operator supplies the expected value.
    if let Some(want) = expect_last {
        if want != prev {
            return Err(format!(
                "tail truncated or rewritten — last hash is {} but {} was expected (entries after that point are gone)",
                prev, want
            ));
        }
    }
    let seq_info = prev_seq
        .map(|s| format!(", ostatni seq {}", s))
        .unwrap_or_default();
    let rot_info = if rotations > 0 {
        format!(", rotacji klucza: {}", rotations)
    } else {
        String::new()
    };
    Ok(format!("{} entries{}{}\n  last hash: {}\n  STORE this hash off-host — without an external anchor, truncating the tail of the log is undetectable", n, seq_info, rot_info, prev))
}

/// HMAC key for the audit chain. `MCP_AUDIT_HMAC_KEY` (the value) or `MCP_AUDIT_HMAC_KEY_FILE`
/// (a path — more convenient for secrets mounted by an orchestrator).
fn audit_key() -> Option<(Vec<u8>, String)> {
    static KEY: Lazy<Option<(Vec<u8>, String)>> = Lazy::new(|| {
        let raw: Option<Vec<u8>> = if let Ok(k) = std::env::var("MCP_AUDIT_HMAC_KEY") {
            (!k.is_empty()).then(|| k.into_bytes())
        } else if let Ok(p) = std::env::var("MCP_AUDIT_HMAC_KEY_FILE") {
            match std::fs::read(&p) {
                // TRIM a trailing newline: `echo key > file`, editors and secret managers append `\n`, so
                // "the same" secret recreated another way produced a different HMAC.
                Ok(b) => {
                    let mut b = b;
                    while matches!(b.last(), Some(b'\n') | Some(b'\r')) {
                        b.pop();
                    }
                    (!b.is_empty()).then_some(b)
                }
                Err(e) => {
                    eprintln!("AUDIT: cannot read MCP_AUDIT_HMAC_KEY_FILE {}: {}", p, e);
                    None
                }
            }
        } else {
            None
        };
        raw.map(|k| {
            let fp = key_fingerprint(&k);
            (k, fp)
        })
    });
    KEY.clone()
}

/// A short, public key identifier (8 hex characters of SHA-256). It reveals no secret — it only
/// matches the right key when verifying a log that survived a rotation.
fn key_fingerprint(k: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(k);
    format!("{:x}", h.finalize()).chars().take(8).collect()
}

/// HMAC-SHA256 per RFC 2104 — the standard construction, written out to keep the crate set minimal.
fn hmac_sha256_hex(key: Vec<u8>, msg: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(&key);
        h.finalize().to_vec()
    } else {
        key
    };
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    format!("{:x}", outer.finalize())
}

// --- caller identity, available to the audit without threading a parameter through six signatures ---
thread_local! {
    static CALLER: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Sets the identity for one request and clears it when the scope ends (including on error or
/// panic), so it cannot leak into the next request handled by the same pool thread.
pub struct CallerScope;
impl Drop for CallerScope {
    fn drop(&mut self) {
        CALLER.with(|c| *c.borrow_mut() = None);
    }
}
fn set_caller(id: Option<String>) -> CallerScope {
    CALLER.with(|c| *c.borrow_mut() = id);
    CallerScope
}
fn current_caller() -> Option<String> {
    CALLER.with(|c| c.borrow().clone())
}

pub struct AuthConfig {
    pub pubkey: Vec<u8>,
    pub aud: String,
    pub iss: String,
}

static AUTH_CONFIG: Lazy<Option<AuthConfig>> = Lazy::new(|| {
    let pem = std::env::var("JWT_PUBKEY_PEM").ok()?;
    Some(AuthConfig {
        pubkey: pem.into_bytes(),
        aud: std::env::var("JWT_AUD").unwrap_or_default(),
        iss: std::env::var("JWT_ISS").unwrap_or_default(),
    })
});

fn enforce_auth(
    headers: &HeaderMap,
    req: &Value,
) -> Result<Option<String>, (u16, String, Option<String>)> {
    let cfg = match &*AUTH_CONFIG {
        Some(c) => c,
        None => return Ok(None),
    };

    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

    if method == "initialize" || method == "tools/list" {
        return Ok(None);
    }

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

    if method == "tools/call" {
        let name = req
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let needed = if name == "query" {
            "mcp:query"
        } else {
            "mcp:read"
        };

        if !ctx.has_scope(needed) && !ctx.has_scope("mcp:admin") {
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
use axum::routing::get;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    query_allowed: AtomicU64,
    denied_validation: AtomicU64,
    denied_cost: AtomicU64,
    denied_auth: AtomicU64,
    denied_rate: AtomicU64,
    audit_write_failed: AtomicU64,
    errors: AtomicU64,
}

static METRICS: Lazy<Metrics> = Lazy::new(Metrics::default);

fn render_metrics() -> String {
    let mut buf = String::new();
    macro_rules! push_metric {
        ($name:expr, $val:expr) => {
            buf.push_str("# HELP ");
            buf.push_str($name);
            buf.push_str(" Total count\n# TYPE ");
            buf.push_str($name);
            buf.push_str(" counter\n");
            buf.push_str($name);
            buf.push(' ');
            buf.push_str(&$val.to_string());
            buf.push('\n');
        };
    }

    push_metric!(
        "mcp_requests_total",
        METRICS.requests.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_query_allowed_total",
        METRICS.query_allowed.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_denied_validation_total",
        METRICS.denied_validation.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_denied_cost_total",
        METRICS.denied_cost.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_denied_auth_total",
        METRICS.denied_auth.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_denied_rate_total",
        METRICS.denied_rate.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_audit_write_failed_total",
        METRICS.audit_write_failed.load(Ordering::Relaxed)
    );
    push_metric!("mcp_errors_total", METRICS.errors.load(Ordering::Relaxed));

    buf
}

async fn metrics_handler(headers: HeaderMap) -> impl IntoResponse {
    // Open by default (scraped from a private network). When `MCP_METRICS_TOKEN` is set we require it —
    // otherwise a public deployment lets anyone watch traffic and how well auth denials are working.
    if let Ok(expected) = std::env::var("MCP_METRICS_TOKEN") {
        if !expected.is_empty() {
            let given = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            // constant-time comparison — the token must not leak through response timing
            let eq = given.len() == expected.len()
                && given
                    .as_bytes()
                    .iter()
                    .zip(expected.as_bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;
            if !eq {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(CONTENT_TYPE, "text/plain")],
                    "unauthorized\n".to_string(),
                );
            }
        }
    }
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_metrics(),
    )
}

async fn health_handler() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

async fn ready_handler() -> impl axum::response::IntoResponse {
    // pool.get() is blocking (r2d2/postgres block_on) and panics from an async handler
    // ("runtime within runtime"), so the DB check goes through spawn_blocking.
    let res = tokio::task::spawn_blocking(|| match pool_for(None) {
        // get_timeout, not get(): with a busy pool the probe must answer "not ready" within a second
        // rather than hang until connection_timeout — otherwise the orchestrator restarts the container
        // mid-attack and deepens the outage.
        Ok(pool) => pool
            .get_timeout(std::time::Duration::from_secs(1))
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.clone()),
    })
    .await;
    match res {
        Ok(Ok(())) => (axum::http::StatusCode::OK, "ready"),
        Ok(Err(_)) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "db unavailable",
        ),
        Err(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "internal error",
        ),
    }
}

/// RFC 9728 Protected Resource Metadata — pairs with the `WWW-Authenticate` header on a 401.
/// It lets a client (and registry scanners) discover the authorization server and start OAuth discovery.
async fn oauth_protected_resource_handler() -> impl axum::response::IntoResponse {
    let base = std::env::var("MCP_PUBLIC_URL").unwrap_or_default();
    let auth_servers: Vec<String> = std::env::var("MCP_AUTH_SERVERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Json(json!({
        "resource": base.trim_end_matches('/'),
        "authorization_servers": auth_servers,
        "scopes_supported": ["mcp:query"],
        "bearer_methods_supported": ["header"]
    }))
}

/// Server card — server metadata for MCP registries (name, version, transport, auth, tools).
async fn server_card_handler() -> impl axum::response::IntoResponse {
    let base = std::env::var("MCP_PUBLIC_URL").unwrap_or_default();
    let base = base.trim_end_matches('/');
    let auth_required = std::env::var("JWT_PUBKEY_PEM").is_ok();
    let tools = handle_tools_list()["result"]["tools"].clone();
    Json(json!({
        "name": "postgres-mcp-hardened",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Read-only PostgreSQL MCP server in Rust: AST-enforced read-only queries plus database-level read-only transaction, per-session statement_timeout, schema inspection.",
        "protocolVersion": "2025-06-18",
        "transport": ["streamable-http", "stdio"],
        "endpoint": if base.is_empty() { "/mcp".to_string() } else { format!("{}/mcp", base) },
        "authentication": {
            "required": auth_required,
            "type": if auth_required { "oauth2.1" } else { "none" },
            "protectedResourceMetadata": "/.well-known/oauth-protected-resource"
        },
        "tools": tools
    }))
}

fn handle_request(req: &Value) -> Value {
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

    match method {
        "initialize" => handle_initialize(),
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(&params),
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
    }
}

fn handle_initialize() -> Value {
    json!({
        "result": {
            "protocolVersion": "2025-06-18",
            // MCP_SERVER_LABEL lets an operator running several instances tell them apart in the
            // client UI ("postgres-mcp-hardened (production)") instead of seeing identical entries.
            "serverInfo": { "name": server_label(), "version": "0.1.0" },
            "capabilities": { "tools": {}, "resources": {} }
        }
    })
}

fn handle_tools_list() -> Value {
    let tools = vec![
        tool_def(
            "query",
            "Execute a read-only SQL query",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" },
                    "limit": { "type": "integer", "minimum": 1, "default": 1000 }
                },
                "required": ["sql"]
            })
        ),
        tool_def(
            "list_schemas",
            "List all schemas",
            json!({"type": "object", "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }}),
        ),
        tool_def("list_tables", "List tables, views and materialized views in a schema", json!({
            "type": "object",
            "properties": { "schema": { "type": "string" }, "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } },
            "required": ["schema"]
        })),
        tool_def("describe_table", "Describe table columns: type, nullability, default, primary key, and the schema comment documenting what the column means", json!({
            "type": "object",
            "properties": { "schema": { "type": "string" }, "table": { "type": "string" }, "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } },
            "required": ["schema", "table"]
        })),
    ];
    json!({ "result": { "tools": tools } })
}

fn tool_def(name: &str, desc: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": input_schema,
        "annotations": { "readOnlyHint": true }
    })
}

fn handle_tools_call(params: &Value) -> Value {
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
        _ => json!({ "error": { "code": -32601, "message": format!("Unknown tool: {}", name) } }),
    }
}

fn handle_query_tool(args: &Value) -> Value {
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
    //    fragment as the whole (`rowCount: 1000` was indistinguishable from a complete result).
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000)
        .min(MAX_LIMIT);
    let final_sql = match validate::enforce_limit(sql, limit.saturating_add(1)) {
        Ok(s) => s,
        Err(e) => return json!({ "error": { "code": -32602, "message": e.to_string() } }),
    };

    // cost guard only for queries EXPLAIN can plan (SELECT/WITH/VALUES/TABLE); EXPLAIN/SHOW are
    // skipped (you cannot EXPLAIN an EXPLAIN — statement_timeout is the backstop there).
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
fn mark_truncation(data: &mut Value, limit: u64) {
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
        data["rowCount"] = json!(limit);
    }
    data["truncated"] = json!(truncated);
    data["rowLimit"] = json!(limit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    /// Truncation MUST be explicit in the response (and must not overstate rowCount).
    #[test]
    fn truncation_is_reported() {
        let mut full = json!({"rowCount": 3, "rows": [{"a":1},{"a":2},{"a":3}]});
        mark_truncation(&mut full, 2);
        assert_eq!(full["truncated"], json!(true));
        assert_eq!(full["rowCount"], json!(2));
        assert_eq!(full["rows"].as_array().unwrap().len(), 2);
        assert_eq!(full["rowLimit"], json!(2));

        let mut partial = json!({"rowCount": 2, "rows": [{"a":1},{"a":2}]});
        mark_truncation(&mut partial, 5);
        assert_eq!(partial["truncated"], json!(false));
        assert_eq!(partial["rowCount"], json!(2));
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
        assert_eq!(result["protocolVersion"], "2025-06-18");
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
        let resp = handle_request(&req);
        assert!(resp.get("error").is_some());
        let err = &resp["error"];
        assert_eq!(err["code"], -32602); // Invalid params (validation error)
        assert!(
            err["message"].as_str().unwrap().contains("read-only")
                | err["message"].as_str().unwrap().contains("Read-only")
        );
    }
}
