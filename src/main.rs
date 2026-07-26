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
mod ratelimit;
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
    if let Ok(pem) = std::env::var("JWT_PUBKEY_PEM") {
        if jsonwebtoken::DecodingKey::from_rsa_pem(pem.as_bytes()).is_err() {
            fatal.push("JWT_PUBKEY_PEM is not a valid RSA public key in PEM format".to_string());
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
pub(crate) async fn mcp_handler(
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

pub struct AuthConfig {
    pub pubkey: Vec<u8>,
    pub aud: String,
    pub iss: String,
}

pub(crate) static AUTH_CONFIG: Lazy<Option<AuthConfig>> = Lazy::new(|| {
    let pem = std::env::var("JWT_PUBKEY_PEM").ok()?;
    Some(AuthConfig {
        pubkey: pem.into_bytes(),
        aud: std::env::var("JWT_AUD").unwrap_or_default(),
        iss: std::env::var("JWT_ISS").unwrap_or_default(),
    })
});

pub(crate) fn enforce_auth(
    headers: &HeaderMap,
    req: &Value,
) -> Result<Option<String>, (u16, String, Option<String>)> {
    // A shared bearer token: the simplest possible protection for people who do not run an identity
    // provider. Both alternatives have an open request for exactly this. Checked before OAuth so a
    // deployment can use either, and compared in constant time.
    if let Some(expected) = std::env::var("MCP_BEARER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
    {
        let given = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        let equal = given.len() == expected.len()
            && given
                .as_bytes()
                .iter()
                .zip(expected.as_bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !equal {
            return Err((401, "invalid or missing bearer token".into(), None));
        }
        if AUTH_CONFIG.is_none() {
            return Ok(None);
        }
    }
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

pub(crate) fn handle_initialize() -> Value {
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

pub(crate) fn handle_tools_list() -> Value {
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
        tool_def("explain_query", "Show the PostgreSQL execution plan for a read-only query; set analyze=true to run it and report actual timings and buffer usage", json!({
            "type": "object",
            "properties": {
                "sql": { "type": "string" },
                "analyze": { "type": "boolean", "default": false },
                "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
            },
            "required": ["sql"]
        })),
        tool_def("database_health", "Health snapshot: cache hit ratio, connections, long-running statements, vacuum backlog, invalid indexes, sequences near their limit, replication lag", json!({
            "type": "object",
            "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }
        })),
        tool_def("top_queries", "Heaviest statements by total execution time, from pg_stat_statements", json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
            }
        })),
        tool_def("analyze_indexes", "Index findings for a schema: unused indexes, duplicates, and tables scanned sequentially where an index would likely pay off", json!({
            "type": "object",
            "properties": {
                "schema": { "type": "string", "default": "public" },
                "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
            }
        })),
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
    let opts = if analyze {
        "FORMAT JSON, ANALYZE true, BUFFERS true"
    } else {
        "FORMAT JSON"
    };
    let stmt = format!("EXPLAIN ({}) {}", opts, sql);
    match query_catalog(&stmt, &[], db) {
        Ok(v) => {
            audit("explain_query", "allowed", Some(sql));
            ok_content(&v)
        }
        Err(e) => {
            audit("explain_query", "error", Some(sql));
            err_content(-32000, e)
        }
    }
}

/// A health snapshot an operator would otherwise assemble by hand from half a dozen catalog views.
/// Every check degrades gracefully: a role that cannot read a view yields a note, not a failure.
pub(crate) fn handle_database_health(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    const CHECKS: &[(&str, &str)] = &[
        (
            "cache_hit_ratio",
            "SELECT round(100.0 * sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0), 2) AS pct_from_cache, sum(heap_blks_hit) + sum(heap_blks_read) AS blocks_sampled, CASE WHEN COALESCE(sum(heap_blks_hit) + sum(heap_blks_read), 0) = 0 THEN 'no I/O recorded yet — statistics reset with the server' END AS note FROM pg_statio_user_tables",
        ),
        (
            "connections",
            "SELECT count(*) AS in_use,                     (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections,                     count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_transaction              FROM pg_stat_activity",
        ),
        (
            "longest_running",
            "SELECT round(EXTRACT(epoch FROM max(now() - query_start))::numeric, 1) AS longest_query_seconds,                     round(EXTRACT(epoch FROM max(now() - xact_start))::numeric, 1) AS longest_transaction_seconds              FROM pg_stat_activity WHERE state <> 'idle'",
        ),
        (
            "vacuum_backlog",
            "SELECT relname AS table_name, n_dead_tup AS dead_rows, n_live_tup AS live_rows, last_autovacuum              FROM pg_stat_user_tables WHERE n_dead_tup > 1000              ORDER BY n_dead_tup DESC LIMIT 10",
        ),
        (
            "invalid_indexes",
            "SELECT c.relname AS index_name FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid              WHERE NOT i.indisvalid",
        ),
        (
            "sequences_near_limit",
            "SELECT schemaname || '.' || sequencename AS sequence, last_value, max_value,                     round(100.0 * last_value / NULLIF(max_value, 0), 2) AS pct_used              FROM pg_sequences WHERE last_value IS NOT NULL                AND 100.0 * last_value / NULLIF(max_value, 0) > 50 ORDER BY 4 DESC LIMIT 10",
        ),
        (
            "replication",
            "SELECT pg_is_in_recovery() AS is_standby,                     CASE WHEN pg_is_in_recovery()                          THEN round(EXTRACT(epoch FROM now() - pg_last_xact_replay_timestamp())::numeric, 1)                          END AS replay_lag_seconds",
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
        "SELECT calls, round(total_exec_time::numeric, 1) AS total_ms,                 round(mean_exec_time::numeric, 2) AS mean_ms, rows,                 left(query, 300) AS query          FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT {}",
        limit
    );
    match query_catalog(&sql, &[], db) {
        Ok(v) => {
            audit("top_queries", "allowed", None);
            ok_content(&v)
        }
        Err(e) => {
            audit("top_queries", "error", None);
            if e.contains("does not exist") || e.contains("42P01") {
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
    const UNUSED: &str =
        "SELECT s.relname AS table_name, s.indexrelname AS index_name, s.idx_scan AS scans,                 pg_size_pretty(pg_relation_size(s.indexrelid)) AS size          FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid          WHERE s.schemaname = $1 AND s.idx_scan = 0 AND NOT i.indisprimary AND NOT i.indisunique          ORDER BY pg_relation_size(s.indexrelid) DESC LIMIT 20";
    const DUPLICATES: &str =
        // array_to_string, not array_agg: an array column comes back as null through the driver.
        "SELECT t.relname AS table_name, array_to_string(array_agg(c.relname ORDER BY c.relname), ', ') AS duplicate_indexes, pg_size_pretty(sum(pg_relation_size(c.oid))) AS combined_size FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = $1 GROUP BY t.relname, i.indrelid, i.indkey::text, i.indclass::text, (i.indpred IS NULL) HAVING count(*) > 1 ORDER BY sum(pg_relation_size(c.oid)) DESC LIMIT 20";
    const SEQ_SCANS: &str =
        "SELECT relname AS table_name, seq_scan, idx_scan, n_live_tup AS rows,                 pg_size_pretty(pg_relation_size(relid)) AS size          FROM pg_stat_user_tables WHERE schemaname = $1 AND seq_scan > COALESCE(idx_scan, 0)            AND n_live_tup > 10000 ORDER BY seq_scan DESC LIMIT 10";
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
            "Counters come from pg_stat_*, which reset with the server and start empty; read them              after a representative period of traffic, not straight after a restart."
                .into(),
        ),
    );
    audit("analyze_indexes", "allowed", None);
    ok_content(&Value::Object(out))
}

pub(crate) fn tool_def(name: &str, desc: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": input_schema,
        "annotations": { "readOnlyHint": true }
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
