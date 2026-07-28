//! Split out of `main.rs`, which had grown to 2572 lines holding the entry point, the
//! configuration gate, both transports, authorisation and the tool dispatcher at once. The
//! code below is UNCHANGED — this was a move, so that the diff reads as "the same thing,
//! somewhere else" on the most security-sensitive file in the project.

use crate::*;

// --- STDIO TRANSPORT ---
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
    // The same reader the start-policy check used, so the address it judged is the address we bind.
    let addr = listen_addr();
    let state = AppState::default();

    let app = Router::new()
        .route("/", get(root_handler))
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

    // A port already in use is the most ordinary thing that can go wrong on someone else's machine,
    // and it used to answer with a Rust panic and a backtrace hint. Our own CI found it: six jobs
    // died on `AddrInUse` because the runner shares a host with a service already holding 8080.
    // A server whose entire claim is "check, do not trust" cannot fall over with a stack trace on
    // the first obstacle — it says what happened, in terms of the setting the operator controls.
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "Cannot listen on {}: {}.{}",
                addr,
                e,
                match e.kind() {
                    std::io::ErrorKind::AddrInUse =>
                        " Something else already holds that port — stop it, or set MCP_ADDR to a free one.",
                    std::io::ErrorKind::PermissionDenied =>
                        " Ports below 1024 need privileges this server deliberately does not have; set MCP_ADDR higher.",
                    std::io::ErrorKind::AddrNotAvailable =>
                        " No interface on this machine has that address; set MCP_ADDR to one that exists.",
                    _ => "",
                }
            );
            std::process::exit(1);
        }
    };
    eprintln!("MCP HTTP listening on http://{}", addr);
    // ConnectInfo: the rate limiter needs the peer address (headers are client-controlled, so untrusted).
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        eprintln!("HTTP server stopped: {}", e);
        std::process::exit(1);
    }
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
    // On a container platform the PLATFORM owns the port: Apify Standby passes it in
    // `ACTOR_WEB_SERVER_PORT` and routes to it, so a server that binds somewhere else is simply
    // never reached — the run waits for a readiness probe that cannot arrive and then times out
    // with nothing in the log to explain it. That is why the platform's port wins over `MCP_ADDR`
    // here rather than the other way round: a copied `MCP_ADDR=127.0.0.1:8080` is the likeliest
    // way to produce exactly that silent hang.
    //
    // It is said out loud, not applied quietly, because overriding an operator's explicit setting
    // is the kind of helpfulness that costs an hour when it is wrong.
    //
    // `0.0.0.0` rather than loopback: the container is reached from outside it. This makes the
    // origin check STRICTER, not weaker — `check_origin` stops treating loopback origins as
    // automatically allowed once the server is not on loopback, so a browser page needs
    // `MCP_ALLOWED_ORIGINS` to talk to us at all.
    if let Ok(port) = std::env::var("ACTOR_WEB_SERVER_PORT") {
        let port = port.trim();
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(explicit) = std::env::var("MCP_ADDR") {
                if !explicit.trim().is_empty() && !explicit.ends_with(&format!(":{port}")) {
                    eprintln!(
                        "ACTOR_WEB_SERVER_PORT={port} overrides MCP_ADDR={explicit}: on this \
                         platform the port is assigned, and binding elsewhere means the run is \
                         never marked ready."
                    );
                }
            }
            return format!("0.0.0.0:{port}");
        }
        eprintln!("ACTOR_WEB_SERVER_PORT={port:?} is not a port number — ignoring it.");
    }
    std::env::var("MCP_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

/// `GET /` — the platform's readiness probe, and a signpost for anything else that lands here.
///
/// Apify sends `GET /` with `x-apify-container-server-readiness-probe` and waits for a response:
/// "You must return a response; otherwise, the Actor run will never be marked as ready." It must not
/// touch the database — readiness of the container is not readiness of Postgres, and a probe that
/// blocks on a busy pool turns a slow database into a container that never starts. `/ready` is where
/// the database question is answered.
pub(crate) async fn root_handler(headers: HeaderMap) -> impl IntoResponse {
    if headers.contains_key("x-apify-container-server-readiness-probe") {
        return (StatusCode::OK, "ready").into_response();
    }
    (
        StatusCode::OK,
        "postgres-mcp-hardened — MCP endpoint is POST /mcp (Streamable HTTP). \
         Probes: GET /health, GET /ready. Metrics: GET /metrics.\n",
    )
        .into_response()
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
    // Carries the revision this session agreed on at `initialize`, so a request that arrives
    // without the header is answered under the contract the client actually negotiated.
    let mut session_rev: Option<protocol::Rev> = None;
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        let mut known = state.sessions.write().await;
        match known.get_mut(sid) {
            Some((last, rev)) => {
                *last = uptime_secs(); // refresh so an active session does not expire
                session_rev = Some(*rev);
            }
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
    // OAuth 2.1: enforce token and scope (active once JWT_PUBKEY_PEM is set).
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
    // 1. No "id" means a notification: 202 Accepted with no body.
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
    //
    // Always Some: an HTTP request must not inherit the revision *another* client negotiated —
    // several clients share one process here. It may, and must, inherit the one THIS session
    // negotiated, which is why the fallback goes through `session_rev` rather than straight to the
    // oldest revision. The transport specification permits the default only "if the server does
    // not receive an MCP-Protocol-Version header, and has no other way to identify the version —
    // for example, by relying on the protocol version negotiated during initialization".
    //
    // The last resort is the oldest revision we implement, not the `2025-03-26` the specification
    // names: that revision is not in `Rev::parse`, so assuming it would mean answering under a
    // contract this server cannot honour. The oldest one we do implement is the conservative
    // reading the clause asks for.
    //
    // The draft carries the version in the body's `_meta`; earlier revisions use the header. Read
    // both here, because the header agreement check below needs to know which contract applies
    // before the request reaches the thread that runs it.
    let body_params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    // A header we cannot parse is refused, not downgraded — the specification makes this a MUST,
    // and the difference matters: an absent header means "an older client", a header reading
    // `not-a-date` means a client that believes it negotiated something we never agreed to.
    //
    // `initialize` is exempt, and deliberately so. Two rules meet here: the transport says a bad
    // header MUST get a 400, but it says so about "all subsequent requests" — requests after the
    // handshake — while the lifecycle says the server MUST answer `initialize` with a version it
    // supports rather than an error. On `initialize` the specific rule wins: an older client that
    // hardcodes `2025-03-26` in its header would otherwise be locked out of a handshake that would
    // have succeeded, which is the opposite of what the backwards-compatibility clause is for.
    // Negotiation belongs in the body there; the header rule applies from the next request on.
    let is_initialize = req.get("method").and_then(|v| v.as_str()) == Some("initialize");
    if let Some(asked) = headers
        .get("mcp-protocol-version")
        .filter(|_| !is_initialize)
        .and_then(|v| v.to_str().ok())
    {
        if protocol::Rev::parse(asked).is_none() {
            let mut body = protocol::unsupported_header_error(asked);
            body["jsonrpc"] = Value::String("2.0".into());
            body["id"] = req.get("id").cloned().unwrap_or(Value::Null);
            return (StatusCode::BAD_REQUEST, HeaderMap::new(), Json(body)).into_response();
        }
    }
    let rev_for_request = protocol::rev_from_meta(&body_params).unwrap_or_else(|| {
        headers
            .get("mcp-protocol-version")
            .and_then(|v| v.to_str().ok())
            .and_then(protocol::Rev::parse)
            .or(session_rev)
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
    // What we ANSWERED with, not what the client asked for: that string is the contract this
    // session now runs under, so that is the one worth remembering. A failed `initialize` has no
    // `result` and leaves nothing to remember.
    let negotiated = if method == "initialize" {
        resp.get("result")
            .and_then(|r| r.get("protocolVersion"))
            .and_then(|v| v.as_str())
            .and_then(protocol::Rev::parse)
    } else {
        None
    };
    // A handshake that failed is not a session. Creating one anyway would hand the client an id it
    // could keep using, under whatever revision the fallback picked, since a rejected `initialize`
    // has no negotiated version to remember.
    //
    // Stated plainly because it matters when reading this: the guard is DEFENSIVE. No current path
    // reaches it — `initialize` negotiates rather than refusing, and an authorisation failure
    // returns long before this line. There is deliberately no acceptance check for it, because a
    // check that cannot fail is not coverage, it is the appearance of coverage. It stays because
    // the cost is one condition and the failure it prevents is silent.
    let final_session_id =
        if method == "initialize" && session_id.is_none() && resp.get("result").is_some() {
            let new_id = Uuid::new_v4().to_string();
            let now = uptime_secs();
            let mut s = state.sessions.write().await;
            if s.len() >= MAX_SESSIONS {
                s.retain(|_, (last, _)| now.saturating_sub(*last) < SESSION_IDLE_SECS);
                if s.len() >= MAX_SESSIONS {
                    s.clear(); // still full = someone is inflating it; start clean rather than grow
                }
            }
            s.insert(
                new_id.clone(),
                (now, negotiated.unwrap_or(protocol::Rev::V20250618)),
            );
            new_id
        } else {
            let sid = session_id.unwrap_or_default();
            // Re-initializing over a live session changes the contract, so the remembered revision has
            // to change with it — otherwise the session would keep answering under the old one.
            if let Some(rev) = negotiated {
                if let Some(entry) = state.sessions.write().await.get_mut(&sid) {
                    entry.1 = rev;
                }
            }
            sid
        };

    if !final_session_id.is_empty() {
        resp_headers.insert(
            "mcp-session-id",
            HeaderValue::from_str(&final_session_id).unwrap(),
        );
    }

    (StatusCode::OK, resp_headers, Json(resp)).into_response()
}
