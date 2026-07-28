//! HTTP surface: metrics, health probes and the well-known discovery endpoints.

use crate::*;
use once_cell::sync::Lazy;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) requests: AtomicU64,
    pub(crate) query_allowed: AtomicU64,
    pub(crate) denied_validation: AtomicU64,
    pub(crate) denied_cost: AtomicU64,
    pub(crate) denied_auth: AtomicU64,
    pub(crate) denied_rate: AtomicU64,
    pub(crate) denied_origin: AtomicU64,
    pub(crate) audit_write_failed: AtomicU64,
    pub(crate) errors: AtomicU64,
}

pub(crate) static METRICS: Lazy<Metrics> = Lazy::new(Metrics::default);

pub(crate) fn render_metrics() -> String {
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
        "mcp_denied_origin_total",
        METRICS.denied_origin.load(Ordering::Relaxed)
    );
    push_metric!(
        "mcp_audit_write_failed_total",
        METRICS.audit_write_failed.load(Ordering::Relaxed)
    );
    push_metric!("mcp_errors_total", METRICS.errors.load(Ordering::Relaxed));

    buf
}

/// Refuses browser-originated requests unless the operator named the origin.
///
/// A page the user is merely visiting can make its browser POST to `http://localhost:8080/mcp`.
/// That is DNS rebinding's whole trick, and against a local database server it is the difference
/// between reading a news site and reading `salaries`. The MCP specification requires 403 here.
///
/// One origin is trusted without configuration: a LOOPBACK origin, and only while we listen on
/// loopback ourselves. That is not a hole — an attacker's page carries its own origin, never
/// `http://localhost:<port>` — and refusing it was a real defect the official conformance suite
/// caught: out of the box, no browser-based client on the same machine could reach this server.
/// Everything else still has to be named in `MCP_ALLOWED_ORIGINS`.
///
/// `Host` is checked only when we listen on loopback. That is precisely the rebinding case — a name
/// the attacker controls resolving to 127.0.0.1 — while a server behind a reverse proxy legitimately
/// sees any hostname, and refusing those would break real deployments to guard against nothing.
pub(crate) fn check_origin(headers: &HeaderMap, listen: &str) -> Result<(), String> {
    let on_loopback = listen.starts_with("127.")
        || listen.starts_with("[::1]")
        || listen.starts_with("localhost");
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let allowed = std::env::var("MCP_ALLOWED_ORIGINS").unwrap_or_default();
        let ok = allowed
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            // Exact match on the whole origin, never a prefix or suffix: `https://evil-localhost.com`
            // contains `localhost` and would sail through a substring test.
            .any(|a| a.eq_ignore_ascii_case(origin.trim_end_matches('/')))
            // A loopback server accepts a LOOPBACK origin with nothing configured. Found by the
            // official conformance suite, which sends a valid `Origin: http://localhost:<port>` and
            // requires 2xx; we answered 403 whenever `MCP_ALLOWED_ORIGINS` was unset — which is the
            // default, so out of the box no browser-based client on the same machine could talk to
            // us at all. The rebinding defence is untouched: an attacker's page carries its OWN
            // origin (`http://evil.com`), never a loopback one, and that is still refused.
            || (on_loopback && origin_is_loopback(origin));
        if !ok {
            return Err(format!(
                "origin {:?} is not allowed — a browser page may not talk to this server unless its \
                 origin is listed in MCP_ALLOWED_ORIGINS",
                origin
            ));
        }
    }
    if on_loopback {
        if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
            let bare = host.split(':').next().unwrap_or(host);
            let extra = std::env::var("MCP_ALLOWED_HOSTS").unwrap_or_default();
            let ok = matches!(bare, "localhost" | "127.0.0.1" | "::1" | "[::1]")
                || extra
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .any(|a| a.eq_ignore_ascii_case(bare));
            if !ok {
                return Err(format!(
                    "host header {:?} does not name this loopback server — a name that resolves to \
                     127.0.0.1 is how DNS rebinding reaches it; add it to MCP_ALLOWED_HOSTS if it is yours",
                    host
                ));
            }
        }
    }
    Ok(())
}

/// Whether an `Origin` names this machine — parsed, never substring-matched.
///
/// `https://evil-localhost.com` CONTAINS "localhost" and a substring test would wave it through,
/// which is the whole attack this function exists to stop. So the host is taken from between the
/// scheme and the port and compared exactly.
fn origin_is_loopback(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or("");
    let host = rest.trim_end_matches('/');
    let host = match host.rsplit_once(':') {
        // IPv6 in brackets keeps its colons; only a trailing :port is stripped.
        Some((h, port)) if !h.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

pub(crate) async fn metrics_handler(headers: HeaderMap) -> impl IntoResponse {
    // This endpoint reports traffic volume and how often authentication denials fire, so who may read
    // it follows what the server itself requires:
    //   MCP_METRICS_TOKEN set      → that token (a scraper does not have to hold a database credential)
    //   otherwise, bearer auth     → the bearer token
    //   otherwise, OAuth           → refused: a JWT is the wrong shape for a scraper, and leaving the
    //                                endpoint open on an authenticated server was the earlier bug —
    //                                inheriting only from MCP_BEARER_TOKEN protected the weaker setup
    //                                and left the stronger one public.
    //   otherwise (no auth at all) → open, for scraping from a private network
    let expected = std::env::var("MCP_METRICS_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            // Only when the shared token is the server's actual mechanism. With OAuth configured
            // `enforce_auth` ignores it, and accepting it here made the same variable simultaneously
            // "ignored" and "sufficient" depending on which endpoint you asked.
            if AUTH_CONFIG.is_some() {
                return None;
            }
            std::env::var("MCP_BEARER_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
        });
    let deny = |msg: &str| {
        (
            StatusCode::UNAUTHORIZED,
            [(CONTENT_TYPE, "text/plain")],
            format!("{}\n", msg),
        )
    };
    match expected {
        Some(expected) => {
            let given = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .unwrap_or("");
            if !crate::secret_eq(given, &expected) {
                return deny("unauthorized");
            }
        }
        None => {
            if AUTH_CONFIG.is_some() {
                return deny(
                    "unauthorized: this server requires authentication, so /metrics is closed — set \
                     MCP_METRICS_TOKEN to a token your scraper can present",
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

pub(crate) async fn health_handler() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

pub(crate) async fn ready_handler() -> impl axum::response::IntoResponse {
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
pub(crate) async fn oauth_protected_resource_handler() -> impl axum::response::IntoResponse {
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
pub(crate) async fn server_card_handler() -> impl axum::response::IntoResponse {
    let base = std::env::var("MCP_PUBLIC_URL").unwrap_or_default();
    let base = base.trim_end_matches('/');
    // A shared bearer token counts as authentication too — reporting "open" while it is enforced
    // would make a registry advertise the server as public when it is not.
    // Behind Apify Standby the caller DOES need a credential — the platform's, not ours. Reporting
    // `required: false` there would tell a registry the server is open when reaching it requires an
    // Apify token, which is the same class of untruth as reporting a revision we do not speak.
    let auth_required = ["JWT_PUBKEY_PEM", "MCP_BEARER_TOKEN"]
        .iter()
        .any(|k| std::env::var(k).map(|v| !v.trim().is_empty()) == Ok(true))
        || posture::platform_authenticates();
    let tools = handle_tools_list()["result"]["tools"].clone();
    Json(json!({
        "name": "postgres-mcp-hardened",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Read-only PostgreSQL MCP server in Rust: AST-enforced read-only queries plus database-level read-only transaction, per-session statement_timeout, schema inspection.",
        // What a registry reads to decide whether an agent can talk to us. It advertised only
        // `2025-06-18` while the server has spoken `2025-11-25` since it shipped — a scanner had no
        // way to learn that. Newest first, and the full list beside it.
        "protocolVersion": protocol::Rev::latest().as_str(),
        "protocolVersions": protocol::Rev::supported(),
        "transport": ["streamable-http", "stdio"],
        "endpoint": if base.is_empty() { "/mcp".to_string() } else { format!("{}/mcp", base) },
        "authentication": {
            "required": auth_required,
            "type": if std::env::var("JWT_PUBKEY_PEM").map(|v| !v.trim().is_empty()) == Ok(true) {
                        "oauth2.1"
                    } else if std::env::var("MCP_BEARER_TOKEN").map(|v| !v.trim().is_empty()) == Ok(true) {
                        "bearer"
                    } else if posture::platform_authenticates() {
                        "apify-platform"
                    } else { "none" },
            "protectedResourceMetadata": "/.well-known/oauth-protected-resource"
        },
        "tools": tools
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    // `check_origin` is the only defence against DNS rebinding — a browser page that resolves its
    // own name to 127.0.0.1 and thereby talks to a server bound to loopback. Until now it had not a
    // single assertion, despite being a security gate.
    fn hdr(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn a_local_client_without_an_origin_is_allowed() {
        // An MCP client on the same machine (Claude Desktop, curl) sends no Origin — it is not a
        // browser. A gate that refused it would be useless in the server's primary mode.
        assert!(check_origin(&hdr(&[("host", "localhost:8080")]), "127.0.0.1:8080").is_ok());
    }

    #[test]
    fn a_loopback_origin_is_trusted_on_a_loopback_server_without_configuration() {
        // The official conformance suite sends `Origin: http://localhost:<port>` and requires 2xx.
        // We answered 403 with `MCP_ALLOWED_ORIGINS` unset — the default — so out of the box no
        // browser-based client on the same machine could talk to us. My own unit test that morning
        // had asserted the refusal was CORRECT: I encoded our behaviour instead of the specification,
        // which is exactly why an outside judge is worth more than another test of my own writing.
        for origin in [
            "http://localhost:6274",
            "http://127.0.0.1:8080",
            "https://localhost",
            "http://[::1]:9000",
        ] {
            assert!(
                check_origin(&hdr(&[("origin", origin)]), "127.0.0.1:8080").is_ok(),
                "a loopback origin must reach a loopback server: {origin}"
            );
        }
    }

    #[test]
    fn a_lookalike_of_localhost_is_still_refused() {
        // The whole point of parsing rather than substring-matching: these all CONTAIN "localhost".
        for origin in [
            "http://evil-localhost.com",
            "http://localhost.evil.com",
            "http://notlocalhost",
            "http://localhost@evil.com",
        ] {
            assert!(
                check_origin(&hdr(&[("origin", origin)]), "127.0.0.1:8080").is_err(),
                "a lookalike must not pass as loopback: {origin}"
            );
        }
    }

    #[test]
    fn a_loopback_origin_does_not_help_against_a_network_listener() {
        // Off loopback there is no rebinding scenario to accommodate, so the exemption does not apply
        // and the operator's list is the only way in.
        assert!(
            check_origin(&hdr(&[("origin", "http://localhost:6274")]), "0.0.0.0:8080").is_err()
        );
    }

    #[test]
    fn a_browser_origin_is_refused_unless_the_operator_listed_it() {
        let e = check_origin(
            &hdr(&[("origin", "https://evil.example")]),
            "127.0.0.1:8080",
        )
        .expect_err("an unlisted origin must be refused");
        assert!(
            e.contains("MCP_ALLOWED_ORIGINS"),
            "the message must name the setting to change: {e}"
        );
    }

    #[test]
    fn a_lookalike_origin_does_not_pass_as_the_listed_one() {
        std::env::set_var("MCP_ALLOWED_ORIGINS", "https://localhost");
        let ok = check_origin(&hdr(&[("origin", "https://localhost")]), "127.0.0.1:8080");
        // `https://evil-localhost.com` CONTAINS `localhost` — a substring test would let it through.
        let bad = check_origin(
            &hdr(&[("origin", "https://evil-localhost.com")]),
            "127.0.0.1:8080",
        );
        std::env::remove_var("MCP_ALLOWED_ORIGINS");
        assert!(ok.is_ok(), "a listed origin must pass");
        assert!(bad.is_err(), "a lookalike is NOT the listed origin");
    }

    #[test]
    fn a_trailing_slash_is_not_a_different_origin() {
        std::env::set_var("MCP_ALLOWED_ORIGINS", "https://app.example");
        let r = check_origin(
            &hdr(&[("origin", "https://app.example/")]),
            "127.0.0.1:8080",
        );
        std::env::remove_var("MCP_ALLOWED_ORIGINS");
        assert!(
            r.is_ok(),
            "a trailing slash is the same origin, not a different one"
        );
    }

    #[test]
    fn dns_rebinding_is_refused_on_a_loopback_listener() {
        // An attacker's name resolved to 127.0.0.1 reaches the socket; the only thing separating it
        // from a genuine localhost client is the Host header.
        let e = check_origin(
            &hdr(&[("host", "rebind.attacker.example")]),
            "127.0.0.1:8080",
        )
        .expect_err("a foreign Host on a loopback listener is rebinding");
        assert!(
            e.contains("MCP_ALLOWED_HOSTS"),
            "the message must point at the way out: {e}"
        );
    }

    #[test]
    fn the_operators_own_name_can_be_allowed_and_a_port_does_not_break_it() {
        std::env::set_var("MCP_ALLOWED_HOSTS", "mcp.internal");
        let named = check_origin(&hdr(&[("host", "mcp.internal:8080")]), "127.0.0.1:8080");
        std::env::remove_var("MCP_ALLOWED_HOSTS");
        assert!(
            named.is_ok(),
            "a port in the Host header must not invalidate an allowed name"
        );
    }

    #[test]
    fn a_network_listener_does_not_get_the_loopback_host_check() {
        // Off loopback the server already sits behind the start-up gate (token/OAuth), and the host
        // name is legitimately somebody else's — demanding "localhost" would block real deployments.
        assert!(check_origin(&hdr(&[("host", "mcp.example.com")]), "0.0.0.0:8080").is_ok());
    }

    #[test]
    fn metrics_are_prometheus_shaped() {
        let out = render_metrics();
        assert!(
            out.contains("# TYPE"),
            "no TYPE headers — this is not the Prometheus exposition format"
        );
        assert!(
            out.lines()
                .all(|l| l.is_empty() || l.starts_with('#') || l.contains(' ')),
            "every line is a comment or a name/value pair"
        );
    }
}
