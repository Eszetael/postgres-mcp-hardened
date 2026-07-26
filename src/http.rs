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
        "mcp_audit_write_failed_total",
        METRICS.audit_write_failed.load(Ordering::Relaxed)
    );
    push_metric!("mcp_errors_total", METRICS.errors.load(Ordering::Relaxed));

    buf
}

pub(crate) async fn metrics_handler(headers: HeaderMap) -> impl IntoResponse {
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
