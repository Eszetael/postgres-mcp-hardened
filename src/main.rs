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

// Third-party names the modules share. They used to sit loose in the middle of this file and were
// visible to everyone only because this file IS the crate root; after the split they have to be
// re-exported deliberately, which is the same prelude idea stated out loud.
pub(crate) use axum::http::header::CONTENT_TYPE;
pub(crate) use once_cell::sync::Lazy;
pub(crate) use postgres::Row;
pub(crate) use r2d2::Pool;
pub(crate) use r2d2_postgres::PostgresConnectionManager;
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
    // Dev/CI/auto-research: a deterministic validator fuzz — no database, no LLM.
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

// `main.rs` used to be 2572 lines: the entry point, the configuration gate, both transports,
// authorisation and the tool dispatcher in one file. It was the first file a stranger opens, and it
// read as something that had grown rather than been designed. These four modules are that file,
// split along the seams it already had — the code inside them is unchanged.
mod authz;
mod handlers;
mod startup;
mod transport;

pub(crate) use authz::*;
pub(crate) use handlers::*;
pub(crate) use startup::*;
pub(crate) use transport::*;

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
        ] {
            assert_eq!(required_scope(read_only), "mcp:read", "{read_only}");
        }
        // A name nobody classified is an admin's problem, not a reader's.
        assert_eq!(required_scope("anything_added_later"), "mcp:admin");
    }

    /// Reads the tool list the server actually publishes, so adding a tool without deciding what it
    /// may cost fails here rather than shipping under whatever the fallback happens to be.
    #[test]
    fn every_tool_has_a_scope_decision() {
        let listed = handle_tools_list();
        let tools = listed["result"]["tools"].as_array().expect("tools array");
        assert!(!tools.is_empty(), "the tool list must not be empty");
        for t in tools {
            let name = t["name"].as_str().expect("tool name");
            assert_ne!(
                required_scope(name),
                "mcp:admin",
                "tool {name:?} has no scope decision — add it to required_scope"
            );
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
