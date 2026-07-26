//! Which revision of MCP we are speaking, and what a refusal looks like in it.
//!
//! Two revisions matter today: `2025-06-18`, which shipping clients still speak, and `2025-11-25`,
//! the current one. They disagree about something that matters more than it sounds — where a tool's
//! refusal belongs.
//!
//! Under `2025-06-18` we answered "this statement is not read-only" as a JSON-RPC error. That is a
//! protocol-level failure: the client sees a broken call, and the model often never sees the reason
//! at all. `2025-11-25` (SEP-1303) says input-validation failures are *tool execution errors* —
//! part of the result, with `isError: true` — precisely so the model reads what went wrong and
//! writes a better query instead of handing the user a stack trace.
//!
//! What does **not** change is the audit. A refusal is recorded in the chain by the code that
//! refuses, before anything here reshapes it for the wire; the tests assert both halves together, so
//! "we made the errors friendlier" can never quietly mean "we stopped logging them".

use serde_json::{json, Value};
use std::cell::RefCell;
use std::sync::RwLock;

use once_cell::sync::Lazy;

/// Namespace for our own `_meta` keys, reverse-DNS as the specification asks.
const NS: &str = "io.github.eszetael.postgres-mcp-hardened";

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rev {
    /// What Claude Desktop and most shipping clients speak today.
    V20250618,
    /// Current: tool execution errors, RFC 9728 discovery fallback, JSON Schema 2020-12.
    V20251125,
}

impl Rev {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Rev::V20250618 => "2025-06-18",
            Rev::V20251125 => "2025-11-25",
        }
    }
    pub(crate) fn parse(s: &str) -> Option<Rev> {
        match s.trim() {
            "2025-06-18" => Some(Rev::V20250618),
            "2025-11-25" => Some(Rev::V20251125),
            _ => None,
        }
    }
    /// The newest we implement. A client asking for something later gets this, and decides whether
    /// it can work with it — which is what the specification tells it to do.
    pub(crate) const LATEST: Rev = Rev::V20251125;
}

thread_local! {
    /// Per request, for HTTP, where several clients may be talking at once.
    static REQUEST_REV: RefCell<Option<Rev>> = const { RefCell::new(None) };
}

/// For stdio, where the process serves exactly one client and the version is agreed once.
static SESSION_REV: Lazy<RwLock<Option<Rev>>> = Lazy::new(|| RwLock::new(None));

/// Restores the previous value when dropped, so one request cannot leak its revision into the next.
pub(crate) struct RevScope(Option<Rev>);

impl Drop for RevScope {
    fn drop(&mut self) {
        REQUEST_REV.with(|r| *r.borrow_mut() = self.0);
    }
}

pub(crate) fn set_request_rev(rev: Option<Rev>) -> RevScope {
    REQUEST_REV.with(|r| {
        let prev = *r.borrow();
        *r.borrow_mut() = rev;
        RevScope(prev)
    })
}

pub(crate) fn remember_session_rev(rev: Rev) {
    *SESSION_REV.write().unwrap() = Some(rev);
}

/// What this request is speaking.
///
/// HTTP always sets the per-request value (falling back to the older revision when the client sends
/// no header), so one client's negotiation can never change the contract another client is served
/// under — several clients share one process there. stdio leaves it unset and the session value
/// applies, which is correct because that process serves exactly one client.
pub(crate) fn current() -> Rev {
    REQUEST_REV
        .with(|r| *r.borrow())
        .or(*SESSION_REV.read().unwrap())
        .unwrap_or(Rev::V20250618)
}

/// The revision to answer `initialize` with: the client's if we implement it, otherwise ours.
pub(crate) fn negotiate_initialize(params: &Value) -> Rev {
    let asked = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .and_then(Rev::parse);
    let chosen = asked.unwrap_or(Rev::LATEST);
    remember_session_rev(chosen);
    chosen
}

/// Failures the caller can do something about, as opposed to failures of the protocol itself.
///
/// A rejected statement, a query that costs too much, a column that does not exist: the model can
/// rewrite the query. A malformed JSON-RPC envelope, an unknown method, a missing token: it cannot,
/// and those stay protocol errors where a client's error handling expects them.
fn is_tool_execution_error(code: i64) -> bool {
    matches!(code, -32602 | -32000 | -32001)
}

/// Turns a tool's error into whatever the negotiated revision expects.
pub(crate) fn shape_tool_result(resp: Value, rev: Rev) -> Value {
    if rev < Rev::V20251125 {
        return resp;
    }
    let Some(err) = resp.get("error") else {
        return resp;
    };
    let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    if !is_tool_execution_error(code) {
        return resp;
    }
    let message = err
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("tool call failed")
        .to_string();
    json!({
        "result": {
            "isError": true,
            "content": [{ "type": "text", "text": message }],
            "_meta": {
                format!("{NS}/errorCode"): code,
                // Security refusals are not worth retrying unchanged; saying so keeps a client from
                // turning a refusal into a loop.
                format!("{NS}/retriable"): false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revisions_order_and_round_trip() {
        assert!(Rev::V20250618 < Rev::V20251125);
        for r in [Rev::V20250618, Rev::V20251125] {
            assert_eq!(Rev::parse(r.as_str()), Some(r));
        }
        assert_eq!(Rev::parse("1999-01-01"), None);
    }

    /// A client asking for something we do not implement gets our newest, not silence.
    #[test]
    fn initialize_answers_with_something_we_can_speak() {
        assert_eq!(
            negotiate_initialize(&json!({"protocolVersion": "2025-06-18"})),
            Rev::V20250618
        );
        assert_eq!(
            negotiate_initialize(&json!({"protocolVersion": "2099-01-01"})),
            Rev::LATEST
        );
        assert_eq!(negotiate_initialize(&json!({})), Rev::LATEST);
    }

    #[test]
    fn old_clients_keep_the_error_shape_they_expect() {
        let e = json!({"error": {"code": -32602, "message": "non-read-only statement: Insert"}});
        assert_eq!(shape_tool_result(e.clone(), Rev::V20250618), e);
    }

    /// The reason has to reach the model, which is the whole point of SEP-1303.
    #[test]
    fn a_rejected_statement_becomes_something_the_model_can_read() {
        let e = json!({"error": {"code": -32602, "message": "non-read-only statement: Insert"}});
        let shaped = shape_tool_result(e, Rev::V20251125);
        assert_eq!(shaped["result"]["isError"], json!(true));
        assert_eq!(
            shaped["result"]["content"][0]["text"],
            json!("non-read-only statement: Insert")
        );
        assert_eq!(
            shaped["result"]["_meta"][format!("{NS}/retriable")],
            json!(false)
        );
    }

    /// Protocol failures stay protocol failures: a client cannot recover from them by rewriting SQL.
    #[test]
    fn protocol_failures_are_left_alone() {
        for code in [-32600, -32601, -32003, -32700] {
            let e = json!({"error": {"code": code, "message": "nope"}});
            assert_eq!(
                shape_tool_result(e.clone(), Rev::V20251125),
                e,
                "code {code} must stay a protocol error"
            );
        }
    }

    #[test]
    fn a_successful_result_is_untouched() {
        let ok = json!({"result": {"content": []}});
        assert_eq!(shape_tool_result(ok.clone(), Rev::V20251125), ok);
    }
}
