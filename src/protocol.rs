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
    /// The next revision, still a draft upstream, reachable only behind `MCP_PROTOCOL_PREVIEW=1`.
    ///
    /// The identifier is not a release date and nobody has announced one. MCP versions are named for
    /// "the last date a backwards-incompatible change was made", so `2026-07-28` describes something
    /// that has already happened in the draft — and it MOVES if one more breaking change lands before
    /// the revision is promoted. It is taken from `LATEST_PROTOCOL_VERSION` in the normative
    /// schema.ts, which is the only place it is authoritative. Re-read that constant when the draft
    /// becomes current, rather than trusting this line.
    ///
    /// It is the largest break MCP has had: no `initialize`, no session header, no `ping`. Every
    /// request carries its own protocol version in `_meta`, and `server/discover` replaces the
    /// handshake. We implement it early and behind a switch for one reason — a draft still moves,
    /// and a server that announces support for a moving target will be wrong in public. Behind the
    /// switch an operator can test against it today; with the switch off, nothing about our answers
    /// changes.
    V20260728,
}

impl Rev {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Rev::V20250618 => "2025-06-18",
            Rev::V20251125 => "2025-11-25",
            Rev::V20260728 => "2026-07-28",
        }
    }
    pub(crate) fn parse(s: &str) -> Option<Rev> {
        match s.trim() {
            "2025-06-18" => Some(Rev::V20250618),
            "2025-11-25" => Some(Rev::V20251125),
            // Only recognised when the operator asked for it. Otherwise a client offering the draft
            // is answered with our stable revision, which is what the specification tells it to
            // expect from a server that does not implement its version.
            "2026-07-28" if preview_enabled() => Some(Rev::V20260728),
            _ => None,
        }
    }
    /// The newest we implement. A client asking for something later gets this, and decides whether
    /// it can work with it — which is what the specification tells it to do.
    pub(crate) fn latest() -> Rev {
        if preview_enabled() {
            Rev::V20260728
        } else {
            Rev::V20251125
        }
    }
    /// Every revision we would accept, newest first — the answer `server/discover` owes a client.
    pub(crate) fn supported() -> Vec<&'static str> {
        if preview_enabled() {
            vec!["2026-07-28", "2025-11-25", "2025-06-18"]
        } else {
            vec!["2025-11-25", "2025-06-18"]
        }
    }
}

/// Read once: the answer must not change between two requests of the same client.
pub(crate) fn preview_enabled() -> bool {
    static ON: Lazy<bool> = Lazy::new(|| {
        matches!(
            std::env::var("MCP_PROTOCOL_PREVIEW").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    });
    *ON
}

/// Error codes the draft allocates to itself. It renumbered them late — `HeaderMismatch` moved from
/// `-32001` to `-32020` — so they live here as named constants rather than scattered literals.
pub(crate) const ERR_HEADER_MISMATCH: i64 = -32020;
pub(crate) const ERR_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The draft has no handshake: the version travels in `_meta` on every request.
pub(crate) fn rev_from_meta(params: &Value) -> Option<Rev> {
    meta_version(params).and_then(Rev::parse)
}

fn meta_version(params: &Value) -> Option<&str> {
    params
        .get("_meta")
        .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(|v| v.as_str())
}

/// A client that states a version we do not implement must be told so, not quietly served under a
/// contract it did not ask for. Silently downgrading is how a client ends up parsing our answer with
/// the wrong set of expectations — and, when the difference is where errors live, how a refusal
/// stops being visible to it at all.
pub(crate) fn unsupported_version_error(params: &Value) -> Option<Value> {
    let asked = meta_version(params)?;
    if Rev::parse(asked).is_some() {
        return None;
    }
    Some(json!({
        "error": {
            "code": ERR_UNSUPPORTED_PROTOCOL_VERSION,
            "message": format!("unsupported protocol version {asked:?}"),
            "data": { "supported": Rev::supported() }
        }
    }))
}

/// Results the draft says a client may cache, with how long it may hold them.
///
/// This is not decoration. An agent that re-reads a 40-table schema on every turn spends more
/// tokens on the schema than on the work; a freshness hint lets it stop. `private` because the
/// answer depends on which role connected — two callers of one proxy must not share it.
fn cache_hint(method: &str) -> Option<(u64, &'static str)> {
    match method {
        "tools/list" | "prompts/list" => Some((300_000, "private")),
        "resources/list" | "resources/templates/list" | "resources/read" => {
            Some((60_000, "private"))
        }
        _ => None,
    }
}

/// Everything the draft requires on a result but earlier revisions never had.
///
/// Applied last, to whatever the handler produced, so no handler has to know which revision it is
/// answering. Errors are left alone — they are not results.
pub(crate) fn decorate_result(mut resp: Value, rev: Rev, method: &str, label: &str) -> Value {
    if rev < Rev::V20260728 {
        return resp;
    }
    let Some(result) = resp.get_mut("result").and_then(|r| r.as_object_mut()) else {
        return resp;
    };
    // Required on every result: "complete" as opposed to the interim result of a multi round-trip
    // request. We never ask the client for more input, so ours are always complete.
    result.insert("resultType".into(), json!("complete"));
    if let Some((ttl, scope)) = cache_hint(method) {
        result.insert("ttlMs".into(), json!(ttl));
        result.insert("cacheScope".into(), json!(scope));
    }
    let meta = result.entry("_meta").or_insert_with(|| json!({}));
    if let Some(m) = meta.as_object_mut() {
        m.insert(
            "io.modelcontextprotocol/serverInfo".into(),
            json!({ "name": label, "version": "0.1.0" }),
        );
    }
    resp
}

/// The draft requires `Mcp-Method` and `Mcp-Name` on every HTTP POST, and requires the server to
/// refuse when they disagree with the body.
///
/// We treat this as a security control, not a formality. The headers exist so a proxy can route and
/// authorise without parsing the body; if the header and the body may disagree, then the thing that
/// decided and the thing that executes saw two different requests — which is how an allowlist in a
/// gateway gets walked past. Refusing the mismatch is what makes the header safe to trust.
pub(crate) fn check_header_agreement(
    rev: Rev,
    body_method: &str,
    body_name: Option<&str>,
    hdr_method: Option<&str>,
    hdr_name: Option<&str>,
) -> Result<(), (i64, String)> {
    if rev < Rev::V20260728 {
        return Ok(());
    }
    match hdr_method {
        None => {
            return Err((
                ERR_HEADER_MISMATCH,
                "missing Mcp-Method header (required from 2026-07-28)".into(),
            ))
        }
        Some(h) if h != body_method => {
            return Err((
                ERR_HEADER_MISMATCH,
                format!("Mcp-Method header says {h:?} but the body calls {body_method:?}"),
            ))
        }
        Some(_) => {}
    }
    // `Mcp-Name` names the tool or resource the call targets, and only calls that have one carry it.
    if let Some(expected) = body_name {
        match hdr_name {
            None => {
                return Err((
                    ERR_HEADER_MISMATCH,
                    format!("missing Mcp-Name header for {body_method}"),
                ))
            }
            Some(h) if h != expected => {
                return Err((
                    ERR_HEADER_MISMATCH,
                    format!("Mcp-Name header says {h:?} but the body targets {expected:?}"),
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Which name, if any, a request body targets — the value `Mcp-Name` has to match.
pub(crate) fn body_target_name(method: &str, params: &Value) -> Option<String> {
    let key = match method {
        "tools/call" => "name",
        "prompts/get" => "name",
        "resources/read" => "uri",
        _ => return None,
    };
    params.get(key).and_then(|v| v.as_str()).map(String::from)
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
    let chosen = asked.unwrap_or_else(Rev::latest);
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

    // The draft is reached only through the switch. These run with it off, which is the state
    // every user is in until they opt in — so they assert what a normal deployment answers.
    #[test]
    fn draft_is_invisible_until_the_operator_asks_for_it() {
        assert!(!preview_enabled(), "tests must run with the preview off");
        assert_eq!(Rev::parse("2026-07-28"), None);
        assert_eq!(Rev::latest(), Rev::V20251125);
        assert!(!Rev::supported().contains(&"2026-07-28"));
        // A client offering the draft is answered with our newest stable, not refused.
        assert_eq!(
            negotiate_initialize(&json!({"protocolVersion": "2026-07-28"})),
            Rev::V20251125
        );
    }

    #[test]
    fn a_version_we_do_not_speak_is_said_out_loud_not_downgraded_silently() {
        let e = unsupported_version_error(
            &json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2099-01-01"}}),
        )
        .expect("an unknown version must produce an error");
        assert_eq!(e["error"]["code"], ERR_UNSUPPORTED_PROTOCOL_VERSION);
        assert!(e["error"]["data"]["supported"].is_array());
        // A version we do speak produces nothing.
        assert!(unsupported_version_error(
            &json!({"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}})
        )
        .is_none());
        // No version stated at all is not an error — earlier revisions never state one.
        assert!(unsupported_version_error(&json!({})).is_none());
    }

    // The header check is a routing-integrity control, so it is tested by passing the draft
    // revision directly rather than through the environment switch.
    #[test]
    fn a_header_that_disagrees_with_the_body_is_refused() {
        let d = Rev::V20260728;
        // Agreement is accepted.
        assert!(check_header_agreement(
            d,
            "tools/call",
            Some("query"),
            Some("tools/call"),
            Some("query")
        )
        .is_ok());
        // A missing header is a refusal, not a default.
        assert_eq!(
            check_header_agreement(d, "tools/list", None, None, None)
                .unwrap_err()
                .0,
            ERR_HEADER_MISMATCH
        );
        // The gateway was told one method and we would have run another.
        assert_eq!(
            check_header_agreement(
                d,
                "tools/call",
                Some("query"),
                Some("tools/list"),
                Some("query")
            )
            .unwrap_err()
            .0,
            ERR_HEADER_MISMATCH
        );
        // The method matched but the tool did not — this is the shape that walks past an allowlist
        // permitting `describe_table` while `query` actually runs.
        let err = check_header_agreement(
            d,
            "tools/call",
            Some("query"),
            Some("tools/call"),
            Some("describe_table"),
        )
        .unwrap_err();
        assert_eq!(err.0, ERR_HEADER_MISMATCH);
        assert!(
            err.1.contains("query"),
            "the refusal must name what the body really targets: {}",
            err.1
        );
        // Older revisions never required the headers, so their absence must not break them.
        assert!(
            check_header_agreement(Rev::V20251125, "tools/call", Some("query"), None, None).is_ok()
        );
    }

    #[test]
    fn draft_results_carry_what_the_draft_requires() {
        let plain = json!({"result": {"tools": []}});
        // Nothing is added under the revisions that never asked for it.
        assert_eq!(
            decorate_result(plain.clone(), Rev::V20251125, "tools/list", "srv"),
            plain
        );
        let d = decorate_result(plain.clone(), Rev::V20260728, "tools/list", "srv");
        assert_eq!(d["result"]["resultType"], "complete");
        assert_eq!(d["result"]["ttlMs"], 300_000);
        // Never "public": the rows a caller may see depend on the role that connected, so a shared
        // proxy must not hand one caller's answer to another.
        assert_eq!(d["result"]["cacheScope"], "private");
        assert_eq!(
            d["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "srv"
        );
        // A method with no cache hint gets the required field and no freshness claim we cannot keep.
        let c = decorate_result(
            json!({"result": {"content": []}}),
            Rev::V20260728,
            "tools/call",
            "srv",
        );
        assert_eq!(c["result"]["resultType"], "complete");
        assert!(c["result"].get("ttlMs").is_none());
        // An error is not a result and must not be dressed as one.
        let e = json!({"error": {"code": -32601, "message": "no"}});
        assert_eq!(
            decorate_result(e.clone(), Rev::V20260728, "tools/list", "srv"),
            e
        );
    }

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
            Rev::latest()
        );
        assert_eq!(negotiate_initialize(&json!({})), Rev::latest());
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
