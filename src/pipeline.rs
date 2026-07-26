//! The gates every request passes, whichever transport it arrived on.
//!
//! They used to live inside the HTTP handler, which meant stdio — the transport Claude Desktop and
//! Claude Code actually use — had none of them: no rate limit, no per-client concurrency cap, no
//! share of the database pool, and `caller: "-"` in the audit for every single request. The most
//! common way to run this server was the least protected one.
//!
//! Both transports call `gate` now. They differ only in how a refusal is spelled: HTTP has status
//! codes, stdio has JSON-RPC errors.

use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use tokio::sync::OwnedSemaphorePermit;

use crate::audit;
use crate::db::DB_SEM;
use crate::http::METRICS;
use crate::ratelimit::{self, SlotGuard};

/// Why a request was turned away before any work happened.
pub(crate) enum Rejection {
    RateLimit,
    InFlight,
    Busy,
}

impl Rejection {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Rejection::RateLimit => "rate limit exceeded, slow down",
            Rejection::InFlight => "too many requests in flight from this client",
            Rejection::Busy => "server busy, retry shortly",
        }
    }
    pub(crate) fn decision(&self) -> &'static str {
        match self {
            Rejection::RateLimit => "denied_rate",
            Rejection::InFlight => "denied_busy",
            Rejection::Busy => "denied_busy",
        }
    }
}

/// Held for exactly as long as the work runs.
///
/// Both guards must travel to the thread that does the work, not stay with whatever is waiting for
/// it: when they were released as soon as an HTTP client disconnected, the query kept running with
/// its slot already handed to someone else, and the pool drained.
pub(crate) struct Guards {
    pub(crate) _slot: SlotGuard,
    pub(crate) _permit: OwnedSemaphorePermit,
}

/// The three gates as separate steps, because HTTP has to authenticate between the second and the
/// third: a request with a bad token must not first take a database permit. `gate` runs them in
/// order for stdio, where there is nothing to interleave.
pub(crate) fn gate_rate(key: &str, transport: &str) -> Result<(), Rejection> {
    if ratelimit::allow_for(key, transport) {
        return Ok(());
    }
    METRICS.denied_rate.fetch_add(1, Ordering::Relaxed);
    // Refusals belong in the durable chain, not only in a counter that dies with the process.
    audit(transport, Rejection::RateLimit.decision(), None);
    Err(Rejection::RateLimit)
}

/// Once the pool is under pressure the per-client cap tightens to one, so flooding needs as many
/// identities as there are slots rather than a quarter of that.
pub(crate) fn gate_in_flight(key: &str, transport: &str) -> Result<SlotGuard, Rejection> {
    let tight = DB_SEM.available_permits() <= (crate::db::MAX_DB_CONNS as usize) / 4;
    let cap = if tight { 1 } else { ratelimit::max_in_flight() };
    match ratelimit::acquire_slot_capped(key, cap) {
        Some(g) => Ok(g),
        None => {
            audit(transport, Rejection::InFlight.decision(), None);
            Err(Rejection::InFlight)
        }
    }
}

pub(crate) fn gate_pool(transport: &str) -> Result<OwnedSemaphorePermit, Rejection> {
    match DB_SEM.clone().try_acquire_owned() {
        Ok(p) => Ok(p),
        Err(_) => {
            audit(transport, Rejection::Busy.decision(), None);
            Err(Rejection::Busy)
        }
    }
}

/// Rate, per-client concurrency, and a share of the database pool — cheapest first.
pub(crate) fn gate(key: &str, transport: &str) -> Result<Guards, Rejection> {
    gate_rate(key, transport)?;
    let slot = gate_in_flight(key, transport)?;
    let permit = gate_pool(transport)?;
    Ok(Guards {
        _slot: slot,
        _permit: permit,
    })
}

/// Who is calling over stdio.
///
/// There is no token here — the transport is a pipe from a process on the same machine — so the
/// honest identity is the operating system's, plus whatever the client chose to call itself.
/// `caller: "-"` on every record made the audit useless for exactly the deployment people run:
/// several agents, one laptop, one log.
pub(crate) fn stdio_caller() -> String {
    if let Ok(id) = std::env::var("MCP_CLIENT_ID") {
        let id = id.trim();
        if !id.is_empty() {
            return format!("client:{}", crate::strip_invisible(id));
        }
    }
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(String::from))
        })
        .unwrap_or_else(|| "?".into());
    format!("stdio:uid={},pid={}", uid, std::process::id())
}

/// A refusal shaped as JSON-RPC, for the transport that has no status codes.
pub(crate) fn rejection_response(r: &Rejection, id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32000, "message": r.message() }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rejection_has_a_message_and_an_audit_decision() {
        for r in [Rejection::RateLimit, Rejection::InFlight, Rejection::Busy] {
            assert!(!r.message().is_empty());
            assert!(r.decision().starts_with("denied_"));
        }
    }

    /// The label an operator reads in the log has to say which client, not merely that there was one.
    #[test]
    fn stdio_identity_is_never_a_dash() {
        std::env::remove_var("MCP_CLIENT_ID");
        let auto = stdio_caller();
        assert!(auto.starts_with("stdio:uid="), "{auto}");
        assert!(auto.contains("pid="));
        std::env::set_var("MCP_CLIENT_ID", "ada-laptop");
        assert_eq!(stdio_caller(), "client:ada-laptop");
        std::env::remove_var("MCP_CLIENT_ID");
    }
}
