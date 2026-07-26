//! Per-client request rate limiting — a token bucket.
//!
//! `DB_SEM` caps CONCURRENCY (how many queries at once) but not RATE: one client could loop cheap
//! requests and keep the server busy indefinitely, or flood it with bad tokens — and verifying an
//! RS256 signature costs real CPU. That is why this limit runs BEFORE authentication.
//!
//! The key is the peer address, never a header (the client controls headers). Behind a reverse
//! proxy set `MCP_TRUST_PROXY=1` and the first `X-Forwarded-For` entry is used instead.
//! Disable with `MCP_RATE_RPM=0`. Default: 120 requests/min with burst headroom.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use once_cell::sync::Lazy;

/// Maximum tracked keys — the map itself must not become a memory-exhaustion vector.
const MAX_KEYS: usize = 20_000;
/// An entry idle for longer than this is evicted during cleanup.
const IDLE_SECS: f64 = 600.0;

struct Bucket {
    tokens: f64,
    last: f64, // sekundy od startu procesu
}

struct Limiter {
    buckets: HashMap<String, Bucket>,
    start: Instant,
}

static LIMITER: Lazy<Mutex<Limiter>> = Lazy::new(|| {
    Mutex::new(Limiter {
        buckets: HashMap::new(),
        start: Instant::now(),
    })
});

fn rpm() -> f64 {
    std::env::var("MCP_RATE_RPM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120.0)
}

fn burst(rpm: f64) -> f64 {
    std::env::var("MCP_RATE_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| (rpm / 4.0).max(5.0))
}

/// Pure bucket logic, with time as a parameter so it can be tested deterministically.
fn take(b: &mut Bucket, now: f64, rate_per_s: f64, cap: f64) -> bool {
    let elapsed = (now - b.last).max(0.0);
    b.tokens = (b.tokens + elapsed * rate_per_s).min(cap);
    b.last = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// `true` = allow. `false` = over the limit (answer 429).
pub fn allow(key: &str) -> bool {
    let rpm = rpm();
    if rpm <= 0.0 {
        return true; // deliberately disabled
    }
    let cap = burst(rpm);
    let rate = rpm / 60.0;
    let mut l = match LIMITER.lock() {
        Ok(l) => l,
        Err(p) => p.into_inner(), // a poisoned mutex must not switch the limiter off
    };
    let now = l.start.elapsed().as_secs_f64();
    if l.buckets.len() >= MAX_KEYS {
        l.buckets.retain(|_, b| now - b.last < IDLE_SECS);
        if l.buckets.len() >= MAX_KEYS {
            // still full (a multi-address flood) — start clean rather than grow without bound
            l.buckets.clear();
        }
    }
    let b = l.buckets.entry(key.to_string()).or_insert(Bucket {
        tokens: cap,
        last: now,
    });
    take(b, now, rate, cap)
}

// --- second gate: how many requests from ONE client may be in flight at once ---
/// Rate limiting does not help against "few requests, each very slow": a single client can occupy
/// every DB slot with queries that `EXPLAIN` prices at nothing yet run for the whole
/// `statement_timeout`. A per-client cap raises the cost of that attack.
///
/// HONEST ABOUT THE LIMITS: the key is an IP address, and addresses are cheap — an attacker with a
/// handful of them (loopback `127.0.0.x`, or an ordinary IPv6 /64) still fills the pool. A per-IP
/// cap does NOT isolate an actor and must not be advertised as if it did. Two defences that do not
/// depend on the address run alongside it: the cap tightens once the pool is busy, and slots are
/// reserved for AUTHENTICATED traffic (see `main.rs`) so an anonymous flood cannot push out clients
/// holding a valid token. Real isolation needs identity, or network controls in front of the server.
static IN_FLIGHT: Lazy<Mutex<HashMap<String, u32>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn max_in_flight() -> u32 {
    std::env::var("MCP_MAX_INFLIGHT_PER_CLIENT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
}

/// The slot is released AUTOMATICALLY when the guard leaves scope (including on error or panic),
/// so a slot cannot leak on an error path.
pub struct SlotGuard(String);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut m = match IN_FLIGHT.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        if let Some(n) = m.get_mut(&self.0) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.0); // the map cleans itself up — no unbounded growth
            }
        }
    }
}

/// `None` = this client already has the maximum in flight (answer 503). The cap is supplied by the
/// caller, which tightens it when the database pool is already under pressure.
pub fn acquire_slot_capped(key: &str, cap: u32) -> Option<SlotGuard> {
    if cap == 0 {
        return Some(SlotGuard(String::new())); // deliberately disabled
    }
    let cap = cap.max(1);
    let mut m = match IN_FLIGHT.lock() {
        Ok(m) => m,
        Err(p) => p.into_inner(),
    };
    let n = m.entry(key.to_string()).or_insert(0);
    if *n >= cap {
        return None;
    }
    *n += 1;
    Some(SlotGuard(key.to_string()))
}

/// Client key: the peer address, or the first X-Forwarded-For entry when we explicitly trust a proxy.
pub fn client_key(peer: &str, xff: Option<&str>) -> String {
    let trust = std::env::var("MCP_TRUST_PROXY")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if trust {
        if let Some(v) = xff {
            if let Some(first) = v.split(',').next() {
                let first = first.trim();
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    peer.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let cap = 5.0;
        let rate = 1.0; // 60 rpm
        let mut b = Bucket {
            tokens: cap,
            last: 0.0,
        };
        // the full burst passes
        for i in 0..5 {
            assert!(take(&mut b, 0.0, rate, cap), "token {i} should pass");
        }
        // the sixth, at the same instant, does not
        assert!(!take(&mut b, 0.0, rate, cap));
        // after one second exactly one token is back
        assert!(take(&mut b, 1.0, rate, cap));
        assert!(!take(&mut b, 1.0, rate, cap));
        // after a long pause the bucket refills to capacity at most (no accumulated "debt")
        assert!(take(&mut b, 1000.0, rate, cap));
        assert!(b.tokens <= cap);
    }

    /// The in-flight cap must release slots automatically and must never leak them.
    #[test]
    fn in_flight_cap_releases_slots() {
        std::env::set_var("MCP_MAX_INFLIGHT_PER_CLIENT", "2");
        let a = acquire_slot_capped("klient-x", max_in_flight()).expect("1. slot");
        let b = acquire_slot_capped("klient-x", max_in_flight()).expect("2. slot");
        assert!(
            acquire_slot_capped("klient-x", max_in_flight()).is_none(),
            "the 3rd slot is over the cap and must be refused"
        );
        // a different client has its own allowance
        assert!(
            acquire_slot_capped("klient-y", max_in_flight()).is_some(),
            "cap jest PER KLIENT"
        );
        drop(b);
        assert!(
            acquire_slot_capped("klient-x", max_in_flight()).is_some(),
            "po zwolnieniu slot wraca"
        );
        drop(a);
        std::env::remove_var("MCP_MAX_INFLIGHT_PER_CLIENT");
    }

    #[test]
    fn xff_only_when_trusted() {
        std::env::remove_var("MCP_TRUST_PROXY");
        assert_eq!(client_key("10.0.0.1", Some("1.2.3.4")), "10.0.0.1");
        std::env::set_var("MCP_TRUST_PROXY", "1");
        assert_eq!(client_key("10.0.0.1", Some("1.2.3.4, 5.6.7.8")), "1.2.3.4");
        assert_eq!(client_key("10.0.0.1", None), "10.0.0.1");
        std::env::remove_var("MCP_TRUST_PROXY");
    }
}
