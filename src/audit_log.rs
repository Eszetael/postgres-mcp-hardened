//! Tamper-evident audit trail: hash chain, optional HMAC, and its verifier.

use crate::*;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Global hash chain state ---
pub(crate) static AUDIT_PREV: Lazy<Mutex<String>> = Lazy::new(|| {
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
pub(crate) static AUDIT_SEQ: Lazy<std::sync::atomic::AtomicU64> = Lazy::new(|| {
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
pub(crate) fn sql_fingerprint(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let result = hasher.finalize();
    // Manual hex formatting; we keep the first 16 characters (8 bytes)
    format!("{:x}", result).chars().take(16).collect()
}

// --- Main audit function ---
pub(crate) fn audit(tool: &str, decision: &str, sql: Option<&str>) {
    audit_extra(tool, decision, sql, serde_json::Map::new())
}

/// As `audit`, with additional fields on the record.
///
/// Extra keys are safe for the chain because `serde_json` here builds a `BTreeMap` (the
/// `preserve_order` feature is off), so every record serialises with its keys sorted and the
/// verifier — which strips `prev`/`hash` and re-serialises — reproduces the same bytes. A test pins
/// this, because turning that feature on somewhere in the dependency tree would break every chain
/// silently.
pub(crate) fn audit_extra(
    tool: &str,
    decision: &str,
    sql: Option<&str>,
    extra: serde_json::Map<String, Value>,
) {
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
    if let Some(obj) = entry.as_object_mut() {
        for (k, v) in extra {
            obj.insert(k, v);
        }
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
pub(crate) fn verify_audit_file(path: &str, expect_last: Option<&str>) -> Result<String, String> {
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
pub(crate) fn audit_key() -> Option<(Vec<u8>, String)> {
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
pub(crate) fn key_fingerprint(k: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(k);
    format!("{:x}", h.finalize()).chars().take(8).collect()
}

/// HMAC-SHA256 per RFC 2104 — the standard construction, written out to keep the crate set minimal.
pub(crate) fn hmac_sha256_hex(key: Vec<u8>, msg: &[u8]) -> String {
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
pub(crate) fn set_caller(id: Option<String>) -> CallerScope {
    CALLER.with(|c| *c.borrow_mut() = id);
    CallerScope
}
pub(crate) fn current_caller() -> Option<String> {
    CALLER.with(|c| c.borrow().clone())
}
