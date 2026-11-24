//! Tamper-evident audit trail: hash chain, optional HMAC, and its verifier.

use crate::*;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Global hash chain state ---
//
// The high-water mark lives BESIDE the log, not inside it. A verifier whose memory sits within the
// thing it protects cannot detect that thing being shortened: truncate the tail, restart, and both
// the last hash and the last sequence number are re-read from the new final line. The chain is
// internally consistent, the numbering is contiguous, and nothing objects. The previous docstring
// claimed tail truncation was detectable; it was not, for exactly that reason.
//
// `<log>.hwm` therefore records the last (seq, hash) we ourselves wrote. On start we compare it with
// the log. Disagreement is reported loudly — it is not proof of tampering (an unclean shutdown looks
// the same), but it is proof that something is worth looking at, which is the whole job of a
// tamper-EVIDENT trail.
fn hwm_path() -> Option<String> {
    std::env::var("MCP_AUDIT_LOG")
        .ok()
        .map(|p| format!("{}.hwm", p))
}

/// Ścieżka znacznika dla WSKAZANEGO logu — bez sięgania po zmienną środowiskową.
fn hwm_path_of(log: &str) -> String {
    format!("{}.hwm", log)
}

/// Last entry recorded in the log itself: `(seq, hash, signed)`, where `signed` says the entry
/// carries `key_fp`, i.e. it was written with an HMAC key.
/// `None` = the file does not exist. `Some(None)` = it exists but its last line is unusable.
fn last_entry_of(path: &str) -> Option<Option<(u64, String, bool)>> {
    let path = path.to_string();
    if !std::path::Path::new(&path).exists() {
        return None; // genuinely a first run — silence is correct here
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            // The file IS there and we cannot read it. Falling back to GENESIS here would make a
            // deleted or unreadable audit trail indistinguishable from a first run.
            eprintln!(
                "AUDIT: {} exists but cannot be read ({}) — the chain cannot be continued.",
                path, e
            );
            return Some(None);
        }
    };
    let last = content.lines().rev().find(|l| !l.trim().is_empty());
    let Some(last) = last else {
        // Present but empty: the start-up check creates the file before the chain is read, so on
        // a first run this is what a new log looks like. A log emptied after entries were written
        // still has its mark beside it, and the comparison with the mark reports that.
        return None;
    };
    match serde_json::from_str::<Value>(last) {
        Ok(v) => {
            let seq = v.get("seq").and_then(|s| s.as_u64());
            let hash = v.get("hash").and_then(|h| h.as_str()).map(String::from);
            let signed = v.get("key_fp").is_some();
            match (seq, hash) {
                (Some(s), Some(h)) => Some(Some((s, h, signed))),
                _ => {
                    eprintln!(
                        "AUDIT: last line of {} has no seq/hash — chain state unknown.",
                        path
                    );
                    Some(None)
                }
            }
        }
        Err(e) => {
            eprintln!(
                "AUDIT: last line of {} is not valid JSON ({}) — chain state unknown.",
                path, e
            );
            Some(None)
        }
    }
}

/// What we resume from, and whether anything about it deserves a shout.
///
/// The anomaly is a RETURNED VALUE, not a side effect on stderr. A detector whose only output is
/// a print cannot be tested, and an untested detector is a claim — which is precisely the defect
/// this change exists to remove.
pub(crate) struct Resume {
    pub seq: u64,
    pub hash: String,
    pub anomaly: Option<String>,
    /// Worth saying, not a sign of tampering (a key configured for the first time).
    pub note: Option<String>,
}

pub(crate) fn resume_state() -> Resume {
    match std::env::var("MCP_AUDIT_LOG") {
        Ok(p) => resume_state_of(&p),
        Err(_) => resume_state_of(""),
    }
}

/// Stan wznowienia dla WSKAZANEGO logu.
///
/// Istnieje, bo `resume_state()` czyta `MCP_AUDIT_LOG` — zmienną GLOBALNĄ dla procesu — a `cargo test`
/// uruchamia testy równolegle w wątkach jednego procesu. Test, który tę zmienną ustawiał, kierował na
/// swój plik KAŻDE wywołanie `audit()` z innego wątku, więc dopisywały mu one wpisy w trakcie
/// sprawdzania. Objaw: 105 przechodzi, jeden oblewa, i tylko czasem — u nas pięć przebiegów pod rząd
/// było czyste, a CI oblało za pierwszym razem.
///
/// Ten wariant nie dotyka niczego globalnego, więc test może liczyć wpisy, które sam zapisał.
pub(crate) fn resume_state_of(log: &str) -> Resume {
    resume_state_with(log, &key_set())
}

/// The current key first, then the retired ones from `MCP_AUDIT_HMAC_KEYS_OLD`: what the verifier
/// accepts, and what a mark written before a rotation was signed with.
pub(crate) fn key_set() -> Vec<(Vec<u8>, String)> {
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
    keys
}

/// Whether this log was written with a key by a build that signs its mark (0.1.12 and later): a
/// startup record carrying both `key_fp` and such a version. A mark without a MAC beside such a log
/// was not written by us; beside an older or unkeyed log it is what an upgrade looks like.
fn written_with_signed_marks(log: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(log) else {
        return false;
    };
    content
        .lines()
        .filter(|l| l.contains("\"decision\":\"startup\"") && l.contains("\"key_fp\""))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| {
            v.get("version")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .any(|ver| {
            let n: Vec<u64> = ver.split('.').filter_map(|p| p.parse().ok()).collect();
            n.len() == 3 && (n[0], n[1], n[2]) >= (0, 1, 12)
        })
}

/// [`resume_state_of`] with the key set passed in, so a test can exercise a keyed log without the
/// process-wide key.
pub(crate) fn resume_state_with(log: &str, keys: &[(Vec<u8>, String)]) -> Resume {
    let last = if log.is_empty() {
        None
    } else {
        last_entry_of(log)
    };
    let signed_log = matches!(last, Some(Some((_, _, true))));
    let in_log = last.map(|o| o.map(|(s, h, _)| (s, h)));
    let hwm = (if log.is_empty() {
        None
    } else {
        Some(hwm_path_of(log))
    })
    .and_then(|p| std::fs::read_to_string(p).ok())
    .and_then(|c| serde_json::from_str::<Value>(&c).ok())
    .and_then(|v| {
        let (seq, hash) = (
            v.get("seq")?.as_u64()?,
            v.get("hash")?.as_str()?.to_string(),
        );
        let mac = v.get("mac").and_then(|m| m.as_str()).map(str::to_string);
        Some((seq, hash, mac))
    });
    // A mark that cannot be authenticated is no evidence either way: with a key set, one without a
    // valid MAC was written by someone who did not have it. Say so, and do not trust its numbers.
    let mut mark_anomaly: Option<String> = None;
    let mut note: Option<String> = None;
    let hwm = match (hwm, keys.is_empty()) {
        (Some((s, h, mac)), false) => {
            let valid = mac
                .as_deref()
                .is_some_and(|m| keys.iter().any(|(k, _)| m == hwm_mac(k, s, &h).as_str()));
            if valid {
                Some((s, h))
            } else if mac.is_none() && !written_with_signed_marks(log) {
                // R13 of the 0.1.12 review: introducing a key on an existing log, or upgrading a
                // keyed log from a build that did not sign its mark, was reported as tampering.
                note = Some(
                    "the high-water mark carries no MAC because it was written without a key (or \
                     by a build before 0.1.12); from now on it is signed"
                        .into(),
                );
                Some((s, h))
            } else {
                mark_anomaly = Some(
                    "the high-water mark has no valid MAC under the configured key — it was \
                     written without the key (or edited), so it cannot vouch for the log"
                        .into(),
                );
                None
            }
        }
        // R5 of the 0.1.12 review: deleting the mark of a keyed log made a truncated log look like
        // an upgrade from a build without marks. A keyed log always has a mark beside it, so its
        // absence is itself the finding.
        (None, false) if signed_log => {
            mark_anomaly = Some(
                "the high-water mark is missing although the log is keyed (its last entry carries \
                 key_fp): entries may have been cut from the end and the mark deleted to hide it"
                    .into(),
            );
            None
        }
        (Some((s, h, _)), true) => Some((s, h)),
        (None, _) => None,
    };
    let mut r = resume_from(&in_log, &hwm);
    if r.anomaly.is_none() {
        r.anomaly = mark_anomaly;
    }
    if r.anomaly.is_none() {
        r.note = note;
    }
    r
}

fn resume_from(in_log: &Option<Option<(u64, String)>>, hwm: &Option<(u64, String)>) -> Resume {
    match (in_log, hwm) {
        // First run: no log, no mark. Nothing to say.
        (None, None) => Resume {
            seq: 0,
            hash: "GENESIS".into(),
            note: None,
            anomaly: None,
        },
        // A mark but no log at all — the log was removed.
        (None, Some((s, _))) => Resume {
            seq: *s,
            hash: "GENESIS".into(),
            note: None,
            anomaly: Some(format!(
                "the log is gone but the high-water mark says {} entries were written — the trail \
                 has been removed or moved",
                s
            )),
        },
        // A log we cannot parse. `last_entry_in_log` already said why, on stderr.
        (Some(None), _) => Resume {
            seq: hwm.as_ref().map(|(s, _)| *s).unwrap_or(0),
            hash: "GENESIS".into(),
            note: None,
            anomaly: Some(
                "the log exists but its last entry is unusable — chain state unknown".into(),
            ),
        },
        // A log we can read, and no mark to compare with (upgrade from an older build).
        (Some(Some((s, h))), None) => Resume {
            seq: *s,
            hash: h.clone(),
            note: None,
            anomaly: None,
        },
        // Both present — this is the comparison that makes truncation visible.
        (Some(Some((s_log, h_log))), Some((s_hwm, h_hwm))) => {
            let anomaly = if *s_log < *s_hwm {
                Some(format!(
                    "the log ends at entry {} but {} were written — {} entries are MISSING FROM \
                     THE END. A truncated log is internally consistent, which is why this check \
                     lives outside it",
                    s_log,
                    s_hwm,
                    s_hwm - s_log
                ))
            } else if *s_log == *s_hwm && h_log != h_hwm {
                Some(format!(
                    "entry {} is present but its hash differs from the recorded one — the last \
                     entry was rewritten",
                    s_log
                ))
            } else {
                None
            };
            Resume {
                seq: *s_log.max(s_hwm),
                hash: h_log.clone(),
                note: None,
                anomaly,
            }
        }
    }
}

/// One read of the state, shared by both statics — and the single place the anomaly is announced.
/// The previous code read the file twice, once per static, which was both wasteful and a way for
/// the two to disagree.
static RESUME: Lazy<Resume> = Lazy::new(|| {
    let r = resume_state();
    if let Some(a) = &r.anomaly {
        eprintln!("AUDIT: {}", a);
    }
    if let Some(n) = &r.note {
        eprintln!("AUDIT: note: {}", n);
    }
    r
});

/// What the chain found out about itself at startup (truncation, a removed log, an unauthenticated
/// mark), for the startup record: on stderr alone it vanishes with the terminal.
pub(crate) fn startup_anomaly() -> Option<String> {
    RESUME.anomaly.clone()
}

/// What the chain noticed at startup that is not an anomaly (a key configured for the first time).
pub(crate) fn startup_note() -> Option<String> {
    RESUME.note.clone()
}

pub(crate) static AUDIT_PREV: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(RESUME.hash.clone()));

/// Sequence number of the last entry. A gap reveals a deleted entry; comparison with the sidecar
/// high-water mark reveals a shortened one.
pub(crate) static AUDIT_SEQ: Lazy<std::sync::atomic::AtomicU64> =
    Lazy::new(|| std::sync::atomic::AtomicU64::new(RESUME.seq));

fn hwm_mac(key: &[u8], seq: u64, hash: &str) -> String {
    hmac_sha256_hex(key.to_vec(), format!("hwm:{seq}:{hash}").as_bytes())
}

/// Records (seq, hash) beside the log. Best effort: a failure here must never lose an audit entry,
/// but it is reported, because a silent failure would quietly disarm the truncation check.
fn write_hwm(seq: u64, hash: &str) {
    let Some(p) = hwm_path() else { return };
    let mut mark = json!({ "seq": seq, "hash": hash });
    // With a key the mark is authenticated: without it anyone who can write the log can write the
    // mark too, and truncating the log then looks like a clean state.
    if let Some((k, _)) = audit_key() {
        mark["mac"] = Value::String(hwm_mac(&k, seq, hash));
    }
    let body = mark.to_string();
    if let Err(e) = std::fs::write(&p, body) {
        eprintln!(
            "AUDIT: could not update {} ({}) — truncation detection is degraded.",
            p, e
        );
    }
}

/// Lowercase hex of a digest.
///
/// This used to be `format!("{:x}", digest)`. `sha2` 0.11 returns `Array` instead of
/// `GenericArray`, and `Array` does not implement `LowerHex`, so six call sites stopped compiling.
/// Writing the encoding out is the better answer anyway: every hash in this file ends up in an
/// audit record or a chain link, and the byte-for-byte shape of those strings is a compatibility
/// promise to logs already written. A promise that rests on a formatting trait in someone else's
/// crate is a promise held by somebody else.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `unwrap` is unreachable: writing to a String cannot fail.
        let _ = write!(out, "{:02x}", b);
    }
    out
}

// --- SQL fingerprint (first 16 hex characters of SHA-256) ---
pub(crate) fn sql_fingerprint(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let result = hasher.finalize();
    // Manual hex formatting; we keep the first 16 characters (8 bytes)
    hex(&result).chars().take(16).collect()
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
    //
    //    The chain lock is taken BEFORE the sequence number is drawn. Drawing it first let two threads
    //    take 5 and 6 and then write 6 before 5 (the chain itself stayed valid), which the verifier
    //    reported as "entries were removed", and a restart after a crash re-issued 6. A false
    //    TAMPERED teaches the operator to ignore the real one.
    let mut prev_guard = AUDIT_PREV.lock().unwrap_or_else(|p| p.into_inner());
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
    let prev_hash = prev_guard.clone();
    let entry_str = serde_json::to_string(&entry).expect("serializacja entry");
    let payload = format!("{}{}", prev_hash, entry_str);
    let current_hash = match &key {
        Some((k, _)) => hmac_sha256_hex(k.clone(), payload.as_bytes()),
        None => {
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            hex(&hasher.finalize())
        }
    };

    // 5. Extend the entry with the chain fields
    let mut full_entry = entry;
    full_entry["prev"] = Value::String(prev_hash);
    full_entry["hash"] = Value::String(current_hash.clone());

    // 6. Aktualizacja stanu globalnego (the guard stays held through the append below, so the file
    //    order is the sequence order)
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
        } else {
            // The mark moves only AFTER the entry is durably appended. The other order would let a
            // crash between the two leave a mark ahead of the log and cry truncation on every start.
            write_hwm(seq, full_entry["hash"].as_str().unwrap_or_default());
        }
    }
}

/// Walks the audit file and checks that every entry has a correct `prev` and `hash`. Returns the
/// entry count, or a description of the first mismatch (the line number is where the log was touched).
/// It uses EXACTLY the same hash function as the writer, so the verdict never depends on interpretation.
/// Returns `(human summary, last hash)`. The hash is separate because the anchor is meant to be
/// stored and compared by a script, and a caller should not have to parse prose to get it.
pub(crate) fn verify_audit_file(
    path: &str,
    expect_last: Option<&str>,
) -> Result<(String, String), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;

    // Key set: the current one plus (optionally) previous ones, comma-separated. A log that survived a
    // ROTATION must verify end to end — otherwise every rotation looks like sabotage.
    let keys = key_set();
    verify_audit_content(&content, &keys, expect_last)
}

/// The verification itself, with the key set passed in so a test can exercise keyed chains without
/// touching the process environment (tests run in parallel threads of one process).
pub(crate) fn verify_audit_content(
    content: &str,
    keys: &[(Vec<u8>, String)],
    expect_last: Option<&str>,
) -> Result<(String, String), String> {
    let mut prev = "GENESIS".to_string();
    let mut prev_seq: Option<u64> = None;
    let mut n = 0usize;
    let mut rotations = 0usize;
    let mut last_fp: Option<String> = None;
    let mut unsigned = 0usize;

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
        // The hash covers the parsed object, and parsing keeps only the LAST of two equal keys, so
        // `"caller":"alice", ... "caller":"bob"` verified while a reader taking the first value (grep,
        // a SIEM parser) saw alice. The writer always emits sorted keys without spaces, so a line that
        // does not reserialise to itself was not written by us.
        if serde_json::to_string(&v).map_err(|e| format!("line {}: {}", ln, e))? != line.trim_end()
        {
            return Err(format!(
                "line {}: not in the form this server writes (duplicate keys, reordered fields or extra whitespace)",
                ln
            ));
        }
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
        // The log starts at 1. A file that starts anywhere else had its head cut off, or is what a
        // restart wrote after the old file was deleted (it resumes from the high-water mark, with a
        // fresh chain): either way entries are missing and a clean chain over the rest proves nothing.
        if n == 0 {
            if let Some(first) = obj.get("seq").and_then(|s| s.as_u64()) {
                if first != 1 {
                    return Err(format!(
                        "line {}: the log starts at entry {}, not 1 — earlier entries are missing (rotated away, cut off, or the file was replaced)",
                        ln, first
                    ));
                }
            }
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
                // With a key in hand, an unsigned entry after a signed one is how the HMAC is walked
                // around: drop the middle, strip `key_fp` from the entries after it, recompute them
                // with plain SHA-256, and the old verifier still said "OK (HMAC-SHA256)". A log may
                // begin unsigned (the key was introduced later); it may not go back to unsigned.
                if last_fp.is_some() {
                    return Err(format!(
                        "line {}: unsigned entry after signed ones — the HMAC protection was stripped from here on",
                        ln
                    ));
                }
                unsigned += 1;
                let mut h = Sha256::new();
                h.update(payload.as_bytes());
                hex(&h.finalize())
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
    // The operator gave us a key and expects a keyed log. If nothing in it is signed, the chain
    // proves nothing against someone who can write the file, and saying "OK" would be a lie.
    if !keys.is_empty() && n > 0 && last_fp.is_none() {
        return Err(
            "a key was provided but no entry is signed with it — the whole log is unkeyed SHA-256, \
             which anyone with write access can recompute"
                .into(),
        );
    }
    let mode = if last_fp.is_none() {
        "SHA-256, unkeyed".to_string()
    } else if unsigned > 0 {
        format!("HMAC-SHA256, {} leading entries unsigned", unsigned)
    } else {
        "HMAC-SHA256".to_string()
    };
    let seq_info = prev_seq
        .map(|s| format!(", last seq {}", s))
        .unwrap_or_default();
    let rot_info = if rotations > 0 {
        format!(", key rotations: {}", rotations)
    } else {
        String::new()
    };
    Ok((
        format!(
            "[{}] {} entries{}{}\n  last hash: {}\n  STORE this hash off-host — without an external \
             anchor, truncating the tail of the log is undetectable",
            mode, n, seq_info, rot_info, prev
        ),
        prev,
    ))
}

/// HMAC key for the audit chain. `MCP_AUDIT_HMAC_KEY` (the value) or `MCP_AUDIT_HMAC_KEY_FILE`
/// (a path — more convenient for secrets mounted by an orchestrator).
pub(crate) fn audit_key() -> Option<(Vec<u8>, String)> {
    static KEY: Lazy<Option<(Vec<u8>, String)>> = Lazy::new(|| {
        // An EMPTY `MCP_AUDIT_HMAC_KEY` counts as unset and falls through to the file: compose files
        // expand `${VAR}` to "" when the variable is missing, and the old `if let Ok(k)` stopped
        // there, silently running unkeyed with a perfectly good key file beside it.
        let from_env = std::env::var("MCP_AUDIT_HMAC_KEY")
            .ok()
            .filter(|k| !k.is_empty());
        let raw: Option<Vec<u8>> = if let Some(k) = from_env {
            Some(k.into_bytes())
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
    hex(&h.finalize()).chars().take(8).collect()
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
    hex(&outer.finalize())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Tests that point `MCP_AUDIT_LOG` at a file take this first; the variable is process-global.
    static LOG_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Builds a well-formed chain, using the same hashing the writer uses, so a test cannot pass by
    /// agreeing with itself about a format the writer does not produce.
    fn chain(entries: &[Value]) -> String {
        let key = audit_key();
        let mut prev = "GENESIS".to_string();
        let mut out = String::new();
        for e in entries {
            let mut entry = e.clone();
            if let (Some(obj), Some((_, fp))) = (entry.as_object_mut(), &key) {
                obj.insert("key_fp".into(), Value::String(fp.clone()));
            }
            let body = serde_json::to_string(&entry).unwrap();
            let payload = format!("{}{}", prev, body);
            let hash = match &key {
                Some((k, _)) => hmac_sha256_hex(k.clone(), payload.as_bytes()),
                None => {
                    let mut h = Sha256::new();
                    h.update(payload.as_bytes());
                    hex(&h.finalize())
                }
            };
            let mut full = entry.as_object().unwrap().clone();
            full.insert("prev".into(), Value::String(prev.clone()));
            full.insert("hash".into(), Value::String(hash.clone()));
            out.push_str(&serde_json::to_string(&Value::Object(full)).unwrap());
            out.push('\n');
            prev = hash;
        }
        out
    }

    fn entry(seq: u64, tool: &str) -> Value {
        json!({"seq": seq, "ts": 1_700_000_000 + seq, "tool": tool,
               "decision": "allowed", "sql_fp": "abcdef0123456789", "caller": "-"})
    }

    fn write(name: &str, content: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("audit_test_{}_{}.log", name, std::process::id()));
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn keyed_chain(key: &[u8], entries: &[Value], sign: &dyn Fn(usize) -> bool) -> String {
        let fp = key_fingerprint(key);
        let mut prev = "GENESIS".to_string();
        let mut out = String::new();
        for (i, e) in entries.iter().enumerate() {
            let mut e = e.clone();
            let signed = sign(i);
            if signed {
                e["key_fp"] = json!(fp);
            }
            let body = serde_json::to_string(&e).unwrap();
            let payload = format!("{}{}", prev, body);
            let hash = if signed {
                hmac_sha256_hex(key.to_vec(), payload.as_bytes())
            } else {
                let mut h = Sha256::new();
                h.update(payload.as_bytes());
                hex(&h.finalize())
            };
            let mut full = e.as_object().unwrap().clone();
            full.insert("prev".into(), json!(prev));
            full.insert("hash".into(), json!(hash));
            out.push_str(&serde_json::to_string(&Value::Object(full)).unwrap());
            out.push('\n');
            prev = hash;
        }
        out
    }

    fn keys_of(key: &[u8]) -> Vec<(Vec<u8>, String)> {
        vec![(key.to_vec(), key_fingerprint(key))]
    }

    /// The bypass: with the key in hand the verifier took any entry WITHOUT `key_fp` as plain SHA-256,
    /// so cutting entries out and recomputing the tail unsigned still said "OK (HMAC-SHA256)".
    #[test]
    fn stripping_the_signature_from_the_tail_is_caught_when_a_key_is_given() {
        let key = b"audit-key-for-test".to_vec();
        let es: Vec<Value> = (1..=5).map(|i| entry(i, "query")).collect();
        let honest = keyed_chain(&key, &es, &|_| true);
        verify_audit_content(&honest, &keys_of(&key), None).expect("an honest keyed log verifies");

        // forged: entries 1-2 signed, 3-5 recomputed with no key_fp at all
        let forged = keyed_chain(&key, &es, &|i| i < 2);
        let err = verify_audit_content(&forged, &keys_of(&key), None).unwrap_err();
        assert!(err.contains("unsigned entry after signed"), "{err}");

        // wholly unsigned log presented against a key
        let none = keyed_chain(&key, &es, &|_| false);
        let err = verify_audit_content(&none, &keys_of(&key), None).unwrap_err();
        assert!(err.contains("no entry is signed"), "{err}");
    }

    #[test]
    fn a_log_that_began_unsigned_and_gained_a_key_still_verifies_and_says_so() {
        let key = b"audit-key-for-test".to_vec();
        let es: Vec<Value> = (1..=4).map(|i| entry(i, "query")).collect();
        let mixed = keyed_chain(&key, &es, &|i| i >= 2);
        let (summary, _) = verify_audit_content(&mixed, &keys_of(&key), None).unwrap();
        assert!(
            summary.starts_with("[HMAC-SHA256, 2 leading entries unsigned]"),
            "{summary}"
        );
        let plain = keyed_chain(&key, &es, &|_| false);
        let (summary, _) = verify_audit_content(&plain, &[], None).unwrap();
        assert!(summary.starts_with("[SHA-256, unkeyed]"), "{summary}");
    }

    #[test]
    fn a_log_that_does_not_start_at_one_is_refused() {
        let es: Vec<Value> = (7..=9).map(|i| entry(i, "query")).collect();
        let err = verify_audit_content(&chain(&es), &[], None).unwrap_err();
        assert!(err.contains("starts at entry 7"), "{err}");
    }

    #[test]
    fn a_duplicated_key_does_not_hide_behind_the_last_value() {
        let es: Vec<Value> = (1..=2).map(|i| entry(i, "query")).collect();
        let good = chain(&es);
        let first = good.lines().next().unwrap().to_string();
        let doctored = good.replacen(
            "\"caller\":\"-\"",
            "\"caller\":\"alice\",\"caller\":\"-\"",
            1,
        );
        assert_ne!(first, doctored.lines().next().unwrap());
        let err = verify_audit_content(&doctored, &[], None).unwrap_err();
        assert!(err.contains("not in the form this server writes"), "{err}");
    }

    /// Entries written from many threads must verify: the sequence number used to be drawn before the
    /// chain lock, so two threads could write 6 then 5.
    #[test]
    fn concurrent_writers_produce_a_log_that_verifies() {
        let dir = std::env::temp_dir().join(format!("seq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("a.log");
        std::fs::remove_file(&log).ok();
        let _g = LOG_ENV.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("MCP_AUDIT_LOG", &log);
        let hs: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..100 {
                        audit_extra("t", "allowed", None, serde_json::Map::new());
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        std::env::remove_var("MCP_AUDIT_LOG");
        let body = std::fs::read_to_string(&log).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let seqs: Vec<u64> = body
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v["seq"].as_u64())
            .collect();
        assert!(
            seqs.len() >= 800,
            "only {} entries reached the file",
            seqs.len()
        );
        assert!(
            seqs.windows(2).all(|w| w[1] == w[0] + 1),
            "sequence out of order in the file"
        );
    }

    #[test]
    fn a_well_formed_chain_verifies_and_returns_its_last_hash() {
        let c = chain(&[
            entry(1, "query"),
            entry(2, "list_tables"),
            entry(3, "query"),
        ]);
        let p = write("ok", &c);
        let (summary, last) = verify_audit_file(&p, None).expect("chain should verify");
        assert!(
            c.contains(&last),
            "the reported last hash must be the one in the file"
        );
        assert!(summary.contains("3 entries"), "{summary}");
        std::fs::remove_file(p).ok();
    }

    /// The point of hashing each entry: changing one has to be visible, and the message has to say
    /// WHICH one, or an operator with a large log learns nothing actionable.
    #[test]
    fn a_modified_entry_is_caught_and_located() {
        let c = chain(&[entry(1, "query"), entry(2, "query"), entry(3, "query")]);
        let tampered = c.replacen(
            "\"decision\":\"allowed\"",
            "\"decision\":\"denied_rate\"",
            1,
        );
        let p = write("modified", &tampered);
        let err = verify_audit_file(&p, None).expect_err("a modified entry must not verify");
        assert!(
            err.contains("line 1"),
            "the failure must name the line: {err}"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn a_removed_entry_is_caught() {
        let c = chain(&[entry(1, "query"), entry(2, "query"), entry(3, "query")]);
        let lines: Vec<&str> = c.lines().collect();
        let p = write("removed", &format!("{}\n{}\n", lines[0], lines[2]));
        let err = verify_audit_file(&p, None).expect_err("a gap must not verify");
        assert!(!err.is_empty());
        std::fs::remove_file(p).ok();
    }

    /// The limit SECURITY.md states, asserted rather than described. Cutting the tail leaves a log
    /// that is internally consistent, so only an anchor kept elsewhere can catch it. A test that
    /// pretended otherwise would be worse than no test.
    #[test]
    fn a_truncated_tail_is_invisible_without_an_anchor_and_caught_with_one() {
        let c = chain(&[entry(1, "query"), entry(2, "query"), entry(3, "query")]);
        let (_, real_last) = verify_audit_file(&write("full", &c), None).unwrap();
        let lines: Vec<&str> = c.lines().collect();
        let cut = format!("{}\n{}\n", lines[0], lines[1]);
        let p = write("truncated", &cut);
        verify_audit_file(&p, None)
            .expect("a truncated log still verifies — this is the known limit");
        let err = verify_audit_file(&p, Some(&real_last))
            .expect_err("with an external anchor, truncation must be caught");
        assert!(
            err.to_lowercase().contains("last") || err.contains(&real_last[..8]),
            "{err}"
        );
        std::fs::remove_file(p).ok();
    }

    /// R5 of the 0.1.12 review: with a key, cutting the tail and deleting the mark passed as an
    /// upgrade from a build without marks.
    #[test]
    fn a_keyed_log_without_its_mark_is_an_anomaly() {
        let dir = std::env::temp_dir().join(format!("hwm-r5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let path = log.to_str().unwrap().to_string();
        let key = b"r5-key".to_vec();
        let keys = vec![(key.clone(), key_fingerprint(&key))];
        let c = keyed_chain(
            &key,
            &[entry(1, "query"), entry(2, "query"), entry(3, "query")],
            &|_| true,
        );
        let lines: Vec<&str> = c.lines().collect();
        let last: Value = serde_json::from_str(lines[2]).unwrap();
        let (s3, h3) = (
            last["seq"].as_u64().unwrap(),
            last["hash"].as_str().unwrap().to_string(),
        );
        std::fs::write(&log, &c).unwrap();
        std::fs::write(
            hwm_path_of(&path),
            json!({"seq": s3, "hash": h3, "mac": hwm_mac(&key, s3, &h3)}).to_string(),
        )
        .unwrap();
        assert!(
            resume_state_with(&path, &keys).anomaly.is_none(),
            "intact keyed log"
        );
        // cut the tail, delete the mark
        std::fs::write(&log, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        std::fs::remove_file(hwm_path_of(&path)).unwrap();
        let a = resume_state_with(&path, &keys)
            .anomaly
            .expect("must be reported");
        assert!(a.contains("missing although the log is keyed"), "{a}");
        // an unkeyed log without a mark is still an upgrade, not an alarm
        std::fs::write(&log, chain(&[entry(1, "query")])).unwrap();
        assert!(resume_state_with(&path, &[]).anomaly.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R13 of the 0.1.12 review: false alarms at key introduction, at rotation and on a new log.
    #[test]
    fn a_new_key_a_rotation_and_a_new_log_are_not_tampering() {
        let dir = std::env::temp_dir().join(format!("hwm-r13-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let path = log.to_str().unwrap().to_string();
        let mark = |seq: u64, hash: &str, key: Option<&[u8]>| {
            let mut m = json!({"seq": seq, "hash": hash});
            if let Some(k) = key {
                m["mac"] = json!(hwm_mac(k, seq, hash));
            }
            std::fs::write(hwm_path_of(&path), m.to_string()).unwrap();
        };
        let last = |c: &str| {
            let v: Value = serde_json::from_str(c.lines().last().unwrap()).unwrap();
            (
                v["seq"].as_u64().unwrap(),
                v["hash"].as_str().unwrap().to_string(),
            )
        };
        let (k1, k2) = (b"r13-old".to_vec(), b"r13-new".to_vec());
        let keyset = |ks: &[&Vec<u8>]| -> Vec<(Vec<u8>, String)> {
            ks.iter()
                .map(|k| ((*k).clone(), key_fingerprint(k)))
                .collect()
        };

        // 1. an unkeyed log and its unkeyed mark, then a key is configured: a note, not an anomaly
        let c = chain(&[entry(1, "query"), entry(2, "query")]);
        std::fs::write(&log, &c).unwrap();
        let (s, h) = last(&c);
        mark(s, &h, None);
        let r = resume_state_with(&path, &keyset(&[&k1]));
        assert!(r.anomaly.is_none(), "{:?}", r.anomaly);
        assert!(r.note.is_some());

        // 2. rotation: the mark is signed with the retired key, which is offered as old
        let c = keyed_chain(&k1, &[entry(1, "query"), entry(2, "query")], &|_| true);
        std::fs::write(&log, &c).unwrap();
        let (s, h) = last(&c);
        mark(s, &h, Some(&k1));
        let r = resume_state_with(&path, &keyset(&[&k2, &k1]));
        assert!(r.anomaly.is_none(), "{:?}", r.anomaly);
        // without the retired key it cannot be vouched for
        assert!(resume_state_with(&path, &keyset(&[&k2])).anomaly.is_some());

        // 3. a log keyed by a build that signs its mark, beside an unsigned mark: still an anomaly
        let mut start = entry(1, "server");
        start["decision"] = json!("startup");
        start["version"] = json!("0.1.12");
        let c = keyed_chain(&k1, &[start, entry(2, "query")], &|_| true);
        std::fs::write(&log, &c).unwrap();
        let (s, h) = last(&c);
        mark(s, &h, None);
        let a = resume_state_with(&path, &keyset(&[&k1]))
            .anomaly
            .expect("forged mark");
        assert!(a.contains("no valid MAC"), "{a}");

        // 4. the empty file the start-up check creates is a first run; emptied after use it is not
        std::fs::write(&log, "").unwrap();
        std::fs::remove_file(hwm_path_of(&path)).unwrap();
        assert!(resume_state_with(&path, &[]).anomaly.is_none());
        mark(5, "abc", None);
        assert!(resume_state_with(&path, &[]).anomaly.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The truncation detector must FIRE, not merely exist. The previous mechanism had a docstring
    /// promising exactly this and could never deliver it, because its memory lived inside the file
    /// it was guarding. This test cuts the tail and asserts the anomaly is reported.
    #[test]
    fn a_shortened_log_is_detected_by_the_sidecar_mark() {
        let dir = std::env::temp_dir().join(format!("hwm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let hwm = dir.join("audit.jsonl.hwm");
        let c = chain(&[entry(1, "query"), entry(2, "query"), entry(3, "query")]);
        std::fs::write(&log, &c).unwrap();
        let last = serde_json::from_str::<Value>(c.lines().last().unwrap()).unwrap();
        std::fs::write(
            &hwm,
            json!({"seq": last["seq"], "hash": last["hash"]}).to_string(),
        )
        .unwrap();

        // NIE ustawiamy `MCP_AUDIT_LOG`: to zmienna globalna dla procesu, a `cargo test` biegnie
        // równolegle w wątkach. Ustawienie jej kierowało na TEN plik każde wywołanie `audit()`
        // z innego testu, więc dopisywały mu one wpisy w trakcie sprawdzania. CI oblało za pierwszym
        // razem, u nas pięć przebiegów pod rząd było czyste — testu, który psuje się losowo, nie da
        // się odróżnić od kodu, który psuje się losowo ([[feedback_never_executed_path]] od drugiej
        // strony: ścieżka wykonywana, ale nie ta, o której myślę).
        let sciezka = log.to_str().unwrap().to_string();
        let intact = resume_state_of(&sciezka);
        assert!(
            intact.anomaly.is_none(),
            "an intact log must not raise: {:?}",
            intact.anomaly
        );

        // Cut the last entry — the log stays internally consistent, which is the whole problem.
        let lines: Vec<&str> = c.lines().collect();
        std::fs::write(&log, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        let cut = resume_state_of(&sciezka);
        let a = cut.anomaly.expect("a shortened log MUST be reported");
        assert!(a.contains("MISSING FROM"), "{a}");
        assert!(
            a.contains("2") && a.contains("3"),
            "should name both counts: {a}"
        );

        // A rewritten last entry is a different anomaly, and must also be seen.
        let mut tampered: Value = serde_json::from_str(lines[2]).unwrap();
        tampered["hash"] =
            json!("0000000000000000000000000000000000000000000000000000000000000000");
        std::fs::write(&log, format!("{}\n{}\n{}\n", lines[0], lines[1], tampered)).unwrap();
        let rew = resume_state_of(&sciezka);
        assert!(
            rew.anomaly.as_deref().unwrap_or("").contains("rewritten"),
            "{:?}",
            rew.anomaly
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Adding fields to a record must not invalidate the chain: the startup and posture entries carry
    /// extra keys, and `serde_json` here builds a BTreeMap, so serialisation is key-sorted and stable.
    /// If a dependency ever switched on `preserve_order`, every chain would break silently — this is
    /// the test that would say so.
    #[test]
    fn extra_fields_do_not_break_the_chain() {
        let mut rich = entry(1, "server");
        rich["config_fp"] = json!("deadbeef");
        rich["version"] = json!("0.1.0");
        rich["transport"] = json!("stdio");
        let c = chain(&[rich, entry(2, "query")]);
        let p = write("extra", &c);
        verify_audit_file(&p, None).expect("records with additional fields must still verify");
        std::fs::remove_file(p).ok();
    }

    /// A rotated key must not look like sabotage: entries written under a previous key still verify
    /// when that key is offered in MCP_AUDIT_HMAC_KEYS_OLD.
    #[test]
    fn a_rotated_key_still_verifies() {
        let old_key = b"previous-audit-key".to_vec();
        let fp = key_fingerprint(&old_key);
        let mut prev = "GENESIS".to_string();
        let mut out = String::new();
        for seq in 1..=2u64 {
            let mut e = entry(seq, "query");
            e["key_fp"] = json!(fp);
            let body = serde_json::to_string(&e).unwrap();
            let hash = hmac_sha256_hex(old_key.clone(), format!("{}{}", prev, body).as_bytes());
            let mut full = e.as_object().unwrap().clone();
            full.insert("prev".into(), json!(prev));
            full.insert("hash".into(), json!(hash));
            out.push_str(&serde_json::to_string(&Value::Object(full)).unwrap());
            out.push('\n');
            prev = hash;
        }
        // The key set goes in as an argument: setting `MCP_AUDIT_HMAC_KEYS_OLD` made every other
        // verification test in the process see a key for a moment, and an unsigned log then (rightly)
        // failed for having none of its entries signed.
        verify_audit_content(&out, &[(old_key, fp)], None)
            .expect("a log written under a rotated-out key must still verify");
    }

    /// The log records a fingerprint, not the statement. README says so; this is what makes it true.
    #[test]
    fn the_log_keeps_a_fingerprint_not_the_statement() {
        let secret = "SELECT card_number FROM payments WHERE customer='ada'";
        let fp = sql_fingerprint(secret);
        assert_eq!(fp.len(), 16);
        for window in secret.as_bytes().windows(8) {
            let piece = String::from_utf8_lossy(window);
            assert!(
                !fp.contains(piece.as_ref()),
                "the fingerprint leaked {piece:?}"
            );
        }
        assert_ne!(fp, sql_fingerprint("SELECT 1"));
    }
}

#[cfg(test)]
mod hex_tests {
    use super::*;

    /// Pinned to the FIPS 180-2 vector for SHA-256("abc"). The point is not that SHA-256 works —
    /// it is that the *string* this file produces did not change when `sha2` went from 0.10 to 0.11
    /// and the hand-written `hex` replaced `format!("{:x}", …)`. Every audit record already on disk
    /// carries hashes in this exact shape, and `--verify-audit` compares them as text. A silent
    /// change of case or padding here would not fail to compile; it would quietly declare every
    /// existing log tampered with.
    #[test]
    fn hex_encoding_is_byte_for_byte_what_it_always_was() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            hex(&h.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// A leading zero byte is where a naive encoder loses a character and every hash after it
    /// shifts. SHA-256 of this input starts with 0x04.
    #[test]
    fn a_leading_zero_nibble_is_not_dropped() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
    }
}
