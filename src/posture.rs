//! What this server is *able* to do, asked of the database rather than assumed.
//!
//! Three adversarial rounds established that a validator cannot be the boundary: SQL has more ways to
//! name a value than any filter can enumerate. The boundary is a privilege the connected role does
//! not have — which means the only honest thing a server can do is go and find out which privileges
//! it actually holds, and refuse to expose itself to a network when the answer is "all of them".
//!
//! This module is the first half of that: the facts about the role, and the gate that acts on them.

use once_cell::sync::Lazy;
use serde_json::Value;
use std::sync::RwLock;

use crate::query_catalog;

/// What the connected role can do, as the database reports it.
#[derive(Clone, Debug, Default)]
pub(crate) struct RoleFacts {
    pub(crate) user: String,
    pub(crate) superuser: bool,
    pub(crate) bypass_rls: bool,
    pub(crate) create_db: bool,
    pub(crate) create_role: bool,
    pub(crate) replication: bool,
    /// Predefined roles the caller is a MEMBER of — see the note on `SET ROLE` below.
    pub(crate) dangerous_roles: Vec<String>,
    /// Tables in the sample this role may write to.
    pub(crate) writable: u64,
    /// How many relations the sample covered; the query is bounded so a huge schema cannot stall startup.
    pub(crate) scanned: u64,
    pub(crate) sampled: bool,
    pub(crate) writable_examples: Vec<String>,
}

impl RoleFacts {
    /// Everything that makes this role more than a reader. Any one of these is enough to refuse a
    /// network listener: they differ in how the damage happens, not in whether it can.
    pub(crate) fn excessive(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.superuser {
            out.push("is a superuser".to_string());
        }
        if self.bypass_rls {
            out.push("has BYPASSRLS, so row-level security does not apply to it".to_string());
        }
        if self.create_db {
            out.push("may create databases".to_string());
        }
        if self.create_role {
            out.push("may create roles".to_string());
        }
        if self.replication {
            out.push("has REPLICATION, which can stream the whole cluster".to_string());
        }
        for r in &self.dangerous_roles {
            out.push(format!("is a member of {}", r));
        }
        if self.writable > 0 {
            let sample = if self.writable_examples.is_empty() {
                String::new()
            } else {
                format!(" (for example {})", self.writable_examples.join(", "))
            };
            out.push(format!(
                "can write to {} of the {} tables examined{}",
                self.writable, self.scanned, sample
            ));
        }
        out
    }
}

static FACTS: Lazy<RwLock<Option<RoleFacts>>> = Lazy::new(|| RwLock::new(None));
/// Set when the listener is exposed and the facts are not in yet: the data path stays closed rather
/// than serving through a gate we have not been able to check.
static PENDING: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));

fn as_bool(row: &Value, key: &str) -> bool {
    row.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn as_u64(row: &Value, key: &str) -> u64 {
    row.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

/// Asks the database what the connected role is allowed to do.
pub(crate) fn evaluate(db: Option<&str>) -> Result<RoleFacts, String> {
    // `pg_roles`, deliberately, not `pg_authid`: `pg_authid` needs superuser, so basing the check on
    // it would return "cannot tell" for exactly the least-privileged roles we most want to confirm.
    const ROLE: &str = "SELECT current_user AS usr, rolsuper, rolbypassrls, rolcreatedb, \
         rolcreaterole, rolreplication FROM pg_roles WHERE rolname = current_user";
    // MEMBER, not USAGE. A role with NOINHERIT does not *hold* its groups' privileges until it runs
    // SET ROLE — but it can run SET ROLE, so a USAGE test reports "safe" about a role that is one
    // statement away from being unsafe. Asking about membership is asking the question that matters.
    //
    // Roles absent from older versions simply do not come back, so one query covers 13 through 17.
    const MEMBERSHIPS: &str = "SELECT rolname FROM pg_roles \
         WHERE rolname IN ('pg_write_all_data','pg_read_all_data','pg_read_server_files', \
                           'pg_write_server_files','pg_execute_server_program','pg_maintain', \
                           'pg_signal_backend','pg_checkpoint') \
           AND pg_has_role(current_user, oid, 'MEMBER')";
    // Bounded: a schema with hundreds of thousands of relations must not turn a start-up check into
    // an outage. When the bound is hit we say so rather than reporting a partial count as the whole.
    const WRITABLE: &str = "WITH s AS ( \
             SELECT c.oid, n.nspname, c.relname FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE c.relkind IN ('r','p','f') \
               AND n.nspname NOT IN ('pg_catalog','information_schema') \
               AND n.nspname NOT LIKE 'pg\\_%' LIMIT 5000) \
         SELECT count(*) AS scanned, \
                count(*) FILTER (WHERE has_table_privilege(oid,'INSERT') \
                                    OR has_table_privilege(oid,'UPDATE') \
                                    OR has_table_privilege(oid,'DELETE') \
                                    OR has_table_privilege(oid,'TRUNCATE')) AS writable, \
                (array_agg(nspname || '.' || relname) FILTER (WHERE has_table_privilege(oid,'INSERT')))[1:3] \
                  AS examples \
         FROM s";

    let rows = |v: Value| -> Vec<Value> {
        v.get("rows")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default()
    };

    let role = rows(query_catalog(ROLE, &[], db)?);
    let r = role
        .first()
        .ok_or_else(|| "the database did not describe the connected role".to_string())?;
    let mut facts = RoleFacts {
        user: r
            .get("usr")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string(),
        superuser: as_bool(r, "rolsuper"),
        bypass_rls: as_bool(r, "rolbypassrls"),
        create_db: as_bool(r, "rolcreatedb"),
        create_role: as_bool(r, "rolcreaterole"),
        replication: as_bool(r, "rolreplication"),
        ..Default::default()
    };

    facts.dangerous_roles = rows(query_catalog(MEMBERSHIPS, &[], db)?)
        .iter()
        .filter_map(|r| r.get("rolname").and_then(|v| v.as_str()).map(String::from))
        .collect();

    if let Some(w) = rows(query_catalog(WRITABLE, &[], db)?).first() {
        facts.scanned = as_u64(w, "scanned");
        facts.writable = as_u64(w, "writable");
        facts.sampled = facts.scanned >= 5000;
        facts.writable_examples = w
            .get("examples")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
    }
    Ok(facts)
}

/// True when the listen address is reachable only from this machine.
pub(crate) fn is_loopback(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn hatch(name: &str) -> bool {
    // A value, not `1`: an escape hatch that can be switched on by a typo is not an escape hatch.
    // It is also recorded in the startup audit entry, so the decision to lower the bar is written down.
    std::env::var(name).is_ok_and(|v| v == "i-accept-the-risk")
}

/// Refuses to serve a network when the role or the configuration makes that dangerous.
///
/// Loopback and stdio are left alone: there the caller is the operator, and a server that will not
/// start is a server people abandon for the one with no checks at all. Exposure is what changes the
/// question from "who might misuse this" to "who might find it".
pub(crate) fn enforce_start_policy(transport: &str, addr: &str) {
    if transport == "stdio" || is_loopback(addr) {
        return;
    }

    if std::env::var("MCP_BEARER_TOKEN").is_ok_and(|t| !t.trim().is_empty())
        || std::env::var("JWT_PUBKEY_PEM").is_ok_and(|t| !t.trim().is_empty())
    {
        // authenticated — the remaining question is what the role can do
    } else if hatch("MCP_ALLOW_ANONYMOUS_NETWORK") {
        eprintln!(
            "WARNING: serving {} with no authentication at all, because \
             MCP_ALLOW_ANONYMOUS_NETWORK=i-accept-the-risk is set.",
            addr
        );
    } else {
        eprintln!("REFUSING TO START — {} is reachable from the network and this server requires no authentication.", addr);
        eprintln!("  Anyone who can reach that address can read everything the database role can read.");
        eprintln!("  Set MCP_BEARER_TOKEN (a shared secret) or JWT_PUBKEY_PEM + JWT_AUD + JWT_ISS (OAuth 2.1),");
        eprintln!("  bind to 127.0.0.1 instead, or set MCP_ALLOW_ANONYMOUS_NETWORK=i-accept-the-risk to override.");
        std::process::exit(3);
    }

    match evaluate(None) {
        Ok(facts) => {
            let problems = facts.excessive();
            *FACTS.write().unwrap() = Some(facts.clone());
            if problems.is_empty() {
                eprintln!(
                    "Role {}: read-only as far as the database is concerned ({} tables examined).",
                    facts.user, facts.scanned
                );
                return;
            }
            if hatch("MCP_ALLOW_EXCESSIVE_ROLE") {
                eprintln!(
                    "WARNING: serving {} as {}, which {} — MCP_ALLOW_EXCESSIVE_ROLE=i-accept-the-risk is set.",
                    addr,
                    facts.user,
                    problems.join("; ")
                );
                return;
            }
            eprintln!(
                "REFUSING TO START — {} is reachable from the network and the role {} is more than a reader:",
                addr, facts.user
            );
            for p in &problems {
                eprintln!("  - it {}", p);
            }
            if facts.sampled {
                eprintln!("  (the write check examined the first 5000 relations; there may be more)");
            }
            eprintln!();
            eprintln!("This server enforces read-only itself, but that enforcement is code, and code has");
            eprintln!("been wrong before. A role that cannot write is the part no bug of ours can undo.");
            eprintln!();
            eprintln!("  postgres-mcp-hardened --print-setup-sql > setup.sql   # generates the role to use");
            eprintln!();
            eprintln!("Or bind to 127.0.0.1, or set MCP_ALLOW_EXCESSIVE_ROLE=i-accept-the-risk to override");
            eprintln!("(the override is recorded in the audit log).");
            std::process::exit(3);
        }
        Err(e) => {
            // The database is not answering yet — a perfectly ordinary state when the server and the
            // database start together. We do not exit, because an orchestrator would restart us into
            // the same race for ever; and we do not serve either, because the gate has not been
            // checked. `/health` stays up so liveness probes see a live process.
            eprintln!(
                "Cannot check the database role yet ({}). Serving is held until the check succeeds; \
                 /health stays up.",
                e
            );
            *PENDING.write().unwrap() = true;
            std::thread::spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if let Ok(facts) = evaluate(None) {
                    let problems = facts.excessive();
                    if !problems.is_empty() && !hatch("MCP_ALLOW_EXCESSIVE_ROLE") {
                        eprintln!(
                            "REFUSING TO SERVE — the role {} is more than a reader: {}",
                            facts.user,
                            problems.join("; ")
                        );
                        std::process::exit(3);
                    }
                    eprintln!("Database role checked; serving.");
                    *FACTS.write().unwrap() = Some(facts);
                    *PENDING.write().unwrap() = false;
                    return;
                }
            });
        }
    }
}

/// `Err` while the start-up check has not completed on an exposed listener.
pub(crate) fn serving_blocked() -> Option<&'static str> {
    if *PENDING.read().unwrap() {
        Some("the server has not yet been able to check what the database role is allowed to do, and does not serve queries until it has")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_recognised_in_every_spelling() {
        for a in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.9.9.9:1"] {
            assert!(is_loopback(a), "{a} should count as loopback");
        }
        for a in ["0.0.0.0:8080", "[::]:8080", "10.0.0.5:8080", "example.com:80"] {
            assert!(!is_loopback(a), "{a} should not count as loopback");
        }
    }

    /// Each of these alone justifies refusing a network listener, and the message has to name which.
    #[test]
    fn every_excess_is_reported_separately() {
        let f = RoleFacts {
            user: "app".into(),
            superuser: true,
            bypass_rls: true,
            writable: 3,
            scanned: 10,
            writable_examples: vec!["public.orders".into()],
            dangerous_roles: vec!["pg_write_all_data".into()],
            ..Default::default()
        };
        let p = f.excessive();
        assert_eq!(p.len(), 4, "four separate reasons: {p:?}");
        assert!(p.iter().any(|s| s.contains("superuser")));
        assert!(p.iter().any(|s| s.contains("BYPASSRLS")));
        assert!(p.iter().any(|s| s.contains("pg_write_all_data")));
        assert!(p.iter().any(|s| s.contains("public.orders")));
    }

    #[test]
    fn a_plain_reader_has_nothing_to_report() {
        let f = RoleFacts {
            user: "reader".into(),
            scanned: 42,
            ..Default::default()
        };
        assert!(f.excessive().is_empty());
    }
}
