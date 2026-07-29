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
use crate::validate;
use serde_json::json;

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
        // A truncated scan is not evidence. The write query stops at a bound and has no `ORDER BY`,
        // so the relations it examined are an arbitrary subset: a role writable only to tables
        // outside that subset looks exactly like a reader. "We found nothing" and "there is nothing"
        // are different statements, and only the second one justifies exposing a network listener.
        if self.sampled && self.writable == 0 {
            out.push(format!(
                "may or may not be able to write: the check stopped at {} relations and this schema                  has more, so \"cannot write\" is something we did not verify",
                self.scanned
            ));
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
/// Ta sama tresc co `MEMBERSHIPS` w `evaluate` — wystawiona, zeby test mogl sprawdzic, o co
/// naprawde pytamy bazy. Bez tego "pytamy tez o role wlasne" byloby twierdzeniem, nie kontrola.
#[cfg(test)]
pub(crate) const MEMBERSHIPS_FOR_TEST: &str = MEMBERSHIPS_SQL;

const MEMBERSHIPS_SQL: &str = "SELECT rolname FROM pg_roles \
     WHERE ( rolname IN ('pg_write_all_data','pg_read_all_data','pg_read_server_files', \
                         'pg_write_server_files','pg_execute_server_program','pg_maintain', \
                         'pg_signal_backend','pg_checkpoint') \
             OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication ) \
       AND rolname <> current_user \
       AND pg_has_role(current_user, oid, 'MEMBER')";

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
    // Jedno zrodlo tresci — patrz `MEMBERSHIPS_SQL` wyzej.
    const MEMBERSHIPS: &str = MEMBERSHIPS_SQL;
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

/// True when a container platform stands in front of us and authenticates the caller itself.
///
/// Today that means Apify Standby, which routes only after checking the caller's Apify token —
/// header `Authorization: Bearer <token>` or `?token=`, with no anonymous path documented. Our
/// process cannot see that check, so without this it refuses to start: from inside the container,
/// `0.0.0.0` with no `MCP_BEARER_TOKEN` looks exactly like an open server.
///
/// This is NOT a general relaxation and deliberately not an escape hatch. It requires **two**
/// markers the platform sets and a user cannot plausibly set by accident, and it changes the
/// reported posture to `apify-platform` rather than `none` — we are not claiming there is no
/// authentication problem, we are naming who solves it. Anywhere else, the refusal stands.
///
/// The alternative was to demand `MCP_BEARER_TOKEN` on top of the platform's token. That would mean
/// an agent which finds this server in the Store cannot call it without a second secret it has no
/// way to obtain — which defeats the point of being there.
pub(crate) fn platform_authenticates() -> bool {
    let at_home = std::env::var("APIFY_IS_AT_HOME").is_ok_and(|v| {
        let v = v.trim();
        !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
    });
    let assigned_port = std::env::var("ACTOR_WEB_SERVER_PORT").is_ok_and(|v| {
        let v = v.trim();
        !v.is_empty() && v.chars().all(|c| c.is_ascii_digit())
    });
    at_home && assigned_port
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
    } else if platform_authenticates() {
        eprintln!(
            "Serving {} without our own authentication: the Apify platform authenticates callers \
             before routing to this container (Standby requires an Apify token). Set \
             MCP_BEARER_TOKEN as well if you want a second lock on the same door.",
            addr
        );
    } else if hatch("MCP_ALLOW_ANONYMOUS_NETWORK") {
        eprintln!(
            "WARNING: serving {} with no authentication at all, because \
             MCP_ALLOW_ANONYMOUS_NETWORK=i-accept-the-risk is set.",
            addr
        );
    } else {
        eprintln!("REFUSING TO START — {} is reachable from the network and this server requires no authentication.", addr);
        eprintln!(
            "  Anyone who can reach that address can read everything the database role can read."
        );
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
                eprintln!(
                    "  (the write check examined the first 5000 relations; there may be more)"
                );
            }
            eprintln!();
            eprintln!(
                "This server enforces read-only itself, but that enforcement is code, and code has"
            );
            eprintln!(
                "been wrong before. A role that cannot write is the part no bug of ours can undo."
            );
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

/// How bad a finding is. The grade is the worst one present — never an average, because averaging
/// lets nine good answers hide one fatal one, and a report that does that teaches operators to skim.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Severity {
    Ok,
    Note,
    Warn,
    Critical,
}

impl Severity {
    fn grade(self) -> &'static str {
        match self {
            Severity::Ok => "A",
            Severity::Note => "B",
            Severity::Warn => "C",
            Severity::Critical => "F",
        }
    }
}

pub(crate) struct Finding {
    pub(crate) id: &'static str,
    pub(crate) severity: Severity,
    pub(crate) fact: String,
    /// What to run. A finding without one is a complaint.
    pub(crate) fix: Option<String>,
}

fn env_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.trim().is_empty())
}

/// Whether the connection to PostgreSQL is actually encrypted — asked of the server, not inferred
/// from our own configuration. `pg_stat_ssl` shows a role its own backend, so this works unprivileged.
fn tls_fact(db: Option<&str>) -> Option<bool> {
    let v = query_catalog(
        "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        &[],
        db,
    )
    .ok()?;
    v.get("rows")?.as_array()?.first()?.get("ssl")?.as_bool()
}

/// The whole posture: what the role may do, how the transport is exposed, and what to do about it.
pub(crate) fn report(db: Option<&str>) -> Value {
    let mut findings: Vec<Finding> = Vec::new();
    let addr = crate::listen_addr();
    let exposed = !is_loopback(&addr);

    let facts = evaluate(db).ok();
    match &facts {
        Some(f) => {
            for problem in f.excessive() {
                findings.push(Finding {
                    id: "role.excessive",
                    severity: Severity::Critical,
                    fact: format!("the role {} {}", f.user, problem),
                    fix: Some("postgres-mcp-hardened --print-setup-sql > setup.sql".into()),
                });
            }
            if f.excessive().is_empty() {
                findings.push(Finding {
                    id: "role.reader",
                    severity: Severity::Ok,
                    fact: format!(
                        "the role {} cannot write to any of the {} tables examined",
                        f.user, f.scanned
                    ),
                    fix: None,
                });
            }
            if f.sampled {
                findings.push(Finding {
                    id: "role.sampled",
                    severity: Severity::Note,
                    fact: "the write check stopped at 5000 relations; there may be more".into(),
                    fix: None,
                });
            }
        }
        None => findings.push(Finding {
            id: "role.unknown",
            severity: Severity::Warn,
            fact: "the database has not answered, so what the role may do is unknown".into(),
            fix: None,
        }),
    }

    let authed = env_set("MCP_BEARER_TOKEN") || env_set("JWT_PUBKEY_PEM");
    if exposed && !authed {
        findings.push(Finding {
            id: "transport.anonymous",
            severity: Severity::Critical,
            fact: format!(
                "{} is reachable from the network and requires no authentication",
                addr
            ),
            fix: Some("set MCP_BEARER_TOKEN, or JWT_PUBKEY_PEM with JWT_AUD and JWT_ISS".into()),
        });
    }
    // Authentication that a client cannot discover is authentication the operator will end up
    // explaining by hand. RFC 9728 says the 401 points at the metadata document; we refuse to build
    // that pointer from the request's own Host header, because then the answer to "where do I
    // authenticate" would be chosen by whoever asked. So it needs configuring — and when it is
    // missing, that has to be visible somewhere other than a packet capture.
    if authed && !env_set("MCP_PUBLIC_URL") {
        findings.push(Finding {
            id: "auth.undiscoverable",
            // On a loopback listener this is usually a client with a hardcoded token, so it is a
            // note. Exposed, it is a warning: the people who will hit it are the ones who cannot
            // ask you how to log in.
            severity: if exposed {
                Severity::Warn
            } else {
                Severity::Note
            },
            fact: "authentication is required, but a 401 cannot tell a client where to authenticate: \
                   MCP_PUBLIC_URL is unset, so the WWW-Authenticate header degrades to a bare \"Bearer\""
                .into(),
            fix: Some("set MCP_PUBLIC_URL to the address clients reach this server on".into()),
        });
    }
    if !env_set("MCP_AUDIT_LOG") {
        findings.push(Finding {
            id: "audit.stderr_only",
            severity: Severity::Note,
            fact: "the audit goes to stderr only, so it does not survive the process".into(),
            fix: Some("set MCP_AUDIT_LOG to a file".into()),
        });
    } else if !env_set("MCP_AUDIT_HMAC_KEY") && !env_set("MCP_AUDIT_HMAC_KEY_FILE") {
        findings.push(Finding {
            id: "audit.unkeyed",
            severity: Severity::Note,
            fact: "the audit chain is hashed but not keyed: anyone who can write the file can \
                   recompute it and the result still verifies"
                .into(),
            fix: Some("set MCP_AUDIT_HMAC_KEY_FILE, with the key held off this host".into()),
        });
    }
    if validate::redaction_configured() {
        findings.push(Finding {
            id: "redaction.depth_only",
            severity: Severity::Note,
            fact: "column redaction is configured; it is defence in depth, not a boundary — the \
                   startup check reports where the role can still read those columns"
                .into(),
            fix: Some("postgres-mcp-hardened --print-setup-sql --redact <columns>".into()),
        });
    }
    match tls_fact(db) {
        Some(true) => findings.push(Finding {
            id: "tls.on",
            severity: Severity::Ok,
            fact: "the connection to PostgreSQL is encrypted (measured, not assumed)".into(),
            fix: None,
        }),
        Some(false) => findings.push(Finding {
            id: "tls.off",
            severity: if exposed {
                Severity::Warn
            } else {
                Severity::Note
            },
            fact: "the connection to PostgreSQL is NOT encrypted".into(),
            fix: Some("add ?sslmode=verify-full to the connection string".into()),
        }),
        None => {}
    }

    let worst = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Ok);
    let items: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut o = serde_json::Map::new();
            o.insert("id".into(), json!(f.id));
            o.insert(
                "severity".into(),
                json!(format!("{:?}", f.severity).to_lowercase()),
            );
            o.insert("fact".into(), json!(f.fact));
            if let Some(fix) = &f.fix {
                o.insert("fix".into(), json!(fix));
            }
            Value::Object(o)
        })
        .collect();

    json!({
        "grade": worst.grade(),
        "listening": addr,
        "exposedToNetwork": exposed,
        // "none" would be a lie behind Apify Standby, where the platform checks the caller's token
        // before we see the request — and "shared token" would be a different lie, since we hold no
        // secret. Naming the authenticator is the only honest answer, and it is the one a client
        // reading this needs: it says whose credential to present.
        "authentication": if env_set("JWT_PUBKEY_PEM") { "oauth" }
                          else if env_set("MCP_BEARER_TOKEN") { "shared token" }
                          else if platform_authenticates() { "apify-platform" }
                          else { "none" },
        "findings": items,
        "note": "The grade is the worst finding, not an average. A is: a role that cannot write, \
                 authentication where it is exposed, a keyed audit, and an encrypted connection."
    })
}

/// The MCP tool. Wrapped as untrusted output like everything else: it carries table names that came
/// from the database, and a name is content.
pub(crate) fn handle_security_posture(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let v = report(db);
    crate::audit("security_posture", "allowed", None);
    crate::wrap_untrusted(&v, "security_posture")
}

/// Two or three sentences for `initialize`, because in stdio nobody sees stderr and the agent is the
/// only messenger the operator has.
pub(crate) fn instructions() -> String {
    // `initialize` is answered without a token when OAuth is configured — that is what the protocol
    // asks for. So when the server requires authentication, this says only that a report exists:
    // otherwise anyone who can reach the port learns the role name, the grade and which tables are
    // writable, which is a map of the weaknesses drawn for the person least entitled to it.
    let authed = env_set("MCP_BEARER_TOKEN") || env_set("JWT_PUBKEY_PEM");
    if authed {
        return "This server publishes a security posture report: call the security_posture tool \
                (it needs the same credentials as any other call) for what this deployment is able \
                to do to the database, and the commands that narrow it."
            .into();
    }
    let v = report(None);
    let grade = v.get("grade").and_then(|g| g.as_str()).unwrap_or("?");
    let worst: Vec<String> = v
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter(|f| {
                    matches!(
                        f.get("severity").and_then(|s| s.as_str()),
                        Some("critical") | Some("warn")
                    )
                })
                .filter_map(|f| f.get("fact").and_then(|x| x.as_str()).map(String::from))
                .take(2)
                .collect()
        })
        .unwrap_or_default();
    let mut s = format!("Security posture of this deployment: {}.", grade);
    if !worst.is_empty() {
        s.push(' ');
        s.push_str(&worst.join("; "));
        s.push('.');
    }
    s.push_str(" Call the security_posture tool for the detail and the commands that fix it.");
    s.chars().take(600).collect()
}

/// Records the posture in the audit chain, right after the configuration record.
pub(crate) fn audit_posture() {
    let v = report(None);
    let mut extra = serde_json::Map::new();
    for k in ["grade", "authentication", "exposedToNetwork"] {
        if let Some(x) = v.get(k) {
            extra.insert(k.to_string(), x.clone());
        }
    }
    let worst: Vec<&str> = v
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("critical"))
                .filter_map(|f| f.get("id").and_then(|x| x.as_str()))
                .collect()
        })
        .unwrap_or_default();
    // Deduplicated: thirteen repetitions of role.excessive say no more than one, and a log entry
    // that scrolls is a log entry nobody reads.
    let mut uniq: Vec<&str> = worst;
    uniq.sort_unstable();
    uniq.dedup();
    extra.insert("critical".into(), json!(uniq));
    crate::audit_extra("server", "posture", None, extra);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_recognised_in_every_spelling() {
        for a in [
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
            "127.9.9.9:1",
        ] {
            assert!(is_loopback(a), "{a} should count as loopback");
        }
        for a in [
            "0.0.0.0:8080",
            "[::]:8080",
            "10.0.0.5:8080",
            "example.com:80",
        ] {
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

    /// A bounded scan may not be reported as a clean result.
    ///
    /// The write query has no `ORDER BY`, so the relations it reaches are an arbitrary subset of a
    /// large schema. Finding no writable table among them says nothing about the ones it never
    /// looked at, and a network listener may only be opened on what was actually verified.
    #[test]
    fn a_truncated_scan_is_not_a_clean_bill_of_health() {
        let truncated = RoleFacts {
            user: "app".into(),
            writable: 0,
            scanned: 5000,
            sampled: true,
            ..Default::default()
        };
        let p = truncated.excessive();
        assert_eq!(p.len(), 1, "niezmierzone musi byc nazwane: {p:?}");
        assert!(p[0].contains("did not verify"), "{p:?}");

        // A complete scan with no writable tables is still clean. Without this half the check would
        // block every honest deployment, and a check that blocks everything gets switched off.
        let complete = RoleFacts {
            user: "app".into(),
            writable: 0,
            scanned: 120,
            sampled: false,
            ..Default::default()
        };
        assert!(complete.excessive().is_empty());
    }

    /// Custom roles carry attributes too, and membership in one is a single `SET ROLE` away from
    /// holding them. Naming only the built-in roles would answer a narrower question than the one
    /// that matters: what this login can end up being able to do.
    #[test]
    fn membership_query_asks_about_custom_roles_too() {
        let q = super::MEMBERSHIPS_FOR_TEST;
        for attr in [
            "rolsuper",
            "rolbypassrls",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
        ] {
            assert!(q.contains(attr), "zapytanie nie pyta o {attr}: {q}");
        }
        assert!(
            q.contains("pg_write_all_data"),
            "wbudowane role nadal objete"
        );
        assert!(
            q.contains("rolname <> current_user"),
            "wlasna rola uzytkownika liczona osobno"
        );
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
