//! The methods themselves: what each MCP call answers, and what it declines to answer.
//!
//! Every response leaves through one place, so no handler has to know which protocol revision it is
//! speaking or how a refusal is shaped this year. Tool descriptions are written for the caller that
//! actually reads them — a model choosing between eight tools with no other context — which is why
//! each one names its limits rather than leaving them to be discovered by a truncated answer.

use crate::*;

/// Reverse-DNS namespace for `_meta` keys that are ours rather than the specification's.
pub(crate) const PRIVATE_NS: &str = "io.github.eszetael.postgres-mcp-hardened";

pub(crate) fn handle_request(req: &Value) -> Value {
    // JSON-RPC version check.
    if req.get("jsonrpc") != Some(&json!("2.0")) {
        return json!({ "error": { "code": -32600, "message": "Invalid Request: jsonrpc must be 2.0" } });
    }

    // JSON-RPC 2.0 §4: an `id`, when present, "MUST contain a String, Number, or NULL value".
    // Objects, arrays and booleans are not identifiers. This server accepted all three and echoed
    // them back until 0.1.7 — harmless in itself, since the id is only mirrored, but inconsistent
    // with rejecting `jsonrpc: "1.0"` and a missing `method` two lines above. A protocol server that
    // is strict about the parts it happened to think of and lenient elsewhere is not strict, it is
    // arbitrary, and the client cannot tell which rule it is meeting.
    //
    // An ABSENT id is a notification and stays legal — that is a different thing from an invalid one.
    if let Some(id) = req.get("id") {
        if !(id.is_string() || id.is_number() || id.is_null()) {
            return json!({ "error": { "code": -32600,
                "message": "Invalid Request: id must be a string, a number or null (JSON-RPC 2.0 §4)" } });
        }
    }

    let method = match req.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return json!({ "error": { "code": -32600, "message": "Invalid Request: missing method" } })
        }
    };

    let params = req.get("params").cloned().unwrap_or(json!({}));

    // From 2026-07-28 the version is not agreed once at the start — it rides on every request, so
    // it has to be read here, before anything decides what shape the answer takes.
    // `initialize` is exempt, for the same reason the HTTP header check exempts it: the lifecycle
    // says the handshake MUST be answered with a version the server supports, not with an error, and
    // `negotiate_initialize` already does that. Refusing here would make a client that offers a
    // revision we do not enable unable to negotiate down to one we do.
    if method != "initialize" {
        if let Some(err) = protocol::unsupported_version_error(&params) {
            return err;
        }
    }
    let _meta_rev = protocol::rev_from_meta(&params).map(|r| protocol::set_request_rev(Some(r)));
    let rev = protocol::current();

    let resp = match method {
        "initialize" => handle_initialize(&params),
        // Required from 2026-07-28, and answered under every revision: a client may call it as a
        // backwards-compatibility probe, which only works if old servers answer it too.
        "server/discover" => handle_server_discover(),
        "tools/list" => handle_tools_list(),
        // SEP-1303: from 2025-11-25 a tool's refusal belongs in the result, so the model reads the
        // reason and rewrites the query, instead of the client seeing a broken call. The audit
        // record was already written by the code that refused — reshaping happens after, never
        // instead.
        "tools/call" => {
            protocol::shape_tool_result(handle_tools_call(&params), protocol::current())
        }
        // `ping` is part of MCP utilities — clients use it as a keepalive. The answer is an empty object;
        // not handling it made us look like a server that does not know the protocol.
        "ping" => json!({ "result": {} }),
        // Resources: the deprecated server we replace exposed every table schema as a resource.
        // Without them we are not a "drop-in" replacement — a client browsing the schema through resources
        // would lose that capability. Ours carry MORE: comments, primary keys and foreign keys.
        "resources/list" => handle_resources_list(),
        "resources/read" => handle_resources_read(&params),
        _ => {
            json!({ "error": { "code": -32601, "message": format!("Method not found: {}", method) } })
        }
    };
    // Applied once, at the edge, so no handler has to know which revision it is answering.
    protocol::decorate_result(resp, rev, method, &server_label())
}

/// What we are, which revisions we speak, and how safely we are connected.
///
/// The draft made this the first thing a client may ask, replacing the handshake. That makes it the
/// right place for the posture: a client can learn that this server is connected as a superuser
/// before it sends a single query — and, because it arrives as protocol data rather than prose, it
/// can act on it instead of hoping a model read the instructions.
pub(crate) fn handle_server_discover() -> Value {
    // The posture is genuinely useful here — a client can see it is talking to a superuser
    // connection before it sends a query. But this is the one method that answers without
    // credentials, so on a server that wants credentials it would be telling anyone who asks how
    // badly configured we are. When auth is on, the posture is available through the
    // `security_posture` tool, which requires a token and a scope. When auth is off there is
    // nobody to hide it from, and the whole point is that the agent tells the operator.
    let auth_on = AUTH_CONFIG.is_some()
        || std::env::var("MCP_BEARER_TOKEN").is_ok_and(|t| !t.trim().is_empty());
    let meta = if auth_on {
        json!({ format!("{}/postureAvailable", PRIVATE_NS): "call the security_posture tool with a token" })
    } else {
        // Namespaced under our own reverse-DNS: the specification reserves io.modelcontextprotocol/*
        json!({ format!("{}/securityPosture", PRIVATE_NS): posture::report(None) })
    };
    json!({
        "result": {
            "protocolVersions": protocol::Rev::supported(),
            "serverInfo": {
                "name": server_label(),
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Read-only PostgreSQL for AI agents, with the read-only part enforced before the database sees the statement."
            },
            "capabilities": { "tools": {}, "resources": {} },
            "instructions": posture::instructions(),
            "_meta": meta
        }
    })
}

pub(crate) fn handle_initialize(params: &Value) -> Value {
    // Answer with a revision this server can actually speak: the client's if we implement it, ours
    // otherwise. Announcing a constant would hand an older contract to a client that asked for a
    // newer one and could have had the better error shape.
    let rev = protocol::negotiate_initialize(params);
    json!({
        "result": {
            "protocolVersion": rev.as_str(),
            // MCP_SERVER_LABEL lets an operator running several instances tell them apart in the
            // client UI ("postgres-mcp-hardened (production)") instead of seeing identical entries.
            // The one channel that reaches the person, through the agent, on a transport where
            // stderr is invisible. Kept to a few sentences: a wall of text here is ignored.
            "instructions": posture::instructions(),
            "serverInfo": {
                "name": server_label(),
                "version": env!("CARGO_PKG_VERSION"),
                // `description` on Implementation, from 2025-11-25: a client listing several
                // servers can say what each one is without the user opening its documentation.
                "description": "Read-only PostgreSQL for AI agents, with the read-only part enforced before the database sees the statement."
            },
            "capabilities": { "tools": {}, "resources": {} }
        }
    })
}

pub(crate) fn handle_tools_list() -> Value {
    // Descriptions are written for the caller that actually reads them — a model choosing between
    // eight tools with no other context. Each says what the tool answers, what it costs, and where
    // it will disappoint: a cap that applies silently, a column that is null unless someone wrote a
    // COMMENT, an extension that has to be installed. An agent told the limit in advance does not
    // have to discover it by mistaking a truncated page for the whole table.
    let tools = vec![
        tool_def(
            "query",
            "Run SQL (read-only)",
            "Run a read-only SQL query and return rows. Writes, DDL and administrative functions are refused before the statement reaches the database. \
             At most 1000 rows come back unless you pass `limit` (server maximum 10000); `truncated: true` in the response means there is more data — \
             page through it with `offset`, and give the query an ORDER BY when you do, or the rows you get on page two depend on the planner's mood. \
             This is for reading DATA. Do not hand-write catalog queries against pg_class or information_schema: `list_schemas`, `list_tables` and \
             `describe_table` already return that, with comments and foreign keys, and they cannot be tripped up by search_path. For the plan of a \
             statement use `explain_query` rather than writing EXPLAIN yourself.",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "a single read-only statement: SELECT, WITH, VALUES, EXPLAIN or SHOW. One statement only — a semicolon-separated batch is refused before it reaches the database. Write `SELECT * FROM t`, not `TABLE t`. Writes, DDL and administrative functions are rejected at the parsed SQL, so there is no point trying them." },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 1000, "description": "maximum rows to return; larger values are capped at 10000 and the response says so" },
                    "offset": { "type": "integer", "minimum": 0, "maximum": 1000000000, "default": 0, "description": "rows to skip, for paging; pair it with ORDER BY for stable pages" }
                },
                "required": ["sql"]
            })
        ),
        tool_def(
            "list_schemas",
            "List schemas",
            "List the schemas in the database, excluding PostgreSQL's own catalogs. Start here when you do not know the layout yet. \
             Returns one row per schema with its name and comment; feed a name straight into `list_tables`. \
             It does not list tables — that is `list_tables` — and it does not read data.",
            json!({"type": "object", "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }}),
        ),
        tool_def(
            "list_tables",
            "List tables in a schema",
            "List tables, views and materialized views in one schema, with their comments. Only objects the connected role may read are shown. \
             Call `list_schemas` first if you do not know the schema name. For the columns of one table use `describe_table`; this returns names, not structure.",
            json!({
                "type": "object",
                "properties": {
                    "schema": { "type": "string", "description": "one schema name, spelled exactly as `list_schemas` returned it: case-sensitive, unquoted, no wildcards. One schema per call." },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                },
                "required": ["schema"]
            })
        ),
        tool_def(
            "describe_table",
            "Describe a table",
            "Column names, types, nullability, defaults and primary key for one table, plus each column's comment. \
             `description` is null unless somebody ran COMMENT ON — that means undocumented, not unused, so do not infer a column is dead from it.",
            json!({
                "type": "object",
                "properties": {
                    "schema": { "type": "string", "description": "the schema holding the table, as `list_schemas` or `list_tables` returned it; case-sensitive and unquoted" },
                    "table": { "type": "string", "description": "one table, view or materialized view, as `list_tables` returned it. Unqualified: put the schema in `schema`, not here — `public.orders` will not be found." },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                },
                "required": ["schema", "table"]
            })
        ),
        tool_def(
            "explain_query",
            "Explain one query",
            "Why THIS statement is slow: the PostgreSQL execution plan for a query you provide. With analyze=true it actually runs the query and reports \
             measured timings and buffer usage (still read-only, still rolled back). Use it on a specific statement you already have. \
             To find out WHICH statement is worth looking at, use `top_queries` first. If the plan shows a sequential scan you think an index would fix, \
             `simulate_index` tests that without creating one. This tool never suggests indexes itself; it only explains what the planner decided.",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "the single read-only statement to plan, written out in full — the same text you would pass to `query`. Not a statement id and not a fragment." },
                    "analyze": { "type": "boolean", "default": false, "description": "run the query and report real timings instead of estimates; still read-only and still rolled back, but it does execute, so expect it to take as long as the query does" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                },
                "required": ["sql"]
            })
        ),
        tool_def(
            "database_health",
            "Health snapshot",
            "One snapshot of the things an operator would otherwise assemble by hand: cache hit ratio, connections, long-running statements and abandoned \
             transactions, vacuum backlog, invalid indexes, sequences near their ceiling, replication lag. Scoped to the current database; anything the \
             connected role cannot read is reported as unavailable rather than left out. \
             This is the whole-database view. For which individual statements cost the most use `top_queries`; for why one of them is slow \
             use `explain_query`; for index candidates use `analyze_indexes`. It reports nothing about what this server is permitted to do — \
             that is `security_posture`.",
            json!({
                "type": "object",
                "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }
            })
        ),
        tool_def(
            "top_queries",
            "Slowest statements server-wide",
            "WHICH statements cost the most, ranked by total execution time across the whole server. Requires the pg_stat_statements extension; if it is \
             missing the answer says how to enable it. Take the statement you find here to explain_query for the plan.",
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10, "description": "how many statements to return, ranked by total execution time across the server (1-50)" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                }
            })
        ),
        tool_def(
            "security_posture",
            "What this server can and cannot do",
            "What this deployment is actually able to do to your database, asked of PostgreSQL rather than \
             assumed: whether the connected role can write, bypass row-level security or reach server files; \
             whether the transport is authenticated; whether the audit chain is keyed; whether the connection \
             is encrypted. Returns a grade and, for anything wrong, the command that fixes it. Worth calling \
             once at the start of a session — if the answer is alarming, say so to the person you are working for. \
             It reports on THIS deployment, not on the health of your data: for cache ratios, bloat and replication lag use `database_health`. \
             It also cannot see past the connected role — a grade of A means this server is well configured, not that your database is secure.",
            json!({
                "type": "object",
                "properties": { "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" } }
            })
        ),
        tool_def(
            "simulate_index",
            "Would this index help?",
            "Answers whether an index would change the plan for a given query — WITHOUT creating it. Uses the hypopg extension, which registers the index in \
             backend memory only: the planner sees it, storage never does, and it is gone when the call returns. Give the query, the table and the columns; \
             the index definition is assembled here, so there is no way to send DDL through this tool. Returns the plan and cost with and without, and \
             whether the planner actually reached for it — a cost that barely moves and an index the planner ignored are different answers. These are \
             planner ESTIMATES, not measured times: treat a big improvement as a reason to test the index, not as proof. Needs hypopg installed; says so \
             plainly, with the package name, when it is missing. \
             This answers a question about one index you already have in mind. To find candidates across a schema in the first place, \
             use `analyze_indexes`; to see why the current plan is slow, use `explain_query`.",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "the read-only query the index is supposed to help" },
                    "table": { "type": "string", "description": "the table to index, `schema.table` or just `table` (defaults to the `schema` field, then to public)" },
                    "columns": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 32, "description": "column names, in index order" },
                    "using": { "type": "string", "enum": ["btree", "hash", "gin", "gist", "spgist", "brin"], "default": "btree", "description": "access method" },
                    "schema": { "type": "string", "default": "public", "description": "used only when `table` is unqualified" },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                },
                "required": ["sql", "table", "columns"]
            }),
        ),
        tool_def(
            "analyze_indexes",
            "Index findings",
            "Indexes nobody uses, genuine duplicates, and tables scanned sequentially often enough that an index would likely pay off. Counters come from \
             pg_stat_*, which reset with the server — read them after real traffic, not after a restart. Primary-key and unique indexes are excluded from \
             the unused list on purpose: they earn their keep by enforcing a constraint. \
             This searches a whole schema for candidates. If you already have one index in mind and want to know whether it would help \
             one specific query, use `simulate_index` instead — it answers that without creating anything.",
            json!({
                "type": "object",
                "properties": {
                    "schema": { "type": "string", "default": "public", "description": "one schema to examine, as `list_schemas` returned it; defaults to public. One schema per call, so repeat for others." },
                    "database": { "type": "string", "description": "which configured database to use; omit when only one is configured" }
                }
            })
        ),
    ];
    json!({ "result": { "tools": tools } })
}

/// Why an agent needs this: without a plan it guesses why a query is slow, and its guesses are
/// confident and usually wrong. `analyze` actually executes the statement — safe here because the
/// statement is validated read-only first and runs inside the transaction we always roll back.
pub(crate) fn handle_explain_query(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let sql = match args.get("sql").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return err_content(-32602, "missing 'sql'".into()),
    };
    if let Err(e) = validate::validate_readonly(sql) {
        audit("explain_query", "denied_validation", Some(sql));
        return err_content(-32602, e.to_string());
    }
    let analyze = args
        .get("analyze")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // With `analyze` the statement REALLY RUNS, and this path had none of the protections the query
    // tool applies: no cost guard, no row limit, no byte ceiling. `EXPLAIN (ANALYZE) SELECT` over a
    // cross join executed for the whole statement_timeout and returned whatever it produced —
    // a denial of service and a way round the cost guard, available to any caller.
    //
    // Planning alone stays exempt from the COST ceiling, deliberately: "why is this query slow" is
    // the question this tool exists to answer, and refusing to plan an expensive statement refuses
    // the diagnosis. It is NOT exempt from the SURFACE — and it used to be, because both checks live
    // inside `cost_guard` and skipping the guard skipped both. Measured on PostgreSQL 16 on
    // 2026-08-08 with `MCP_ALLOW_SCHEMAS=app`: `query` refused `tajne.pensje`, `explain_query` with
    // `analyze: true` refused it, and `analyze: false` returned the plan — relation name, filter and
    // row estimate, the last of which is a value oracle for anyone willing to vary the filter. The
    // comment that used to sit here reasoned about cost and forgot the guard carries two things.
    //
    // `f64::MAX` says exactly that: enforce the surface, never refuse on price.
    let capped = match validate::enforce_limit(sql, MAX_LIMIT) {
        Ok(s) => s,
        Err(e) => {
            audit("explain_query", "denied_validation", Some(sql));
            return err_content(-32602, e.to_string());
        }
    };
    let inner = {
        if is_row_query(&capped) {
            let max_cost: f64 = if analyze {
                std::env::var("MCP_MAX_COST")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1_000_000.0)
            } else {
                f64::MAX
            };
            match cost_guard(&capped, max_cost, db) {
                Ok(()) => {}
                Err(CostErr::TooExpensive(e)) => {
                    audit("explain_query", "denied_cost", Some(sql));
                    METRICS.denied_cost.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32001, e);
                }
                Err(CostErr::OutsideSurface(e)) => {
                    audit("explain_query", "denied_surface", Some(sql));
                    METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32602, e);
                }
                Err(CostErr::QueryError(e)) => {
                    audit("explain_query", "error", Some(sql));
                    METRICS.errors.fetch_add(1, Ordering::Relaxed);
                    return err_content(-32000, e);
                }
            }
        }
        // The guard runs on the capped text because that is what `analyze` would execute. What gets
        // PLANNED without `analyze` is the caller's own statement, uncapped: a plan for a query the
        // caller did not write is a wrong answer to "why is this slow", and the added LIMIT can
        // change the plan it was asked about. The surface is unaffected by the difference — a LIMIT
        // does not change which relations the statement touches.
        if analyze {
            capped
        } else {
            sql.to_string()
        }
    };
    let opts = if analyze {
        "FORMAT JSON, ANALYZE true, BUFFERS true"
    } else {
        "FORMAT JSON"
    };
    let stmt = format!("EXPLAIN ({}) {}", opts, inner);
    match query_catalog(&stmt, &[], db) {
        Ok(mut v) => {
            audit("explain_query", "allowed", Some(sql));
            attach_plan_summary(&mut v);
            // `analyze` really runs the statement, so it runs a capped one — but until now nothing
            // said so. Measured 2026-08-08 on a 300 000-row table: `EXPLAIN ANALYZE SELECT id, h
            // FROM duza` came back with `Execution Time: 2.015` and `Actual Rows: 10000`. The
            // question asked was about 300 000 rows; the answer describes 10 000, and a caller
            // reading it concludes the query is fast. The `Limit` node is visible in the plan, which
            // is enough for a human who reads plans for a living and not enough for the audience
            // this tool is written for — our own `query` tool reports `appliedLimit` explicitly for
            // exactly that reason. A number that quietly answers a different question is the failure
            // this project exists to refuse.
            if analyze && inner != sql {
                v["analyzedStatementCapped"] = json!({
                    "appliedLimit": MAX_LIMIT,
                    "note": format!(
                        "these timings are for your statement with LIMIT {} applied, not for the \
                         statement as written — running it whole could take far longer. Ask again \
                         with analyze:false for the plan of the statement exactly as you sent it",
                        MAX_LIMIT
                    )
                });
            }
            ok_content(&v)
        }
        Err(e) => {
            audit("explain_query", "error", Some(sql));
            err_content(-32000, e)
        }
    }
}

/// A few lines of conclusion in front of the plan.
///
/// A plan for a ten-row query is eleven kilobytes of JSON across seventeen nodes, every one carrying
/// `Local Dirtied Blocks: 0`. The caller asked why the statement is slow; handing back the raw tree
/// makes that their problem, and for an agent it is also several thousand tokens per call. The tree
/// stays — this only says which node cost the most and where the planner's estimate was furthest
/// from reality, because a bad estimate is the usual reason a plan is wrong at all.
fn attach_plan_summary(v: &mut Value) {
    let Some(plan) = v
        .get("rows")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.as_object())
        .and_then(|o| o.values().next())
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .cloned()
    else {
        return;
    };
    let root = match plan.get("Plan") {
        Some(p) => p.clone(),
        None => return,
    };

    let mut slowest: Option<(String, f64)> = None;
    let mut worst_estimate: Option<(String, f64, f64)> = None;
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        let label = node
            .get("Relation Name")
            .and_then(|r| r.as_str())
            .map(|r| {
                format!(
                    "{} on {}",
                    node.get("Node Type")
                        .and_then(|n| n.as_str())
                        .unwrap_or("?"),
                    r
                )
            })
            .unwrap_or_else(|| {
                node.get("Node Type")
                    .and_then(|n| n.as_str())
                    .unwrap_or("?")
                    .to_string()
            });

        // Self time, not inclusive time: an inclusive figure always names the root and tells nobody
        // anything.
        if let Some(total) = node.get("Actual Total Time").and_then(|t| t.as_f64()) {
            let children: f64 = node
                .get("Plans")
                .and_then(|p| p.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.get("Actual Total Time").and_then(|t| t.as_f64()))
                        .sum()
                })
                .unwrap_or(0.0);
            let self_ms = (total - children).max(0.0);
            if slowest.as_ref().is_none_or(|(_, s)| self_ms > *s) {
                slowest = Some((label.clone(), self_ms));
            }
        }
        if let (Some(est), Some(act)) = (
            node.get("Plan Rows").and_then(|r| r.as_f64()),
            node.get("Actual Rows").and_then(|r| r.as_f64()),
        ) {
            let off = (est.max(1.0) / act.max(1.0)).max(act.max(1.0) / est.max(1.0));
            if worst_estimate.as_ref().is_none_or(|(_, e, a)| {
                off > (e.max(1.0) / a.max(1.0)).max(a.max(1.0) / e.max(1.0))
            }) {
                worst_estimate = Some((label, est, act));
            }
        }
        if let Some(children) = node.get("Plans").and_then(|p| p.as_array()) {
            stack.extend(children.iter().cloned());
        }
    }

    let mut summary = serde_json::Map::new();
    for (field, key) in [
        ("execution_ms", "Execution Time"),
        ("planning_ms", "Planning Time"),
    ] {
        if let Some(t) = plan.get(key).and_then(|t| t.as_f64()) {
            summary.insert(field.into(), json!((t * 100.0).round() / 100.0));
        }
    }
    if let Some((label, ms)) = slowest {
        summary.insert(
            "most_time_in".into(),
            json!({ "node": label, "self_ms": (ms * 100.0).round() / 100.0 }),
        );
    }
    if let Some((label, est, act)) = worst_estimate {
        let off = (est.max(1.0) / act.max(1.0)).max(act.max(1.0) / est.max(1.0));
        summary.insert(
            "worst_row_estimate".into(),
            json!({ "node": label, "estimated": est, "actual": act, "off_by": (off * 10.0).round() / 10.0 }),
        );
        if off >= 10.0 {
            summary.insert(
                "note".into(),
                json!("the planner's row estimate is off by an order of magnitude here — usually stale \
                       or missing statistics; run ANALYZE on the tables involved and read the plan again"),
            );
        }
    }
    if !summary.is_empty() {
        v["summary"] = Value::Object(summary);
    }
}

/// A health snapshot an operator would otherwise assemble by hand from half a dozen catalog views.
/// Every check degrades gracefully: a role that cannot read a view yields a note, not a failure.
pub(crate) fn handle_database_health(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    // Every query here is scoped to the CURRENT DATABASE and filtered by the caller's table
    // privileges. Both were missing and both produced confident nonsense: `pg_stat_activity` spans
    // the whole cluster, so a fresh database with two connections reported nineteen; and the catalog
    // views happily describe tables the role cannot read, so a restricted role could enumerate
    // index and table names it has no access to.
    const CHECKS: &[(&str, &str)] = &[
        (
            "cache_hit_ratio",
            "SELECT round(100.0 * (t.hit + x.hit) / NULLIF(t.hit + t.read + x.hit + x.read, 0), 2) AS pct_from_cache, \
                    t.hit + t.read + x.hit + x.read AS blocks_sampled, \
                    round(100.0 * t.hit / NULLIF(t.hit + t.read, 0), 2) AS pct_tables, \
                    round(100.0 * x.hit / NULLIF(x.hit + x.read, 0), 2) AS pct_indexes, \
                    CASE WHEN COALESCE(t.hit + t.read + x.hit + x.read, 0) = 0 \
                         THEN 'no I/O recorded yet — statistics reset with the server' END AS note \
             FROM (SELECT COALESCE(sum(heap_blks_hit), 0) AS hit, COALESCE(sum(heap_blks_read), 0) AS read \
                     FROM pg_statio_user_tables WHERE has_table_privilege(relid, 'SELECT')) t, \
                  (SELECT COALESCE(sum(idx_blks_hit), 0) AS hit, COALESCE(sum(idx_blks_read), 0) AS read \
                     FROM pg_statio_user_indexes WHERE has_table_privilege(relid, 'SELECT')) x",
        ),
        (
            "connections",
            "SELECT count(*) FILTER (WHERE datname = current_database()) AS in_use, \
                    count(*) AS in_use_cluster_wide, \
                    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections, \
                    count(*) FILTER (WHERE datname = current_database() AND state = 'idle in transaction') AS idle_in_transaction, \
                    count(*) FILTER (WHERE state IS NULL AND pid <> pg_backend_pid() \
                                     AND (backend_type IS NULL OR backend_type = 'client backend')) AS backends_not_visible \
             FROM pg_stat_activity",
        ),
        (
            // Active queries and idle-in-transaction sessions are reported separately, because
            // `query_start` on an idle session marks when its LAST query ended: counted together,
            // a connection abandoned for three hours reads as a three-hour running query and hides
            // the actual diagnosis. Split apart, the second figure names the leak.
            "longest_running",
            "SELECT round(EXTRACT(epoch FROM max(now() - query_start) FILTER (WHERE state = 'active'))::numeric, 1) AS longest_active_query_seconds, \
                    round(EXTRACT(epoch FROM max(now() - xact_start))::numeric, 1) AS longest_transaction_seconds, \
                    round(EXTRACT(epoch FROM max(now() - state_change) FILTER (WHERE state = 'idle in transaction'))::numeric, 1) AS longest_idle_in_transaction_seconds, \
                    CASE WHEN count(*) FILTER (WHERE state IS NULL AND pid <> pg_backend_pid() \
                                                AND (backend_type IS NULL OR backend_type = 'client backend')) > 0 \
                         THEN 'this role cannot see other backends (grant pg_read_all_stats or pg_monitor); the count \
                               includes PostgreSQL background processes, and the figures above describe only what this \
                               role can see — a zero here does NOT mean the database is idle' \
                         END AS note \
             FROM pg_stat_activity WHERE datname = current_database()",
        ),
        (
            "vacuum_backlog",
            "SELECT relname AS table_name, n_dead_tup AS dead_rows, n_live_tup AS live_rows, last_autovacuum, \
                    count(*) OVER () AS matching_total \
             FROM pg_stat_user_tables WHERE n_dead_tup > 1000 AND has_table_privilege(relid, 'SELECT') \
             ORDER BY n_dead_tup DESC LIMIT 10",
        ),
        (
            "invalid_indexes",
            "SELECT c.relname AS index_name, t.relname AS table_name \
             FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
             WHERE NOT i.indisvalid AND has_table_privilege(i.indrelid, 'SELECT')",
        ),
        (
            "sequences_near_limit",
            "SELECT schemaname || '.' || sequencename AS sequence, last_value, max_value, \
                    round(100.0 * last_value / NULLIF(max_value, 0), 2) AS pct_used, \
                    count(*) OVER () AS matching_total \
             FROM pg_sequences WHERE last_value IS NOT NULL \
               AND 100.0 * last_value / NULLIF(max_value, 0) > 50 ORDER BY 4 DESC LIMIT 10",
        ),
        (
            // Without this, a sequence at 95% of its ceiling was indistinguishable from no risk at
            // all: PostgreSQL returns last_value as NULL when the role lacks USAGE/SELECT, the filter
            // above drops the row, and an empty list reads as "nothing to worry about".
            // last_value is NULL for two unrelated reasons — no privilege, or never used. Reporting
            // both as "cannot read" sent a superuser hunting for a permission problem that did not
            // exist: a lie in the opposite direction, with instructions attached.
            "sequences_unreadable",
            "SELECT count(*) AS count, \
                    'this role cannot read these sequences (needs USAGE or SELECT); their headroom was NOT checked' AS note \
             FROM pg_sequences WHERE last_value IS NULL \
               AND NOT has_sequence_privilege(quote_ident(schemaname) || '.' || quote_ident(sequencename), 'SELECT,USAGE') \
             HAVING count(*) > 0",
        ),
        (
            // The check that was missing entirely. A database whose tables have never been analysed
            // has no planner statistics at all — the usual reason "everything looks healthy" and the
            // queries are still slow. vacuum_backlog cannot see it: n_dead_tup is 0 precisely because
            // nothing has collected statistics.
            "tables_never_analyzed",
            "SELECT relname AS table_name, n_live_tup AS estimated_rows, \
                    pg_size_pretty(pg_relation_size(relid)) AS size, \
                    count(*) OVER () AS matching_total \
             FROM pg_stat_user_tables \
             WHERE has_table_privilege(relid, 'SELECT') \
               AND last_analyze IS NULL AND last_autoanalyze IS NULL \
             ORDER BY pg_relation_size(relid) DESC LIMIT 10",
        ),
        (
            // Every counter above is meaningless without the window it was collected over.
            "statistics_window",
            "SELECT stats_reset AS counters_since, \
                    CASE WHEN stats_reset IS NULL \
                         THEN 'counters have never been reset — they cover the whole life of this database' \
                         END AS note \
             FROM pg_stat_database WHERE datname = current_database()",
        ),
        (
            "replication",
            "SELECT pg_is_in_recovery() AS is_standby, \
                    CASE WHEN pg_is_in_recovery() \
                         THEN round(EXTRACT(epoch FROM now() - pg_last_xact_replay_timestamp())::numeric, 1) \
                         END AS replay_lag_seconds",
        ),
    ];
    let mut out = serde_json::Map::new();
    for (name, sql) in CHECKS {
        match query_catalog(sql, &[], db) {
            Ok(v) => {
                out.insert(
                    (*name).to_string(),
                    v.get("rows").cloned().unwrap_or(Value::Null),
                );
            }
            // Not fatal: a least-privilege role legitimately cannot see some of these.
            Err(e) => {
                out.insert((*name).to_string(), json!({ "unavailable": e }));
            }
        }
    }
    audit("database_health", "allowed", None);
    ok_content(&Value::Object(out))
}

/// The heaviest statements, from pg_stat_statements. When the extension is absent we say so and
/// how to enable it — a missing extension is a setup fact, not an error the agent should retry.
pub(crate) fn handle_top_queries(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(50) as i64;
    let sql = format!(
        "SELECT calls, round(total_exec_time::numeric, 1) AS total_ms,                 round(mean_exec_time::numeric, 2) AS mean_ms, rows,                 left(query, 300) AS query, count(*) OVER () AS matching_total          FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT {}",
        limit
    );
    match query_catalog(&sql, &[], db) {
        Ok(v) => {
            audit("top_queries", "allowed", None);
            ok_content(&v)
        }
        Err(e) => {
            audit("top_queries", "error", None);
            // Two different setup states, two different next steps. Conflating them sent people to
            // run CREATE EXTENSION again when what they actually needed was a server restart.
            if e.contains("55000") || e.contains("must be loaded") {
                err_content(
                    -32000,
                    "pg_stat_statements is installed but not loaded — add it to shared_preload_libraries and RESTART PostgreSQL (CREATE EXTENSION alone is not enough)"
                        .into(),
                )
            } else if e.contains("does not exist") || e.contains("42P01") {
                err_content(
                    -32000,
                    "pg_stat_statements is not enabled on this server — add it to shared_preload_libraries and run CREATE EXTENSION pg_stat_statements"
                        .into(),
                )
            } else {
                err_content(-32000, e)
            }
        }
    }
}

/// Index findings that are cheap to compute and expensive to notice by hand: indexes nobody uses,
/// duplicates, and tables scanned sequentially often enough that an index would likely pay off.
/// "Would this index help?" — answered without creating one.
///
/// The argument shape is deliberate: a table name, a list of columns, an access method from a fixed
/// list. NOT a CREATE INDEX statement. A tool that accepted DDL from a model would be a tool that
/// accepts DDL from a model, whatever it promised to do with it.
pub(crate) fn handle_simulate_index(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let sql = match args.get("sql").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return err_content(
                -32602,
                "missing 'sql': the query the index is meant to help".into(),
            )
        }
    };
    if let Err(e) = validate::validate_readonly(sql) {
        audit("simulate_index", "denied_validation", Some(sql));
        return err_content(-32602, e.to_string());
    }
    let table = match args.get("table").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return err_content(-32602, "missing 'table'".into()),
    };
    // `public.orders` in one field is what a model will send, so accept it rather than making the
    // caller guess which field the schema belongs in.
    let (schema, table) = match table.split_once('.') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => (
            args.get("schema")
                .and_then(|v| v.as_str())
                .unwrap_or("public")
                .to_string(),
            table.to_string(),
        ),
    };
    let columns: Vec<String> = match args.get("columns").and_then(|v| v.as_array()) {
        Some(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        None => {
            return err_content(
                -32602,
                "missing 'columns' (an array of column names)".into(),
            )
        }
    };
    let method = args
        .get("using")
        .and_then(|v| v.as_str())
        .unwrap_or("btree")
        .to_lowercase();

    // The surface allowlist. `simulate_index` planned the caller's query on its own connection, so
    // it never reached `cost_guard` — and a plan is exactly what the allowlist exists to withhold:
    // it names the table, its columns, the filter and the planner's row estimates, and repeated with
    // different constants those estimates are an oracle for values nobody was allowed to read. The
    // same hole was found and closed for EXPLAIN once already; a new tool reopened it.
    if surface::active() {
        match cost_guard(sql, f64::MAX, db) {
            Ok(()) => {}
            Err(CostErr::OutsideSurface(e)) => {
                audit("simulate_index", "denied_surface", Some(sql));
                METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                return err_content(-32602, e);
            }
            Err(CostErr::QueryError(e)) | Err(CostErr::TooExpensive(e)) => {
                audit("simulate_index", "error", Some(sql));
                return err_content(-32000, e);
            }
        }
        // And the table we have been asked to index, separately: whether the catalogue lookup
        // succeeds or reports "no such table" is itself an answer about a table outside the surface.
        let asked = vec![(schema.clone(), table.clone())];
        let refused = surface::refused(&asked, &|_, _| None);
        if !refused.is_empty() {
            audit("simulate_index", "denied_surface", Some(sql));
            METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
            return err_content(-32602, surface::refusal_message(&refused));
        }
    }

    match db::simulate_index(sql, &schema, &table, &columns, &method, db) {
        Ok(v) => {
            audit("simulate_index", "allowed", Some(sql));
            ok_content(&v)
        }
        Err(e) => {
            audit("simulate_index", "error", Some(sql));
            err_content(-32000, e)
        }
    }
}

pub(crate) fn handle_analyze_indexes(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let schema = args
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    // `supports_foreign_key` is the context that decides whether "unused" means "droppable".
    // idx_scan does not count the lookups a foreign-key check performs, so an index backing an FK can
    // sit at zero scans for the life of the database and still be the only thing keeping DELETE on the
    // parent table off a sequential scan. Without this the tool named indexes it was not safe to drop.
    //
    // `matching_total` exists because the list is capped at 20: a caller asking "which indexes are
    // unused" was handed 20 of 29 with nothing to indicate the rest — the same silent truncation this
    // server refuses to commit anywhere else.
    const UNUSED: &str =
        "SELECT s.relname AS table_name, s.indexrelname AS index_name, s.idx_scan AS scans, \
                pg_size_pretty(pg_relation_size(s.indexrelid)) AS size, \
                EXISTS (SELECT 1 FROM pg_constraint con \
                         WHERE con.contype = 'f' AND con.conrelid = s.relid \
                           AND con.conkey[1] = i.indkey[0]) AS supports_foreign_key, \
                count(*) OVER () AS matching_total \
         FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid \
         WHERE s.schemaname = $1 AND s.idx_scan = 0 AND NOT i.indisprimary AND NOT i.indisunique \
           AND has_table_privilege(s.relid, 'SELECT') \
         ORDER BY pg_relation_size(s.indexrelid) DESC LIMIT 20";
    // Grouping on `indpred IS NULL` would ask whether an index is partial but not WHICH rows it
    // covers, so `WHERE active` and `WHERE NOT active` — indexing disjoint sets — would be reported
    // as duplicates. Ignoring `indisunique` would put a UNIQUE index in a cluster with ordinary
    // ones, where "drop the redundant copy" could remove the only thing enforcing uniqueness.
    // The grouping key has to be everything that makes two indexes interchangeable. Adding the
    // predicate was not enough: expression indexes all share indkey='0', so `lower(a)` and `upper(b)`
    // grouped together and the tool advised dropping a working index. Sort order (indoption) and
    // collation belong there for the same reason.
    //
    // Uniqueness is REPORTED, not grouped on. Grouping by it removed the most common real duplicate
    // in production — an ordinary index sitting next to an existing UNIQUE on the same column — which
    // is exactly the one worth dropping. The unique index is listed first and marked, so the answer
    // says which of the pair earns its keep instead of hiding the pair.
    const DUPLICATES: &str =
        // array_to_string, not array_agg: an array column comes back as null through the driver.
        "SELECT t.relname AS table_name, \
                array_to_string(array_agg(c.relname || CASE WHEN i.indisunique THEN ' [unique — keep this one]' ELSE '' END \
                                          ORDER BY i.indisunique DESC, c.relname), ', ') AS duplicate_indexes, \
                count(*) FILTER (WHERE i.indisunique) AS unique_in_group, \
                pg_size_pretty(sum(pg_relation_size(c.oid))) AS combined_size, count(*) OVER () AS matching_total \
         FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid \
              JOIN pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = $1 AND has_table_privilege(i.indrelid, 'SELECT') \
         GROUP BY t.relname, i.indrelid, i.indkey::text, i.indclass::text, i.indoption::text, \
                  i.indcollation::text, \
                  COALESCE(pg_get_expr(i.indexprs, i.indrelid), ''), \
                  COALESCE(pg_get_expr(i.indpred, i.indrelid), '') \
         HAVING count(*) > 1 ORDER BY sum(pg_relation_size(c.oid)) DESC LIMIT 20";
    const SEQ_SCANS: &str =
        "SELECT relname AS table_name, seq_scan, idx_scan, n_live_tup AS rows, \
                pg_size_pretty(pg_relation_size(relid)) AS size, count(*) OVER () AS matching_total \
         FROM pg_stat_user_tables WHERE schemaname = $1 AND seq_scan > COALESCE(idx_scan, 0) \
           AND n_live_tup > 10000 AND has_table_privilege(relid, 'SELECT') \
         ORDER BY seq_scan DESC LIMIT 10";
    if let Some(e) = schema_missing(schema, db) {
        audit("analyze_indexes", "error", None);
        return e;
    }
    let mut out = serde_json::Map::new();
    for (name, sql) in [
        ("unused_indexes", UNUSED),
        ("duplicate_indexes", DUPLICATES),
        ("tables_scanned_sequentially", SEQ_SCANS),
    ] {
        match query_catalog(sql, &[&schema], db) {
            Ok(v) => {
                out.insert(
                    name.to_string(),
                    v.get("rows").cloned().unwrap_or(Value::Null),
                );
            }
            Err(e) => {
                out.insert(name.to_string(), json!({ "unavailable": e }));
            }
        }
    }
    out.insert(
        "note".to_string(),
        Value::String(
            "Counters come from pg_stat_*, which reset with the server and start empty; read them \
             after a representative period of traffic, not straight after a restart. \
             unused_indexes deliberately omits primary-key and unique indexes: they earn their keep by \
             enforcing a constraint, so a scan count of zero does not make them removable."
                .into(),
        ),
    );
    audit("analyze_indexes", "allowed", None);
    ok_content(&Value::Object(out))
}

/// `title` is what a user sees in a client's tool list; `name` is what the model calls. Both matter:
/// agents pick tools from the description, humans approve them from the title.
///
/// The annotations are the full set from the 2025-06-18 specification rather than `readOnlyHint`
/// alone. `openWorldHint: false` because the domain is closed — the configured databases and nothing
/// else; `idempotentHint: true` because a repeated call changes nothing (the DATA may have changed
/// underneath, which is a different property and not what this hint describes).
pub(crate) fn tool_def(name: &str, title: &str, desc: &str, input_schema: Value) -> Value {
    // MCP schemas are JSON Schema 2020-12. Saying which dialect a schema is written in is not
    // decoration: a validator that guesses will guess wrong on the keywords that differ between
    // drafts, and the caller reading our schema is a machine choosing how to build the call.
    let mut input_schema = input_schema;
    if let Some(obj) = input_schema.as_object_mut() {
        obj.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
    }
    json!({
        "name": name,
        "title": title,
        "description": desc,
        "inputSchema": input_schema,
        "annotations": {
            "title": title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

pub(crate) fn handle_tools_call(params: &Value) -> Value {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({ "error": { "code": -32602, "message": "Missing tool name" } }),
    };

    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "query" => handle_query_tool(&args),
        "list_schemas" => handle_list_schemas(&args),
        "list_tables" => handle_list_tables(&args),
        "describe_table" => handle_describe_table(&args),
        "explain_query" => handle_explain_query(&args),
        "database_health" => handle_database_health(&args),
        "top_queries" => handle_top_queries(&args),
        "analyze_indexes" => handle_analyze_indexes(&args),
        "simulate_index" => handle_simulate_index(&args),
        "security_posture" => posture::handle_security_posture(&args),
        _ => json!({ "error": { "code": -32601, "message": format!("Unknown tool: {}", name) } }),
    }
}

pub(crate) fn handle_query_tool(args: &Value) -> Value {
    let db = args.get("database").and_then(|v| v.as_str());
    let sql = match args.get("sql").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return json!({ "error": { "code": -32602, "message": "Missing 'sql' argument" } }),
    };

    // 1. Read-only validation.
    if let Err(e) = validate::validate_readonly(sql) {
        audit("query", "denied_validation", Some(sql));
        METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
        return json!({ "error": { "code": -32602, "message": e.to_string() } });
    }

    // 2. Limit (1000 by default). We ask the database for ONE row MORE than we return — the extra row
    //    is proof that the data was cut, so we can TELL the agent instead of quietly presenting a
    //    fragment as the whole (`returnedRows: 1000` was indistinguishable from a complete result).
    let requested_limit = args.get("limit").and_then(|v| v.as_u64());
    let limit = requested_limit.unwrap_or(1000).min(MAX_LIMIT);
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
    let final_sql = match validate::enforce_limit_offset(sql, limit.saturating_add(1), offset) {
        Ok(s) => s,
        Err(e) => return json!({ "error": { "code": -32602, "message": e.to_string() } }),
    };

    // cost guard only for queries EXPLAIN can plan (SELECT/WITH/VALUES/TABLE); EXPLAIN/SHOW are
    // skipped (you cannot EXPLAIN an EXPLAIN — statement_timeout is the backstop there).
    // EXPLAIN skips the cost guard (you cannot plan a plan), and the surface check lived inside it —
    // so `EXPLAIN VERBOSE SELECT ... FROM elsewhere` reported the table's existence, its columns, the
    // filter and the planner's row estimates, all from outside the configured surface. Row estimates
    // are an oracle: repeated with different constants they leak values, without ever running.
    if surface::active() && !is_row_query(&final_sql) {
        if let Some(inner) = validate::explained_statement(&final_sql) {
            let max_cost = f64::MAX; // the surface is the question here, not the cost
            match cost_guard(&inner, max_cost, db) {
                Ok(()) => {}
                Err(CostErr::OutsideSurface(e)) => {
                    audit("query", "denied_surface", Some(sql));
                    METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                    return json!({ "error": { "code": -32602, "message": e } });
                }
                // A plan we cannot obtain is not permission to proceed.
                Err(CostErr::QueryError(e)) | Err(CostErr::TooExpensive(e)) => {
                    audit("query", "error", Some(sql));
                    return json!({ "error": { "code": -32000, "message": e } });
                }
            }
        }
    }
    if is_row_query(&final_sql) {
        let max_cost: f64 = std::env::var("MCP_MAX_COST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1_000_000.0);
        match cost_guard(&final_sql, max_cost, db) {
            Ok(()) => {}
            Err(CostErr::TooExpensive(e)) => {
                audit("query", "denied_cost", Some(sql));
                METRICS.denied_cost.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32001, "message": e } });
            }
            Err(CostErr::OutsideSurface(e)) => {
                // Its own decision in the log: "reached somewhere it should not" is a different
                // event from "asked for too much", and an operator reviewing the chain wants to
                // tell them apart.
                audit("query", "denied_surface", Some(sql));
                METRICS.denied_validation.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32602, "message": e } });
            }
            Err(CostErr::QueryError(e)) => {
                // an error in the query itself (a missing column) — NOT denied_cost; an ordinary error. Audited.
                audit("query", "error", Some(sql));
                METRICS.errors.fetch_add(1, Ordering::Relaxed);
                return json!({ "error": { "code": -32000, "message": e } });
            }
        }
    }
    match execute_readonly(&final_sql, db) {
        Ok(mut data) => {
            mark_truncation(&mut data, limit);
            // Say what was actually applied. A request for 50000 rows silently became 10000, and the
            // response looked identical to one that had asked for 10000 — the agent had no way to
            // tell a server cap from the end of the data.
            if requested_limit.is_some_and(|r| r > MAX_LIMIT) {
                data["requestedLimit"] = json!(requested_limit);
                data["limitNote"] = json!(format!(
                    "requested limit exceeds the server maximum of {}; {} was applied",
                    MAX_LIMIT, limit
                ));
            }
            if offset > 0 {
                data["offset"] = json!(offset);
                // The description says to add ORDER BY; the loop that pages through a table reads the
                // response, not the description. Without an ordering PostgreSQL may return the same
                // row twice across pages and never return another, and nothing in the result would
                // show it.
                if !sql.to_uppercase().contains("ORDER BY") {
                    data["pagingNote"] = json!(
                        "this query has no ORDER BY, so page boundaries are not stable — rows may \
                         repeat or be skipped between pages"
                    );
                }
            }
            audit("query", "allowed", Some(sql));
            METRICS.query_allowed.fetch_add(1, Ordering::Relaxed);
            wrap_untrusted(&data, "query")
        }
        Err(e) => {
            audit("query", "error", Some(sql));
            METRICS.errors.fetch_add(1, Ordering::Relaxed);
            json!({ "error": { "code": -32000, "message": e } })
        }
    }
}

/// Trims the result to `limit` and states plainly whether anything was cut.
///
/// The query went to the database with `LIMIT limit+1`; an extra row means there is more data. An
/// AI agent draws conclusions from what it received — "1000 rows" without a note that this is the
/// first thousand of sixteen is a quiet untruth, even when every value in it is correct.
pub(crate) fn mark_truncation(data: &mut Value, limit: u64) {
    let n = data
        .get("rows")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as u64;
    let truncated = n > limit;
    if truncated {
        if let Some(arr) = data.get_mut("rows").and_then(|r| r.as_array_mut()) {
            arr.truncate(limit as usize);
        }
        data["returnedRows"] = json!(limit);
    }
    data["truncated"] = json!(truncated);
    data["appliedLimit"] = json!(limit);
}

#[cfg(test)]
mod tool_surface_tests {
    use super::*;

    fn tools() -> Vec<Value> {
        handle_tools_list()["result"]["tools"]
            .as_array()
            .expect("tools/list returns an array")
            .clone()
    }

    /// Every parameter of every tool must carry a description.
    ///
    /// This is not decoration. The description is what an agent reads when it decides how to fill
    /// the field, and a bare `{"type": "string"}` tells it nothing about where the value comes
    /// from — which is why `describe_table` used to be called with `public.orders` in `table`.
    /// An external review of the tool surface in August 2026 scored the four tools with undescribed
    /// parameters lowest of the ten, every time for the same reason.
    ///
    /// It is a test rather than a habit because the gap appeared by accretion: descriptions were
    /// added where somebody happened to think of it, and nothing noticed the ones nobody did.
    #[test]
    fn every_tool_parameter_is_described() {
        let mut missing = Vec::new();
        for t in tools() {
            let name = t["name"].as_str().unwrap_or("?").to_string();
            let Some(props) = t["inputSchema"]["properties"].as_object() else {
                continue;
            };
            for (param, spec) in props {
                let described = spec
                    .get("description")
                    .and_then(|d| d.as_str())
                    .is_some_and(|d| d.trim().len() > 10);
                if !described {
                    missing.push(format!("{}.{}", name, param));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "these tool parameters have no usable description: {:?}",
            missing
        );
    }

    /// A tool that never mentions another tool leaves the agent to guess which of ten to reach for.
    ///
    /// The same review marked every one of our best-scoring tools down for exactly this: they said
    /// what they do and never what to use instead. Naming a sibling is the cheapest way to stop an
    /// agent using `database_health` when it wanted `top_queries`.
    #[test]
    fn every_tool_points_at_a_sibling() {
        let names: Vec<String> = tools()
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect();
        let mut lonely = Vec::new();
        for t in tools() {
            let me = t["name"].as_str().unwrap_or_default().to_string();
            let text = format!(
                "{} {}",
                t["description"].as_str().unwrap_or_default(),
                t["inputSchema"]
            );
            if !names.iter().any(|o| *o != me && text.contains(o.as_str())) {
                lonely.push(me);
            }
        }
        assert!(
            lonely.is_empty(),
            "these tools never name another tool, so an agent cannot tell when to use something else: {:?}",
            lonely
        );
    }
}

#[cfg(test)]
mod jsonrpc_id_tests {
    use super::*;

    fn code(req: Value) -> Option<i64> {
        handle_request(&req)
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64())
    }

    /// JSON-RPC 2.0 §4. Accepted and echoed back until 0.1.7.
    #[test]
    fn an_id_that_is_not_a_string_number_or_null_is_an_invalid_request() {
        for id in [json!({"a": 1}), json!([1, 2]), json!(true), json!(false)] {
            let req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"});
            assert_eq!(code(req), Some(-32600), "id {id} should be refused");
        }
    }

    /// The legal shapes stay legal, and an absent id is a notification rather than a bad one.
    #[test]
    fn strings_numbers_null_and_absence_are_all_fine() {
        for req in [
            json!({"jsonrpc": "2.0", "id": "abc", "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": -1, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 1.5, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": null, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "method": "tools/list"}),
        ] {
            assert_ne!(
                code(req.clone()),
                Some(-32600),
                "{req} should not be refused for its id"
            );
        }
    }
}
