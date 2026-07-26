//! Which relations a query is allowed to reach.
//!
//! The reason this exists as its own module, rather than as more rules in the validator, is the
//! lesson of three adversarial rounds: reasoning about what a statement will touch by reading its
//! syntax loses to SQL. Aliases, CTEs that shadow table names, views, `search_path`, partition
//! inheritance — every one of them is a place where the text says one thing and the engine does
//! another.
//!
//! So we do not read the text. We ask PostgreSQL for the **plan** and take the relations from there.
//! The planner has already applied `search_path`, resolved every alias, expanded every view down to
//! base tables, and knows that a CTE named `customers` is not the table `customers`. That is not a
//! cleverer parser; it is the same parser the query will actually run through.
//!
//! Opt-in. With neither variable set the server behaves as before, and the role's privileges remain
//! the only limit on reach — which is why `security_posture` reports an inactive allowlist rather
//! than staying quiet about it.

use once_cell::sync::Lazy;
use serde_json::Value;

/// A pattern from the configuration: either a whole schema or one relation.
#[derive(Debug, PartialEq, Eq)]
enum Pattern {
    Schema(String),
    Relation(String, String),
}

fn parse_patterns() -> Vec<Pattern> {
    let mut out = Vec::new();
    if let Ok(v) = std::env::var("MCP_ALLOW_SCHEMAS") {
        for s in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            out.push(Pattern::Schema(s.to_lowercase()));
        }
    }
    if let Ok(v) = std::env::var("MCP_ALLOW_TABLES") {
        for t in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match t.split_once('.') {
                // `schema.*` is the same thing as naming the schema.
                Some((s, "*")) => out.push(Pattern::Schema(s.to_lowercase())),
                Some((s, r)) => out.push(Pattern::Relation(s.to_lowercase(), r.to_lowercase())),
                // An unqualified name means "in whichever schema the search path finds it", which is
                // exactly the ambiguity this feature exists to remove. Treat it as public.
                None => out.push(Pattern::Relation("public".into(), t.to_lowercase())),
            }
        }
    }
    out
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(parse_patterns);

pub(crate) fn active() -> bool {
    !PATTERNS.is_empty()
}

/// Catalogs are excluded unless asked for: with an allowlist configured, an agent that can still
/// read `pg_catalog` can enumerate everything the allowlist was meant to hide.
fn catalog_allowed() -> bool {
    std::env::var("MCP_ALLOW_CATALOG").is_ok_and(|v| v == "1" || v == "true")
}

/// Patterns passed in rather than read from the `Lazy`: a test that set the environment would pass
/// or fail depending on which test touched the static first — the same trap the redaction tests hit.
fn permitted_in(pats: &[Pattern], schema: &str, relation: &str) -> bool {
    let (s, r) = (schema.to_lowercase(), relation.to_lowercase());
    if s == "pg_catalog" || s == "information_schema" {
        return catalog_allowed();
    }
    pats.iter().any(|p| match p {
        Pattern::Schema(ps) => *ps == s,
        Pattern::Relation(ps, pr) => *ps == s && *pr == r,
    })
}

/// Every relation the plan says the query will read, as `(schema, relation)`.
///
/// `EXPLAIN (VERBOSE)` labels each scan node with `Schema` and `Relation Name`; nodes nest through
/// `Plans`, and CTEs and sub-plans hang off the top level, so the walk has to cover all of them.
pub(crate) fn relations_in_plan(plan: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<&Value> = Vec::new();
    if let Some(root) = plan.get(0).and_then(|p| p.get("Plan")) {
        stack.push(root);
    }
    // The top level also carries CTE and InitPlan trees in some shapes; sweep the whole document.
    stack.push(plan);
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                if let (Some(Value::String(s)), Some(Value::String(r))) =
                    (map.get("Schema"), map.get("Relation Name"))
                {
                    out.push((s.clone(), r.clone()));
                }
                for v in map.values() {
                    stack.push(v);
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The relations the plan touches that the operator did not allow.
///
/// A partition is allowed when its parent is: the caller asked for the table, and PostgreSQL decided
/// which children to read. Refusing them would make partitioned tables unusable for no gain, since
/// the parent is what the query names.
/// Answers "what is this relation a partition of", or `None`.
pub(crate) type ParentLookup<'f> = &'f dyn Fn(&str, &str) -> Option<(String, String)>;

pub(crate) fn refused<'a>(
    found: &'a [(String, String)],
    parents: ParentLookup<'_>,
) -> Vec<&'a (String, String)> {
    refused_in(&PATTERNS, found, parents)
}

fn refused_in<'a>(
    pats: &[Pattern],
    found: &'a [(String, String)],
    parents: ParentLookup<'_>,
) -> Vec<&'a (String, String)> {
    found
        .iter()
        .filter(|(s, r)| {
            if permitted_in(pats, s, r) {
                return false;
            }
            match parents(s, r) {
                Some((ps, pr)) => !permitted_in(pats, &ps, &pr),
                None => true,
            }
        })
        .collect()
}

/// The message a refusal carries. It names what was reached and what is configured, because an agent
/// that is told only "denied" will try the same thing with a different alias.
pub(crate) fn refusal_message(refused: &[&(String, String)]) -> String {
    let names: Vec<String> = refused
        .iter()
        .map(|(s, r)| format!("{}.{}", s, r))
        .collect();
    format!(
        "outside the configured surface: {}. This server is limited to {} — ask the operator to \
         extend MCP_ALLOW_SCHEMAS or MCP_ALLOW_TABLES if you need it",
        names.join(", "),
        describe()
    )
}

pub(crate) fn describe() -> String {
    if PATTERNS.is_empty() {
        return "everything the database role can read".into();
    }
    let mut parts: Vec<String> = PATTERNS
        .iter()
        .map(|p| match p {
            Pattern::Schema(s) => format!("{}.*", s),
            Pattern::Relation(s, r) => format!("{}.{}", s, r),
        })
        .collect();
    parts.sort();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds the pattern list directly, without touching the process environment.
    fn pats(spec: &[&str]) -> Vec<Pattern> {
        spec.iter()
            .map(|t| match t.split_once('.') {
                Some((s, "*")) => Pattern::Schema(s.to_lowercase()),
                Some((s, r)) => Pattern::Relation(s.to_lowercase(), r.to_lowercase()),
                None => Pattern::Schema(t.to_lowercase()),
            })
            .collect()
    }

    #[test]
    fn patterns_cover_schemas_relations_and_wildcards() {
        let p = pats(&["public", "analytics.events", "reporting.*"]);
        assert!(p.contains(&Pattern::Schema("public".into())));
        assert!(p.contains(&Pattern::Schema("reporting".into())));
        assert!(p.contains(&Pattern::Relation("analytics".into(), "events".into())));
    }

    /// A CTE named after a table is the shape that defeats syntax-based reasoning; the plan does not
    /// have that problem, because the planner already knows which is which. This test guards the
    /// extraction, not the planner.
    #[test]
    fn relations_come_from_every_level_of_the_plan() {
        let plan = json!([{
            "Plan": {
                "Node Type": "Aggregate",
                "Plans": [
                    { "Node Type": "Seq Scan", "Schema": "public", "Relation Name": "orders" },
                    { "Node Type": "Nested Loop", "Plans": [
                        { "Node Type": "Index Scan", "Schema": "analytics", "Relation Name": "events" }
                    ]}
                ]
            }
        }]);
        let found = relations_in_plan(&plan);
        assert_eq!(
            found,
            vec![
                ("analytics".to_string(), "events".to_string()),
                ("public".to_string(), "orders".to_string())
            ]
        );
    }

    #[test]
    fn only_what_was_named_is_permitted() {
        let p = pats(&["public", "analytics.events"]);
        assert!(permitted_in(&p, "public", "anything"));
        assert!(permitted_in(&p, "analytics", "events"));
        assert!(!permitted_in(&p, "analytics", "salaries"));
        assert!(!permitted_in(&p, "secret", "anything"));
        // The catalog is its own decision: with an allowlist on, being able to read pg_catalog
        // would let an agent enumerate exactly what the allowlist is for.
        assert!(!permitted_in(&p, "pg_catalog", "pg_class"));
    }

    #[test]
    fn a_partition_rides_on_its_parent() {
        let p = pats(&["public.events"]);
        let found = vec![("public".to_string(), "events_2026".to_string())];
        let parents = |_s: &str, _r: &str| Some(("public".to_string(), "events".to_string()));
        assert!(refused_in(&p, &found, &parents).is_empty());
        let orphan = |_s: &str, _r: &str| None;
        assert_eq!(refused_in(&p, &found, &orphan).len(), 1);
    }

    #[test]
    fn nothing_configured_means_nothing_changes() {
        std::env::remove_var("MCP_ALLOW_SCHEMAS");
        std::env::remove_var("MCP_ALLOW_TABLES");
        assert_eq!(parse_patterns().len(), 0);
    }
}
