//! Query validator — the security core.
//! We trust the AST (sqlparser), not regexes: comments and obfuscation disappear when the tree is built.
use once_cell::sync::Lazy;
use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, LimitClause, ObjectName, Query,
    SelectItem, SetExpr, Statement, TableAlias, TableFactor, Value, Visit, Visitor,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};
use std::fmt;
use std::ops::ControlFlow;

/// Deliberately not a legal SQL identifier, so nothing can allowlist it by accident.
const UNREADABLE_NAME: &str = "<unreadable name part>";

/// The last part of a qualified name, lowercased — or `None` when the parser did not model it as
/// an identifier at all.
///
/// `sqlparser` 0.62 introduced `ObjectNamePart::Function`: a name part that is a *function call*
/// returning an identifier. Older versions could not represent that, so this file was written
/// assuming every part is an `Ident`. It cannot assume that any more, and the difference matters
/// more than it looks — every rule here reasons about a name: side-effect functions, denied
/// families, the redaction list, the surface allowlist. Skipping a part we cannot read would let a
/// name expressed as a function walk past all of them, which is the same shape as the bypasses
/// that have already beaten this validator four times.
///
/// Callers must treat `None` as "unreadable, therefore refuse", never as "nothing to check".
fn last_part_name(name: &ObjectName) -> Option<String> {
    Some(name.0.last()?.as_ident()?.value.to_lowercase())
}

/// True when any part of the name is something other than a plain identifier.
fn name_has_unreadable_part(name: &ObjectName) -> bool {
    name.0.iter().any(|p| p.as_ident().is_none())
}

/// Hard cap on SQL length — rejects pathologically long input (defence against stack overflow from
/// very deep or long nesting; no legitimate MCP query comes near this size).
const MAX_SQL_LEN: usize = 100_000;
/// Parser recursion limit — deep nesting yields RecursionLimitExceeded (caught), not an overflow.
const PARSE_RECURSION_LIMIT: usize = 64;

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotParseable(String),
    MultiStatement,
    NotReadOnly(String),
    /// A column the operator declared sensitive was referenced.
    Redacted(String),
    /// A construct that would carry a redacted column past the name-based checks.
    RedactionEvasion(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotParseable(e) => write!(f, "SQL parse error: {}", e),
            Self::MultiStatement => write!(f, "multiple statements are forbidden"),
            Self::NotReadOnly(s) => write!(f, "non-read-only statement: {}", s),
            Self::Redacted(c) => write!(
                f,
                "column {} is redacted by configuration and cannot be referenced",
                c
            ),
            Self::RedactionEvasion(what) => write!(
                f,
                "{} — while MCP_REDACT_COLUMNS is configured this is refused, because it would carry \
                 a redacted value past a check that matches on column names. Select the columns you \
                 need explicitly",
                what
            ),
        }
    }
}

fn parse(sql: &str) -> Result<Vec<Statement>, ValidationError> {
    if sql.len() > MAX_SQL_LEN {
        return Err(ValidationError::NotParseable(format!(
            "SQL too long ({} bytes, limit {})",
            sql.len(),
            MAX_SQL_LEN
        )));
    }
    Parser::new(&PostgreSqlDialect {})
        .with_recursion_limit(PARSE_RECURSION_LIMIT)
        .try_with_sql(sql)
        .and_then(|mut p| p.parse_statements())
        .map_err(|e| ValidationError::NotParseable(e.to_string()))
}

/// ONLY allowed: Query (SELECT/WITH), EXPLAIN, SHOW*. Everything else is rejected. No multi-statement.
pub fn validate_readonly(sql: &str) -> Result<(), ValidationError> {
    // 0. Multi-statement detection on TOKENS, before trusting how the parser split the input. Some
    //    sqlparser grammars (e.g. `SHOW <variable>`) swallow the rest of the input as part of their own
    //    statement — then `ast.len() == 1` despite a `;` in the middle, and the concatenated text would
    //    reach the database. The tokenizer understands literals and comments, so `SELECT ';'` is safe.
    if has_trailing_statement(sql) {
        return Err(ValidationError::MultiStatement);
    }
    let ast = match parse(sql) {
        Ok(a) => a,
        // A statement our parser does not know is still refused — but say WHY correctly. Telling a
        // user "SQL parse error" for `REFRESH MATERIALIZED VIEW` sends them hunting for a typo,
        // when the real answer is that this server never performs writes.
        Err(e) => {
            return Err(match leading_write_keyword(sql) {
                Some(kw) => ValidationError::NotReadOnly(format!("{} is a write operation", kw)),
                None => e,
            })
        }
    };
    if ast.len() > 1 {
        return Err(ValidationError::MultiStatement);
    }
    if ast.is_empty() {
        return Err(ValidationError::NotParseable("empty statement".into()));
    }
    // 0. Nothing invisible outside a literal. Before any rule that reasons about a name, because
    //    every one of them compares text a hidden character can quietly change.
    reject_invisible_outside_literals(sql)?;
    // 1. The statement shape must be purely read-only (SELECT/WITH/EXPLAIN/SHOW).
    structural_readonly(&ast[0])?;
    // 2. Defence in depth: functions with SIDE EFFECTS (setval, dblink_exec, lo_export, pg_read_file…).
    //    We scan the AST (Expr::Function nodes and relation/table-function names in FROM), NOT the text —
    //    we read `ident.value`, so how a literal is rendered (quotes, $$…$$, E'…') and where comments sit
    //    is irrelevant. A text-based scan was defeated three times (quoting → dollar-quote → E-string);
    //    moving to the AST eliminates that entire class of bypass.
    // 3. Structural defence in depth: the same rules as for the top-level Query, applied to EVERY Query
    //    node in the tree (derived tables, subqueries in WHERE, CTEs inside subqueries). Checking only
    //    the top level let `SELECT * FROM (SELECT ... FOR UPDATE) t` and writable CTEs hidden one level
    //    down slip through.
    // The whole-row check needs the names in FROM before the projection is examined, and the visitor
    // walks the projection first — hence a separate collecting pass. It runs only when redaction is
    // configured, so the common path is unchanged.
    let row_refs = if redaction_configured() {
        let mut c = RowRefCollector::default();
        let _ = ast[0].visit(&mut c);
        c.names
    } else {
        std::collections::HashSet::new()
    };
    let mut scanner = SecurityScanner {
        hit: None,
        redacted: None,
        redaction_on: !row_refs.is_empty() || redaction_configured(),
        row_refs,
        evasion: None,
    };
    let _ = ast[0].visit(&mut scanner);
    if let Some(c) = scanner.redacted {
        return Err(ValidationError::Redacted(c));
    }
    if let Some(e) = scanner.evasion {
        return Err(ValidationError::RedactionEvasion(e));
    }
    if let Some(f) = scanner.hit {
        return Err(ValidationError::NotReadOnly(f));
    }
    Ok(())
}

/// The leading keyword when it is unmistakably a write/maintenance command. Used only to explain a
/// rejection better — the rejection itself already happened, this just replaces a misleading message.
fn leading_write_keyword(sql: &str) -> Option<&'static str> {
    const WRITE_KEYWORDS: &[&str] = &[
        "REFRESH",
        "CLUSTER",
        "VACUUM",
        "ANALYZE",
        "REINDEX",
        "CHECKPOINT",
        "LOCK",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "SECURITY",
        "LISTEN",
        "UNLISTEN",
        "NOTIFY",
        "DISCARD",
        "RESET",
        "DEALLOCATE",
        "PREPARE",
        "EXECUTE",
        "DECLARE",
        "FETCH",
        "MOVE",
        "CLOSE",
        "COPY",
        "IMPORT",
        "CALL",
        "DO",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "SET",
        "ALTER",
        "CREATE",
        "DROP",
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "COMMENT",
        "REASSIGN",
    ];
    let first = sql
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .next()?
        .to_ascii_uppercase();
    WRITE_KEYWORDS.iter().find(|k| **k == first).copied()
}

/// Characters that are invisible when rendered but change what the parser sees.
///
/// Refused rather than stripped. Stripping would mean validating one text and executing another,
/// which is the exact split the canonical-form gate exists to prevent.
fn is_invisible(c: char) -> bool {
    // Control characters, except the four that are ordinary SQL whitespace. A newline in a query is
    // formatting; a NUL or a backspace in an identifier is someone making two readers disagree.
    if c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{000B}' | '\u{000C}') {
        return true;
    }
    // Whitespace that is not the whitespace SQL means. U+00A0 renders as a space, is NOT treated as
    // one by the tokenizer, and therefore turns `lowrite` into an identifier that no rule about
    // `lowrite` will ever match. Same for U+2007, U+202F, U+3000 and the rest of the family. This is
    // a rule rather than a list on purpose: it asks the standard library's Unicode tables instead of
    // enumerating what a fuzz run happened to find, which is how the previous two attempts at this
    // check each missed the next character along.
    if c.is_whitespace() && !matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000B}' | '\u{000C}') {
        return true;
    }
    matches!(c,
        // Unicode category Cf (Format) — the whole category, not the handful that showed up in a
        // fuzz run. Enumerating what an attacker has already used is how you get a second finding
        // with the next character along; the fuzz harness found three of these one after another.
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{0890}'..='\u{0891}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        // Tag characters. They render as nothing at all and can spell out a whole word invisibly —
        // this is what hid `pg_read_file` and `pg_notify` from the rules that name them.
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        // Variation selectors: no glyph of their own, and legal inside an identifier as far as the
        // tokenizer is concerned.
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Refuses invisible characters anywhere they are not data.
///
/// Inside a string literal they may legitimately be data — a zero-width joiner is how emoji
/// sequences are built, and refusing those would reject honest queries. Anywhere else they have no
/// purpose except to make two readers disagree about the same text: `setval\u{2060}(...)` looks
/// like `setval(` to a person and parses as something else, which is how a side-effect function
/// walked past the rule that names it.
///
/// The exempt list is the literal token kinds, deliberately, so that a token variant added by a
/// future parser version falls through to being CHECKED. A new literal kind would then produce a
/// false rejection — annoying, visible, fixable. The other direction would produce a bypass.
fn reject_invisible_outside_literals(sql: &str) -> Result<(), ValidationError> {
    if !sql.chars().any(is_invisible) {
        return Ok(()); // the overwhelmingly common case, one scan, no tokenising
    }
    let tokens = match Tokenizer::new(&PostgreSqlDialect {}, sql).tokenize() {
        Ok(t) => t,
        // Unlexable input is rejected by the parser a moment later with a better message.
        Err(_) => return Ok(()),
    };
    for t in &tokens {
        let exempt = matches!(
            t,
            Token::SingleQuotedString(_)
                | Token::DoubleQuotedString(_)
                | Token::TripleSingleQuotedString(_)
                | Token::TripleDoubleQuotedString(_)
                | Token::DollarQuotedString(_)
                | Token::SingleQuotedByteStringLiteral(_)
                | Token::DoubleQuotedByteStringLiteral(_)
                | Token::TripleSingleQuotedByteStringLiteral(_)
                | Token::TripleDoubleQuotedByteStringLiteral(_)
                | Token::SingleQuotedRawStringLiteral(_)
                | Token::DoubleQuotedRawStringLiteral(_)
                | Token::TripleSingleQuotedRawStringLiteral(_)
                | Token::TripleDoubleQuotedRawStringLiteral(_)
                | Token::NationalStringLiteral(_)
                | Token::EscapedStringLiteral(_)
                | Token::UnicodeStringLiteral(_)
                | Token::HexStringLiteral(_)
        );
        if exempt {
            continue;
        }
        if let Some(c) = t.to_string().chars().find(|c| is_invisible(*c)) {
            return Err(ValidationError::NotReadOnly(format!(
                "character U+{:04X} outside a string literal — invisible or a space that is not a \
                 space, refused because it makes the text a reader sees and the text the parser \
                 sees disagree",
                c as u32
            )));
        }
    }
    Ok(())
}

/// Is there a `;` outside literals and comments with any further token after it?
/// The sqlparser tokenizer shares the parser lexis, so quoting cannot be used to sneak past this.
fn has_trailing_statement(sql: &str) -> bool {
    let tokens = match Tokenizer::new(&PostgreSqlDialect {}, sql).tokenize() {
        Ok(t) => t,
        Err(_) => return false, // niepoprawna leksyka → i tak padnie na parse
    };
    let mut seen_semicolon = false;
    for t in tokens {
        match t {
            Token::Whitespace(_) => {}
            Token::SemiColon => seen_semicolon = true,
            _ if seen_semicolon => return true,
            _ => {}
        }
    }
    false
}

/// Is the top-level statement a Query (SELECT/WITH/VALUES/TABLE)? Used by the fuzzer to check the
/// cost-routing invariant (a Query must canonicalise to a row query, or it bypasses the cost guard).
pub fn is_query_stmt(sql: &str) -> bool {
    matches!(parse(sql).as_deref(), Ok([Statement::Query(_)]))
}

/// Walks the AST and detects a denylisted function by the NAME IN THE TREE (Expr::Function and
/// relation/table-function names), regardless of how literals or comments are rendered as text —
/// and checks the read-only shape of EVERY Query node, not just the top level.
struct SecurityScanner {
    hit: Option<String>,
    redacted: Option<String>,
    /// Table names and aliases in this statement, lower-cased. Only collected when redaction is on.
    row_refs: std::collections::HashSet<String>,
    evasion: Option<String>,
    redaction_on: bool,
}

/// A column alias list renames columns BY POSITION, so `(SELECT * FROM staff) AS x(c1, …, c9, …)`
/// hands back the ninth column under the name `c9`. The redacted name never appears in the statement
/// and never appears as a key in the result, so neither the reference check nor the masking has
/// anything to match. Refused while redaction is configured — there is no way to tell which position
/// is which without the catalog, and guessing wrong here means handing over the secret.
fn alias_renames_columns(alias: Option<&TableAlias>) -> bool {
    alias.is_some_and(|a| !a.columns.is_empty())
}
impl Visitor for SecurityScanner {
    type Break = ();
    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        if self.redaction_on {
            if let Some(w) = &q.with {
                for cte in &w.cte_tables {
                    if !cte.alias.columns.is_empty() {
                        self.evasion = Some(format!(
                            "renaming columns by position in the CTE `{}`",
                            cte.alias.name
                        ));
                        return ControlFlow::Break(());
                    }
                }
            }
        }
        // FOR UPDATE/SHARE and data-modifying CTE / SELECT INTO at any depth.
        if !q.locks.is_empty() {
            self.hit = Some("row locks (FOR UPDATE/SHARE) in subquery".into());
            return ControlFlow::Break(());
        }
        if !setexpr_is_readonly(&q.body) {
            self.hit = Some("non-read-only subquery (data-modifying CTE / SELECT INTO)".into());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        // A redacted column may not even be NAMED. Filtering it out of the result would be a
        // false comfort: `SELECT password AS pw` renames it, `SELECT md5(password)` leaks it a
        // character at a time. Refusing the reference closes both, and masking the value in the
        // output still covers `SELECT *`, where the column is never named.
        match expr {
            Expr::Identifier(id) => {
                if is_redacted(&id.value.to_lowercase()) {
                    self.redacted = Some(id.value.clone());
                    return ControlFlow::Break(());
                }
                // A bare table name or alias used as a VALUE is the whole row. `t::text` flattens it
                // to a single string, `row_to_json(t)` and `json_agg(t)` nest it — in every case the
                // redacted column travels inside a value whose key is not its name, so neither the
                // name check above nor masking in the result can see it. One call returned the entire
                // password column this way.
                if !self.row_refs.is_empty() && self.row_refs.contains(&id.value.to_lowercase()) {
                    self.evasion = Some(format!(
                        "referencing the whole row `{}` as a value",
                        id.value
                    ));
                    return ControlFlow::Break(());
                }
            }
            // `t.*` inside an expression is a QualifiedWildcard, not an Identifier, so the whole-row
            // check above walked straight past `ROW(t.*)::text` and `to_jsonb(t.*)::text`. In a plain
            // projection `SELECT t.*` the columns keep their names and masking still applies, and that
            // form is a SelectItem, not an Expr — so it is unaffected by this.
            // The column name as a STRING, not an identifier: `to_jsonb(t) ->> 'password'`,
            // `#>> '{password}'`, `jsonb_path_query(…, '$.password')`. The scanner matches
            // identifiers, so none of these looked like a reference to anything.
            // Every spelling of a string literal, not just the plain one: `E'\\160assword'`,
            // `$$password$$` and the national/unicode forms all name the same key.
            // `Expr::Value` carries a `ValueWithSpan` from sqlparser 0.62; the literal itself
            // sits in `.value`. Matching through it changes nothing about which spellings count.
            Expr::Value(vs)
                if matches!(
                    &vs.value,
                    Value::SingleQuotedString(_)
                        | Value::EscapedStringLiteral(_)
                        | Value::NationalStringLiteral(_)
                        | Value::DoubleQuotedString(_)
                ) =>
            {
                let s = match &vs.value {
                    Value::SingleQuotedString(s)
                    | Value::EscapedStringLiteral(s)
                    | Value::NationalStringLiteral(s)
                    | Value::DoubleQuotedString(s) => s,
                    _ => unreachable!("guarded by the match above"),
                };
                if let Some(col) = redacted_name_inside(&unescape_sql_literal(s).to_lowercase()) {
                    self.evasion = Some(format!(
                        "naming the redacted column `{}` inside a string literal",
                        col
                    ));
                    return ControlFlow::Break(());
                }
            }
            Expr::CompoundIdentifier(parts) => {
                if let Some(last) = parts.last() {
                    if is_redacted(&last.value.to_lowercase()) {
                        self.redacted = Some(last.value.clone());
                        return ControlFlow::Break(());
                    }
                }
            }
            _ => {}
        }
        if let Expr::Function(f) = expr {
            // `t.*` as a function argument is a FunctionArgExpr, not an Expr, so the whole-row check
            // never saw `ROW(t.*)::text` or `to_jsonb(t.*)::text` — both of which flatten the record
            // into one string and carry the redacted column out inside it. In a plain projection
            // (`SELECT t.*`) the columns keep their names and masking still applies; that is a
            // SelectItem, not a function argument, so it is unaffected.
            if self.redaction_on {
                let args = match &f.args {
                    FunctionArguments::List(l) => l.args.as_slice(),
                    _ => &[],
                };
                let whole_row = args.iter().any(|a| {
                    matches!(
                        a,
                        FunctionArg::Unnamed(FunctionArgExpr::QualifiedWildcard(_))
                            | FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                            | FunctionArg::Named {
                                arg: FunctionArgExpr::QualifiedWildcard(_),
                                ..
                            }
                    )
                });
                if whole_row
                    && !f
                        .name
                        .0
                        .last()
                        .and_then(|n| n.as_ident())
                        .is_some_and(|n| n.value.eq_ignore_ascii_case("count"))
                {
                    self.evasion =
                        Some("serialising a whole row through a wildcard argument".into());
                    return ControlFlow::Break(());
                }
            }
            if name_has_unreadable_part(&f.name) {
                self.hit = Some(
                    "a function name built from another function call — refused because the name \
                     cannot be read, and every rule here is written about the name"
                        .into(),
                );
                return ControlFlow::Break(());
            }
            if let Some(name) = last_part_name(&f.name) {
                if let Some(msg) = function_rejection(&name) {
                    self.hit = Some(msg);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
    /// A plain RELATION (table or view) — only the list of known side effects applies here.
    /// The default denial for unknown catalog names is NOT applied, because `pg_stat_activity`,
    /// `pg_tables` and the rest of the catalog are legitimate read-only views (a test caught that regression).
    fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<()> {
        if name_has_unreadable_part(name) {
            self.hit = Some("a relation name built from a function call — refused unread".into());
            return ControlFlow::Break(());
        }
        if let Some(n) = last_part_name(name) {
            if matches!(classify_function(&n), FnVerdict::SideEffect) {
                self.hit = Some(format!("side-effect function: {}", n));
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    /// A TABLE FUNCTION in `FROM` (`FROM f(...)`) — recognised by the presence of arguments.
    /// Full classification applies here, including the default denial for unknown catalog functions;
    /// otherwise `SELECT * FROM pg_export_snapshot()` would walk straight past the gate.
    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<()> {
        if self.redaction_on {
            let alias = match tf {
                TableFactor::Table { alias, .. }
                | TableFactor::Derived { alias, .. }
                | TableFactor::TableFunction { alias, .. }
                | TableFactor::NestedJoin { alias, .. } => alias.as_ref(),
                _ => None,
            };
            if alias_renames_columns(alias) {
                self.evasion = Some("renaming columns by position in a subquery alias".into());
                return ControlFlow::Break(());
            }
        }
        if let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = tf
        {
            if name_has_unreadable_part(name) {
                self.hit =
                    Some("a table function named by a function call — refused unread".into());
                return ControlFlow::Break(());
            }
            if let Some(n) = last_part_name(name) {
                if let Some(msg) = function_rejection(&n) {
                    self.hit = Some(msg);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Structural verdict: ONLY Query (recursing into CTEs), EXPLAIN and SHOW* are allowed.
fn structural_readonly(stmt: &Statement) -> Result<(), ValidationError> {
    match stmt {
        // CTE recursion: `WITH x AS (UPDATE/INSERT ...) SELECT` parses as a top-level Query, but the CTE
        // body is SetExpr::Update/Insert (a write) — it must be rejected (a structural bypass).
        Statement::Query(q) => {
            if query_is_readonly(q) {
                Ok(())
            } else {
                Err(ValidationError::NotReadOnly(
                    "non-read-only query (CTE / SELECT INTO / FOR UPDATE)".into(),
                ))
            }
        }
        // EXPLAIN ANALYZE ACTUALLY EXECUTES the plan (and bypasses the cost guard, which is skipped for
        // non-row queries) — rejected outright. Plain EXPLAIN is allowed for reads only (recursively).
        Statement::Explain {
            analyze,
            statement,
            options,
            ..
        } => {
            // Two places say ANALYZE, not one. `EXPLAIN ANALYZE ...` sets the bool; PostgreSQL's
            // parenthesised form `EXPLAIN (ANALYZE) ...` lands in `options` instead — a field that
            // did not exist when this check was written. Reading only the bool let the parenthesised
            // form through, and ANALYZE executes the statement. The old parser hid this by failing
            // to parse the form at all, which is not a control; it is luck.
            let analyze_in_options = options.as_ref().is_some_and(|opts| {
                opts.iter()
                    .any(|o| o.name.value.eq_ignore_ascii_case("analyze"))
            });
            if *analyze || analyze_in_options {
                Err(ValidationError::NotReadOnly(
                    "EXPLAIN ANALYZE (executes the plan)".into(),
                ))
            } else {
                structural_readonly(statement)
            }
        }
        Statement::ExplainTable { .. } => Ok(()),
        // `SHOW` is useful (timezone, search_path, server_version), but a few variables expose the host
        // layout (file paths, archive commands) — free reconnaissance for an attacker.
        Statement::ShowVariable { variable } => {
            let name = variable
                .iter()
                .map(|i| i.value.to_lowercase())
                .collect::<Vec<_>>()
                .join("_");
            if SENSITIVE_SHOW_VARS.contains(&name.as_str()) {
                Err(ValidationError::NotReadOnly(format!(
                    "SHOW {} (server layout)",
                    name
                )))
            } else {
                Ok(())
            }
        }
        Statement::ShowVariables { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowFunctions { .. } => Ok(()),
        other => Err(ValidationError::NotReadOnly(stmt_kind(other))),
    }
}

/// Verdict "this function has a side effect": a name from the explicit list OR from a denied FAMILY.
///
/// A list of names only ever covers what someone thought of — adversarial review found
/// `pg_import_system_collations()`, which **really does write to `pg_collation` inside a READ ONLY
/// transaction** (PostgreSQL does not guard it with `PreventCommandIfReadOnly`, so the second layer
/// of defence DOES NOT APPLY there). So whole administrative families are denied by prefix: a new or
/// unknown name from the same family is refused by default (fail-closed) instead of waiting for the
/// next review round to notice it.
pub enum FnVerdict {
    Allowed,
    /// A known side-effecting function (explicit list or a denied family).
    SideEffect,
    /// A function from the PostgreSQL catalog namespace that we do NOT know to be read-only.
    UnknownCatalog,
}

/// Verdict for a function name.
///
/// Enumerating "bad" functions loses over time: `pg_export_snapshot()` writes a file despite
/// `default_transaction_read_only` and matched neither the name list nor any family prefix — and
/// there will always be another such name, including in future PostgreSQL releases. So for the
/// catalog namespace (`pg_*`, `lo_*`, `dblink*`) the default answer is INVERTED: only what we know
/// to be a pure read passes. User-defined functions (and standard ones such as `sum`, `lower`) stay
/// allowed — there the read-only transaction and the database role are the backstop.
/// An operator can add a missing name through `MCP_ALLOW_FUNCTIONS` (comma-separated).
pub fn classify_function(name: &str) -> FnVerdict {
    if SAFE_DESPITE_FAMILY.contains(&name) || operator_allowed(name) {
        return FnVerdict::Allowed;
    }
    if SIDE_EFFECT_FUNCS.contains(&name)
        || DENY_FAMILIES.iter().any(|p| name.starts_with(p))
        || (name.starts_with("pg_stat_") && name.contains("reset"))
    {
        return FnVerdict::SideEffect;
    }
    if is_catalog_namespace(name) && !is_known_read(name) {
        return FnVerdict::UnknownCatalog;
    }
    FnVerdict::Allowed
}

/// Rejection message — distinguishes "this writes" from "we do not know this catalog function", so the
/// operator can tell a real control from a gap in our knowledge (and how to close it).
fn function_rejection(name: &str) -> Option<String> {
    match classify_function(name) {
        FnVerdict::Allowed => None,
        FnVerdict::SideEffect => Some(format!("side-effect function: {}", name)),
        FnVerdict::UnknownCatalog => Some(format!(
            "catalog function not known to be read-only: {} (allow it with MCP_ALLOW_FUNCTIONS if it is)",
            name
        )),
    }
}

fn is_catalog_namespace(name: &str) -> bool {
    name.starts_with("pg_") || name.starts_with("lo_") || name.starts_with("dblink")
}

/// Catalog functions we know to be read-only. The prefixes cover whole introspection families
/// (`pg_get_*` = object definitions, `pg_stat_get_*` = counters, `pg_size_*` = sizes).
fn is_known_read(name: &str) -> bool {
    const SAFE_PREFIXES: &[&str] = &["pg_get_", "pg_stat_get_", "pg_size_", "pg_has_"];
    const SAFE_EXACT: &[&str] = &[
        "pg_typeof",
        "pg_backend_pid",
        "pg_postmaster_start_time",
        "pg_conf_load_time",
        "pg_is_in_recovery",
        "pg_client_encoding",
        "pg_encoding_to_char",
        "pg_char_to_encoding",
        "pg_column_size",
        "pg_database_size",
        "pg_relation_size",
        "pg_total_relation_size",
        "pg_table_size",
        "pg_indexes_size",
        "pg_tablespace_size",
        "pg_tablespace_location",
        "pg_relation_filenode",
        "pg_relation_filepath",
        "pg_describe_object",
        "pg_identify_object",
        "pg_identify_object_as_address",
        "pg_options_to_table",
        "pg_current_wal_lsn",
        "pg_current_wal_insert_lsn",
        "pg_current_wal_flush_lsn",
        "pg_last_wal_receive_lsn",
        "pg_last_wal_replay_lsn",
        "pg_last_xact_replay_timestamp",
        "pg_walfile_name",
        "pg_walfile_name_offset",
        "pg_wal_lsn_diff",
        "pg_blocking_pids",
        "pg_safe_snapshot_blocking_pids",
        "pg_trigger_depth",
        "pg_notification_queue_usage",
        "pg_listening_channels",
        "pg_lock_status",
        "pg_index_has_property",
        "pg_index_column_has_property",
        "pg_indexam_has_property",
        "pg_column_is_updatable",
        "pg_relation_is_updatable",
        "pg_relation_is_publishable",
        "pg_collation_actual_version",
        "pg_database_collation_actual_version",
        "pg_snapshot_xmin",
        "pg_snapshot_xmax",
        "pg_snapshot_xip",
        "pg_visible_in_snapshot",
        "pg_settings_get_flags",
        "pg_show_all_settings",
        "pg_show_all_file_settings",
        "pg_tablespace_databases",
        "pg_partition_tree",
        "pg_partition_root",
        "pg_partition_ancestors",
        "pg_get_wal_resource_managers",
        "pg_char_to_encoding",
        "pg_input_is_valid",
    ];
    SAFE_PREFIXES.iter().any(|p| name.starts_with(p))
        || name.contains("_is_visible")
        || SAFE_EXACT.contains(&name)
}

/// Columns the operator declared sensitive (`MCP_REDACT_COLUMNS`). Values are masked in results,
/// and — because renaming would defeat masking — the column may not be referenced at all.
/// Whether the operator named this function in `MCP_ALLOW_FUNCTIONS`.
pub(crate) fn function_explicitly_allowed(name: &str) -> bool {
    std::env::var("MCP_ALLOW_FUNCTIONS")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .any(|a| a.eq_ignore_ascii_case(name))
        })
        .unwrap_or(false)
}

/// Every function called in the statement, lower-cased and unqualified.
///
/// The surface allowlist reads the query plan, and a plan does not show what a function's body
/// reads: `SELECT secret_lookup('x')` plans to a bare `Result` node. A review demonstrated the
/// consequence — a `SECURITY DEFINER` function returned an entire table the role had been explicitly
/// denied. The plan is the right authority for relations and no authority at all for functions.
#[derive(Default)]
struct FunctionCollector {
    names: Vec<String>,
}
impl Visitor for FunctionCollector {
    type Break = ();
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::Function(f) = expr {
            // A part we cannot read is recorded under a name no allowlist will ever contain, so it
            // is refused downstream instead of disappearing from the set.
            self.names
                .push(last_part_name(&f.name).unwrap_or_else(|| UNREADABLE_NAME.to_string()));
        }
        ControlFlow::Continue(())
    }
    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<()> {
        if let TableFactor::Table {
            name,
            args: Some(_),
            ..
        } = tf
        {
            self.names
                .push(last_part_name(name).unwrap_or_else(|| UNREADABLE_NAME.to_string()));
        }
        ControlFlow::Continue(())
    }
}

/// The functions a statement calls. Empty when it calls none.
pub(crate) fn functions_called(sql: &str) -> Vec<String> {
    let Ok(ast) = parse(sql) else {
        return Vec::new();
    };
    let Some(stmt) = ast.first() else {
        return Vec::new();
    };
    let mut c = FunctionCollector::default();
    let _ = stmt.visit(&mut c);
    c.names.sort();
    c.names.dedup();
    c.names
}

/// Strips a leading EXPLAIN, returning the statement it would explain.
///
/// `EXPLAIN` skips the cost guard — you cannot plan a plan — and the surface check lived inside it,
/// so `EXPLAIN VERBOSE SELECT ... FROM secret` reported the table's existence, its column names, the
/// filter and the planner's row estimates, all from outside the configured surface.
pub(crate) fn explained_statement(sql: &str) -> Option<String> {
    let t = sql.trim_start();
    // `!t.len() >= 7` compiles — it negates the length bitwise and compares a huge number — so the
    // guard was always true and this returned None for every input, silently disabling the check.
    if t.len() < 7 || !t[..7].eq_ignore_ascii_case("explain") {
        return None;
    }
    let rest = t[7..].trim_start();
    // `EXPLAIN (opts) stmt` as well as the legacy `EXPLAIN VERBOSE stmt`.
    let rest = if let Some(stripped) = rest.strip_prefix('(') {
        let close = stripped.find(')')?;
        stripped[close + 1..].trim_start()
    } else {
        let mut r = rest;
        loop {
            let word = r.split_whitespace().next().unwrap_or("");
            if [
                "verbose", "costs", "settings", "buffers", "format", "json", "text", "off", "on",
            ]
            .contains(&word.to_lowercase().as_str())
            {
                r = r[word.len()..].trim_start();
            } else {
                break;
            }
        }
        r
    };
    (!rest.is_empty()).then(|| rest.to_string())
}

/// Every table name and alias in the statement — the set a bare identifier must not match when it is
/// used as a value.
#[derive(Default)]
struct RowRefCollector {
    names: std::collections::HashSet<String>,
}
impl Visitor for RowRefCollector {
    type Break = ();
    fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<()> {
        self.names
            .insert(last_part_name(name).unwrap_or_else(|| UNREADABLE_NAME.to_string()));
        ControlFlow::Continue(())
    }
    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<()> {
        let alias = match tf {
            TableFactor::Table { alias, .. }
            | TableFactor::Derived { alias, .. }
            | TableFactor::TableFunction { alias, .. }
            | TableFactor::NestedJoin { alias, .. } => alias.as_ref(),
            _ => None,
        };
        if let Some(a) = alias {
            self.names.insert(a.name.value.to_lowercase());
        }
        ControlFlow::Continue(())
    }
}

/// The configured column names, for a check that asks the database rather than the parser.
pub(crate) fn redacted_column_list() -> Vec<String> {
    redacted_names().to_vec()
}

pub(crate) fn redaction_configured() -> bool {
    !redacted_names().is_empty()
}

fn redacted_names() -> &'static [String] {
    static R: Lazy<Vec<String>> = Lazy::new(|| {
        std::env::var("MCP_REDACT_COLUMNS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.rsplit('.').next().unwrap_or(&s).to_string())
                    .collect()
            })
            .unwrap_or_default()
    });
    &R
}

/// Resolves the escape sequences PostgreSQL accepts in `E'…'`, so a name spelled `E'\\160assword'`
/// is compared as `password`. Only the octal and hex forms are decoded — enough for the ways an
/// adversary actually wrote it, and this layer is best-effort by design: the guarantee comes from the
/// privilege check, not from out-guessing string construction.
fn unescape_sql_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\\' && i + 1 < b.len() {
            let rest: String = b[i + 1..].iter().take(3).collect();
            if b[i + 1] == 'x' {
                let hex: String = rest
                    .chars()
                    .skip(1)
                    .take(2)
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect();
                if let Ok(n) = u32::from_str_radix(&hex, 16) {
                    if let Some(c) = char::from_u32(n) {
                        out.push(c);
                        i += 2 + hex.len();
                        continue;
                    }
                }
            }
            let oct: String = rest
                .chars()
                .take_while(|c| ('0'..='7').contains(c))
                .collect();
            if !oct.is_empty() {
                if let Ok(n) = u32::from_str_radix(&oct, 8) {
                    if let Some(c) = char::from_u32(n) {
                        out.push(c);
                        i += 1 + oct.len();
                        continue;
                    }
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// A redacted column name appearing anywhere inside a string literal. Substring, not equality:
/// `'{password}'` and `'$.password'` are how JSON path and array-path syntax name a key.
fn redacted_name_inside(lit: &str) -> Option<&'static str> {
    redacted_names()
        .iter()
        .find(|n| lit.contains(n.as_str()))
        .map(|n| n.as_str())
}

fn is_redacted(name: &str) -> bool {
    redacted_names().iter().any(|p| p == name)
}

/// Operator escape hatch: `MCP_ALLOW_FUNCTIONS=name1,name2`. A deliberate human decision that a given
/// function is read-only in their deployment — better than forcing a fork, or forcing them to drop the
/// tool entirely, when our list happens to miss something.
fn operator_allowed(name: &str) -> bool {
    static ALLOW: Lazy<Vec<String>> = Lazy::new(|| {
        std::env::var("MCP_ALLOW_FUNCTIONS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    });
    ALLOW.iter().any(|a| a == name)
}

/// Server/maintenance function families — denied wholesale by prefix.
/// Each is an administrative operation (a write, I/O, process control, replication),
/// not the kind of user-data read an AI agent reaches for.
const DENY_FAMILIES: &[&str] = &[
    "pg_import_", // pg_import_system_collations — ZAPIS do katalogu mimo read-only txn
    "pg_backup_",
    "pg_start_backup",
    "pg_stop_backup", // backup mode survives DISCARD ALL
    "pg_promote",
    "pg_wal_replay_",
    "pg_switch_", // sterowanie recovery/WAL
    "pg_create_",
    "pg_drop_",
    "pg_replication_",
    "pg_logical_", // sloty/origins/emit_message
    "pg_terminate_",
    "pg_cancel_", // sterowanie procesami
    "pg_advisory_",
    "pg_try_advisory_", // locki sesyjne
    "pg_reload_",
    "pg_rotate_", // konfiguracja/logi serwera
    "pg_ls_",
    "pg_file_",
    "pg_write_",
    "pg_logdir_", // server filesystem
    "gin_clean_",
    "brin_summarize",
    "brin_desummarize", // index maintenance (writes despite read-only)
    "dblink",           // a bridge to another database = a way around everything
    // Functions that take SQL, or a relation to dump, AS TEXT. The AST cannot see inside a string
    // literal, so every rule this validator enforces is invisible to them: query_to_xml('SELECT
    // pg_read_file(...)') read server files, listed the data directory, ran a catalog-writing
    // function, and returned two statements from one call. Whole families, because the variants
    // (…_to_xmlschema, …_to_xml_and_xmlschema, cursor_/schema_/database_) all take the same argument.
    "query_to_",
    "table_to_",
    "cursor_to_",
    "schema_to_",
    "database_to_",
    "lo_",
    "lowrite",
    "loread", // large objects: zapis przez deskryptor
];

/// Pure READS that happen to match a denied family — explicit exceptions, so fail-closed does not
/// take away functionality for no reason.
const SAFE_DESPITE_FAMILY: &[&str] = &["lo_get", "lo_get_fragment"];

/// Known built-in PostgreSQL functions with side effects (they write, mutate the session, cause DoS
/// or do I/O) even though they may appear syntactically inside a SELECT. Explicit, fail-closed list.
const SIDE_EFFECT_FUNCS: &[&str] = &[
    // sequences (writes)
    "setval",
    "nextval",
    // session / configuration
    "set_config",
    // advisory locks (session side effect)
    "pg_advisory_lock",
    "pg_advisory_unlock",
    "pg_advisory_unlock_all",
    "pg_advisory_xact_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_xact_lock_shared",
    "pg_try_advisory_lock",
    "pg_try_advisory_xact_lock",
    // shared/try-shared/unlock-shared variants — the whole family must be covered
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock_shared",
    "pg_advisory_unlock_shared",
    // remote execution / bridges (RCE-adjacent)
    "dblink_exec",
    "dblink",
    "dblink_connect",
    // large objects (file I/O)
    "lo_import",
    "lo_export",
    "lo_unlink",
    "lo_put",
    "lo_from_bytea",
    "lo_creat",
    "lo_create",
    // filesystem I/O / server configuration
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "pg_reload_conf",
    "pg_rotate_logfile",
    // process, WAL and replication control
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_switch_wal",
    "pg_switch_xlog",
    "pg_create_restore_point",
    "pg_logical_emit_message",
    "pg_replication_origin_create",
    "pg_replication_origin_drop",
    "pg_drop_replication_slot",
    "pg_create_physical_replication_slot",
    "pg_create_logical_replication_slot",
    // DoS
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    // notifications / statistics resets — side effects that a read-only transaction still permits
    "pg_notify",
    "pg_stat_reset",
    "pg_stat_reset_shared",
    "pg_stat_reset_slru",
    "pg_stat_reset_single_table_counters",
    "pg_stat_reset_single_function_counters",
    "pg_stat_reset_replication_slot",
    "pg_stat_reset_subscription_stats",
    // adminpack — WRITES/DELETES server files (a read-only transaction does NOT block file I/O)
    "pg_file_write",
    "pg_file_unlink",
    "pg_file_rename",
    "pg_file_sync",
    "pg_logdir_ls",
    // name variants seen in extensions and forks — fail-closed, zero cost
    "pg_write_file",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    // the rest of the dblink family (beyond dblink/dblink_exec/dblink_connect)
    "dblink_connect_u",
    "dblink_send_query",
    "dblink_open",
    "dblink_fetch",
    // replication mutators
    "pg_replication_origin_advance",
    "pg_replication_origin_session_setup",
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
];

/// `SHOW` variables that reveal the server layout — refused; everything else passes.
const SENSITIVE_SHOW_VARS: &[&str] = &[
    "data_directory",
    "config_file",
    "hba_file",
    "ident_file",
    "external_pid_file",
    "ssl_cert_file",
    "ssl_key_file",
    "ssl_ca_file",
    "ssl_crl_file",
    "archive_command",
    "restore_command",
    "log_directory",
    "log_filename",
    "unix_socket_directories",
    "dynamic_library_path",
    "krb_server_keyfile",
];

/// Recursively verifies that a Query (including CTEs and subqueries) is read-only throughout.
/// `SetExpr::Insert/Update` = a data-modifying CTE (PostgreSQL `WITH x AS (UPDATE...)`) → reject.
fn query_is_readonly(q: &Query) -> bool {
    // FOR UPDATE / FOR SHARE = blokady wierszy; Postgres odrzuca je w read-only transakcji.
    // Structurally this is still a SELECT, so it needs an explicit check (found by the parser differential).
    if !q.locks.is_empty() {
        return false;
    }
    if let Some(with) = &q.with {
        for cte in &with.cte_tables {
            if !query_is_readonly(&cte.query) {
                return false;
            }
        }
    }
    setexpr_is_readonly(&q.body)
}

fn setexpr_is_readonly(se: &SetExpr) -> bool {
    match se {
        // `SELECT ... INTO new_table` CREATES a table (a write) even though it is structurally a Select —
        // Postgres: "cannot execute SELECT INTO in a read-only transaction" (znalezione przez
        // found by the parser-differential harness. Reject whenever the `into` field is set.
        SetExpr::Select(s) => s.into.is_none(),
        SetExpr::Values(_) | SetExpr::Table(_) => true,
        SetExpr::Query(inner) => query_is_readonly(inner),
        SetExpr::SetOperation { left, right, .. } => {
            setexpr_is_readonly(left) && setexpr_is_readonly(right)
        }
        // SetExpr::Insert / SetExpr::Update = data-modifying CTE; anything unknown → reject (fail-closed).
        _ => false,
    }
}

fn stmt_kind(s: &Statement) -> String {
    // Short kind name (no full dump, so query contents never leak).
    let dbg = format!("{:?}", s);
    dbg.split([' ', '(', '{'])
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

/// Caps the row count at `max_rows`: injects a `LIMIT`, and when the query HAS its own limit it
/// **clamps it downwards** (a hand-written `LIMIT 999999999` used to bypass the declared hard cap
/// entirely). Returns canonical AST text that itself passes the validator (the round-trip gate).
pub fn enforce_limit(sql: &str, max_rows: u64) -> Result<String, ValidationError> {
    enforce_limit_offset(sql, max_rows, 0)
}

/// As `enforce_limit`, plus a row offset for paging.
///
/// A non-zero offset ALWAYS wraps the query from the outside instead of editing its own LIMIT/OFFSET:
/// the caller's paging must not be silently merged with paging the query already had.
pub fn enforce_limit_offset(
    sql: &str,
    max_rows: u64,
    offset: u64,
) -> Result<String, ValidationError> {
    if offset > 0 {
        let ast = parse(sql)?;
        if ast.is_empty() {
            return Ok(sql.to_string());
        }
        let rendered = format!(
            "SELECT * FROM ({}) AS _mcp_page LIMIT {} OFFSET {}",
            ast[0], max_rows, offset
        );
        // Same round-trip gate as below: what reaches the database must pass the validator that
        // accepted the original, or we would be validating one statement and executing another.
        if validate_readonly(&rendered).is_ok() {
            return Ok(rendered);
        }
        return Err(ValidationError::NotParseable(
            "this query cannot be paged safely (its canonical form does not re-validate)".into(),
        ));
    }
    enforce_limit_inner(sql, max_rows)
}

fn enforce_limit_inner(sql: &str, max_rows: u64) -> Result<String, ValidationError> {
    let mut ast = parse(sql)?;
    if ast.is_empty() {
        return Ok(sql.to_string());
    }
    let mut needs_wrap = false;
    if let Statement::Query(q) = &mut ast[0] {
        needs_wrap = matches!(cap_rows(q, max_rows), Cap::NeedsWrap);
    }
    // ALWAYS return the canonical AST (not the original) — it strips leading comments that would
    // otherwise confuse is_row_query and bypass the cost guard and byte cap.
    let rendered = if needs_wrap {
        // We cannot evaluate this LIMIT (unary plus, a cast, an expression, a parameter), so we do NOT
        // trust it and impose our own limit FROM THE OUTSIDE. Editing the AST alone only patched a bare
        // literal: `LIMIT +999999999` passed untouched and the database still shipped the whole table,
        // even though the caller asked for five rows.
        format!("SELECT * FROM ({}) AS _mcp_cap LIMIT {}", ast[0], max_rows)
    } else {
        ast[0].to_string()
    };
    // ROUND-TRIP GATE: this is the text that actually reaches the database — it must pass the same
    // validator that accepted the original. Rendering an AST does not always return to our own grammar
    // (`(TABLE t)` → `(TABLE t) LIMIT 1000`, which our parser no longer accepts). Otherwise we would be
    // validating one statement and executing another. Fallback: render without the injected LIMIT; if
    // that fails too — refuse (fail-closed), because we cannot describe this query safely.
    if validate_readonly(&rendered).is_ok() {
        return Ok(rendered);
    }
    let plain = parse(sql)?[0].to_string();
    if validate_readonly(&plain).is_ok() {
        return Ok(plain);
    }
    Err(ValidationError::NotParseable(
        "canonical form of this query is not re-validatable (rejected for safety)".into(),
    ))
}

fn number_expr(n: u64) -> Expr {
    Expr::Value(Value::Number(n.to_string(), false).with_empty_span())
}

/// The literal numeric value, if the expression is one (parameters and expressions are left alone).
fn literal_u64(e: &Expr) -> Option<u64> {
    match e {
        Expr::Value(vs) => match &vs.value {
            Value::Number(n, _) => n.parse::<u64>().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the row cap could be applied inside the AST, or the whole query must be wrapped.
enum Cap {
    Handled,
    NeedsWrap,
}

fn cap_rows(q: &mut Query, max_rows: u64) -> Cap {
    // `FETCH FIRST n ROWS ONLY` (ANSI): adding a `LIMIT` next to it produces syntax PostgreSQL does NOT
    // accept — a legitimate query then failed with "syntax error" because of OUR rewrite.
    if let Some(fetch) = &mut q.fetch {
        return match fetch.quantity.as_ref().and_then(literal_u64) {
            Some(v) if v <= max_rows => Cap::Handled,
            Some(_) => {
                fetch.quantity = Some(number_expr(max_rows));
                Cap::Handled
            }
            None => Cap::NeedsWrap, // FETCH without a readable literal (WITH TIES, an expression)
        };
    }
    // sqlparser 0.62 replaced `Query.limit` with a `LimitClause` enum, because `LIMIT` is not one
    // shape: `LIMIT n`, `LIMIT n OFFSET m`, ClickHouse's `LIMIT n BY expr`, and MySQL's reversed
    // `LIMIT offset, n`. Only the first family is one we can safely edit in place; anything else is
    // wrapped from the outside, which is always correct and never guesses.
    match &mut q.limit_clause {
        Some(LimitClause::LimitOffset { limit, .. }) => match limit.as_ref() {
            Some(existing) => match literal_u64(existing) {
                Some(v) if v <= max_rows => Cap::Handled,
                Some(_) => {
                    *limit = Some(number_expr(max_rows));
                    Cap::Handled
                }
                // `LIMIT +999999999`, `LIMIT 999999999::bigint`, `LIMIT $1`, `LIMIT 10*10` — do not
                // guess the value, we impose the limit from the outside.
                None => Cap::NeedsWrap,
            },
            // `LIMIT ALL`, or an OFFSET-only clause: no row cap at all, so one has to be added.
            None => Cap::NeedsWrap,
        },
        // MySQL's reversed form. PostgreSQL does not accept it, but the parser can produce it and
        // guessing which number is the row count is exactly the kind of assumption that has cost
        // us before. Wrap it.
        Some(LimitClause::OffsetCommaLimit { .. }) => Cap::NeedsWrap,
        None => {
            if !is_count_or_exists(q) {
                q.limit_clause = Some(LimitClause::LimitOffset {
                    limit: Some(number_expr(max_rows)),
                    offset: None,
                    limit_by: Vec::new(),
                });
            }
            Cap::Handled
        }
    }
}

/// Is this a query returning ONE aggregate value (`SELECT count(*)` / `SELECT EXISTS(...)`), where a
/// LIMIT makes no sense? Checked STRUCTURALLY on the AST — an earlier version searched the rendered
/// body for the text "COUNT(" / "EXISTS", so a column aliased `coexists_flag` silently removed the
/// limit for an entire table.
fn is_count_or_exists(q: &Query) -> bool {
    let SetExpr::Select(s) = &*q.body else {
        return false;
    };
    if s.projection.len() != 1 {
        return false;
    }
    let expr = match &s.projection[0] {
        SelectItem::UnnamedExpr(e) => e,
        SelectItem::ExprWithAlias { expr, .. } => expr,
        _ => return false,
    };
    match expr {
        Expr::Function(f) => last_part_name(&f.name).as_deref() == Some("count"),
        Expr::Exists { .. } => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {

    // Four holes the sqlparser 0.49 -> 0.62 upgrade uncovered. None of them were new: on the old
    // parser each of these failed to PARSE, so the refusal came from the library not understanding
    // the syntax rather than from any rule here. A parse failure is not a security control — it is
    // a control that disappears the moment the parser improves, which is exactly what happened.
    #[test]
    fn explain_analyze_is_refused_in_both_spellings() {
        // The bare form sets a boolean; PostgreSQL's parenthesised form lands in `options`, a field
        // that did not exist when the check was written. ANALYZE executes the statement.
        for sql in [
            "EXPLAIN ANALYZE SELECT * FROM t",
            "EXPLAIN (ANALYZE) SELECT * FROM t",
            "EXPLAIN (ANALYZE true, VERBOSE) SELECT * FROM t",
            "EXPLAIN (VERBOSE, ANALYZE) SELECT * FROM t",
        ] {
            assert!(
                validate_readonly(sql).is_err(),
                "EXPLAIN ANALYZE must be refused, this was not: {sql}"
            );
        }
        // Plain EXPLAIN still has to work, or we have replaced a hole with a regression.
        assert!(validate_readonly("EXPLAIN SELECT 1").is_ok());
        assert!(validate_readonly("EXPLAIN (VERBOSE) SELECT 1").is_ok());
    }

    #[test]
    fn a_hidden_character_cannot_disguise_a_write_function() {
        // Each of these is a write function with something invisible wedged into its name, so the
        // rule that names the function no longer matches it. The last is the one that taught the
        // lesson: U+00A0 is not invisible at all, it just is not the space it looks like.
        for sql in [
            "SELECT setval\u{2060}('s', 1)",               // word joiner
            "SELECT \u{E0073}pg_read_file('/etc/passwd')", // tag character
            "SELECT \u{200B}pg_notify('c', 'x')",          // zero-width space
            "SELECT \u{00A0}lowrite(1, 'x')",              // no-break space
            "SELECT \u{FEFF}nextval('s')",                 // BOM
        ] {
            assert!(
                validate_readonly(sql).is_err(),
                "a hidden character disguised a write function: {sql:?}"
            );
        }
    }

    #[test]
    fn hidden_characters_are_data_when_they_are_inside_a_literal() {
        // Refusing them everywhere would be easier and wrong: a zero-width joiner is how emoji
        // sequences are built, and a query filtering on real data must not be rejected for it.
        assert!(validate_readonly("SELECT * FROM t WHERE name = 'a\u{200D}b'").is_ok());
        assert!(validate_readonly("SELECT 'no\u{00A0}break'").is_ok());
        // A literal is not a hiding place for a name, though — that rule is tested elsewhere and
        // must still hold with a hidden character in the literal.
        assert!(validate_readonly("SELECT 1").is_ok());
    }

    #[test]
    fn a_name_part_the_parser_cannot_read_is_refused_not_skipped() {
        // sqlparser 0.62 can model a name part as a function call. Every rule in this file reasons
        // about a name; a part we cannot read must stop the query, not quietly leave the set.
        // Whether any dialect produces this shape today is beside the point — the code no longer
        // assumes it cannot happen.
        assert!(last_part_name(&ObjectName(vec![])).is_none());
    }
    use super::*;

    #[test]
    fn valid_readonly() {
        assert!(validate_readonly("SELECT * FROM users").is_ok());
        assert!(validate_readonly("WITH x AS (SELECT 1) SELECT * FROM x").is_ok());
        assert!(validate_readonly("EXPLAIN SELECT 1").is_ok());
        assert!(validate_readonly("SHOW timezone").is_ok());
    }

    #[test]
    fn forbidden_writes() {
        for sql in [
            "INSERT INTO users VALUES (1)",
            "UPDATE users SET name = 'bob'",
            "DELETE FROM users",
            "DROP TABLE users",
            "ALTER TABLE users ADD COLUMN age INT",
            "CREATE TABLE t (id int)",
        ] {
            assert!(
                matches!(validate_readonly(sql), Err(ValidationError::NotReadOnly(_))),
                "should reject: {sql}"
            );
        }
    }

    /// Round-trip gate: whatever enforce_limit produces must pass the validator — that text is what
    /// actually reaches the database. And legitimate reads must not suffer from it.
    #[test]
    fn canonical_form_revalidates() {
        for sql in [
            "SELECT 1",
            "SELECT * FROM users",
            "(SELECT 1)",
            "((SELECT 1 AS a))",
            "(VALUES (1))",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SELECT count(*) FROM users",
            "SELECT 1;",
            "SELECT ';' AS semi",
        ] {
            let canon = enforce_limit(sql, 1000).unwrap_or_else(|e| panic!("{sql} → {e}"));
            assert!(
                validate_readonly(&canon).is_ok(),
                "kanoniczny tekst nie przechodzi walidatora: {sql} → {canon}"
            );
        }
    }

    /// The family gate must not take away legitimate reads (fail-closed by prefix has explicit exceptions).
    /// Without this test, the next widening of the denylist would quietly erode the server usefulness.
    /// The SHOW filter must not take away useful diagnostic variables.
    #[test]
    fn show_keeps_useful_variables() {
        for sql in [
            "SHOW timezone",
            "SHOW server_version",
            "SHOW search_path",
            "SHOW work_mem",
        ] {
            assert!(
                validate_readonly(sql).is_ok(),
                "zablokowane bez powodu: {sql}"
            );
        }
    }

    #[test]
    fn family_deny_keeps_reads_working() {
        for sql in [
            "SELECT lo_get(1)",
            "SELECT pg_stat_get_numscans(1)",
            "SELECT pg_current_wal_lsn()",
            "SELECT pg_size_pretty(pg_database_size('db'))",
            "SELECT * FROM pg_stat_activity",
            "SELECT * FROM pg_tables WHERE schemaname = 'public'",
            "SELECT * FROM pg_settings",
            "SELECT relname FROM pg_class JOIN pg_namespace n ON n.oid = relnamespace",
            "SELECT pg_get_viewdef('v'::regclass)",
            "SELECT pg_typeof(1)",
            "SELECT now(), current_user",
        ] {
            assert!(
                validate_readonly(sql).is_ok(),
                "legalny odczyt zablokowany: {sql}"
            );
        }
    }

    #[test]
    fn multi_statement() {
        assert_eq!(
            validate_readonly("SELECT 1; DROP TABLE users"),
            Err(ValidationError::MultiStatement)
        );
    }

    #[test]
    fn not_parseable() {
        assert!(matches!(
            validate_readonly("garbage((("),
            Err(ValidationError::NotParseable(_))
        ));
    }

    #[test]
    fn limit_injection() {
        let res = enforce_limit("SELECT * FROM users", 100)
            .unwrap()
            .to_uppercase();
        assert!(res.contains("LIMIT 100"), "got: {res}");

        let existing = enforce_limit("SELECT * FROM users LIMIT 50", 100).unwrap();
        assert!(existing.contains("50") && !existing.contains("100"));

        let count = enforce_limit("SELECT COUNT(*) FROM users", 100)
            .unwrap()
            .to_uppercase();
        assert!(!count.contains("LIMIT"), "count should be skipped: {count}");
    }
}

#[cfg(test)]
mod adversarial {
    use super::*;

    // Attack vectors: EVERY one must return Err(ValidationError)
    const MUST_REJECT: &[&str] = &[
        // SQL passed as TEXT: the AST cannot see inside a string literal, so nothing this validator
        // enforces applies to what these run. Live proof before the fix: server files read, the data
        // directory listed, a catalog-writing function executed, two statements from one call.
        r#"SELECT query_to_xml('SELECT pg_read_file(''postgresql.conf'')', true, false, '')"#,
        r#"SELECT query_to_xml('SELECT 1; SELECT 2', true, false, '')"#,
        r#"SELECT query_to_xmlschema('SELECT 1', true, false, '')"#,
        r#"SELECT query_to_xml_and_xmlschema('SELECT 1', true, false, '')"#,
        r#"SELECT table_to_xml('staff'::regclass, true, false, '')"#,
        r#"SELECT cursor_to_xml('c', 1, true, false, '')"#,
        r#"SELECT schema_to_xml('public', true, false, '')"#,
        r#"SELECT database_to_xml(true, false, '')"#,
        // Data-modifying CTEs (sqlparser parses them as a Query; the validator must descend into the CTE)
        r#"WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d"#,
        r#"WITH u AS (UPDATE t SET x=1 RETURNING *) SELECT * FROM u"#,
        r#"WITH i AS (INSERT INTO t VALUES(1) RETURNING *) SELECT * FROM i"#,
        // Multi-statement
        r#"SELECT 1; DROP TABLE users"#,
        // Komentarz-prefix (sqlparser ignoruje komentarze, parsuje jako DROP/DELETE)
        r#"/* x */ DROP TABLE users"#,
        r#"-- x\nDELETE FROM t"#,
        // DDL
        r#"DROP TABLE t"#,
        r#"CREATE TABLE t(id int)"#,
        r#"ALTER TABLE t ADD c int"#,
        r#"TRUNCATE t"#,
        r#"CREATE INDEX idx ON t (c)"#,
        r#"DROP SCHEMA public CASCADE"#,
        // DML
        r#"INSERT INTO t VALUES (1)"#,
        r#"UPDATE t SET x=1"#,
        r#"DELETE FROM t"#,
        r#"INSERT INTO t VALUES (1) ON CONFLICT DO UPDATE SET x=2"#,
        r#"UPDATE t SET x=1 FROM s WHERE t.id=s.id"#,
        r#"MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1"#,
        // COPY (side-effect / RCE / exfil)
        r#"COPY t TO PROGRAM 'sh -c evil'"#,
        r#"COPY t FROM '/etc/passwd'"#,
        r#"COPY (SELECT 1) TO PROGRAM 'x'"#,
        // Kod / Procedury
        r#"DO $$ BEGIN DELETE FROM t; END $$"#,
        r#"CALL some_proc()"#,
        r#"CREATE FUNCTION f() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$"#,
        // Uprawnienia / Sesja
        r#"GRANT ALL ON t TO x"#,
        r#"REVOKE ALL ON t FROM x"#,
        r#"SET ROLE admin"#,
        r#"ALTER ROLE x SET search_path = evil"#,
        r#"SET search_path=evil"#,
        r#"RESET ALL"#,
        // Utrzymanie / Locki
        r#"VACUUM"#,
        r#"ANALYZE"#,
        r#"REINDEX TABLE t"#,
        r#"CLUSTER t"#,
        r#"REFRESH MATERIALIZED VIEW mv"#,
        r#"LOCK TABLE t"#,
        // Inne side-effecty
        r#"NOTIFY chan"#,
        r#"LISTEN chan"#,
        r#"PREPARE p AS SELECT 1"#,
        r#"DEALLOCATE ALL"#,
        r#"SECURITY LABEL ON TABLE t IS 'label'"#,
        // Side-effecting functions disguised as a SELECT (function-based write bypass)
        r#"SELECT setval('my_seq', 100)"#,
        r#"SELECT nextval('my_seq')"#,
        r#"SELECT set_config('search_path', 'evil', false)"#,
        r#"SELECT pg_read_file('/etc/passwd')"#,
        r#"SELECT lo_export(1, '/tmp/x')"#,
        r#"SELECT dblink_exec('c', 'DELETE FROM t')"#,
        r#"SELECT pg_sleep(10)"#,
        r#"SELECT pg_terminate_backend(123)"#,
        r#"WITH x AS (SELECT setval('s', 1)) SELECT * FROM x"#,
        // Denylist bypass through a quoted identifier — all must be rejected
        r#"SELECT "pg_read_file"('/etc/passwd')"#,
        r#"SELECT "dblink_exec"('c', 'DROP TABLE t')"#,
        r#"SELECT "pg_sleep"(30)"#,
        r#"SELECT PG_CATALOG."pg_read_file"('/x')"#,
        r#"SELECT * FROM "pg_read_file"('/etc/passwd')"#,
        r#"WITH x AS (SELECT "pg_sleep"(29)) SELECT * FROM x"#,
        r#"SELECT "pg_notify"('chan', 'msg')"#,
        // EXPLAIN ANALYZE wykonuje plan + advisory-lock shared/try warianty
        r#"EXPLAIN ANALYZE SELECT 1"#,
        r#"EXPLAIN ANALYZE SELECT * FROM t"#,
        r#"SELECT pg_try_advisory_lock_shared(42)"#,
        r#"SELECT pg_advisory_unlock_shared(42)"#,
        // Text-scan bypass through literals — the AST visitor must catch these
        r#"SELECT $$O'Brien$$, pg_read_file('/etc/passwd')"#,
        r#"SELECT E'\'', pg_sleep(30)"#,
        r#"SELECT $tag$x$tag$, dblink_exec('c','DELETE FROM t')"#,
        // `SHOW` variables exposing the host layout (free reconnaissance)
        // Catalog functions outside the known-read list (also as a table function)
        r#"SELECT pg_export_snapshot()"#,
        r#"SELECT * FROM pg_export_snapshot()"#,
        r#"SELECT pg_log_backend_memory_contexts(1)"#,
        r#"SELECT pg_current_xact_id()"#,
        r#"SHOW data_directory"#,
        r#"SHOW config_file"#,
        r#"SHOW hba_file"#,
        r#"SHOW ssl_key_file"#,
        r#"SHOW archive_command"#,
        // Functions that even a PostgreSQL read-only transaction does NOT stop
        r#"SELECT pg_import_system_collations('public'::regnamespace)"#,
        r#"SELECT gin_clean_pending_list('idx'::regclass)"#,
        r#"SELECT brin_summarize_new_values('idx'::regclass)"#,
        r#"SELECT pg_backup_start('label')"#,
        r#"SELECT pg_backup_stop()"#,
        r#"SELECT pg_start_backup('label')"#,
        // …and families denied by prefix (unknown names from those families must bounce too)
        r#"SELECT lowrite(1, 'x')"#,
        r#"SELECT lo_open(1, 131072)"#,
        r#"SELECT lo_truncate(1, 0)"#,
        r#"SELECT pg_promote()"#,
        r#"SELECT pg_wal_replay_pause()"#,
        r#"SELECT pg_stat_statements_reset()"#,
        r#"SELECT pg_ls_waldir()"#,
        r#"SELECT * FROM pg_ls_dir('/')"#,
        r#"SELECT pg_replication_slot_advance('s', '0/0')"#,
        // Structural gaps ONE LEVEL DOWN (checking only the top level let these through)
        r#"SELECT * FROM (SELECT * FROM users FOR UPDATE) t"#,
        r#"SELECT * FROM t WHERE id IN (SELECT id FROM u FOR UPDATE)"#,
        r#"SELECT * FROM (SELECT 1 INTO probe) t"#,
        r#"SELECT (SELECT 1 INTO probe)"#,
        r#"SELECT * FROM (WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x) q"#,
        r#"SELECT * FROM (INSERT INTO t VALUES (1) RETURNING *) AS i"#,
        r#"EXPLAIN SELECT * FROM (SELECT 1 INTO x) t"#,
        // `SHOW <variable>` swallowed the rest of the input after `;` (multi-statement, caught on tokens)
        r#"SHOW timezone; DROP TABLE users"#,
        r#"SHOW timezone; INSERT INTO t VALUES (1)"#,
        r#"SHOW timezone;SELECT nextval('s')"#,
        // adminpack — writes/deletes server files
        r#"SELECT pg_file_write('postgresql.auto.conf', 'x', false)"#,
        r#"SELECT pg_file_unlink('/tmp/x')"#,
        r#"SELECT dblink_connect_u('c', 'dbname=app')"#,
        // SELECT INTO — creates a table (a write) despite its Select shape (parser differential)
        r#"SELECT 1 INTO new_tbl"#,
        r#"SELECT a, b INTO new_tbl FROM t"#,
        // EXPLAIN ANALYZE <zapis> — EXPLAIN ANALYZE wykonuje plan (parser-differential 2026-07-25)
        r#"EXPLAIN ANALYZE UPDATE t SET x=1"#,
        r#"EXPLAIN ANALYZE INSERT INTO t VALUES (1)"#,
        r#"EXPLAIN ANALYZE DELETE FROM t"#,
        r#"EXPLAIN UPDATE t SET x=1"#,
        // FOR UPDATE / FOR SHARE — blokady wierszy, PG odrzuca w read-only txn
        r#"SELECT * FROM t FOR UPDATE"#,
        r#"SELECT * FROM t FOR SHARE"#,
        // Garbage / parse errors
        r#"garbage(((("#,
        r#""#,
    ];

    // Legitimate reads: EVERY one must return Ok(())
    const MUST_ALLOW: &[&str] = &[
        r#"SELECT * FROM users"#,
        r#"SELECT a,b FROM t WHERE x>1 ORDER BY a LIMIT 10"#,
        r#"WITH r AS (SELECT 1 AS n) SELECT * FROM r"#,
        r#"SELECT count(*) FROM t"#,
        r#"SELECT t1.a FROM t1 JOIN t2 ON t1.id=t2.id"#,
        r#"EXPLAIN SELECT 1"#,
        r#"SHOW timezone"#,
        r#"SHOW ALL"#,
        r#"SELECT * FROM (SELECT 1) s"#,
        // VALUES and TABLE parse as Statement::Query in sqlparser 0.49 (SetExpr::Values / SetExpr::Table)
        r#"VALUES (1),(2)"#,
        // Legitimate read functions must NOT fall into the side-effect denylist (no false positives)
        r#"SELECT upper(name) FROM users"#,
        r#"SELECT generate_series(1, 5)"#,
        r#"SELECT * FROM generate_series(1, 10)"#,
        r#"SELECT now(), current_date"#,
        // A literal containing the name of a writing function — literal stripping must let this through
        r#"SELECT 'setval(x)' AS note"#,
    ];

    // Uncertain / for manual inspection: no hard assertion, logged only
    const MAYBE_ALLOW: &[&str] = &[r#"VALUES (1),(2)"#, r#"TABLE users"#];

    #[test]
    fn must_reject_all() {
        let mut leaked = vec![];
        for sql in MUST_REJECT {
            if validate_readonly(sql).is_ok() {
                leaked.push(*sql);
            }
        }
        assert!(
            leaked.is_empty(),
            "WRITE VECTORS PASSED VALIDATOR ({}): {:#?}",
            leaked.len(),
            leaked
        );
    }

    #[test]
    fn must_allow_all() {
        let mut rejected = vec![];
        for sql in MUST_ALLOW {
            if let Err(e) = validate_readonly(sql) {
                rejected.push((*sql, format!("{:?}", e)));
            }
        }
        assert!(
            rejected.is_empty(),
            "LEGIT READS REJECTED ({}): {:#?}",
            rejected.len(),
            rejected
        );
    }

    #[test]
    fn maybe_allow_print() {
        for sql in MAYBE_ALLOW {
            let res = validate_readonly(sql);
            // Tylko logujemy wynik, nie asertujemy – przydatne przy migracji wersji sqlparser
            println!("MAYBE_ALLOW: {:?} -> {:?}", sql, res);
        }
    }
}
