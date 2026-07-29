//! Generates the database role this server should connect as.
//!
//! The start-up gate refuses to expose a role that can write. A refusal without a way out is a dead
//! end, so this is the way out: it prints the DDL that creates a role which cannot write, cannot
//! bypass row-level security, and can read only what the operator names.
//!
//! It **prints**. It never executes. Applying this needs administrative rights, and a tool whose
//! entire identity is "read-only" has no business holding an administrator's password — that would
//! also create exactly the credential path we tell people to avoid. The operator runs it with their
//! own `psql`, having read it.

use crate::query_catalog;

/// PostgreSQL identifier quoting: doubles internal quotes and always quotes, so a name with capitals,
/// spaces or a quote character cannot change the meaning of the statement it lands in.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Refuses names that have no business being identifiers before they reach `quote_ident`.
/// Quoting alone is enough for safety; this exists so a typo produces a message rather than a role
/// called `"; DROP TABLE"`.
/// Escapes a value that goes inside a single-quoted SQL string literal.
///
/// `quote_ident` is the wrong tool here and the difference is not cosmetic: an identifier lives
/// between double quotes, a literal between single ones, and a name that is safe as one can end the
/// other. Hand-rolling `replace('\'', "''")` at each site is how one site ends up without it.
fn quote_literal(value: &str) -> String {
    value.replace('\'', "''")
}

/// Names this tool will put into generated SQL.
///
/// The escaping below is what makes the output safe; this check is the second lock. A role or schema
/// name carrying a quote, a semicolon or a backslash is far likelier to be an injection attempt than
/// a name someone meant — and this SQL is run by a superuser, where being wrong once is enough.
fn sane_ident(name: &str) -> Result<&str, String> {
    if name.is_empty() || name.len() > 63 {
        return Err(format!(
            "{:?} is not a usable identifier (1-63 characters)",
            name
        ));
    }
    if name.contains(['\0', '\n', '\r', '"', '\'', ';', '\\']) {
        return Err(format!(
            "{:?} contains characters an identifier may not",
            name
        ));
    }
    Ok(name)
}

struct Opts {
    role: String,
    schemas: Vec<String>,
    tables: Vec<String>,
    redact: Vec<String>,
    database: Option<String>,
    owner: String,
}

fn csv(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default()
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
}

/// One relation the role should be able to read, with the columns it may see.
struct Grant {
    schema: String,
    table: String,
    /// `None` = grant the whole table; `Some(cols)` = only these (because some column is redacted).
    columns: Option<Vec<String>>,
    hidden: Vec<String>,
}

pub(crate) fn run(args: &[String]) -> i32 {
    let opts = Opts {
        role: flag(args, "--role")
            .cloned()
            .unwrap_or_else(|| "mcp_reader".into()),
        schemas: {
            let s = csv(flag(args, "--schemas"));
            if s.is_empty() {
                csv(std::env::var("MCP_ALLOW_SCHEMAS").ok().as_ref())
            } else {
                s
            }
        },
        tables: csv(flag(args, "--tables")),
        redact: {
            let r = csv(flag(args, "--redact"));
            if r.is_empty() {
                csv(std::env::var("MCP_REDACT_COLUMNS").ok().as_ref())
            } else {
                r
            }
        },
        database: flag(args, "--database").cloned(),
        owner: flag(args, "--owner")
            .cloned()
            .unwrap_or_else(|| "postgres".into()),
    };
    let schemas = if opts.schemas.is_empty() {
        vec!["public".to_string()]
    } else {
        opts.schemas.clone()
    };
    for name in std::iter::once(&opts.role)
        .chain(schemas.iter())
        .chain(std::iter::once(&opts.owner))
    {
        if let Err(e) = sane_ident(name) {
            eprintln!("{}", e);
            return 2;
        }
    }

    // Online where possible: without the catalogue we cannot know which columns to re-grant, and a
    // column-level GRANT written from guesswork would hand back the very column it is meant to hide.
    let (grants, db_name, note) = match discover(&schemas, &opts) {
        Ok((g, d)) => (g, d, None),
        Err(e) => (
            Vec::new(),
            opts.database.clone().unwrap_or_else(|| "<DATABASE>".into()),
            Some(e),
        ),
    };

    print!(
        "{}",
        render(&opts, &schemas, &grants, &db_name, note.as_deref())
    );
    0
}

/// Reads the real tables and columns, so the output is applicable rather than illustrative.
fn discover(schemas: &[String], opts: &Opts) -> Result<(Vec<Grant>, String), String> {
    let db_row = query_catalog("SELECT current_database() AS db", &[], None)?;
    let db_name = db_row
        .get("rows")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.get("db"))
        .and_then(|v| v.as_str())
        .unwrap_or("<DATABASE>")
        .to_string();

    const SQL: &str = "SELECT n.nspname AS schema, c.relname AS rel, \
            array_agg(a.attname ORDER BY a.attnum) AS cols \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped \
         WHERE c.relkind IN ('r','p','v','m','f') AND n.nspname = ANY($1) \
         GROUP BY 1, 2 ORDER BY 1, 2";
    let v = query_catalog(SQL, &[&schemas.to_vec()], None)?;
    let empty = vec![];
    let rows = v.get("rows").and_then(|r| r.as_array()).unwrap_or(&empty);

    let redacted: Vec<String> = opts.redact.iter().map(|s| s.to_lowercase()).collect();
    let mut out = Vec::new();
    for r in rows {
        let schema = r
            .get("schema")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let table = r
            .get("rel")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let qualified = format!("{}.{}", schema, table);
        // An explicit --tables list narrows the schemas; `schema.*` keeps the whole schema.
        if !opts.tables.is_empty()
            && !opts.tables.iter().any(|t| {
                t.eq_ignore_ascii_case(&qualified)
                    || t.eq_ignore_ascii_case(&format!("{}.*", schema))
            })
        {
            continue;
        }
        let cols: Vec<String> = r
            .get("cols")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let hidden: Vec<String> = cols
            .iter()
            .filter(|c| redacted.contains(&c.to_lowercase()))
            .cloned()
            .collect();
        let keep: Vec<String> = cols
            .iter()
            .filter(|c| !redacted.contains(&c.to_lowercase()))
            .cloned()
            .collect();
        out.push(Grant {
            schema,
            table,
            columns: if hidden.is_empty() { None } else { Some(keep) },
            hidden,
        });
    }
    Ok((out, db_name))
}

fn render(
    opts: &Opts,
    schemas: &[String],
    grants: &[Grant],
    db_name: &str,
    offline: Option<&str>,
) -> String {
    let role = quote_ident(&opts.role);
    let mut s = String::new();
    s.push_str(
        "-- Role for postgres-mcp-hardened. READ THIS BEFORE RUNNING IT: it changes privileges.\n",
    );
    s.push_str("--   psql -v pw=\"$(openssl rand -base64 24)\" -f setup.sql\n");
    if let Some(why) = offline {
        s.push_str(&format!(
            "--\n-- NOTE: generated WITHOUT reading the database ({}), so table and column lists are\n\
             -- placeholders. Run this again with DATABASE_URL set and they will be filled in — that\n\
             -- matters most for redaction, where the columns to re-grant must come from the catalogue.\n",
            why
        ));
    }
    s.push_str("\n-- 1. A role that inherits nothing, bypasses nothing, creates nothing.\n");
    s.push_str(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD :'pw'\n  \
         NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION\n  \
         CONNECTION LIMIT 16;\n"
    ));

    s.push_str("\n-- 2. Limits the database enforces even if the client never sets them.\n");
    for (k, v) in [
        ("statement_timeout", "30s"),
        ("idle_in_transaction_session_timeout", "10s"),
        ("lock_timeout", "2s"),
    ] {
        s.push_str(&format!("ALTER ROLE {role} SET {k} = '{v}';\n"));
    }
    s.push_str(&format!(
        "ALTER ROLE {role} SET default_transaction_read_only = on;\n"
    ));
    s.push_str(&format!(
        "ALTER ROLE {role} SET search_path = '{}';\n",
        quote_literal(&schemas.join(","))
    ));

    s.push_str("\n-- 3. Nothing by default. USAGE on the schema, not CREATE.\n");
    s.push_str(&format!(
        "GRANT CONNECT ON DATABASE {} TO {role};\n",
        quote_ident(db_name)
    ));
    for sc in schemas {
        s.push_str(&format!(
            "REVOKE ALL ON SCHEMA {0} FROM {role};\nGRANT USAGE ON SCHEMA {0} TO {role};\n",
            quote_ident(sc)
        ));
    }

    s.push_str("\n-- 4. The surface, named one relation at a time.\n");
    s.push_str(
        "--    Deliberately not `GRANT SELECT ON ALL TABLES`: that grants whatever exists at the\n",
    );
    s.push_str("--    moment you run it, which is not the same as what you meant.\n");
    if grants.is_empty() {
        s.push_str(&format!(
            "GRANT SELECT ON <SCHEMA>.<TABLE> TO {role};   -- repeat per table\n"
        ));
    }
    for g in grants.iter().filter(|g| g.columns.is_none()) {
        s.push_str(&format!(
            "GRANT SELECT ON {}.{} TO {role};\n",
            quote_ident(&g.schema),
            quote_ident(&g.table)
        ));
    }

    let redacting: Vec<&Grant> = grants.iter().filter(|g| g.columns.is_some()).collect();
    if !redacting.is_empty() || !opts.redact.is_empty() {
        s.push_str("\n-- 5. Sensitive columns, revoked so that PostgreSQL enforces it.\n");
        s.push_str("--    A bare `REVOKE SELECT (col) ON t` is SILENTLY A NO-OP while the role holds SELECT\n");
        s.push_str("--    on the whole table. The table-level REVOKE has to come first, then a GRANT of the\n");
        s.push_str("--    columns that stay. Consequence: PostgreSQL then refuses `SELECT *` on that table,\n");
        s.push_str("--    so callers name columns — describe_table lists them and marks the missing one.\n");
    }
    for g in redacting {
        let keep = g
            .columns
            .as_ref()
            .map(|c| {
                c.iter()
                    .map(|x| quote_ident(x))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        s.push_str(&format!(
            "REVOKE SELECT ON {0}.{1} FROM {role};\n",
            quote_ident(&g.schema),
            quote_ident(&g.table)
        ));
        if keep.is_empty() {
            s.push_str(&format!(
                "-- every column of {}.{} is redacted; no GRANT follows, on purpose\n",
                g.schema, g.table
            ));
        } else {
            s.push_str(&format!(
                "GRANT SELECT ({keep}) ON {0}.{1} TO {role};   -- hidden: {2}\n",
                quote_ident(&g.schema),
                quote_ident(&g.table),
                g.hidden.join(", ")
            ));
        }
    }

    s.push_str("\n-- 6. Tables created later must not appear by themselves.\n");
    s.push_str("--    FOR ROLE matters: default privileges are recorded per granting role, so without it\n");
    s.push_str("--    you set a rule for yourself while the tables are created by someone else.\n");
    for sc in schemas {
        s.push_str(&format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} REVOKE ALL ON TABLES FROM {role};\n",
            quote_ident(&opts.owner),
            quote_ident(sc)
        ));
    }

    s.push_str("\n-- 7. Check it did what you think. Each of these should return no rows.\n");
    s.push_str(&format!(
        "SELECT 'still privileged' AS problem, rolname FROM pg_roles\n \
         WHERE rolname = '{0}' AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication);\n",
        quote_literal(&opts.role)
    ));
    s.push_str(&format!(
        "SELECT 'owns a relation (owners bypass column grants and RLS)' AS problem, c.relname\n \
         FROM pg_class c WHERE c.relowner = '{0}'::regrole;\n",
        quote_literal(&opts.role)
    ));
    if !opts.redact.is_empty() {
        s.push_str("-- and the column that must stay hidden, asked as the role itself:\n");
        s.push_str("--   SET ROLE ");
        s.push_str(&role);
        s.push_str("; SELECT <redacted column> FROM <table>;   -- expect SQLSTATE 42501\n");
    }
    s.push_str("\n-- 8. Point the server at it, then confirm from the other side:\n");
    s.push_str(&format!(
        "--   DATABASE_URL=postgres://{}:...@host:5432/{} postgres-mcp-hardened\n",
        opts.role, db_name
    ));
    s.push_str("--   the server prints what the role may do, and refuses a network listener if it may write.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_quoted_not_interpolated() {
        assert_eq!(quote_ident("orders"), "\"orders\"");
        assert_eq!(quote_ident("Weird Name"), "\"Weird Name\"");
        // A quote inside a name is doubled, so it cannot end the identifier and start something else.
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn hostile_role_names_are_refused_before_they_reach_sql() {
        assert!(sane_ident("mcp_reader").is_ok());
        assert!(sane_ident("").is_err());
        assert!(sane_ident("x\"; DROP TABLE users; --").is_err());
        assert!(sane_ident(&"a".repeat(64)).is_err());
    }

    /// The whole point of the redaction section: the table-level REVOKE must precede the column GRANT,
    /// because the other order is silently a no-op.
    #[test]
    fn redaction_revokes_the_table_before_granting_columns() {
        let opts = Opts {
            role: "r".into(),
            schemas: vec!["public".into()],
            tables: vec![],
            redact: vec!["ssn".into()],
            database: None,
            owner: "postgres".into(),
        };
        let grants = vec![Grant {
            schema: "public".into(),
            table: "people".into(),
            columns: Some(vec!["id".into(), "name".into()]),
            hidden: vec!["ssn".into()],
        }];
        let out = render(&opts, &opts.schemas.clone(), &grants, "db", None);
        let revoke = out
            .find("REVOKE SELECT ON \"public\".\"people\"")
            .expect("revoke");
        let grant = out
            .find("GRANT SELECT (\"id\", \"name\")")
            .expect("column grant");
        assert!(revoke < grant, "the table REVOKE must come first:\n{out}");
        assert!(
            !out.contains("\"ssn\""),
            "the hidden column is never granted"
        );
    }
}

#[cfg(test)]
mod injection_tests {
    use super::*;

    /// The generated file is run by a superuser. A name that closes the string literal it sits in
    /// turns "here is a script that creates a read-only role" into arbitrary DDL, and the operator
    /// pasting it has no reason to read 60 lines of SQL first.
    #[test]
    fn a_name_that_closes_a_literal_is_refused() {
        for payload in [
            "public'; DROP DATABASE postgres; --",
            "public'",
            "public; DROP SCHEMA public CASCADE",
            "back\\slash",
        ] {
            assert!(
                sane_ident(payload).is_err(),
                "accepted a name that has no business in generated SQL: {payload:?}"
            );
        }
    }

    /// Ordinary names still work, or the check above would be satisfied by refusing everything.
    #[test]
    fn ordinary_names_still_pass() {
        for ok in [
            "public",
            "app_reader",
            "Sales2026",
            "schema-with-dash",
            "zażółć",
        ] {
            assert!(sane_ident(ok).is_ok(), "rejected a legitimate name: {ok:?}");
        }
    }

    /// Escaping is the fix; the character check is the second lock. This asserts the fix itself, so
    /// loosening the check later cannot quietly reopen the hole.
    #[test]
    fn a_literal_is_escaped_not_merely_rejected() {
        assert_eq!(
            quote_literal("public'; DROP DATABASE postgres; --"),
            "public''; DROP DATABASE postgres; --"
        );
        assert_eq!(quote_literal("plain"), "plain");
    }
}
