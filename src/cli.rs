//! Command-line surface: answer `--help` and `--version`, refuse anything we do not recognise.
//!
//! The server reads its configuration from the environment; the command line only selects a mode.
//! That makes the set of valid options small and closed, which is exactly the shape where "scan for
//! what I know, ignore the rest" is indefensible: an unrecognised option is always a mistake, and
//! the mistake is silent in the worst way — `--stdi` starts a network listener instead of a stdio
//! server, and the client that spawned us waits forever for a handshake on a pipe nobody is writing.

/// Every option the binary understands, including the ones consumed by `--print-setup-sql`.
///
/// One list, in one place. The previous behaviour spread the knowledge across a dozen
/// `position(|a| a == "--x")` calls, so "which options exist" was answerable only by reading all of
/// `main`. A test asserts this list against those call sites, so adding a flag without listing it
/// here fails the build rather than a user's day.
pub(crate) const KNOWN: &[&str] = &[
    "--stdio",
    "--validate",
    "--canon",
    "--fuzz",
    "--verify-audit",
    "--expect-last",
    "--print-setup-sql",
    "--role",
    "--schemas",
    "--tables",
    "--redact",
    "--database",
    "--owner",
];

const USAGE: &str = "\
postgres-mcp-hardened — read-only PostgreSQL MCP server

  postgres-mcp-hardened --stdio        speak MCP over stdin/stdout (what an MCP client spawns)
  postgres-mcp-hardened                serve Streamable HTTP on MCP_ADDR (default 127.0.0.1:8080)

  --validate <sql>                     print the validator's verdict for one statement
  --canon <sql>                        print the text that would actually reach the database
  --verify-audit <path> [--expect-last <hash>]
                                       check the audit log's hash chain against an off-host anchor
  --print-setup-sql [--role R] [--schemas S] [--tables T] [--redact C] [--database D] [--owner O]
                                       print the SQL that creates a least-privilege role
  --fuzz [iterations] [seed]           deterministic validator fuzz; exits 1 on a violation

  -h, --help                           this text
  -V, --version                        version of this binary

Configuration is environment-driven; DATABASE_URL is required to serve.
Reference: https://github.com/Eszetael/postgres-mcp-hardened";

/// `Some(exit_code)` when the caller should stop here, `None` to carry on into normal startup.
pub(crate) fn handle_or_refuse(args: &[String]) -> Option<i32> {
    let opts = || {
        args.iter()
            .skip(1)
            .filter(|a| a.starts_with("--") || a.starts_with('-'))
    };

    if opts().any(|a| a == "-h" || a == "--help") {
        println!("{}", USAGE);
        return Some(0);
    }
    if opts().any(|a| a == "-V" || a == "--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Some(0);
    }

    // Only long options are checked. Values are positional and may legitimately look like anything —
    // an SQL statement passed to `--validate` can begin with a dash, and refusing it would break a
    // documented call. We therefore skip the argument that follows an option which takes a value.
    let takes_value = |a: &str| {
        matches!(
            a,
            "--validate"
                | "--canon"
                | "--verify-audit"
                | "--expect-last"
                | "--role"
                | "--schemas"
                | "--tables"
                | "--redact"
                | "--database"
                | "--owner"
        )
    };
    let mut skip_next = false;
    let mut unknown: Vec<&str> = Vec::new();
    for a in args.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a.starts_with("--") {
            if !KNOWN.contains(&a.as_str()) {
                unknown.push(a);
            } else if takes_value(a) {
                skip_next = true;
            }
        }
    }
    if !unknown.is_empty() {
        eprintln!(
            "unknown option {}\n\nThis server ignores nothing it was given: an option it does not \
             recognise is a mistake, and a mistake in --stdio would otherwise open a network \
             listener instead of speaking over the pipe.\n\n{}",
            unknown.join(", "),
            USAGE
        );
        return Some(2);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        std::iter::once("postgres-mcp-hardened")
            .chain(args.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn help_and_version_answer_instead_of_starting_a_server() {
        assert_eq!(handle_or_refuse(&v(&["--help"])), Some(0));
        assert_eq!(handle_or_refuse(&v(&["-h"])), Some(0));
        assert_eq!(handle_or_refuse(&v(&["--version"])), Some(0));
        assert_eq!(handle_or_refuse(&v(&["-V"])), Some(0));
    }

    #[test]
    fn a_typo_in_stdio_is_refused_not_turned_into_a_listener() {
        // The whole reason this module exists.
        assert_eq!(handle_or_refuse(&v(&["--stdi"])), Some(2));
        assert_eq!(handle_or_refuse(&v(&["--std"])), Some(2));
        assert_eq!(handle_or_refuse(&v(&["--nonsense"])), Some(2));
    }

    #[test]
    fn every_documented_mode_still_starts() {
        for mode in [
            vec!["--stdio"],
            vec![],
            vec!["--print-setup-sql", "--role", "r", "--schemas", "public"],
            vec!["--fuzz", "1000", "7"],
            vec!["--verify-audit", "/tmp/a.log", "--expect-last", "abc"],
        ] {
            assert_eq!(
                handle_or_refuse(&v(&mode)),
                None,
                "mode {:?} must run",
                mode
            );
        }
    }

    #[test]
    fn a_value_that_looks_like_an_option_is_not_refused() {
        // `--validate` takes SQL, and SQL can start with a dash (a comment, or a negative number in
        // an expression). Treating the value as an option would refuse a documented call.
        assert_eq!(handle_or_refuse(&v(&["--validate", "--x"])), None);
        assert_eq!(handle_or_refuse(&v(&["--canon", "-- comment"])), None);
    }

    #[test]
    fn the_list_covers_every_flag_main_actually_looks_for() {
        // Drift guard: a flag added to `main` without being listed here would be refused for the
        // user who reads the documentation and passes it.
        let src = include_str!("main.rs");
        let mut missing = Vec::new();
        for (i, _) in src.match_indices("\"--") {
            let rest = &src[i + 1..];
            if let Some(end) = rest.find('"') {
                let flag = &rest[..end];
                if flag.starts_with("--") && !KNOWN.contains(&flag) {
                    missing.push(flag.to_string());
                }
            }
        }
        assert!(
            missing.is_empty(),
            "flags in main.rs missing from KNOWN: {:?}",
            missing
        );
    }
}
