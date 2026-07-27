#!/bin/sh
# Reads the whole of src/, not one file. It used to grep src/main.rs, which was true only while
# every declaration happened to live there; splitting that file made this gate report twenty
# false failures. A check pinned to a filename tests the layout, not the claim.
# Control A: Ensure every "verified" claim in docs references an existing acceptance test or unit test.
# Control B: Keep documented environment variables in sync with the canonical list in source code.

fail=0
tmpdir=$(mktemp -d) || exit 1
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# CONTROL A
for file in README.md SECURITY.md CHANGELOG.md docs/COMMUNITY_ISSUES.md; do
    [ -f "$file" ] || continue
    # The MARKER, not the word. "certificates are always verified" is prose about TLS, not a claim
    # that a test exists; matching every occurrence produced noise, and a check that cries wolf is a
    # check people switch off. Our convention is the italic/bold marker.
    grep -n -E '\*\*?verified\*\*?' "$file" > "$tmpdir/verified.txt" 2>/dev/null || continue
    while IFS=: read -r lineno line; do
        acceptance_text=$(echo "$line" | sed -n 's/.*(acceptance: "\([^"]*\)").*/\1/p')
        if [ -n "$acceptance_text" ]; then
            # Across every suite, not only acceptance.sh: TLS and the adversarial corpus live in
            # their own files, and a claim proved there is proved just as well.
            if ! grep -Fq "$acceptance_text" tests/*.sh tests/adversarial/*.sh 2>/dev/null; then
                printf 'FAIL %s:%s: %.80s\n' "$file" "$lineno" "$line"
                fail=1
            fi
            continue
        fi
        test_name=$(echo "$line" | sed -n 's/.*(test: \([^)]*\)).*/\1/p')
        if [ -n "$test_name" ]; then
            if ! grep -Fq "$test_name" src/*.rs 2>/dev/null; then
                printf 'FAIL %s:%s: %.80s\n' "$file" "$lineno" "$line"
                fail=1
            fi
            continue
        fi
        printf 'FAIL %s:%s: %.80s\n' "$file" "$lineno" "$line"
        fail=1
    done < "$tmpdir/verified.txt"
done

# CONTROL B
cat src/*.rs 2>/dev/null | sed -n '/const KNOWN_VARS/,/];/p' | sed -n 's/.*"\([^"]*\)".*/\1/p' | sort -u > "$tmpdir/known_vars.txt"
# Only the FIRST cell of a table row, and only tokens shaped like an environment variable. Taking
# every backticked word in the line collected defaults, header names and example values as if they
# were settings, and a check that cries wolf is a check people switch off.
# A settings row is one whose first cell holds NOTHING but backticked names (and separators).
# `INVALID_URL` with special characters in the password  is a row about an error message, not a
# setting, and counting it as one produced a failure that was our regex's fault, not the docs'.
grep '^| *`' README.md 2>/dev/null \
  | sed 's/^\(|[^|]*\).*/\1/' \
  | sed 's/^| *//; s/ *$//' \
  | awk '{ probe = $0; gsub(/`[A-Z][A-Z0-9_]*`/, "", probe); gsub(/[,\/ ]/, "", probe); if (probe == "") print }' \
  | tr '`' '\n' \
  | grep -E '^[A-Z][A-Z0-9_]+$' \
  | sort -u > "$tmpdir/readme_vars.txt"

comm -23 "$tmpdir/known_vars.txt" "$tmpdir/readme_vars.txt" > "$tmpdir/missing_in_readme.txt"
while read var; do
    [ -n "$var" ] && { printf "FAIL env var '%s' in the source but missing in README.md\n" "$var"; fail=1; }
done < "$tmpdir/missing_in_readme.txt"

comm -13 "$tmpdir/known_vars.txt" "$tmpdir/readme_vars.txt" > "$tmpdir/missing_in_source.txt"
while read var; do
    [ -n "$var" ] && { printf "FAIL env var '%s' in README.md but missing in the source\n" "$var"; fail=1; }
done < "$tmpdir/missing_in_source.txt"

# CONTROL C: the package manifest is the shop window — a client shows its tool list before anyone
# connects. It listed four of eight tools, with descriptions from an earlier version, because nothing
# tied it to the source.
# tool_def( calls span several lines, so match on the flattened text rather than line by line.
cat src/*.rs | tr '\n' ' ' | grep -o 'tool_def( *"[a-z_]*"' | sed 's/.*"\([a-z_]*\)"/\1/' | sort -u > "$tmpdir/src_tools.txt"
sed -n 's/.*"name": "\([a-z_]*\)".*/\1/p' mcpb/manifest.json | sort -u > "$tmpdir/manifest_tools.txt"
comm -23 "$tmpdir/src_tools.txt" "$tmpdir/manifest_tools.txt" | while read -r t; do
    [ -n "$t" ] && printf "FAIL tool '%s' exists in the source but is missing from mcpb/manifest.json\n" "$t"
done
if [ -n "$(comm -23 "$tmpdir/src_tools.txt" "$tmpdir/manifest_tools.txt")" ]; then fail=1; fi
comm -13 "$tmpdir/src_tools.txt" "$tmpdir/manifest_tools.txt" | while read -r t; do
    [ -n "$t" ] && printf "FAIL tool '%s' advertised in mcpb/manifest.json but not in the source\n" "$t"
done
if [ -n "$(comm -13 "$tmpdir/src_tools.txt" "$tmpdir/manifest_tools.txt")" ]; then fail=1; fi

# A placeholder that reaches a published package is worse than a missing field: it looks filled in.
if grep -q '<[A-Z_]*>' mcpb/manifest.json; then
    printf "FAIL mcpb/manifest.json still contains a placeholder\n"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS Control A: every 'verified' claim names a test that exists"
    echo "PASS Control B: the documented settings and the source agree"
    echo "PASS Control C: the package manifest matches the tools that exist"
fi

exit "$fail"