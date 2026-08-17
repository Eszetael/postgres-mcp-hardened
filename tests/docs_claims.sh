#!/bin/sh
# Reads the whole of src/, not one file. It used to grep src/main.rs, which was true only while
# every declaration happened to live there; splitting that file made this gate report twenty
# false failures. A check pinned to a filename tests the layout, not the claim.
# Control A: Ensure every "verified" claim in docs references an existing acceptance test or unit test.
# Control B: Keep documented environment variables in sync with the canonical list in source code.
# Control F: The .mcpb manifest must satisfy the official schema. It did not, from the day it was
#   written until 2026-08-17, because nobody ever packed the bundle — so the one-click install path
#   was broken for its whole life and no test noticed. Control C compares its tool list to ours,
#   which is a different question from "will any client open this".
# Control E: Claims about OTHER people's repositories. Controls A-D all guard statements about our
#   own code, and on 2026-08-16 a review found eight errors — every one of them about something
#   external: a fabricated snippet attributed to the archived server, a mistitled OWASP category,
#   reaction counts that had drifted. Those are the claims a hostile reader checks first, because
#   checking them needs nothing from us.

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

# Control D: every source file the documentation points at must exist.
#
# THREAT_MODEL.md is a table of "which control lives where", which is the most useful thing in it and
# the first thing a refactor breaks silently. Splitting main.rs left one row pointing at a file that
# no longer held that control — the reader would go and look, find nothing, and stop trusting the
# rest of the table. Controls A-C compared claims against behaviour and never noticed, because a
# stale file name is not a wrong claim about the software, it is a wrong claim about the repository.
for f in $(grep -ohE '`[a-z_]+\.rs`' README.md SECURITY.md THREAT_MODEL.md CONTRIBUTING.md 2>/dev/null \
           | tr -d '`' | sort -u); do
    [ -f "src/$f" ] || { printf "FAIL documentation points at src/%s, which does not exist\n" "$f"; fail=1; }
done

# A placeholder that reaches a published package is worse than a missing field: it looks filled in.
if grep -q '<[A-Z_]*>' mcpb/manifest.json; then
    printf "FAIL mcpb/manifest.json still contains a placeholder\n"
    fail=1
fi

# CONTROL E: every issue cited in docs/COMMUNITY_ISSUES.md must exist, and its 👍 count must match.
#
# Two different failures, deliberately treated differently. A cited issue that does not exist is OUR
# mistake and fails the build. A count that has drifted is the WORLD moving — people add and remove
# reactions — so it warns and prints the correction rather than turning the build red for something
# nobody here did. A red build that is not the author's fault teaches people to ignore red builds.
#
# Needs network and a token. Without either it SKIPS loudly: a check that silently does nothing is
# worse than no check, because it reports green.
if [ -z "${GITHUB_TOKEN:-}" ] && [ -f /etc/brain/config.env ]; then
    GITHUB_TOKEN=$(sed -n 's/^GITHUB_TOKEN=//p' /etc/brain/config.env | tr -d '"')
    export GITHUB_TOKEN
fi
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "SKIP Control E: no GITHUB_TOKEN, cannot verify claims about other repositories"
elif ! curl -sf -m 10 -o /dev/null https://api.github.com/rate_limit \
        -H "Authorization: Bearer $GITHUB_TOKEN"; then
    echo "SKIP Control E: GitHub API unreachable"
else
    python3 - "$tmpdir" <<'PYEOF' || fail=1
import io, json, re, sys, time, urllib.request

tok = __import__("os").environ["GITHUB_TOKEN"]
h = {"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json",
     "User-Agent": "docs-claims"}
doc = "docs/COMMUNITY_ISSUES.md"
try:
    text = io.open(doc, encoding="utf-8").read()
except OSError:
    print("FAIL Control E: %s is missing" % doc)
    raise SystemExit(1)

bad, drift, rows = [], [], 0
for line in text.splitlines():
    if not line.startswith("|"):
        continue
    cells = [c.strip() for c in line.strip("|").split("|")]
    if len(cells) < 2:
        continue
    ids = re.findall(r"github\.com/([^/]+)/([^/)]+)/issues/(\d+)", cells[0])
    if not ids:
        continue
    try:
        claimed = int(cells[1])
    except ValueError:
        continue
    rows += 1
    total, missing = 0, False
    for owner, repo, num in ids:
        url = "https://api.github.com/repos/%s/%s/issues/%s" % (owner, repo, num)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=20) as r:
                total += (json.load(r).get("reactions") or {}).get("+1", 0)
        except Exception as e:
            bad.append("%s/%s#%s (%s)" % (owner, repo, num, str(e)[:40]))
            missing = True
        time.sleep(0.1)
    if not missing and total != claimed:
        drift.append("%s: says %d, actually %d" %
                     (", ".join("#" + i[2] for i in ids), claimed, total))

for b in bad:
    print("FAIL Control E: cited issue cannot be reached: %s" % b)
for d in drift:
    print("WARN Control E: reaction count drifted — %s" % d)
if not bad:
    print("PASS Control E: all %d cited external issues exist%s"
          % (rows, " (%d counts drifted, see above)" % len(drift) if drift else ""))
raise SystemExit(1 if bad else 0)
PYEOF
fi

# CONTROL F: the .mcpb manifest against the official schema.
#
# Needs npx. Skips loudly without it, for the same reason as Control E: a check that quietly does
# nothing reports green.
if ! command -v npx >/dev/null 2>&1; then
    echo "SKIP Control F: npx not available, cannot validate the .mcpb manifest"
else
    if out=$(npx -y @anthropic-ai/mcpb validate mcpb/manifest.json 2>&1); then
        echo "PASS Control F: the .mcpb manifest satisfies the official schema"
    else
        printf 'FAIL Control F: mcpb/manifest.json is rejected by the official validator\n%s\n' "$out"
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS Control A: every 'verified' claim names a test that exists"
    echo "PASS Control B: the documented settings and the source agree"
    echo "PASS Control C: the package manifest matches the tools that exist"
    echo "PASS Control D: every source file the documentation points at exists"
fi

exit "$fail"