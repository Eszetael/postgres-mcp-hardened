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

bad, drift, flaky, rows = [], [], [], 0
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
        except urllib.error.HTTPError as e:
            # 404/410 mean the claim is wrong: we cite an issue that is not there. Anything else
            # means GitHub hiccuped, which is not a defect in this repository — and a build turned
            # red by somebody else's 503 teaches people to ignore red builds. One retry, then skip.
            if e.code in (404, 410):
                bad.append("%s/%s#%s (%s)" % (owner, repo, num, e.code))
                missing = True
            else:
                time.sleep(2)
                try:
                    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=20) as r:
                        total += (json.load(r).get("reactions") or {}).get("+1", 0)
                except Exception:
                    flaky.append("%s/%s#%s (HTTP %s)" % (owner, repo, num, e.code))
                    missing = True
        except Exception as e:
            time.sleep(2)
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=20) as r:
                    total += (json.load(r).get("reactions") or {}).get("+1", 0)
            except Exception:
                flaky.append("%s/%s#%s (%s)" % (owner, repo, num, str(e)[:30]))
                missing = True
        time.sleep(0.1)
    if not missing and total != claimed:
        drift.append("%s: says %d, actually %d" %
                     (", ".join("#" + i[2] for i in ids), claimed, total))

for b in bad:
    print("FAIL Control E: cited issue does not exist: %s" % b)
for f in flaky:
    print("WARN Control E: could not reach %s — GitHub, not us; count unchecked this run" % f)
for d in drift:
    print("WARN Control E: reaction count drifted — %s" % d)
if not bad:
    notes = []
    if drift:
        notes.append("%d counts drifted" % len(drift))
    if flaky:
        notes.append("%d unreachable this run" % len(flaky))
    print("PASS Control E: no cited issue is missing%s"
          % (" (%s, see above)" % "; ".join(notes) if notes else ""))
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

# Control G: numbers we quote about OTHER people's npm packages. The README's opening sentence —
# the one directories copy verbatim — said "~476k downloads a month" while npm said 437,210. Nobody
# had lied; the figure was measured once and then quietly aged, which is how every stale claim
# starts. A number about the outside world is only true on the day it is checked, so it gets
# checked. Drift beyond the tolerance is a FAIL, not a warning: the sentence is our lead argument.
#
# Tolerance is 8%. npm download counts move a few percent week to week on their own, and a check
# that fires on ordinary noise gets muted, which costs more than it saves.
grep -oE '[0-9]+k downloads a month' README.md | head -1 > "$tmpdir/claimed" || true
if ! curl -sf -m 15 -o "$tmpdir/npm.json" \
        "https://api.npmjs.org/downloads/point/last-month/@modelcontextprotocol/server-postgres"; then
    echo "WARN Control G: npm unreachable — the download figure went unchecked this run"
else
    python3 - "$tmpdir" <<'PYEOF' || fail=1
import io, json, os, re, sys
d = sys.argv[1]
claimed_raw = io.open(os.path.join(d, "claimed"), encoding="utf-8").read().strip()
if not claimed_raw:
    print("FAIL Control G: README no longer states a download figure in the expected form")
    sys.exit(1)
claimed = int(re.match(r"(\d+)k", claimed_raw).group(1)) * 1000
actual = json.load(io.open(os.path.join(d, "npm.json"), encoding="utf-8"))["downloads"]
drift = abs(claimed - actual) / actual
if drift > 0.08:
    print("FAIL Control G: README claims %s for the archived server, npm reports %s (%.0f%% off)"
          % (claimed_raw, format(actual, ","), drift * 100))
    sys.exit(1)
print("PASS Control G: the download figure matches npm today (%s claimed, %s reported)"
      % (claimed_raw, format(actual, ",")))
PYEOF
fi

# Control H: the four --validate examples in the README are the most-read code this project has —
# the opening section asks a stranger to paste them before installing anything, and each carries its
# expected output in a comment. A README that promises REJECT and delivers ALLOW would do more damage
# than a bug, because it is the demonstration that the guard works at all. So the promised output is
# compared against what the binary actually prints.
BIN_H="${BIN:-target/release/postgres-mcp-hardened}"
if [ ! -x "$BIN_H" ]; then
    echo "SKIP Control H: no release binary at $BIN_H, cannot check the README's --validate examples"
else
    python3 - "$BIN_H" <<'PYEOF' || fail=1
import io, re, subprocess, sys
binary = sys.argv[1]
lines = io.open("README.md", encoding="utf-8").read().splitlines()
pairs, bad = [], 0
for i, ln in enumerate(lines):
    m = re.match(r'^npx postgres-mcp-hardened --validate "(.*)"$', ln.strip())
    if not m:
        continue
    want = ""
    for nxt in lines[i + 1:i + 3]:
        if nxt.startswith("# "):
            want = nxt[2:].strip()
            break
        if nxt.strip():
            break
    if want:
        pairs.append((m.group(1), want))
if not pairs:
    print("FAIL Control H: the README no longer shows any --validate example with its output")
    sys.exit(1)
for sql, want in pairs:
    got = subprocess.run([binary, "--validate", sql], capture_output=True, text=True)
    got = (got.stdout + got.stderr).strip().splitlines()
    got = got[0].strip() if got else "<nic>"
    if got != want:
        print("FAIL Control H: README promises %r for %r, binary prints %r" % (want, sql, got))
        bad += 1
if bad:
    sys.exit(1)
print("PASS Control H: all %d README --validate examples print what the README promises" % len(pairs))
PYEOF
fi

# Control I: the workflows pin every action to a commit SHA with the version in a trailing comment.
# The SHA is what runs; the comment is what a human reads. Dependabot's own pull request bumped
# actions/checkout to the v7.0.1 commit and left the comment saying v4.3.0 — so an auditor reading
# the workflow would have concluded this repository runs checkout v4, while it runs v7. Pinning by
# digest is worth nothing if the label beside it is fiction, because the label is the only part
# anybody reads.
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "SKIP Control I: no GITHUB_TOKEN, cannot resolve pinned action SHAs to tags"
else
    grep -rhoE 'uses: [A-Za-z0-9/_.-]+@[a-f0-9]{40} # v[0-9][0-9.]*' .github/workflows/ \
        | sort -u > "$tmpdir/pins" || true
    python3 - "$tmpdir" <<'PYEOF' || fail=1
import io, json, os, sys, urllib.error, urllib.request
d = sys.argv[1]
tok = os.environ["GITHUB_TOKEN"]
bad = warn = seen = 0
for line in io.open(os.path.join(d, "pins"), encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    spec, label = line.split(" # ")
    repo, sha = spec.replace("uses: ", "").split("@")
    seen += 1
    req = urllib.request.Request(
        "https://api.github.com/repos/%s/tags?per_page=100" % repo,
        headers={"Authorization": "Bearer " + tok, "User-Agent": "docs-claims"})
    try:
        tags = json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as e:
        print("WARN Control I: could not resolve %s — %s" % (repo, e))
        warn += 1
        continue
    names = [t["name"] for t in tags if t["commit"]["sha"] == sha]
    if not names:
        # Old pins fall off the end of the tag list. Not a lie, just unresolvable from here.
        print("WARN Control I: %s@%s matches no tag in the last 100 — comment says %s"
              % (repo, sha[:8], label))
        warn += 1
    elif label not in names:
        print("FAIL Control I: %s is pinned to %s, which is %s, but the comment says %s"
              % (repo, sha[:8], "/".join(names), label))
        bad += 1
if bad:
    sys.exit(1)
print("PASS Control I: all %d pinned actions carry the version they actually run%s"
      % (seen, " (%d unresolved)" % warn if warn else ""))
PYEOF
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS Control A: every 'verified' claim names a test that exists"
    echo "PASS Control B: the documented settings and the source agree"
    echo "PASS Control C: the package manifest matches the tools that exist"
    echo "PASS Control D: every source file the documentation points at exists"
fi

exit "$fail"