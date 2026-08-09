#!/usr/bin/env python3
"""Every mutable pointer this release moves must be guarded against a release candidate.

We publish through three channels, and each has something that points at "the current version":
the npm `latest` dist-tag, the container `latest` tag, and the GitHub release itself. A `-rc`
rehearsal must move none of them — that is the whole point of rehearsing.

The rule was known and applied to exactly one channel. On 9.08 the container `latest` pointed at
`0.1.2-rc3` while `0.1.2` was still building, because `type=raw,value=latest` carried no condition.
The npm job three screens above it was guarded, with a comment explaining why.

That is the shape this file exists to catch: not a missing rule, but a rule applied to one site out
of several. Adding a fourth publishing channel without a guard fails here, on the commit that adds
it, rather than on the next rehearsal that quietly overwrites what users pull.

A guard counts if it is anywhere in the step that does the publishing — a step-level
`if: ${{ !contains(github.ref, '-rc') }}` keeps the step from running at all, which is a stronger
guard than a flag on the command. Demanding one particular spelling would flag correct code, and a
check that cries wolf gets deleted long before it gets fixed.
"""
from __future__ import annotations

import re
from pathlib import Path

RELEASE = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"

RC = re.compile(r"-rc")

# Things that move a pointer people follow. Each must live in a step that an `-rc` tag cannot reach
# (or cannot reach in a pointer-moving way).
POINTERS = [
    ("znacznik obrazu `latest`", re.compile(r"type=raw,value=latest")),
    ("publikacja npm", re.compile(r"npm publish(?!.*--dry-run)")),
    ("wydanie GitHuba", re.compile(r"action-gh-release")),
]


def steps(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Split the workflow into steps: (1-based line of the step's first line, its lines)."""
    out: list[tuple[int, list[str]]] = []
    start, buf = None, []
    for i, l in enumerate(lines):
        if re.match(r"^\s{6,10}- (name|uses|run):", l):
            if start is not None:
                out.append((start + 1, buf))
            start, buf = i, [l]
        elif start is not None:
            buf.append(l)
    if start is not None:
        out.append((start + 1, buf))
    return out


def main() -> int:
    if not RELEASE.exists():
        print(f"BŁĄD: nie ma {RELEASE}")
        return 1
    lines = RELEASE.read_text().splitlines()
    wszystkie = steps(lines)
    problems: list[str] = []
    found: list[str] = []

    for name, needle in POINTERS:
        trafienia = [
            (ln, blok)
            for ln, blok in wszystkie
            if any(needle.search(l) and not l.strip().startswith("#") for l in blok)
        ]
        if not trafienia:
            # Silence is not a pass. If a channel disappears from the file, this check has stopped
            # measuring it, and that must be as loud as a missing guard.
            problems.append(f"{name}: nie znaleziono wcale — kontrola przestała to mierzyć")
            continue
        for ln, blok in trafienia:
            tekst = "\n".join(l for l in blok if not l.strip().startswith("#"))
            if RC.search(tekst):
                found.append(f"{name} (krok w linii {ln}) — zabezpieczony przed `-rc`")
            else:
                problems.append(
                    f"{name} (krok w linii {ln}): nic w tym kroku nie odróżnia `-rc` od wydania"
                )

    if problems:
        print("BŁĄD — ruchomy wskaźnik bez zabezpieczenia przed wersją próbną:")
        for p in problems:
            print(f"  - {p}")
        return 1
    for f in found:
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
