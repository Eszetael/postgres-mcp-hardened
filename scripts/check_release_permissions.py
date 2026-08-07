#!/usr/bin/env python3
"""Every job that uploads to a release has `contents: write`, and no other job has it.

Why this exists. On 2026-07-28 a least-privilege pass moved `contents: write` from the workflow
level down to the one job it believed was publishing. Its justification: "grep finds no release
upload, no `gh release`, no token use" in `checks`, `build` or `sbom`. That was true of the string
and false of the jobs — `build` and `sbom` both upload through `softprops/action-gh-release`, which
contains neither "gh release" nor the word "upload" in a form the grep matched. The workflow stayed
green for ten days because nothing published in those ten days; the failure was waiting in a path
nobody executed. It surfaced on the rc7 rehearsal as a 403 on five build jobs and the SBOM.

So the lesson is not "remember to grant the permission". It is that the question "which jobs
publish?" must be answered by reading the workflow, not by recalling it. This script derives both
sides from the file:

  * a job that uses a known publishing action MUST have `contents: write`;
  * a job that does not MUST NOT — otherwise the hardening the original commit was reaching for
    quietly erodes every time someone copies a permissions block around.

Both directions matter. A check that only catches the missing grant would have let the original
over-granted state pass, and that state is what the supply-chain round correctly objected to.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a finding
    # Refusing is the point: a check that cannot run must not look like a check that passed.
    print("REFUSED: PyYAML missing, cannot parse the workflow", file=sys.stderr)
    raise SystemExit(3)

# Actions that create or attach files to a GitHub release. Matched on the part before `@`, so a
# version bump does not silently disable the check.
PUBLISHING_ACTIONS = {
    "softprops/action-gh-release",
    "ncipollo/release-action",
    "actions/create-release",
    "actions/upload-release-asset",
}

# Shell fragments that publish through the CLI instead of an action.
PUBLISHING_SHELL = ("gh release create", "gh release upload", "gh release edit")

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"


def job_publishes(job: dict) -> str | None:
    """Return a human-readable reason this job publishes, or None."""
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = str(step.get("uses") or "")
        if uses.split("@", 1)[0] in PUBLISHING_ACTIONS:
            return f"uses {uses.split('@', 1)[0]}"
        run = str(step.get("run") or "")
        for frag in PUBLISHING_SHELL:
            if frag in run:
                return f"runs `{frag}`"
    return None


def contents_perm(job: dict, workflow_default: str | None) -> str | None:
    perms = job.get("permissions", None)
    if perms is None:
        return workflow_default
    if isinstance(perms, str):  # `permissions: write-all` / `read-all`
        return "write" if perms == "write-all" else "read"
    return perms.get("contents")


def main() -> int:
    doc = yaml.safe_load(WORKFLOW.read_text())
    top = doc.get("permissions")
    workflow_default = (
        ("write" if top == "write-all" else "read")
        if isinstance(top, str)
        else (top or {}).get("contents")
    )

    problems: list[str] = []
    checked = 0
    delegated: list[str] = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if "uses" in job:
            # A reusable workflow declares its own permissions, so its steps are not ours to judge.
            # It is still named in the output: a job excluded in silence is indistinguishable from
            # a job that passed, which is the failure shape this whole script exists to prevent.
            delegated.append(f"{name} → {job['uses']}")
            continue
        checked += 1
        reason = job_publishes(job)
        perm = contents_perm(job, workflow_default)
        if reason and perm != "write":
            problems.append(
                f"job `{name}` {reason} but has contents: {perm or 'unset'} "
                f"— it will fail with 403 the moment a tag is pushed"
            )
        if not reason and perm == "write":
            problems.append(
                f"job `{name}` has contents: write but publishes nothing "
                f"— a token that can push commits handed to a job that only computes"
            )

    if problems:
        print("release.yml permissions do not match what the jobs actually do:\n")
        for p in problems:
            print(f"  - {p}")
        return 1

    note = f"; {len(delegated)} delegated to a reusable workflow ({', '.join(delegated)})" if delegated else ""
    print(f"release.yml: {checked} jobs judged, write granted exactly to those that publish{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
