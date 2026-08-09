#!/usr/bin/env python3
"""The registry manifest must name the identity that actually grants permission to publish.

On 9.08 `v0.1.2` reached npm, signed and released, and the MCP registry refused it:

    403 You have permission to publish: io.github.Eszetael/*
        Attempting to publish:          io.github.eszetael/postgres-mcp-hardened

One letter of case. `server.json` was written by hand and never compared against the account the
OIDC token comes from, and the only job that would have noticed runs on a tag — which is to say
after the version number is spent. This is the same shape as `check_release_permissions.py`: a rule
that lives in a workflow which only ever runs when it is already too late to be cheap. It runs on
every commit instead.

Checks, in the order a failure is cheapest to fix:
  1. `name` is `io.github.<owner>/<repo>`, matching the repository CHARACTER FOR CHARACTER.
  2. `version` agrees with Cargo.toml, and every package entry agrees with `version`.
  3. The npm package identifier is the name npm/package.json actually publishes.
  4. The OCI identifier is lowercase — a registry requirement, and the reason the check in (1)
     cannot simply be "lowercase everything".

The owner comes from `GITHUB_REPOSITORY` in CI and from the git remote locally, so the same rule
holds in both places without a second source of truth.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def repo_slug() -> tuple[str, str] | None:
    """`(owner, repo)` with the case GitHub itself uses, or None if it cannot be established."""
    env = os.environ.get("GITHUB_REPOSITORY")
    if env and "/" in env:
        owner, repo = env.split("/", 1)
        return owner, repo
    try:
        url = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"github\.com[:/]+([^/]+)/([^/.]+)", url)
    return (m.group(1), m.group(2)) if m else None


def cargo_version() -> str | None:
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        # Only the first [package] version, before any dependency table starts.
        if line.startswith("["):
            if line.strip() not in ("[package]",):
                break
        m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
        if m:
            return m.group(1)
    return None


def main() -> int:
    problems: list[str] = []
    srv = json.loads((ROOT / "server.json").read_text())

    slug = repo_slug()
    if slug is None:
        # Not an assertion about the manifest — an admission that this run cannot make one.
        print("  POMINIĘTE: nie ustalono właściciela repozytorium (brak GITHUB_REPOSITORY i remote)")
        return 0
    owner, repo = slug
    want = f"io.github.{owner}/{repo}"
    got = srv.get("name", "")
    if got != want:
        problems.append(
            f"name to {got!r}, a uprawnienie publikacji dostaje {want!r}"
            + (" — różni się WYŁĄCZNIE wielkością liter" if got.lower() == want.lower() else "")
        )

    cv = cargo_version()
    sv = srv.get("version")
    if cv and sv != cv:
        problems.append(f"server.json ma wersję {sv}, a Cargo.toml {cv}")
    for i, p in enumerate(srv.get("packages", [])):
        if p.get("version") != sv:
            problems.append(f"packages[{i}] ma wersję {p.get('version')}, a serwer {sv}")
        ident = p.get("identifier", "")
        if p.get("registryType") == "npm":
            npm_name = json.loads((ROOT / "npm" / "package.json").read_text()).get("name")
            if ident != npm_name:
                problems.append(f"packages[{i}] wskazuje pakiet {ident!r}, a npm publikuje {npm_name!r}")
        if p.get("registryType") == "oci" and ident != ident.lower():
            problems.append(f"packages[{i}] obraz {ident!r} musi być zapisany małymi literami")

    if problems:
        print("BŁĄD — manifest rejestru nie zgadza się z rzeczywistością:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"  manifest rejestru zgodny: {want} w wersji {sv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
