#!/usr/bin/env node
'use strict';

// The launcher an MCP client actually spawns. It hands over to the native binary with execve-like
// semantics: same stdio, same exit code, no wrapper process interpreting the protocol.
//
// It also downloads the binary if it is missing. That is deliberate belt-and-braces: `postinstall`
// normally does it at install time, but plenty of environments run `npm install --ignore-scripts`
// (corporate policy, most CI defaults), and there the postinstall never fires. Without this branch
// those users would get "command not found" from a package that installed successfully — the kind
// of failure people do not report, they just leave.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const { ensureBinary, binaryPath } = require('../lib/install.js');

// Every flag the server understands, top-level and inside `--print-setup-sql`. Kept here because
// the server itself scans for the flags it knows and ignores the rest — so `--stdi` does not fail,
// it starts an HTTP listener instead of a stdio server. For someone wiring this into an MCP client
// that is a silent hang; on a shared machine it is an unintended open port. A test asserts this
// list against the Rust sources, so a new flag upstream breaks the build rather than a user's day.
const KNOWN = new Set([
  '--stdio', '--validate', '--canon', '--fuzz', '--verify-audit', '--expect-last',
  '--print-setup-sql', '--role', '--schemas', '--tables', '--redact', '--database', '--owner',
]);

const USAGE = `postgres-mcp-hardened — read-only PostgreSQL MCP server

  postgres-mcp-hardened --stdio          speak MCP over stdin/stdout (what an MCP client spawns)
  postgres-mcp-hardened                  serve Streamable HTTP on MCP_ADDR (default 127.0.0.1:8080)

  --validate <sql>                       print the validator's verdict for one statement
  --canon <sql>                          print the text that would actually reach the database
  --verify-audit <path> [--expect-last <hash>]   check the audit log's hash chain
  --print-setup-sql [--role R] [--schemas S] [--tables T] [--redact C] [--database D] [--owner O]
                                         print the SQL that creates a least-privilege role
  --fuzz [iterations] [seed]             deterministic validator fuzz; exits 1 on a violation

  -h, --help                             this text
  -V, --version                          package version

Configuration is environment-driven; DATABASE_URL is required to serve.
Full reference: https://github.com/Eszetael/postgres-mcp-hardened`;

function guard(argv) {
  if (argv.includes('-h') || argv.includes('--help')) {
    process.stdout.write(USAGE + '\n');
    return { exit: 0 };
  }
  if (argv.includes('-V') || argv.includes('--version')) {
    process.stdout.write(require('../package.json').version + '\n');
    return { exit: 0 };
  }
  const unknown = argv.filter((a) => a.startsWith('--') && !KNOWN.has(a));
  if (unknown.length) {
    process.stderr.write(
      `postgres-mcp-hardened: unknown option ${unknown.join(', ')}\n` +
      `The server ignores options it does not recognise, so a typo in --stdio would have started ` +
      `a network listener instead of a stdio server. Refusing.\n\n${USAGE}\n`);
    return { exit: 2 };
  }
  return null;
}

async function main() {
  const stop = guard(process.argv.slice(2));
  if (stop) process.exit(stop.exit);

  let bin = binaryPath();
  if (!fs.existsSync(bin)) {
    // stdio is the MCP transport: one stray byte on stdout and the client sees a malformed frame.
    // Progress goes to stderr, which clients log and ignore.
    bin = await ensureBinary();
  }

  const child = spawn(bin, process.argv.slice(2), { stdio: 'inherit' });

  // Signals are forwarded rather than left to kill the launcher: an MCP client shutting a server
  // down sends SIGTERM to the process it spawned, and if that is us, the native process would be
  // orphaned and keep its database connections open.
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => { try { child.kill(sig); } catch { /* already gone */ } });
  }

  child.on('error', (e) => {
    process.stderr.write(`postgres-mcp-hardened: cannot start ${bin}\n${e.message}\n`);
    process.exit(127);
  });
  // A process killed by a signal has no exit code; report it the way a shell does, so a supervisor
  // can tell "crashed" from "exited non-zero".
  child.on('exit', (code, signal) => process.exit(signal ? 128 + osSignalNumber(signal) : code ?? 0));
}

function osSignalNumber(sig) {
  return { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 }[sig] ?? 0;
}

main().catch((e) => {
  process.stderr.write(`postgres-mcp-hardened: ${e.message}\n`);
  process.exit(1);
});
