'use strict';

// These tests exercise the two REFUSALS and the packaging contract. Nothing here touches the
// network: the download path is not the risk. The risk is a wrapper that installs cleanly and
// then cannot start, or one that quietly accepts a binary it could not verify.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const install = require('../lib/install.js');
const pkg = require('../package.json');

const ROOT = path.join(__dirname, '..');

test('every file the package promises to ship exists', () => {
  for (const entry of pkg.files) {
    const p = path.join(ROOT, entry.replace(/\/$/, ''));
    assert.ok(fs.existsSync(p), `package.json "files" lists ${entry}, which is not on disk`);
  }
});

test('the bin entry points at a real, runnable launcher', () => {
  const rel = pkg.bin['postgres-mcp-hardened'];
  const p = path.join(ROOT, rel);
  assert.ok(fs.existsSync(p), `bin points at ${rel}, which does not exist`);
  const src = fs.readFileSync(p, 'utf8');
  assert.match(src, /^#!\/usr\/bin\/env node/, 'launcher needs a shebang or npm cannot link it');
  // A syntax error here would only surface when a user runs it, which is the worst place to find out.
  new (require('node:vm').Script)(src, { filename: p });
});

test('platform map covers exactly the targets the release workflow builds', () => {
  const wf = fs.readFileSync(
    path.join(ROOT, '..', '.github', 'workflows', 'release.yml'), 'utf8');
  const built = new Set([...wf.matchAll(/target:\s*(\S+)/g)].map((m) => m[1]));
  const mapped = new Set(Object.values(install.TARGETS));
  for (const t of mapped) {
    assert.ok(built.has(t), `npm maps to ${t}, but the release workflow does not build it`);
  }
  for (const t of built) {
    assert.ok(mapped.has(t), `release builds ${t}, but npm has no platform mapped to it — ` +
      'users on that platform would be told their system is unsupported');
  }
});

test('an unsupported platform is refused with a way out, not a stack trace', () => {
  const real = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'sunos', configurable: true });
  try {
    assert.throws(() => install.targetOrExplain(), (e) => {
      assert.match(e.message, /No prebuilt binary for sunos/);
      assert.match(e.message, /cargo install/, 'must say how to proceed without a binary');
      return true;
    });
  } finally {
    Object.defineProperty(process, 'platform', real);
  }
});

test('a missing checksum is a refusal, never a shrug', () => {
  // checksums.json ships empty and is filled by the release workflow. If a publish ever skips that
  // step, this is the line between "the install fails loudly" and "everyone runs an unverified
  // binary and nobody finds out".
  //
  // 07-08: this test used to name a REAL archive and assert it throws. That held only while the
  // file was empty — the developer state. In the release job the workflow fills checksums.json
  // before running the tests, the lookup succeeded, and the test failed with "Missing expected
  // exception". It had encoded the state of the repository instead of the rule, so it could only
  // ever pass in the situation nobody ships. It failed the first time the job actually ran, which
  // was today, because that job had never run before.
  //
  // The rule is: an archive with no recorded checksum is refused. That is true whatever the file
  // contains, so the test now uses a name that can never be in it.
  assert.throws(() => install.expectedChecksum('postgres-mcp-hardened-nonexistent-target.tar.gz'),
    /No checksum recorded/);
});

test('a recorded checksum comes back as a usable sha256', () => {
  // The other half, and the half that only means something in the release job: when the workflow
  // HAS filled the file, a real archive must return a real digest. Before this, every assertion
  // about checksums was about their absence — a package published with sixty-four wrong characters
  // would have passed the whole suite.
  const sums = JSON.parse(fs.readFileSync(path.join(ROOT, 'checksums.json'), 'utf8'));
  const names = Object.keys(sums);
  if (names.length === 0) {
    // Developer checkout: nothing to assert, and saying so beats a green tick that measured zero.
    console.log('  (checksums.json empty — developer checkout, this assertion is inert here)');
    return;
  }
  for (const n of names) {
    assert.match(install.expectedChecksum(n), /^[0-9a-f]{64}$/, `${n} has no usable digest`);
  }
});

test('the launcher knows every flag the server knows', () => {
  // Drift here is invisible until a user hits it: the launcher would refuse a flag the server
  // supports, or wave through a typo it was meant to catch. Read the Rust, compare to the list.
  const src = ['src/main.rs', 'src/setup_sql.rs']
    .map((f) => fs.readFileSync(path.join(ROOT, '..', f), 'utf8')).join('\n');
  const inRust = new Set([...src.matchAll(/"(--[a-z-]+)"/g)].map((m) => m[1]));
  const cli = fs.readFileSync(path.join(ROOT, 'bin', 'cli.js'), 'utf8');
  const known = new Set([...cli.matchAll(/'(--[a-z-]+)'/g)].map((m) => m[1]));
  for (const f of inRust) {
    assert.ok(known.has(f), `server accepts ${f}, launcher would refuse it`);
  }
});

test('help and version answer instead of starting a server', () => {
  const { execFileSync } = require('node:child_process');
  const cli = path.join(ROOT, 'bin', 'cli.js');
  // No binary is needed: both must short-circuit before anything is spawned or downloaded.
  const v = execFileSync(process.execPath, [cli, '--version'], { encoding: 'utf8' }).trim();
  assert.strictEqual(v, pkg.version);
  const h = execFileSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.match(h, /--stdio/);
});

test('an unknown flag is refused, not ignored', () => {
  const { spawnSync } = require('node:child_process');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'cli.js'), '--stdi'],
    { encoding: 'utf8' });
  assert.strictEqual(r.status, 2, 'a typo must not fall through to starting a listener');
  assert.match(r.stderr, /unknown option --stdi/);
});

test('checksums.json is valid JSON and keyed by archive name when populated', () => {
  const sums = JSON.parse(fs.readFileSync(path.join(ROOT, 'checksums.json'), 'utf8'));
  for (const [name, sum] of Object.entries(sums)) {
    assert.match(name, /^postgres-mcp-hardened-.+\.(tar\.gz|zip)$/, `odd archive name: ${name}`);
    assert.match(sum, /^[0-9a-f]{64}$/, `not a sha256: ${name}`);
  }
});
