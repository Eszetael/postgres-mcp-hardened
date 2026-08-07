'use strict';

// Fetches the prebuilt binary for this platform from the GitHub Release that matches this package
// version, verifies it against a checksum baked in at publish time, and unpacks it next to this file.
//
// Why the checksum is IN the package rather than fetched alongside the download: a checksum served
// from the same place as the artefact proves the transfer was not corrupted and nothing else. The
// list in `checksums.json` is written by the release workflow from the artefacts it just built, so
// it travels with npm's own integrity guarantee. If the two disagree, the download is wrong — and
// for a tool whose whole selling point is refusing unsafe input, "run it anyway" is not an option.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const REPO = 'Eszetael/postgres-mcp-hardened';
const BIN = 'postgres-mcp-hardened';

// npm's platform names on the left, Rust target triples on the right. Kept explicit rather than
// assembled from parts: a wrong triple would download an archive that unpacks fine and then dies
// with "Exec format error", which is a far worse message than "unsupported platform".
const TARGETS = {
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

const key = () => `${process.platform}-${process.arch}`;

function binaryPath() {
  const exe = process.platform === 'win32' ? `${BIN}.exe` : BIN;
  return path.join(__dirname, '..', 'vendor', exe);
}

function targetOrExplain() {
  const t = TARGETS[key()];
  if (t) return t;
  const supported = Object.keys(TARGETS).join(', ');
  throw new Error(
    `No prebuilt binary for ${key()}. Supported: ${supported}.\n` +
    `Build from source instead: cargo install --git https://github.com/${REPO}\n` +
    `(Alpine/musl is not in that list either — the Linux builds are glibc. Use the container image: ` +
    `ghcr.io/${REPO.toLowerCase()})`
  );
}

function expectedChecksum(archive) {
  let sums;
  try {
    sums = require('../checksums.json');
  } catch {
    sums = null;
  }
  const sum = sums && sums[archive];
  if (!sum) {
    // Fail closed. An empty checksum list means the package was published without the release
    // workflow filling it in — that is a broken publish, and silently trusting the download would
    // turn one mistake into a supply-chain hole that nobody would ever notice.
    throw new Error(
      `No checksum recorded for ${archive}. This package was published incorrectly; ` +
      `refusing to install an unverified binary. Please open an issue at https://github.com/${REPO}/issues`
    );
  }
  return sum;
}

async function download(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`Download failed: ${res.status} ${res.statusText}\n  ${url}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

function unpack(archivePath, into) {
  fs.mkdirSync(into, { recursive: true });
  try {
    // bsdtar ships with macOS, every Linux, and Windows 10+ — and it reads .zip as well as .tar.gz,
    // so one command covers all five targets.
    execFileSync('tar', ['-xf', archivePath, '-C', into], { stdio: 'ignore' });
  } catch (e) {
    if (process.platform !== 'win32') throw e;
    execFileSync('powershell', ['-NoProfile', '-Command',
      `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${into}' -Force`],
      { stdio: 'ignore' });
  }
}

async function ensureBinary({ quiet = false } = {}) {
  const dest = binaryPath();
  if (fs.existsSync(dest)) return dest;

  const target = targetOrExplain();
  const ext = process.platform === 'win32' ? 'zip' : 'tar.gz';
  const archive = `${BIN}-${target}.${ext}`;
  const version = require('../package.json').version;
  const url = `https://github.com/${REPO}/releases/download/v${version}/${archive}`;

  // Ask for the checksum BEFORE spending the bandwidth. If the list is missing an entry we are
  // going to refuse anyway, and refusing after a 10 MB download only makes the failure slower.
  const want = expectedChecksum(archive);

  if (!quiet) process.stderr.write(`postgres-mcp-hardened: fetching ${archive} (v${version})\n`);
  const buf = await download(url);

  const got = crypto.createHash('sha256').update(buf).digest('hex');
  if (got !== want) {
    throw new Error(
      `Checksum mismatch for ${archive}\n  expected ${want}\n  got      ${got}\n` +
      `Refusing to install. Report this at https://github.com/${REPO}/issues`
    );
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pmh-'));
  const archivePath = path.join(tmp, archive);
  fs.writeFileSync(archivePath, buf);
  unpack(archivePath, path.dirname(dest));
  fs.rmSync(tmp, { recursive: true, force: true });

  if (!fs.existsSync(dest)) {
    throw new Error(`Archive ${archive} did not contain ${path.basename(dest)}`);
  }
  if (process.platform !== 'win32') fs.chmodSync(dest, 0o755);
  return dest;
}

module.exports = {
  ensureBinary, binaryPath, TARGETS, REPO, BIN,
  // Exported for the tests: both are refusal paths, and a refusal that is never exercised is a
  // refusal nobody knows still works.
  targetOrExplain, expectedChecksum, key,
};
