'use strict';

// Fetches the binary at install time so the first `npx` run is instant — an MCP client spawns the
// server and waits for a handshake, and a 10 MB download inside that window looks like a hang.
//
// It must never fail the install. Offline machines, proxies and `--ignore-scripts` all exist, and
// the launcher downloads on demand anyway; turning a recoverable situation into a failed
// `npm install` would be worse than the delay it avoids. So: explain, and exit 0.

const { ensureBinary } = require('../lib/install.js');

ensureBinary().catch((e) => {
  process.stderr.write(
    `postgres-mcp-hardened: could not fetch the binary now (${e.message.split('\n')[0]}).\n` +
    `It will be fetched on first run instead.\n`
  );
  process.exit(0);
});
