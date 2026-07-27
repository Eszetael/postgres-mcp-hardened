// Conformance, checked by somebody else's code.
//
// Every other test in this repository is our harness talking to our server: if we misread the
// specification, we misread it consistently in both halves and everything passes. This drives the
// server with the official MCP SDK — the same client library the ecosystem uses — over BOTH
// transports. A protocol mistake shows up here as a client that cannot talk to us.
//
//   BIN=... DBURL=... MCPURL=... TOK=... node probe.mjs
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

let failed = 0;
const ok = (m) => console.log("  PASS " + m);
const no = (m, d) => { console.log("  FAIL " + m + (d ? "\n       " + d : "")); failed++; };

async function exercise(client, label) {
  const info = client.getServerVersion();
  if (!info?.name) no(`${label}: serverInfo has no name`);
  else ok(`${label}: handshake, server identifies as ${info.name} ${info.version}`);

  const { tools } = await client.listTools();
  if (!tools.length) no(`${label}: tools/list is empty`);
  else ok(`${label}: tools/list returned ${tools.length} tools the SDK could parse`);
  for (const t of tools) {
    if (!t.description) no(`${label}: tool ${t.name} has no description`);
    if (t.inputSchema?.type !== "object") no(`${label}: tool ${t.name} has a schema the SDK does not recognise`);
    // Declared read-only. A client may use this to decide what needs confirming.
    if (t.annotations && t.annotations.readOnlyHint !== true) no(`${label}: tool ${t.name} is not annotated read-only`);
  }
  ok(`${label}: every tool has a description, an object schema and a read-only annotation`);

  const good = await client.callTool({ name: "query", arguments: { sql: "SELECT id, customer FROM orders ORDER BY id" } });
  if (good.isError) no(`${label}: a plain SELECT came back as an error`, JSON.stringify(good.content).slice(0, 200));
  else ok(`${label}: a read returned rows`);

  // The refusal has to arrive as a TOOL error, so the model can read it and rewrite the query —
  // not as a JSON-RPC error, which the SDK would raise as an exception and the model never sees.
  const write = await client.callTool({ name: "query", arguments: { sql: "DELETE FROM orders" } });
  if (write.isError) ok(`${label}: a write is refused as a tool execution error, readable by the model`);
  else no(`${label}: a write was not marked isError`, JSON.stringify(write).slice(0, 200));

  const { resources } = await client.listResources();
  if (!resources.length) no(`${label}: resources/list is empty although the database has a table`);
  else {
    ok(`${label}: resources/list returned ${resources.length}`);
    const one = await client.readResource({ uri: resources[0].uri });
    if (!one.contents?.length) no(`${label}: resources/read returned nothing`);
    else ok(`${label}: resources/read on ${resources[0].uri} parsed`);
  }
}

// stdio — how desktop clients run it. Also proves the audit trail on stderr never corrupts the
// protocol stream on stdout, which nothing else checks.
{
  const transport = new StdioClientTransport({
    command: process.env.BIN,
    args: ["--stdio"],
    env: { ...process.env, DATABASE_URL: process.env.DBURL },
  });
  const client = new Client({ name: "conformance-probe", version: "1.0.0" }, { capabilities: {} });
  try {
    await client.connect(transport);
    await exercise(client, "stdio");
    await client.close();
  } catch (e) {
    no("stdio: the SDK could not complete a session", String(e).slice(0, 300));
    try { await client.close(); } catch {}
  }
}

// Streamable HTTP — how it runs as a remote server, with the bearer token a deployment would use.
if (process.env.MCPURL) {
  const transport = new StreamableHTTPClientTransport(new URL(process.env.MCPURL), {
    requestInit: { headers: { authorization: "Bearer " + process.env.TOK } },
  });
  const client = new Client({ name: "conformance-probe-http", version: "1.0.0" }, { capabilities: {} });
  try {
    await client.connect(transport);
    await exercise(client, "http");
    await client.close();
    ok("http: the session closed cleanly");
  } catch (e) {
    no("http: the SDK could not complete a session", String(e).slice(0, 300));
    try { await client.close(); } catch {}
  }
}

console.log(failed ? `\n== ${failed} conformance failures ==` : "\n== conformance clean ==");
process.exit(failed ? 1 : 0);
