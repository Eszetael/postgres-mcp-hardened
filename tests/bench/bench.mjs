// What does the safety cost?
//
// The honest comparison is not "is it fast" but "how much slower than talking to PostgreSQL
// directly". The floor here is the `pg` driver running the same query against the same database on
// the same machine; everything above it is what this server adds: JSON-RPC, the AST validation, the
// canonical re-validation, the cost guard, the row cap and the audit write.
import pg from "pg";

const DB = process.env.DBURL, URL = process.env.MCPURL, TOK = process.env.TOK;
const N = Number(process.env.N ?? 300);
const QUERIES = [
  ["point lookup", "SELECT id, payload FROM bench WHERE id = 4242"],
  ["small scan", "SELECT id FROM bench WHERE id < 500"],
  ["aggregate", "SELECT count(*), avg(id) FROM bench"],
];

const pct = (a, p) => a.slice().sort((x, y) => x - y)[Math.min(a.length - 1, Math.floor(a.length * p))];
const stat = (a) => ({ p50: +pct(a, 0.5).toFixed(2), p95: +pct(a, 0.95).toFixed(2), max: +Math.max(...a).toFixed(2) });

async function direct(sql) {
  const c = new pg.Client({ connectionString: DB });
  await c.connect();
  const t = [];
  for (let i = 0; i < N; i++) { const s = performance.now(); await c.query(sql); t.push(performance.now() - s); }
  await c.end();
  return t;
}
async function viaServer(sql) {
  const t = [];
  for (let i = 0; i < N; i++) {
    const s = performance.now();
    const r = await fetch(URL, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + TOK },
      body: JSON.stringify({ jsonrpc: "2.0", id: i, method: "tools/call",
        params: { name: "query", arguments: { sql } } }),
    });
    const j = await r.json();
    if (j.error) throw new Error(JSON.stringify(j.error).slice(0, 200));
    t.push(performance.now() - s);
  }
  return t;
}

console.log(`  ${N} sequential requests per query, milliseconds\n`);
console.log("  query           driver p50   server p50   overhead   server p95");
for (const [label, sql] of QUERIES) {
  const d = stat(await direct(sql));
  const m = stat(await viaServer(sql));
  const over = (m.p50 - d.p50).toFixed(2);
  console.log(`  ${label.padEnd(15)} ${String(d.p50).padStart(8)}   ${String(m.p50).padStart(10)}   ${String(over).padStart(8)}   ${String(m.p95).padStart(10)}`);
}

// Concurrency: the queue and the pool are the interesting part, not raw speed.
for (const c of [1, 8, 32]) {
  const sql = "SELECT id FROM bench WHERE id < 500";
  const started = performance.now();
  const per = Math.max(10, Math.floor(N / c));
  let served = 0, shed = 0;
  await Promise.all(Array.from({ length: c }, async () => {
    for (let i = 0; i < per; i++) {
      const r = await fetch(URL, { method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer " + TOK },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "query", arguments: { sql } } }) });
      const j = await r.json();
      // Being turned away above the in-flight cap is the server working, not the benchmark failing.
      // Counting it is the whole point: an agent that floods this server is told to wait, and a
      // benchmark that treated that as an error would be measuring how well we ignore our own limits.
      if (j.error) { if (/in flight|rate limit/i.test(j.error.message)) shed++; else throw new Error(JSON.stringify(j.error).slice(0, 160)); }
      else served++;
    }
  }));
  const secs = (performance.now() - started) / 1000;
  console.log(`  concurrency ${String(c).padStart(2)}: ${(served / secs).toFixed(0)} served/second, ${shed} shed by the in-flight cap`);
}
