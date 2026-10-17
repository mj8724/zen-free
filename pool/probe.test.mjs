import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_ALTERNATES,
  PROBE_VERDICTS,
  applyProbeResults,
  countDistinctExitIps,
  distinctIpWarnings,
  dueForProbe,
  mapWithConcurrency,
  parseEgressIP,
  probeNode,
  probeNodes,
  verdictForStatus,
  zenProbeHeaders,
} from "./probe.mjs";

const node = (id, port, extra = {}) => ({ id, port, status: "ready", probeEwmaMs: {}, ...extra });

// A fetch stand-in that answers per (port, url) and records everything it saw,
// so a test can assert which exit address was asked and for which target.
function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    const port = Number(init.proxy.replace(/^http:\/\/127\.0\.0\.1:/, ""));
    calls.push({ url, port });
    const answer = handler(url, port, init);
    if (answer instanceof Error) throw answer;
    return answer instanceof Response ? answer : new Response(answer.body ?? "", { status: answer.status ?? 200 });
  };
  impl.calls = calls;
  return impl;
}

const okIP = (ip) => ({ status: 200, body: ip });

// ------------------------------------------------------------------ verdicts

test("probe: a refusal by the target is the endpoint's problem, not the node's", () => {
  // Zen's free tier answers this to a request that does not look like OpenCode's,
  // whichever exit address sent it.
  assert.equal(verdictForStatus(403), PROBE_VERDICTS.ENDPOINT);
  assert.equal(verdictForStatus(404), PROBE_VERDICTS.ENDPOINT);
  assert.equal(verdictForStatus(401), PROBE_VERDICTS.ENDPOINT);
  // These are delivered from the far side of the tunnel.
  assert.equal(verdictForStatus(429), PROBE_VERDICTS.NODE);
  assert.equal(verdictForStatus(500), PROBE_VERDICTS.NODE);
  assert.equal(verdictForStatus(200), PROBE_VERDICTS.OK);
});

// ------------------------------------------------------------------ egress IP

test("probe: an egress address is read from every shape a neutral endpoint uses", () => {
  assert.equal(parseEgressIP("1.2.3.4"), "1.2.3.4");
  assert.equal(parseEgressIP("  203.0.113.7\n"), "203.0.113.7");
  assert.equal(parseEgressIP("fl=1\nip=198.51.100.9\nwarp=off"), "198.51.100.9");
  assert.equal(parseEgressIP('{"ip":"9.9.9.9"}'), "9.9.9.9");
  assert.equal(parseEgressIP("2001:db8:1:2::3"), "2001:db8:1:2::3");
  assert.equal(parseEgressIP("<html>not an address</html>"), null);
});

// ------------------------------------------------------------------ measuring

test("probe: the two targets are measured separately and never overwrite each other", async () => {
  const fetchImpl = fakeFetch((url, port) =>
    url.includes("opencode.ai") ? { status: 200, body: "{}" } : okIP(port === 28700 ? "1.1.1.1" : "2.2.2.2"),
  );
  const result = await probeNode(node("a", 28700), { fetchImpl });
  assert.equal(result.zen.ok, true);
  assert.equal(result.neutral.ok, true);
  assert.ok(Number.isFinite(result.zen.ms));
  assert.ok(Number.isFinite(result.neutral.ms));
  assert.equal(result.exitIp, "1.1.1.1");

  const applied = applyProbeResults([node("a", 28700)], [result], { now: 1000 });
  assert.ok(Number.isFinite(applied[0].probeEwmaMs.zen), "the zen figure landed in .zen");
  assert.ok(Number.isFinite(applied[0].probeEwmaMs.neutral), "the neutral figure landed in .neutral");
  assert.equal(applied[0].lastExitIp, "1.1.1.1");
  assert.equal(applied[0].lastProbedAt, 1000);
});

test("probe: Zen's own 403 does not cost the node its place", async () => {
  const fetchImpl = fakeFetch((url) => (url.includes("opencode.ai") ? { status: 403, body: '{"error":{"type":"FreeTierError"}}' } : okIP("1.1.1.1")));
  const result = await probeNode(node("a", 28700), { fetchImpl });
  assert.equal(result.ok, false);
  assert.equal(result.verdict, PROBE_VERDICTS.ENDPOINT);

  const applied = applyProbeResults([node("a", 28700)], [result], { now: 1 });
  assert.equal(applied[0].status, "ready", "the node is still a candidate");
  assert.equal(applied[0].failures ?? 0, 0, "no failure was held against it");
});

test("probe: a neutral target that cannot be reached is swapped, and the node is untouched", async () => {
  const fetchImpl = fakeFetch((url) => {
    if (url.includes("opencode.ai")) return { status: 200, body: "{}" };
    if (url.includes("ifconfig.me")) throw new Error("ECONNRESET");
    if (url.includes("cloudflare.com")) return { status: 503, body: "down" };
    return okIP("203.0.113.5");
  });
  const result = await probeNode(node("a", 28700), { fetchImpl });
  assert.equal(result.ok, true, "zen answered, so the node is healthy");
  assert.equal(result.exitIp, "203.0.113.5", "the third target supplied the address");
  assert.equal(result.neutral.url, "https://api.ip.sb/ip");
  const applied = applyProbeResults([node("a", 28700)], [result], { now: 1 });
  assert.equal(applied[0].status, "ready");
});

test("probe: a transport failure on the node's own path does mark the node", async () => {
  const fetchImpl = fakeFetch(() => new Error("ECONNRESET"));
  const result = await probeNode(node("a", 28700), { fetchImpl });
  assert.equal(result.verdict, PROBE_VERDICTS.NODE);
  const applied = applyProbeResults([node("a", 28700)], [result], { now: 1 });
  assert.equal(applied[0].status, "cooling");
  assert.equal(applied[0].failures, 1);
});

test("probe: a node measured healthy again becomes a candidate again", async () => {
  const fetchImpl = fakeFetch((url) => (url.includes("opencode.ai") ? { status: 200, body: "{}" } : okIP("1.1.1.1")));
  const result = await probeNode(node("a", 28700, { status: "cooling", failures: 3 }), { fetchImpl });
  const applied = applyProbeResults([node("a", 28700, { status: "cooling", failures: 3 })], [result], { now: 1 });
  assert.equal(applied[0].status, "ready");
});

test("probe: the EWMA smooths rather than replacing the previous figure", () => {
  const first = applyProbeResults([node("a", 28700)], [{ id: "a", verdict: PROBE_VERDICTS.OK, zen: { ok: true, ms: 100 }, neutral: null }], { now: 1 });
  assert.equal(first[0].probeEwmaMs.zen, 100);
  const second = applyProbeResults(first, [{ id: "a", verdict: PROBE_VERDICTS.OK, zen: { ok: true, ms: 200 }, neutral: null }], { now: 2, alpha: 0.3 });
  assert.equal(Math.round(second[0].probeEwmaMs.zen), 130, "100 kept 70%, 200 contributed 30%");
});

// ------------------------------------------------------------------ fan-out

test("probe: the fan-out stays within the concurrency it was given", async () => {
  let live = 0;
  let peak = 0;
  const items = Array.from({ length: 40 }, (_, index) => index);
  await mapWithConcurrency(items, 5, async () => {
    live += 1;
    peak = Math.max(peak, live);
    await new Promise((resolve) => setTimeout(resolve, 1));
    live -= 1;
  });
  assert.ok(peak <= 5, `peak concurrency was ${peak}`);
  assert.ok(peak > 1, "it should actually run in parallel up to the cap");
});

test("probe: probing a set reports the peak it reached and every result", async () => {
  const fetchImpl = fakeFetch((url) => (url.includes("opencode.ai") ? { status: 200, body: "{}" } : okIP("1.1.1.1")));
  const nodes = [node("a", 28700), node("b", 28701), node("c", 28702)];
  const { results, peakConcurrency } = await probeNodes(nodes, { fetchImpl, concurrency: 2 });
  assert.equal(results.length, 3);
  assert.ok(peakConcurrency <= 2);
});

// ------------------------------------------------------------------ schedule

test("probe: the standing budget is the address in use plus the alternates, per hour", () => {
  const now = 10 * 60 * 60 * 1000;
  const nodes = Array.from({ length: 40 }, (_, index) =>
    node(`n${index}`, 28700 + index, { lastProbedAt: now, lastExitIp: `10.0.0.${index}`, probeEwmaMs: { zen: 100 + index } }),
  );
  // Everything was measured an hour ago: only the address in use is due.
  const staleNodes = nodes.map((entry) => ({ ...entry, lastProbedAt: now - 60 * 60 * 1000 - 1 }));
  const due = dueForProbe(staleNodes, { now, activeId: "n0" });
  // n0 is the address in use; the eight quickest alternates are also stale.
  assert.equal(due.length, 1 + DEFAULT_ALTERNATES);
  // Over an hour that is 6 re-measurements of the active address plus one pass
  // over the alternates.
  const perHour = 6 + DEFAULT_ALTERNATES;
  assert.ok(perHour <= 6 + 8, `standing cost ${perHour}/hour must stay within the budget`);
});

test("probe: a freshly measured pool is not re-probed at all", () => {
  const now = 10 * 60 * 60 * 1000;
  const nodes = Array.from({ length: 20 }, (_, index) => node(`n${index}`, 28700 + index, { lastProbedAt: now }));
  assert.deepEqual(dueForProbe(nodes, { now, activeId: "n0" }), []);
});

test("probe: a node that was never measured is due regardless of the budget", () => {
  const now = 10 * 60 * 60 * 1000;
  const nodes = [node("fresh", 28700, { lastProbedAt: now }), node("new", 28701)];
  assert.deepEqual(dueForProbe(nodes, { now, activeId: "fresh" }), ["new"]);
});

test("probe: retired nodes are never scheduled", () => {
  const now = 10 * 60 * 60 * 1000;
  const nodes = [node("gone", 28700, { status: "retired" })];
  assert.deepEqual(dueForProbe(nodes, { now }), []);
});

// ------------------------------------------------------------------ distinct IPs

test("probe: nodes sharing an exit address do not count as different IPs", () => {
  const nodes = [
    node("a", 28700, { lastExitIp: "1.1.1.1" }),
    node("b", 28701, { lastExitIp: "1.1.1.1" }),
    node("c", 28702, { lastExitIp: "2.2.2.2" }),
    node("d", 28703),
  ];
  assert.equal(countDistinctExitIps(nodes), 2, "three measured nodes, two addresses");
});

test("probe: a pool of many nodes leaving from too few addresses says so", () => {
  const nodes = Array.from({ length: 30 }, (_, index) => node(`n${index}`, 28700 + index, { lastExitIp: "1.1.1.1" }));
  const { distinct, warnings } = distinctIpWarnings(nodes, { minDistinctIps: 10 });
  assert.equal(distinct, 1);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /only 1 distinct exit IP/);
  assert.match(warnings[0], /rate limiting will not be spread/);
});

test("probe: an unmeasured pool is not warned about, and enough addresses are not either", () => {
  assert.deepEqual(distinctIpWarnings([node("a", 28700)], { minDistinctIps: 10 }).warnings, []);
  const many = Array.from({ length: 12 }, (_, index) => node(`n${index}`, 28700 + index, { lastExitIp: `10.0.0.${index}` }));
  assert.deepEqual(distinctIpWarnings(many, { minDistinctIps: 10 }).warnings, []);
});

// ------------------------------------------------------------------ headers

test("probe: the probe asks Zen the way the plugin does, so Zen does not refuse it", () => {
  const headers = zenProbeHeaders("opencode/1.19.0 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14");
  assert.equal(headers["x-opencode-client"], "cli");
  assert.equal(headers.authorization, "Bearer public");
  assert.match(headers["user-agent"], /^opencode\//);
  // Without one it still probes, and the 403 that follows is not the node's fault.
  assert.equal(zenProbeHeaders()["user-agent"], undefined);
});
