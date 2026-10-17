// Measuring the exit addresses, and finding out which addresses they are.
//
// Two things make this module more careful than "time a fetch":
//
// 1. A probe is not free. It spends a request on the very exit IP the pool is
//    trying to keep unspent, so the steady-state budget is deliberately small:
//    the address in use is re-measured every ten minutes (6/hour) and the eight
//    quickest alternates once an hour (8/hour), which is the whole standing
//    cost. Everything else is only measured when it is first taken in, or when
//    it is about to be used and its numbers are stale.
// 2. A probe failing does not mean the NODE failed. Zen answers a request that
//    does not look like OpenCode's with 403 FreeTierError no matter which exit
//    address sent it, and the neutral endpoint can be unreachable from here on
//    its own. Blaming the node for either would evict good addresses, so a
//    verdict of `endpoint` never touches the node's health.

import { DEFAULT_USER_AGENT } from "./sources.mjs";

export const PROBE_VERDICTS = Object.freeze({
  OK: "ok",
  // The address (or the path out through it) is at fault.
  NODE: "node",
  // The measurement itself could not be trusted. Never held against the node.
  ENDPOINT: "endpoint",
});

export const DEFAULT_ZEN_URL = "https://opencode.ai/inference/v1/models";
// api.ipify.org is deliberately absent: it is not reachable directly from this
// deployment, and a probe target that never answers would look like every node
// being down.
export const DEFAULT_NEUTRAL_URLS = Object.freeze([
  "https://ifconfig.me/ip",
  "https://www.cloudflare.com/cdn-cgi/trace",
  "https://api.ip.sb/ip",
]);

export const DEFAULT_TIMEOUT_MS = 8_000;
export const DEFAULT_CONCURRENCY = 16;
export const DEFAULT_ACTIVE_REFRESH_MS = 10 * 60 * 1000;
export const DEFAULT_STALE_MS = 60 * 60 * 1000;
export const DEFAULT_ALTERNATES = 8;
export const DEFAULT_MIN_DISTINCT_IPS = 10;
export const DEFAULT_EWMA_ALPHA = 0.3;

// What Zen sends the free tier when the request is its own: `x-opencode-client`
// and OpenCode's own User-Agent. A probe that omits these gets 403
// FreeTierError whatever exit address sent it, so the caller passes the
// User-Agent in rather than this module guessing one -- provider.mjs is the
// single authority on what the plugin looks like. Importing it here would also
// be a cycle, since provider.mjs imports this module.
//
// With no User-Agent the probe still runs, and the 403 it earns is classified
// as an endpoint problem, so a caller that forgets cannot evict good nodes.
export function zenProbeHeaders(userAgent) {
  const headers = {
    accept: "*/*",
    authorization: "Bearer public",
    "x-opencode-client": "cli",
  };
  if (typeof userAgent === "string" && userAgent !== "") headers["user-agent"] = userAgent;
  return headers;
}

export const PROBE_USER_AGENT = DEFAULT_USER_AGENT;

// ------------------------------------------------------------------ verdicts

// Which failures are the node's and which are the measurement's.
export function verdictForStatus(status) {
  if (status >= 200 && status < 300) return PROBE_VERDICTS.OK;
  // 5xx and 429 come from the far side of the tunnel: the address, or the path
  // through it, did not deliver.
  if (status >= 500 || status === 429) return PROBE_VERDICTS.NODE;
  // 401/403/404 are the target refusing to answer THIS request. Zen's free tier
  // returns 403 FreeTierError for a request that does not look like OpenCode's
  // regardless of the exit address, so this says nothing about the node.
  return PROBE_VERDICTS.ENDPOINT;
}

export function verdictForError(error) {
  if (error?.name === "AbortError") return PROBE_VERDICTS.ENDPOINT;
  return PROBE_VERDICTS.NODE;
}

// ------------------------------------------------------------------ egress IP

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}$/i;

export function looksLikeIP(value) {
  const text = String(value ?? "").trim().replace(/^\[|\]$/g, "");
  return IPV4.test(text) || IPV6.test(text);
}

// The neutral endpoints answer in three different shapes: a bare address
// (ifconfig.me/ip, api.ip.sb/ip), a trace body with an `ip=` line
// (cloudflare.com/cdn-cgi/trace), or JSON. All three are read here so a
// fallback endpoint still yields the address it was chosen for.
export function parseEgressIP(body) {
  const text = String(body ?? "").trim();
  if (text === "") return null;
  if (looksLikeIP(text)) return text.replace(/^\[|\]$/g, "");
  const trace = /^ip=(.+)$/m.exec(text);
  if (trace && looksLikeIP(trace[1])) return trace[1].trim().replace(/^\[|\]$/g, "");
  if (text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text);
      for (const key of ["ip", "origin", "query"]) {
        if (looksLikeIP(parsed?.[key])) return String(parsed[key]).trim().replace(/^\[|\]$/g, "");
      }
    } catch {
      // Not JSON after all; fall through to no answer.
    }
  }
  return null;
}

// ------------------------------------------------------------------ measuring

function proxyFor(port) {
  return `http://127.0.0.1:${port}`;
}

// One request through one node's local inbound. Only the time to the response
// headers is reported, because that is the part the exit address decides; the
// body is read only when the caller wants the address out of it.
async function measure(port, url, { headers, timeoutMs, fetchImpl, wantBody }) {
  const startedAt = Date.now();
  try {
    const response = await fetchImpl(url, {
      proxy: proxyFor(port),
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
    });
    const ms = Date.now() - startedAt;
    const verdict = verdictForStatus(response.status);
    let body = "";
    if (verdict === PROBE_VERDICTS.OK && wantBody) body = await response.text().catch(() => "");
    else await response.body?.cancel().catch(() => {});
    return { ok: verdict === PROBE_VERDICTS.OK, status: response.status, ms, verdict, body };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      ms: Date.now() - startedAt,
      verdict: verdictForError(error),
      error: error?.message ?? String(error),
    };
  }
}

// The neutral target, tried in order until one answers. A target that cannot be
// reached is not the node's fault: it is swapped for the next one and the node
// is left alone.
async function measureNeutral(port, urls, options) {
  let last = null;
  for (const url of urls) {
    const result = await measure(port, url, { ...options, wantBody: true });
    if (result.ok) return { ...result, url, exitIp: parseEgressIP(result.body) };
    last = { ...result, url };
    // A verdict of `node` means the address is suspect; on the neutral target
    // that still only means "try the next target", never "the node is bad",
    // because the endpoint itself may be the unreachable side.
  }
  return last ?? { ok: false, status: 0, ms: 0, verdict: PROBE_VERDICTS.ENDPOINT, error: "no neutral target answered" };
}

export async function probeNode(node, options = {}) {
  const {
    zenUrl = DEFAULT_ZEN_URL,
    neutralUrls = DEFAULT_NEUTRAL_URLS,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    fetchImpl = globalThis.fetch,
    zenHeaders = zenProbeHeaders(),
    neutralHeaders = { "user-agent": DEFAULT_USER_AGENT },
    measureNeutralTarget = true,
  } = options;
  const port = node.port;
  if (!Number.isInteger(port)) {
    return { id: node.id, ok: false, verdict: PROBE_VERDICTS.ENDPOINT, error: "the node has no local port" };
  }

  const zen = await measure(port, zenUrl, { headers: zenHeaders, timeoutMs, fetchImpl, wantBody: false });
  let neutral = null;
  let exitIp = null;
  if (measureNeutralTarget) {
    neutral = await measureNeutral(port, neutralUrls, { headers: neutralHeaders, timeoutMs, fetchImpl });
    exitIp = neutral.exitIp ?? null;
  }

  // The node is only held responsible for a failure the node can cause. A zen
  // verdict of `endpoint` (its own 403 included) leaves the node alone, and a
  // neutral failure is never attributed to the node either.
  const ok = zen.ok;
  const verdict = ok ? PROBE_VERDICTS.OK : zen.verdict === PROBE_VERDICTS.NODE ? PROBE_VERDICTS.NODE : PROBE_VERDICTS.ENDPOINT;
  return {
    id: node.id,
    ok,
    verdict,
    zen: { ok: zen.ok, ms: zen.ms, status: zen.status, error: zen.error },
    neutral: neutral === null ? null : { ok: neutral.ok, ms: neutral.ms, status: neutral.status, url: neutral.url, error: neutral.error },
    exitIp,
  };
}

// A small worker pool: the point is to keep the fan-out bounded, not to be
// clever about ordering.
export async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  const size = Math.max(1, Math.min(concurrency, items.length === 0 ? 1 : items.length));
  await Promise.all(
    Array.from({ length: size }, async () => {
      for (;;) {
        const index = next;
        next += 1;
        if (index >= items.length) return;
        results[index] = await worker(items[index], index);
      }
    }),
  );
  return results;
}

export async function probeNodes(nodes, options = {}) {
  const { concurrency = DEFAULT_CONCURRENCY, onResult, ...rest } = options;
  let peak = 0;
  let live = 0;
  const results = await mapWithConcurrency(nodes, concurrency, async (node) => {
    live += 1;
    peak = Math.max(peak, live);
    try {
      const result = await probeNode(node, rest);
      onResult?.(result);
      return result;
    } finally {
      live -= 1;
    }
  });
  return { results, peakConcurrency: peak };
}

// ------------------------------------------------------------------ schedule

// Which nodes are worth measuring right now. The standing cost is bounded by
// construction: one address in use at activeRefreshMs (6/hour at the default),
// the quickest alternates once per staleMs (8/hour at the default), plus
// whatever has never been measured or is stale and about to be used.
export function dueForProbe(
  nodes,
  {
    now = Date.now(),
    activeId,
    activeRefreshMs = DEFAULT_ACTIVE_REFRESH_MS,
    staleMs = DEFAULT_STALE_MS,
    alternates = DEFAULT_ALTERNATES,
  } = {},
) {
  const due = new Set();
  const known = nodes.filter((node) => node.status !== "retired");
  for (const node of known) {
    if (!node.lastProbedAt) due.add(node.id);
  }
  const active = known.find((node) => node.id === activeId);
  if (active && now - (active.lastProbedAt ?? 0) >= activeRefreshMs) due.add(active.id);
  const ranked = known
    .filter((node) => node.status === "ready" && node.id !== activeId && Number.isFinite(node.probeEwmaMs?.zen))
    .sort((left, right) => left.probeEwmaMs.zen - right.probeEwmaMs.zen)
    .slice(0, alternates);
  for (const node of ranked) {
    if (now - (node.lastProbedAt ?? 0) >= staleMs) due.add(node.id);
  }
  return [...due];
}

// ------------------------------------------------------------------ applying

function nextEwma(previous, sample, alpha) {
  if (!Number.isFinite(sample)) return previous;
  if (!Number.isFinite(previous)) return sample;
  return previous * (1 - alpha) + sample * alpha;
}

// Folds probe results into node records. `endpoint` verdicts deliberately leave
// status and failures untouched: a measurement that failed for its own reasons
// must not cost a node its place.
export function applyProbeResults(nodes, results, { now = Date.now(), alpha = DEFAULT_EWMA_ALPHA } = {}) {
  const byId = new Map(results.map((result) => [result.id, result]));
  return nodes.map((node) => {
    const result = byId.get(node.id);
    if (result === undefined) return node;
    const next = { ...node, lastProbedAt: now, probeEwmaMs: { ...node.probeEwmaMs } };
    if (result.zen?.ok) next.probeEwmaMs.zen = nextEwma(next.probeEwmaMs.zen, result.zen.ms, alpha);
    if (result.neutral?.ok) next.probeEwmaMs.neutral = nextEwma(next.probeEwmaMs.neutral, result.neutral.ms, alpha);
    if (result.exitIp) {
      next.lastExitIp = result.exitIp;
      next.exitIpAt = now;
    }
    if (result.verdict === PROBE_VERDICTS.NODE) {
      next.failures = (node.failures ?? 0) + 1;
      next.status = "cooling";
      next.lastKind = "probe";
    } else if (result.verdict === PROBE_VERDICTS.OK && node.status === "cooling") {
      // A node measured healthy again is a candidate again.
      next.status = "ready";
      next.lastKind = "";
    }
    return next;
  });
}

export function countDistinctExitIps(nodes) {
  const seen = new Set();
  for (const node of nodes) {
    if (node.status === "retired") continue;
    if (typeof node.lastExitIp === "string" && node.lastExitIp !== "") seen.add(node.lastExitIp);
  }
  return seen.size;
}

// What the user actually asked for is a number of different IPs, not a number
// of nodes. A pool of 300 entries that all leave from one address looks healthy
// and is not, so the shortfall is reported rather than left implicit.
export function distinctIpWarnings(nodes, { minDistinctIps = DEFAULT_MIN_DISTINCT_IPS } = {}) {
  const distinct = countDistinctExitIps(nodes);
  const measured = nodes.filter((node) => node.status !== "retired" && node.lastExitIp).length;
  if (measured === 0) return { distinct, warnings: [] };
  if (distinct >= minDistinctIps) return { distinct, warnings: [] };
  return {
    distinct,
    warnings: [
      `the pool has ${measured} measured nodes but only ${distinct} distinct exit IP(s), below the minimum of ${minDistinctIps}: the subscription's nodes may share an address, so rate limiting will not be spread as far as the node count suggests`,
    ],
  };
}
