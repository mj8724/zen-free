// Where a request's exit address comes from.
//
// There are two backends and one contract, because the part that rotates on a
// rate limit is already written, tested and worth keeping: resin.mjs's
// rotate() drives any source that can answer four questions. What differs is
// only how a request reaches the address and what has to be cleaned up when
// one is given up on.
//
//   resin  one Resin Account per exit address, reached through Resin's proxy.
//   pool   one local sing-box inbound per node, reached through 127.0.0.1.

import { join } from "node:path";
import { IPPool, ResinAdmin, accountNames, parseResinURL, requireForwardSupport, rotate } from "../resin.mjs";
import {
  DEFAULT_PORT_BASE,
  buildConfig,
  defaultStateDir,
  provisionBinary,
  readCoreVersion,
  startCore,
} from "./core.mjs";
import {
  DEFAULT_CONCURRENCY,
  DEFAULT_MIN_DISTINCT_IPS,
  DEFAULT_NEUTRAL_URLS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_ZEN_URL,
  applyProbeResults,
  countDistinctExitIps,
  distinctIpWarnings,
  dueForProbe,
  probeNodes,
  zenProbeHeaders,
} from "./probe.mjs";
import { loadCandidates } from "./sources.mjs";
import { load, save } from "./state.mjs";

export const DEFAULT_ADDRESSES = 8;
export const DEFAULT_ATTEMPTS = 3;
export const DEFAULT_MAX_NODES = 300;
export const DEFAULT_REFRESH_TICK_MS = 60_000;
export const DEFAULT_HEADER_TIMEOUT_MS = 120_000;
export const DEFAULT_STATE_FILE = "zen-free-pool.json";

// Resin's forward proxy takes the identity as HTTP proxy credentials:
// Platform.Account as the user and the proxy token as the password.
export function forwardProxyURL({ endpoint, token, platform }, account) {
  const url = new URL(endpoint);
  url.username = `${platform}.${account}`;
  url.password = token;
  return url.href;
}

// Resin's reverse proxy takes the whole target in the path, with the identity
// in a header. It is offered for a runtime whose fetch has no proxy option, at
// the cost of carrying the request to Resin in the clear.
export function reverseProxyURL({ endpoint, token, platform }, target) {
  const url = new URL(target);
  const protocol = url.protocol.replace(":", "");
  return `${endpoint}/${encodeURIComponent(token)}/${encodeURIComponent(platform)}/${protocol}/${url.host}${url.pathname}${url.search}`;
}

function wholeNumber(value, name, fallback, min, max) {
  const number = value ?? fallback;
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new Error(`${name} must be a whole number from ${min} to ${max}, got ${JSON.stringify(value)}`);
  }
  return number;
}

// ---------------------------------------------------------------- ordering

function latencyOf(node) {
  const zen = node.probeEwmaMs?.zen;
  if (Number.isFinite(zen)) return zen;
  const neutral = node.probeEwmaMs?.neutral;
  // A node with only a neutral figure still ranks ahead of an unmeasured one,
  // but behind anything actually measured against the target that matters.
  if (Number.isFinite(neutral)) return neutral + 1_000;
  return Number.POSITIVE_INFINITY;
}

// The order is the priority: IPPool takes the first never-used address it finds
// and, once every address has been used, the one with the smallest measured
// time. So sorting by measured latency gives "spend unused addresses fastest
// first, then keep the quickest". With distinctIps on, a node that repeats an
// exit address already claimed moves BEHIND the others rather than being
// dropped: dropping would change the node set, and the config is generated
// once for the life of the process.
export function rankAccounts(nodes, { distinctIps = true } = {}) {
  const live = nodes.filter((node) => node.status !== "retired");
  const retired = nodes.filter((node) => node.status === "retired");
  const ready = live.filter((node) => node.status !== "cooling").sort((a, b) => latencyOf(a) - latencyOf(b));
  const cooling = live.filter((node) => node.status === "cooling").sort((a, b) => latencyOf(a) - latencyOf(b));
  let preferred = ready;
  let shadowed = [];
  if (distinctIps) {
    const claimed = new Set();
    preferred = [];
    for (const node of ready) {
      const ip = node.lastExitIp;
      if (typeof ip === "string" && ip !== "" && claimed.has(ip)) shadowed.push(node);
      else {
        if (typeof ip === "string" && ip !== "") claimed.add(ip);
        preferred.push(node);
      }
    }
  }
  return [...preferred, ...shadowed, ...cooling, ...retired].map((node) => node.id);
}

// ---------------------------------------------------------------- resin

export function resinExitSource(raw, { log } = {}) {
  if (!raw?.url) return undefined;
  if (typeof raw.url !== "string") throw new Error("resin.url must be a string");
  const { endpoint, token } = parseResinURL(raw.url);
  const transport = raw.transport ?? "forward";
  if (!["forward", "reverse"].includes(transport)) {
    throw new Error(`resin.transport must be forward or reverse, got ${transport}`);
  }
  const addresses = wholeNumber(raw.addresses, "resin.addresses", DEFAULT_ADDRESSES, 1, 1000);
  const prefix = raw.account ?? "zen-free";
  if (!/^[A-Za-z0-9_.-]+$/.test(prefix)) {
    throw new Error("resin.account may only hold letters, digits, dot, dash and underscore");
  }
  const platform = raw.platform ?? "Default";
  const attempts = wholeNumber(raw.attempts, "resin.attempts", DEFAULT_ATTEMPTS, 0, 10);
  // Checked after the options themselves, so a bad option is reported as itself
  // whatever the runtime is.
  requireForwardSupport(transport);
  const admin = raw.adminToken ? new ResinAdmin({ endpoint, token: raw.adminToken, platform }) : undefined;
  const resin = { endpoint, token, platform };
  return {
    kind: "resin",
    pool: new IPPool({ accounts: accountNames(prefix, addresses) }),
    attempts,
    ready: () => true,
    restart: async () => {},
    request(target, init, account) {
      if (transport === "reverse") {
        const headers = new Headers(init.headers);
        headers.set("x-resin-account", account);
        return fetch(reverseProxyURL(resin, target), { ...init, headers });
      }
      return fetch(target, { ...init, proxy: forwardProxyURL(resin, account) });
    },
    onMove(move) {
      log?.(`${move.from} -> ${move.to} after ${move.kind}${move.detail ? `: ${move.detail}` : ""}`);
      // Dropping the lease is what makes a reused Account come back as a
      // different address, so it is started here but never waited on.
      if (admin) void admin.release(move.from);
    },
    stop() {},
  };
}

// The gate that keeps a dead local core from being charged to the nodes.
//
// rotate() records every error that is not the caller walking away against the
// address it was using (resin.mjs). So the health check cannot live inside an
// attempt: it has to stop the request before rotate() is entered at all.
export async function attemptWithGate(source, run) {
  if (source === undefined) return run(undefined);
  if (!source.ready()) {
    await source.restart?.();
    throw new Error(
      `the local ${source.kind} core is not healthy, so no exit address was spent; see the pool log for its reason`,
    );
  }
  return run(source);
}

// Bounds only the wait for the response headers. The timer is cleared as soon
// as the attempt settles -- including when headers arrive -- which leaves the
// caller's own signal in charge of the body. A streamed answer must never be
// cut short by the timeout that gave up on a dead exit address.
export function withHeaderTimeout(send, { callerSignal, headerTimeoutMs }) {
  const controller = new AbortController();
  const relay = () => controller.abort();
  if (callerSignal?.aborted) controller.abort();
  else callerSignal?.addEventListener("abort", relay, { once: true });
  const timer = setTimeout(
    () => controller.abort(new Error("the exit address did not answer in time")),
    headerTimeoutMs,
  );
  return Promise.resolve()
    .then(() => send(controller.signal))
    .finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------- pool

export async function poolExitSource(raw, { input, log, env = process.env, fetchImpl = globalThis.fetch, zenHeaders, deps = {} } = {}) {
  // The seams below exist so the wiring can be driven without a real binary:
  // what is under test here is the contract between this module and the core,
  // not sing-box itself.
  const provision = deps.provisionBinary ?? provisionBinary;
  const readVersion = deps.readCoreVersion ?? readCoreVersion;
  const loadCandidatesFn = deps.loadCandidates ?? loadCandidates;
  const build = deps.buildConfig ?? buildConfig;
  const start = deps.startCore ?? startCore;
  if (!raw) return undefined;
  // The pool always reaches its nodes through a local HTTP proxy, which is the
  // one thing a runtime without Bun's proxy option silently ignores.
  requireForwardSupport("forward");

  const attempts = wholeNumber(raw.attempts, "pool.attempts", DEFAULT_ATTEMPTS, 0, 10);
  const maxNodes = wholeNumber(raw.maxNodes, "pool.maxNodes", DEFAULT_MAX_NODES, 1, 1000);
  // The user was told what this costs and chose it: a pin is what authenticates
  // a node whose SNI is camouflage, and sing-box below 1.15.0 cannot carry a
  // certificate hash, so the alternative is losing 23% of the pool.
  const allowUnpinned = raw.allowUnpinnedNodes ?? true;
  const distinctIps = raw.distinctIps ?? true;
  const portBase = wholeNumber(raw.core?.portBase, "pool.core.portBase", DEFAULT_PORT_BASE, 1, 65_535);
  const coreConfig = raw.core ?? {};
  const probeConfig = raw.probe ?? {};
  const stateDir = coreConfig.stateDir ?? join(input?.directory ?? defaultStateDir(env), "zen-free");
  const statePath = raw.statePath ?? join(stateDir, DEFAULT_STATE_FILE);
  const warnings = [];

  // 1. The core has to exist before anything can be measured or dialled, and
  //    that includes fetching it: the user asked for the install to be handled.
  //
  //    provisionBinary owns the whole order — an explicit core.binary, then
  //    whatever is on PATH, then the managed copy, and only then the network.
  //    Handing it the managed path as `binary` made it read that path as an
  //    explicitly configured one, so it threw "... is not a file" at the first
  //    branch and the managed copy and the download were both unreachable: the
  //    automatic install could never run. It gets only what the user set.
  const provisioned = await provision({
    binary: coreConfig.binary,
    stateDir,
    download: coreConfig.download !== false,
    env,
    fetchImpl,
    log,
  });
  // provisionBinary answers with a record, not a path: it knows which of the
  // four ways it found the binary, and which release it downloaded.
  const binary = typeof provisioned === "string" ? provisioned : provisioned.path;
  if (typeof binary !== "string" || binary === "") {
    throw new Error("pool: the core could not be located or provisioned");
  }
  const coreVersion = readVersion(binary);
  const version = typeof coreVersion === "string" ? coreVersion : coreVersion?.normalized;

  // 2. What the last run measured. A corrupt or missing file is not fatal.
  const seeded = load(statePath);
  for (const warning of seeded.warnings) warnings.push(warning.message ?? String(warning));

  // 3. What the subscriptions say now.
  const candidates = await loadCandidatesFn({
    subscriptions: raw.subscriptions ?? [],
    manual: raw.manual ?? [],
    coreVersion: version,
    allowUnpinned,
    maxNodes,
    timeoutMs: probeConfig.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    fetchImpl,
  });
  warnings.push(...candidates.warnings);

  const remembered = new Map(seeded.state.nodes.map((node) => [node.id, node]));
  let nodes = candidates.nodes.map((node) => {
    const previous = remembered.get(node.id);
    return previous
      ? { ...node, port: undefined, lastExitIp: previous.lastExitIp, exitIpAt: previous.exitIpAt, probeEwmaMs: { ...previous.probeEwmaMs }, lastProbedAt: previous.lastProbedAt, status: previous.status, failures: previous.failures, lastKind: previous.lastKind }
      : { ...node, lastExitIp: "", exitIpAt: 0, probeEwmaMs: {}, lastProbedAt: 0, status: "ready", failures: 0, lastKind: "" };
  });

  // 4. A pool that is configured but has nothing to dial is a configuration
  //    error, and must be said at load rather than turning into direct traffic.
  if (nodes.length === 0) {
    const detail = candidates.sources.filter((source) => !source.ok).map((source) => source.detail).join("; ");
    throw new Error(
      `pool: no usable node. ${candidates.counts.skipped} candidate(s) were skipped` +
        `${detail ? `; ${detail}` : ""}. Refusing to start rather than sending traffic out directly.`,
    );
  }

  // 5. One inbound per node, at portBase + index. buildConfig reports the ports
  //    it wrote; if it accepted fewer nodes than were handed over, the mapping
  //    would silently shift, so that is a hard error rather than a guess.
  const built = build(nodes.map((node) => ({ protocol: node.scheme, name: node.name, outbound: node.outbound })), {
    coreVersion: version,
    portBase,
    ...coreConfig,
  });
  if (built.counts.inbound !== nodes.length) {
    throw new Error(
      `pool: the core accepted ${built.counts.inbound} of ${nodes.length} nodes, so the port of each node is no longer known`,
    );
  }
  nodes = nodes.map((node, index) => ({ ...node, port: built.ports[index] }));

  const core = await start({
    binary,
    nodes: nodes.map((node) => ({ protocol: node.scheme, name: node.name, outbound: node.outbound })),
    core: { ...coreConfig, portBase },
    stateDir,
    log,
  });

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const pool = new IPPool({ accounts: rankAccounts(nodes, { distinctIps }) });
  const probeOptions = {
    zenUrl: probeConfig.zenUrl ?? DEFAULT_ZEN_URL,
    neutralUrls: probeConfig.neutralUrls ?? DEFAULT_NEUTRAL_URLS,
    timeoutMs: probeConfig.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    concurrency: probeConfig.concurrency ?? DEFAULT_CONCURRENCY,
    // Built by the caller, because provider.mjs is the one authority on what
    // the plugin looks like to Zen.
    zenHeaders: zenHeaders ?? zenProbeHeaders(),
    fetchImpl,
  };
  const minDistinctIps = probeConfig.minDistinctIps ?? DEFAULT_MIN_DISTINCT_IPS;
  const activeRefreshMs = probeConfig.activeRefreshMs ?? undefined;
  const staleMs = probeConfig.staleMs ?? undefined;

  let stopped = false;
  let refresher = null;
  function persist() {
    try {
      const { warnings: saveWarnings } = save(statePath, {
        ...seeded.state,
        nodes: nodes.map(({ port, name, ...node }) => node),
        portAssignment: { base: portBase },
      });
      for (const warning of saveWarnings ?? []) warnings.push(warning.message ?? String(warning));
    } catch (error) {
      warnings.push(`pool: the state file could not be written: ${error?.message ?? error}`);
    }
  }

  // Measurement never blocks a request: the first request uses the order the
  // last run left behind, and the pool is re-ranked as numbers arrive.
  async function refreshNow() {
    if (stopped) return;
    const active = pool.account();
    const due = dueForProbe(nodes, { activeId: active, activeRefreshMs, staleMs });
    if (due.length === 0) return;
    const targets = nodes.filter((node) => due.includes(node.id));
    const { results } = await probeNodes(targets, probeOptions);
    nodes = applyProbeResults(nodes, results);
    for (const node of nodes) byId.set(node.id, node);
    pool.setAccounts(rankAccounts(nodes, { distinctIps }));
    const distinct = countDistinctExitIps(nodes);
    const shortfall = distinctIpWarnings(nodes, { minDistinctIps });
    for (const warning of shortfall.warnings) log?.(`pool: ${warning}`);
    persist();
    log?.(`pool: measured ${results.length} node(s); ${distinct} distinct exit IP(s) over ${nodes.length} node(s)`);
  }

  function refresh() {
    if (stopped) return Promise.resolve();
    if (refresher !== null) return refresher;
    refresher = refreshNow()
      .catch((error) => log?.(`pool: probing failed: ${error?.message ?? error}`))
      .finally(() => {
        refresher = null;
      });
    return refresher;
  }

  const timer = setInterval(() => void refresh(), raw.refreshTickMs ?? DEFAULT_REFRESH_TICK_MS);
  timer.unref?.();

  if (candidates.counts.unpinned > 0) {
    log?.(
      `pool: ${candidates.counts.unpinned} node(s) are used WITHOUT their certificate pin (tls.insecure), because sing-box ${version} cannot carry a certificate hash (that needs 1.15.0). Set pool.allowUnpinnedNodes false to refuse them instead.`,
    );
  }
  for (const [key, count] of Object.entries(candidates.counts.ignoredParams ?? {})) {
    log?.(`pool: ignored ${count} "${key}" parameter(s) that cannot affect what is dialled`);
  }
  log?.(
    `pool: ${nodes.length} node(s) on ports ${built.ports[0]}..${built.ports[built.ports.length - 1]}, core ${version}, ${candidates.counts.byReason?.duplicate ?? 0} duplicate(s) dropped`,
  );
  // Start measuring, but do not wait for it.
  void refresh();

  return {
    kind: "pool",
    pool,
    attempts,
    warnings,
    ready: () => core.healthy(),
    // What the pool holds right now, for anything that reports on it: the
    // account's usage row is the one place magpie shows a plugin's own status.
    // A read of what is already in memory — it measures nothing, persists
    // nothing, and changes nothing.
    //
    // "alive" means an address the pool can actually leave from, by the same
    // rule the rest of the pool already uses (distinctIpWarnings): a retired
    // node is out for good, and a node with no measured address never answered.
    // Counting either would report IPs the pool does not have, which is the
    // number this exists to report.
    status() {
      const total = nodes.length;
      const alive = nodes.filter((node) => node.status !== "retired" && node.lastExitIp).length;
      return {
        total,
        alive,
        dead: total - alive,
        // countDistinctExitIps is the authority on this, and ignores retired
        // nodes too, so the two numbers agree.
        distinctIps: countDistinctExitIps(nodes),
        retired: nodes.filter((node) => node.status === "retired").length,
        cooling: nodes.filter((node) => node.status === "cooling").length,
        core: { version, healthy: core.healthy() },
      };
    },
    // The core supervises itself with backoff and stops after five failures, so
    // there is nothing to restart from here: report the core's own reason.
    async restart() {
      const info = core.info?.() ?? {};
      log?.(`pool: the local core is not healthy: ${info.lastError ?? info.phase ?? "unknown"}`);
    },
    request(target, init, id) {
      const node = byId.get(id);
      if (node === undefined) return Promise.reject(new Error(`pool: no node with id ${id}`));
      return fetch(target, { ...init, proxy: `http://127.0.0.1:${node.port}` });
    },
    onMove(move) {
      const node = byId.get(move.from);
      log?.(`${move.from} -> ${move.to} after ${move.kind}${move.detail ? `: ${move.detail}` : ""}`);
      if (node !== undefined) {
        // The node keeps its port and its place in the config; it is only taken
        // out of the running and re-measured later.
        node.status = "cooling";
        node.failures = (node.failures ?? 0) + 1;
        node.lastKind = move.kind;
        nodes = nodes.map((entry) => (entry.id === node.id ? { ...entry, ...node } : entry));
        persist();
      }
      void refresh();
    },
    async stop() {
      stopped = true;
      clearInterval(timer);
      await refresher?.catch(() => {});
      await core.stop();
    },
  };
}

// ---------------------------------------------------------------- choosing

export async function resolveExitSource(options, context = {}) {
  const pool = await poolExitSource(options.pool, context);
  if (pool !== undefined) return pool;
  return resinExitSource(options.resin, context);
}

export { rotate };
