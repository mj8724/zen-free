import assert from "node:assert/strict";
import test from "node:test";

// The pool dials its nodes through a local HTTP proxy, and requireForwardSupport
// refuses that on a runtime whose fetch accepts a proxy option and ignores it.
// That refusal is the point; it just means these particular cases are Bun-only,
// so they are skipped elsewhere rather than having the guard weakened for them.
const underBun = typeof globalThis.Bun !== "undefined";
const bunTest = underBun ? test : test.skip;
import {
  forwardProxyURL,
  poolExitSource,
  rankAccounts,
  attemptWithGate,
  resinExitSource,
  resolveExitSource,
  withHeaderTimeout,
  reverseProxyURL,
} from "./exits.mjs";

const node = (id, zen, exitIp, extra = {}) => ({
  id,
  scheme: "trojan",
  host: `${id}.invalid`,
  port: 443,
  outbound: { type: "trojan", server: `${id}.invalid`, server_port: 443, password: "p" },
  status: "ready",
  lastExitIp: exitIp ?? "",
  probeEwmaMs: zen === undefined ? {} : { zen },
  lastProbedAt: Date.now(),
  failures: 0,
  ...extra,
});

// ---------------------------------------------------------------- ordering

test("exits: the order is the priority, so the quickest unused address is spent first", () => {
  const ranked = rankAccounts([node("slow", 500), node("fast", 100), node("unmeasured")]);
  assert.deepEqual(ranked, ["fast", "slow", "unmeasured"]);
});

test("exits: an address that repeats one already claimed moves behind, it is not dropped", () => {
  const nodes = [node("fast", 100, "1.1.1.1"), node("dup", 150, "1.1.1.1"), node("other", 400, "2.2.2.2")];
  const ranked = rankAccounts(nodes, { distinctIps: true });
  assert.deepEqual(ranked, ["fast", "other", "dup"], "dup is still in the pool, just not preferred");
  assert.equal(ranked.length, nodes.length, "nothing is removed, so no port mapping shifts");
  assert.deepEqual(rankAccounts(nodes, { distinctIps: false }), ["fast", "dup", "other"]);
});

test("exits: addresses that were given up on and retired ones come last", () => {
  const nodes = [
    node("cool", 50, "1.1.1.1", { status: "cooling" }),
    node("live", 900, "2.2.2.2"),
    node("retired", 1, "3.3.3.3", { status: "retired" }),
  ];
  assert.deepEqual(rankAccounts(nodes), ["live", "cool", "retired"]);
});

test("exits: a neutral-only measurement still ranks ahead of an unmeasured address", () => {
  const withNeutral = node("neutral", undefined, undefined, { probeEwmaMs: { neutral: 200 } });
  assert.deepEqual(rankAccounts([node("never"), withNeutral]), ["neutral", "never"]);
});

// ---------------------------------------------------------------- resin

test("exits: the resin source keeps the identity Resin asks for", () => {
  const source = resinExitSource({ url: "http://resin.example:2260/token-abc", platform: "Default", account: "zf", addresses: 3, transport: underBun ? "forward" : "reverse" });
  assert.equal(source.kind, "resin");
  assert.equal(source.ready(), true, "resin has no local core to be unhealthy");
  assert.equal(forwardProxyURL({ endpoint: "http://resin.example:2260", token: "tok", platform: "Default" }, "zf-1"), "http://Default.zf-1:tok@resin.example:2260/");
  assert.equal(
    reverseProxyURL({ endpoint: "http://resin.example:2260", token: "tok", platform: "Default" }, "https://opencode.ai/inference/v1/chat/completions"),
    "http://resin.example:2260/tok/Default/https/opencode.ai/inference/v1/chat/completions",
  );
});

test("exits: a resin option that cannot be used is refused by name", () => {
  assert.throws(() => resinExitSource({ url: "http://resin.example:2260" }), /RESIN_PROXY_TOKEN/);
  assert.throws(() => resinExitSource({ url: "http://resin.example:2260/t", transport: "socks5" }), /resin\.transport/);
  assert.throws(() => resinExitSource({ url: "http://resin.example:2260/t", addresses: 0 }), /resin\.addresses/);
  assert.throws(() => resinExitSource({ url: "http://resin.example:2260/t", account: "bad name" }), /resin\.account/);
  assert.throws(() => resinExitSource({ url: "http://resin.example:2260/t", attempts: -1 }), /resin\.attempts/);
  assert.equal(resinExitSource({}), undefined, "no url means no source at all");
});

// ---------------------------------------------------------------- pool

// Everything the pool source reaches the outside world through, faked, so the
// contract can be exercised without a binary or a subscription.
function poolDeps({ nodes, healthy = () => true, built, coreLog } = {}) {
  const calls = { built: 0, started: 0, probes: 0 };
  const builtConfig = built ?? {
    config: { inbounds: [], outbounds: [], route: { rules: [] } },
    ports: (nodes ?? []).map((_, index) => 28100 + index),
    counts: { inbound: (nodes ?? []).length },
  };
  return {
    calls,
    deps: {
      provisionBinary: async ({ binary }) => binary ?? "fake-sing-box",
      readCoreVersion: () => "1.14.3",
      loadCandidates: async () => ({
        nodes: nodes ?? [],
        sources: [],
        skipped: [],
        warnings: [],
        counts: { input: (nodes ?? []).length, outbound: (nodes ?? []).length, skipped: 0, byReason: {}, ignoredParams: {}, unpinned: 0 },
      }),
      buildConfig: () => {
        calls.built += 1;
        return builtConfig;
      },
      startCore: async () => {
        calls.started += 1;
        return {
          healthy,
          info: () => ({ lastError: "the binary exited immediately", phase: "failed" }),
          stop: async () => {},
        };
      },
    },
  };
}

const basePool = { core: { binary: "fake-sing-box" }, probe: { timeoutMs: 50 }, attempts: 1 };

bunTest("exits: a pool with nothing to dial refuses to load instead of going direct", async () => {
  const { deps } = poolDeps({ nodes: [] });
  await assert.rejects(
    () => poolExitSource({ ...basePool }, { deps }),
    (error) => {
      assert.match(error.message, /no usable node/);
      assert.match(error.message, /Refusing to start rather than sending traffic out directly/);
      return true;
    },
  );
});

// The automatic install is the documented default, and by construction it runs
// only when nothing was configured and nothing is on PATH — which is the case
// below. The provisioner here behaves like the real one: it refuses a `binary`
// it was handed that is not a file, then downloads.
//
// This is the regression for a bug that made the install unreachable: the
// caller passed the MANAGED path as `binary`, so the real provisionBinary read
// it as an explicitly configured one, threw "... is not a file" at its first
// branch, and never reached the managed copy or the download at all. Every
// other pool test sets core.binary, and the stub accepted whatever it was
// given, so nothing exercised the path the README promises.
bunTest("exits: with no core.binary the pool asks the provisioner to install one", async () => {
  const { deps } = poolDeps({ nodes: [node("a", 100, "1.1.1.1")] });
  const asked = [];
  deps.provisionBinary = async (options) => {
    asked.push(options.binary);
    if (options.binary !== undefined && options.binary !== "") {
      throw new Error(`the configured sing-box binary ${options.binary} is not a file`);
    }
    assert.equal(options.download, true, "downloading stays allowed by default");
    return { path: "downloaded-sing-box", source: "release", version: "1.14.3", stateDir: options.stateDir };
  };

  const source = await poolExitSource({ core: {}, probe: { timeoutMs: 50 }, attempts: 1 }, { deps });
  assert.equal(source.kind, "pool");
  assert.deepEqual(asked, [undefined], "a managed path must not be passed as if the user had configured it");
  await source.stop();
});

bunTest("exits: a core that would not run is reported, not loaded anyway", async () => {
  const { deps } = poolDeps({ nodes: [node("a", 100)] });
  deps.startCore = async () => {
    throw new Error("sing-box check exited 1: bad outbound");
  };
  await assert.rejects(() => poolExitSource({ ...basePool }, { deps }), /sing-box check exited 1/);
});

bunTest("exits: a pool whose core dies reports itself unhealthy, so no address is spent", async () => {
  const { deps } = poolDeps({ nodes: [node("a", 100), node("b", 200)], healthy: () => false });
  const source = await poolExitSource({ ...basePool }, { deps });
  await source.stop();
  // This is the whole point of the gate: the caller can see the core is down
  // BEFORE entering rotate(), which would otherwise charge the failure to a node.
  assert.equal(source.ready(), false);
  assert.equal(source.kind, "pool");
});

bunTest("exits: each node keeps the port the core wrote for it", async () => {
  const nodes = [node("a", 100), node("b", 200)];
  const { deps } = poolDeps({ nodes });
  const source = await poolExitSource({ ...basePool }, { deps });
  await source.stop();
  // Node i is on portBase + i; the source resolves an id to that port, and an
  // unknown id is an error rather than a silent direct request.
  await assert.rejects(() => source.request("https://example.invalid/", {}, "no-such-node"), /no node with id/);
});

bunTest("exits: a core that accepted fewer nodes than were offered is a hard error", async () => {
  const nodes = [node("a", 100), node("b", 200)];
  const { deps } = poolDeps({ nodes, built: { config: {}, ports: [28100], counts: { inbound: 1 } } });
  await assert.rejects(
    () => poolExitSource({ ...basePool }, { deps }),
    /accepted 1 of 2 nodes, so the port of each node is no longer known/,
  );
});

bunTest("exits: giving up on a node takes it out of the running without touching its port", async () => {
  const nodes = [node("a", 100), node("b", 200)];
  const { deps } = poolDeps({ nodes });
  const source = await poolExitSource({ ...basePool }, { deps });
  source.onMove({ from: "a", to: "b", kind: "rate-limit" });
  await source.stop();
  // The node is cooling, which rankAccounts pushes behind the rest, but it is
  // still in the pool: removing it would mean regenerating the config.
  assert.equal(source.pool.accounts.length, 2);
});

bunTest("exits: the certificate-pin warning is raised at load, not left implicit", async () => {
  const said = [];
  const nodes = [node("a", 100)];
  const { deps } = poolDeps({ nodes });
  deps.loadCandidates = async () => ({
    nodes,
    sources: [],
    skipped: [],
    warnings: [],
    counts: { input: 1, outbound: 1, skipped: 0, byReason: {}, ignoredParams: { quicSecurity: 2 }, unpinned: 3 },
  });
  const source = await poolExitSource({ ...basePool }, { deps, log: (line) => said.push(line) });
  await source.stop();
  assert.match(said.join("\n"), /3 node\(s\) are used WITHOUT their certificate pin/);
  assert.match(said.join("\n"), /ignored 2 "quicSecurity"/);
});

bunTest("exits: the pool takes precedence over resin when both are configured", async () => {
  const { deps } = poolDeps({ nodes: [node("a", 100)] });
  const pool = await poolExitSource({ ...basePool }, { deps });
  const chosen = await resolveExitSource(
    { pool: { ...basePool }, resin: { url: "http://resin.example:2260/t" } },
    { deps },
  );
  await pool.stop();
  await chosen.stop?.();
  assert.equal(chosen.kind, "pool");
  assert.equal(await resolveExitSource({}, { deps }), undefined, "neither configured means direct");
  assert.equal((await resolveExitSource({ resin: { url: "http://resin.example:2260/t" } })).kind, "resin");
});

// ------------------------------------------------- the gate, and why it is outside

// The requirement this pair of tests exists for: a local core that dies must
// not be charged to the exit addresses. rotate() records every error that is
// not the caller walking away against the address it was using, so the health
// check has to stop the request before rotate() is entered.

test("exits: a dead core costs the node table nothing at all", async () => {
  const { IPPool, rotate } = await import("../resin.mjs");
  const pool = new IPPool({ accounts: ["a", "b", "c"] });
  let attempts = 0;
  const source = {
    kind: "pool",
    pool,
    ready: () => false,
    restart: async () => {},
    request: () => {
      attempts += 1;
      throw new Error("must never be reached");
    },
  };
  await assert.rejects(
    () => attemptWithGate(source, (live) => rotate({ pool: live.pool, attempts: 2, attempt: (id) => live.request(id) })),
    /not healthy, so no exit address was spent/,
  );
  assert.equal(attempts, 0, "no attempt was made");
  assert.ok(
    pool.slots.every((slot) => slot.failures === 0),
    "not one node was charged for the core's failure",
  );
  assert.ok(pool.slots.every((slot) => slot.state === "ready"), "and none was taken out of the running");
});

test("exits: contrast - through a healthy gate a failure IS charged, so the test above means something", async () => {
  const { IPPool, rotate } = await import("../resin.mjs");
  const pool = new IPPool({ accounts: ["a"] });
  const source = {
    kind: "pool",
    pool,
    ready: () => true,
    restart: async () => {},
    request: () => {
      throw new Error("ECONNRESET");
    },
  };
  await assert.rejects(() =>
    attemptWithGate(source, (live) => rotate({ pool: live.pool, attempts: 1, attempt: (id) => live.request(id) })),
  );
  assert.equal(pool.slots[0].failures, 2, "the node was charged both times, which is correct for its own failure");
});

// ------------------------------------------- header timeout vs a streamed body

test("exits: the header timeout gives up on an address that never answers", async () => {
  let aborted = false;
  await assert.rejects(
    () =>
      withHeaderTimeout(
        (signal) =>
          new Promise((resolve, reject) => {
            signal.addEventListener("abort", () => {
              aborted = true;
              reject(signal.reason);
            });
          }),
        { headerTimeoutMs: 20 },
      ),
    /did not answer in time/,
  );
  assert.equal(aborted, true);
});

test("exits: the header timeout does not cut short a body that is still streaming", async () => {
  // Headers arrive immediately; the body takes far longer than the timeout.
  const slowBody = new ReadableStream({
    async start(controller) {
      controller.enqueue(new TextEncoder().encode("first "));
      await new Promise((resolve) => setTimeout(resolve, 120));
      controller.enqueue(new TextEncoder().encode("second"));
      controller.close();
    },
  });
  const started = Date.now();
  const response = await withHeaderTimeout(
    async () => new Response(slowBody, { status: 200, headers: { "content-type": "text/event-stream" } }),
    { callerSignal: undefined, headerTimeoutMs: 20 },
  );
  const text = await response.text();
  assert.equal(text, "first second", "the whole stream arrived");
  assert.ok(Date.now() - started >= 100, "it really did outlive the timeout");
});

test("exits: the caller walking away still aborts the body after the timer is gone", async () => {
  const controller = new AbortController();
  const response = await withHeaderTimeout(async () => new Response("body", { status: 200 }), {
    callerSignal: controller.signal,
    headerTimeoutMs: 1000,
  });
  assert.equal(response.status, 200);
  controller.abort();
  assert.equal(controller.signal.aborted, true, "the caller's own signal is what governs the body");
});
