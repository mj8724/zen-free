import assert from "node:assert/strict";
import test from "node:test";
import { SourceError, loadCandidates, readBody, scrubUrls } from "./sources.mjs";
import { SOURCE_REASONS } from "./sources.mjs";

const VLESS = "vless://11111111-1111-4111-8111-111111111111@example.invalid:443?type=ws&security=tls";
const VLESS_OTHER = "vless://22222222-2222-4222-8222-222222222222@other.invalid:443?type=ws&security=tls";
const TROJAN = "trojan://fixture-pass@trojan.invalid:443";
const HY2 = "hysteria2://fixture-pass@hy.invalid:443?sni=www.apple.com&pinSHA256=" + "a".repeat(64);

const json = (value, init = {}) =>
  new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" }, ...init });

const text = (value, init = {}) =>
  new Response(value, { status: 200, headers: { "content-type": "text/plain" }, ...init });

const fetchOf = (responses) => async (url) => {
  const entry = responses[url];
  if (entry === undefined) throw new Error(`unexpected fetch of ${url}`);
  if (typeof entry === "function") return entry();
  return entry;
};

// ------------------------------------------------------------------ format

test("sources: a base64 body is unwrapped into the link list it carries", () => {
  const wrapped = Buffer.from([VLESS, VLESS_OTHER].join("\n"), "utf8").toString("base64");
  const { format, body } = readBody(wrapped);
  assert.equal(format, "uri-lines");
  assert.match(body, /^vless:\/\//);
});

test("sources: a link list passes through and a bare address list is recognised", () => {
  assert.equal(readBody([VLESS, TROJAN].join("\n")).format, "uri-lines");
  assert.equal(readBody("198.51.100.20:17981\n198.51.100.21:17981").format, "plain-lines");
});

test("sources: sing-box JSON is recognised, an empty body and an unknown body are refused", () => {
  assert.equal(readBody('{"outbounds":[]}').format, "json");
  assert.throws(() => readBody("   "), /nothing to parse/);
  assert.throws(() => readBody("hello there, this is prose"), /neither a link list/);
});

test("sources: a Clash profile is refused with the way out, not parsed", () => {
  const clash = "proxies:\n  - name: a\n    type: ss\n    server: example.invalid\n    port: 443\n";
  assert.throws(
    () => readBody(clash, { url: "https://p.example/sub?token=SECRET" }),
    (error) => {
      assert.equal(error.code, "SOURCE_CLASH");
      assert.match(error.message, /base64 \/ v2ray/);
      assert.doesNotMatch(error.message, /SECRET/, "the token must not ride along in the message");
      return true;
    },
  );
});

// ----------------------------------------------------------------- fetching

test("sources: a body larger than the cap is refused, and reported as a source failure", async () => {
  const big = "x".repeat(5000);
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub", name: "big" }],
    maxBytes: 1000,
    fetchImpl: async () => text(big),
  });
  assert.equal(result.sources[0].ok, false);
  assert.equal(result.sources[0].code, "SOURCE_TOO_LARGE");
  assert.equal(result.counts.input, 0, "a source that could not be read contributes no candidates");
  assert.equal(result.nodes.length, 0);
});

test("sources: a fetch failure never leaks the subscription token", async () => {
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub?token=SUPERSECRET", name: "p" }],
    fetchImpl: async (url) => {
      // Exactly what a real fetch error looks like: the whole URL, token and all.
      throw new Error(`connect ECONNREFUSED while fetching ${url}`);
    },
  });
  const shown = JSON.stringify(result);
  assert.doesNotMatch(shown, /SUPERSECRET/, "the token must not appear anywhere in the result");
  assert.equal(result.sources[0].ok, false);
  assert.equal(result.nodes.length, 0);
  assert.match(result.sources[0].detail, /ECONNREFUSED/, "the reason itself is still reported");
});

test("sources: every URL in a message is reduced to something safe to log", () => {
  const scrubbed = scrubUrls("failed for https://p.example/sub?token=SECRET and https://q.example/api?k=2");
  assert.doesNotMatch(scrubbed, /SECRET/);
  assert.match(scrubbed, /https:\/\/p\.example\/sub/);
  assert.doesNotMatch(scrubbed, /k=2/);
});

// ------------------------------------------------------------------ loading

test("sources: subscriptions and manual entries land in one deduplicated pool", async () => {
  const body = Buffer.from([VLESS, VLESS_OTHER].join("\n"), "utf8").toString("base64");
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub", name: "providerA" }],
    manual: [TROJAN, "198.51.100.20:17981"],
    fetchImpl: fetchOf({ "https://p.example/sub": () => text(body) }),
    coreVersion: "1.14.3",
  });
  assert.deepEqual(result.nodes.map((n) => n.scheme).sort(), ["http", "trojan", "vless", "vless"]);
  assert.equal(result.nodes.find((n) => n.scheme === "vless").sourceTag, "providerA");
  assert.equal(result.nodes.find((n) => n.scheme === "trojan").sourceTag, "manual");
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});

test("sources: the same node from two sources is one slot, counted as a duplicate", async () => {
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub", name: "a" }],
    manual: [VLESS],
    fetchImpl: fetchOf({ "https://p.example/sub": () => text(VLESS) }),
    coreVersion: "1.14.3",
  });
  assert.equal(result.nodes.length, 1);
  assert.equal(result.counts.input, 2);
  assert.equal(result.counts.byReason.duplicate, 1);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
  // The identity has to be the same one state.mjs would compute, or a restart
  // would treat the same node as new.
  const same = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub", name: "renamed" }],
    fetchImpl: fetchOf({ "https://p.example/sub": () => text(VLESS) }),
    coreVersion: "1.14.3",
  });
  assert.equal(result.nodes[0].id, same.nodes[0].id, "a source that renamed itself is still one node");
});

test("sources: nodes past the cap are counted as over-capacity, not dropped", async () => {
  const body = [VLESS, VLESS_OTHER, TROJAN].join("\n");
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub" }],
    fetchImpl: fetchOf({ "https://p.example/sub": () => text(body) }),
    maxNodes: 2,
    coreVersion: "1.14.3",
  });
  assert.equal(result.nodes.length, 2);
  assert.equal(result.counts.byReason[SOURCE_REASONS.OVER_CAPACITY], 1);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});

test("sources: sing-box JSON becomes nodes and its tags stay with the caller", async () => {
  const payload = {
    outbounds: [
      { type: "trojan", tag: "from-json", server: "json.invalid", server_port: 8443, password: "p" },
      { type: "selector", tag: "s", outbounds: ["a"] },
      { type: "trojan", tag: "no-server", server_port: 1 },
    ],
  };
  const result = await loadCandidates({
    subscriptions: [{ url: "https://p.example/sub" }],
    fetchImpl: fetchOf({ "https://p.example/sub": () => json(payload) }),
    coreVersion: "1.14.3",
  });
  assert.equal(result.nodes.length, 1);
  assert.equal(result.nodes[0].name, "from-json");
  assert.equal(result.nodes[0].outbound.tag, undefined, "core.mjs owns tags");
  assert.equal(result.counts.byReason["parse-error"], 2);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});

test("sources: the certificate-pin policy is threaded through, so unpinned nodes are visible", async () => {
  const strict = await loadCandidates({
    manual: [HY2],
    coreVersion: "1.14.3",
    fetchImpl: async () => text(""),
  });
  assert.equal(strict.nodes.length, 0);
  assert.equal(strict.counts.byReason[SOURCE_REASONS.CORE_TOO_OLD], 1);

  const allowed = await loadCandidates({ manual: [HY2], coreVersion: "1.14.3", allowUnpinned: true });
  assert.equal(allowed.nodes.length, 1);
  assert.equal(allowed.counts.unpinned, 1, "a node used without its pin is counted, never silent");
});

test("sources: a subscription that fails does not stop the ones that work", async () => {
  const result = await loadCandidates({
    subscriptions: [
      { url: "https://dead.example/sub", name: "dead" },
      { url: "https://live.example/sub", name: "live" },
    ],
    fetchImpl: fetchOf({
      "https://dead.example/sub": () => {
        throw new Error("ENOTFOUND");
      },
      "https://live.example/sub": () => text(VLESS),
    }),
    coreVersion: "1.14.3",
  });
  assert.equal(result.nodes.length, 1, "the live source still contributes");
  assert.equal(result.sources.filter((s) => s.ok).length, 1);
  assert.equal(result.sources.filter((s) => !s.ok).length, 1);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});

test("sources: leftover exporter noise is reported by name, not hidden", async () => {
  const noisy = "vless://11111111-1111-4111-8111-111111111111@example.invalid:443?type=ws&quicSecurity=none";
  const result = await loadCandidates({ manual: [noisy], coreVersion: "1.14.3" });
  assert.equal(result.nodes.length, 1);
  assert.deepEqual(result.counts.ignoredParams, { quicSecurity: 1 });
});

test("sources: nothing configured yields nothing, without inventing a node", async () => {
  const result = await loadCandidates({});
  assert.deepEqual(result.nodes, []);
  assert.equal(result.counts.input, 0);
  assert.equal(result.counts.outbound, 0);
  assert.ok(result instanceof Object);
  assert.ok(new SourceError("X", "y") instanceof Error);
});
