// The wiring between the plugin and Resin: every upstream request leaves
// through the pooled exit address, and a refusal makes the plugin ask again
// from a different one without the caller seeing it happen.
//
// The forward transport is Bun's alone (its fetch takes a proxy option), so
// the tests about what a refusal does pick whichever transport the runtime
// actually has. What each transport puts on the wire is asserted separately.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import test from "node:test";

const subject = import("./index.mjs").then((module) => module.ZenFreePlugin);

const ANSWER =
  'data: {"id":"chat-1","model":"chat-free","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n';
const publicAuth = async () => ({ type: "api", key: "public" });
const underBun = typeof globalThis.Bun !== "undefined";
const workingTransport = () => (underBun ? "forward" : "reverse");

function listen(server) {
  server.listen(0, "127.0.0.1");
  return once(server, "listening").then(() => `127.0.0.1:${server.address().port}`);
}

function credentials(header) {
  if (!header?.startsWith("Basic ")) return undefined;
  return Buffer.from(header.slice(6), "base64").toString("utf8");
}

// Resin reads the identity as Platform.Account, splitting on the first dot and
// the last colon, so the double reproduces that split.
function identity(credential) {
  if (!credential) return {};
  const colon = credential.lastIndexOf(":");
  const pair = colon === -1 ? credential : credential.slice(0, colon);
  const dot = pair.indexOf(".");
  return dot === -1
    ? { account: pair }
    : { platform: pair.slice(0, dot), account: pair.slice(dot + 1) };
}

function teardown(t, server) {
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
}

// Zen's side: model discovery plus one inference endpoint whose answers a
// test drives.
async function upstream(t) {
  const state = {
    calls: 0,
    refuse: 0,
    status: 429,
    body: JSON.stringify({ error: { message: "rate limit" } }),
  };
  const server = createServer(async (req, res) => {
    if (req.url.startsWith("/v1/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: [{ id: "chat-free" }] }));
      return;
    }
    if (req.url.startsWith("/catalog")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          opencode: {
            npm: "@ai-sdk/openai-compatible",
            models: { "chat-free": { name: "Chat Free", limit: { context: 1000, output: 100 } } },
          },
        }),
      );
      return;
    }
    if (req.url.startsWith("/docs")) {
      res.writeHead(404);
      res.end();
      return;
    }
    for await (const _ of req);
    state.calls += 1;
    if (state.calls <= state.refuse) {
      res.writeHead(state.status, { "content-type": "application/json" });
      res.end(state.body);
      return;
    }
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end(ANSWER);
  });
  const host = await listen(server);
  teardown(t, server);
  return { state, origin: `http://${host}`, host };
}

// Resin's side. One endpoint plays every role a real Resin does: the proxy a
// request is dialled through (forward or reverse form), and the dashboard API
// the plugin drops a spent lease with. Both proxy forms are answered by the
// upstream, so a request that arrives here is a request that reached Zen.
async function resin(t) {
  const state = { calls: [], forward: [], reverse: [], releases: [], platforms: 0 };
  const server = createServer(async (req, res) => {
    if (req.url === "/api/v1/platforms?limit=200") {
      state.platforms += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ items: [{ id: "p1", name: "Default" }] }));
      return;
    }
    const release = /^\/api\/v1\/platforms\/p1\/leases\/(.+)$/.exec(req.url);
    if (release) {
      state.releases.push(decodeURIComponent(release[1]));
      res.writeHead(200);
      res.end("{}");
      return;
    }
    let text = "";
    for await (const chunk of req) text += chunk;

    // Resin's reverse form: <token>/<platform>/<protocol>/<host><path>, with
    // the identity in a header.
    const reverse = /^\/([^/]+)\/([^/]+)\/(https?)\/([^/]+)(\/.*)$/.exec(req.url);
    let target;
    if (reverse) {
      const [, token, platform, protocol, host, path] = reverse;
      const entry = { token, platform, protocol, host, path, account: req.headers["x-resin-account"] };
      state.reverse.push(entry);
      state.calls.push(entry);
      target = `${protocol}://${host}${path}`;
    } else {
      const credential = credentials(req.headers["proxy-authorization"]);
      const entry = { url: req.url, raw: credential, ...identity(credential) };
      state.forward.push(entry);
      state.calls.push(entry);
      target = req.url;
    }

    const body = { ...req.headers, host: new URL(target).host };
    delete body["proxy-authorization"];
    delete body["proxy-connection"];
    const out = await fetch(target, { method: req.method, headers: body, body: text || undefined });
    res.writeHead(out.status, {
      "content-type": out.headers.get("content-type") ?? "application/json",
    });
    res.end(await out.text());
  });
  const host = await listen(server);
  teardown(t, server);
  return { state, origin: `http://${host}`, host };
}

async function ask(plugin, origin, { stream = true } = {}) {
  await plugin.provider.models({ models: {} }, { auth: await publicAuth() });
  const loader = await plugin.auth.loader(publicAuth);
  const response = await loader.fetch(`${origin}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "chat-free", stream }),
  });
  return { response, text: await response.text() };
}

async function load(resinOptions, upstreamOrigin) {
  const plugin = await subject;
  return plugin(
    {},
    {
      baseURL: `${upstreamOrigin}/v1`,
      catalogURL: `${upstreamOrigin}/catalog`,
      docsURL: `${upstreamOrigin}/docs`,
      resin: resinOptions,
    },
  );
}

const pool = (hub, extra) => ({
  url: `${hub.origin}/secret-token`,
  platform: "Default",
  account: "zen-free",
  addresses: 4,
  ...extra,
});

test("without Resin configured the request goes out directly, as before", async (t) => {
  const zen = await upstream(t);
  const plugin = await load(undefined, zen.origin);
  const { response, text } = await ask(plugin, zen.origin);
  assert.equal(response.status, 200);
  assert.match(text, /hello/);
  assert.equal(zen.state.calls, 1);
});

test(
  "the forward transport hands Resin the exit address's identity",
  { skip: underBun ? false : "the forward transport needs Bun's fetch proxy option" },
  async (t) => {
    const zen = await upstream(t);
    const hub = await resin(t);
    const plugin = await load(pool(hub), zen.origin);
    const { response, text } = await ask(plugin, zen.origin);
    assert.equal(response.status, 200);
    assert.match(text, /hello/);
    assert.equal(hub.state.forward.length, 1);
    assert.deepEqual(hub.state.forward[0], {
      url: `${zen.origin}/v1/chat/completions`,
      raw: "Default.zen-free-1:secret-token",
      platform: "Default",
      account: "zen-free-1",
    });
  },
);

test("the reverse transport carries the target in the path and the identity in a header", async (t) => {
  const zen = await upstream(t);
  const hub = await resin(t);
  const plugin = await load(pool(hub, { transport: "reverse" }), zen.origin);
  const { response, text } = await ask(plugin, zen.origin);
  assert.equal(response.status, 200);
  assert.match(text, /hello/);
  assert.deepEqual(hub.state.reverse[0], {
    token: "secret-token",
    platform: "Default",
    protocol: "http",
    host: zen.host,
    path: "/v1/chat/completions",
    account: "zen-free-1",
  });
  assert.equal(hub.state.forward.length, 0, "the reverse form is not a forward-proxy request");
});

test("a rate limit is answered from a different exit address, unseen by the caller", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 1;
  const hub = await resin(t);
  const plugin = await load(pool(hub, { transport: workingTransport() }), zen.origin);
  const { response, text } = await ask(plugin, zen.origin);
  assert.equal(response.status, 200, "the caller only ever sees the answer");
  assert.match(text, /hello/);
  assert.deepEqual(
    hub.state.calls.map((entry) => entry.account),
    ["zen-free-1", "zen-free-2"],
    "the retry leaves from a new address",
  );
});

test("a policy refusal is answered the same way", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 1;
  zen.state.status = 403;
  zen.state.body = JSON.stringify({
    error: { message: "Your access has been restricted due to repeated policy violations." },
  });
  const hub = await resin(t);
  const plugin = await load(pool(hub, { transport: workingTransport() }), zen.origin);
  const { response } = await ask(plugin, zen.origin);
  assert.equal(response.status, 200);
  assert.deepEqual(
    hub.state.calls.map((entry) => entry.account),
    ["zen-free-1", "zen-free-2"],
  );
});

test("an upstream failure is answered from a different address too", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 1;
  zen.state.status = 500;
  zen.state.body = JSON.stringify({ error: { message: "upstream error: do request failed" } });
  const hub = await resin(t);
  const plugin = await load(pool(hub, { transport: workingTransport() }), zen.origin);
  const { response } = await ask(plugin, zen.origin);
  assert.equal(response.status, 200);
  assert.equal(hub.state.calls.length, 2);
});

test("the plugin's own 403 is handed back without spending another address", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 99;
  zen.state.status = 403;
  zen.state.body = JSON.stringify({
    error: { type: "FreeTierError", message: "can only be used from within OpenCode" },
  });
  const hub = await resin(t);
  const plugin = await load(pool(hub, { transport: workingTransport() }), zen.origin);
  const { response, text } = await ask(plugin, zen.origin);
  assert.equal(response.status, 403);
  assert.match(text, /FreeTierError/, "the upstream's own words reach the caller");
  assert.equal(hub.state.calls.length, 1, "an IP change cannot fix this, so none is spent");
});

test("once every address has been tried the upstream's own refusal is handed back", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 99;
  const hub = await resin(t);
  const plugin = await load(
    pool(hub, { transport: workingTransport(), addresses: 2, attempts: 2 }),
    zen.origin,
  );
  const { response, text } = await ask(plugin, zen.origin);
  assert.equal(response.status, 429);
  assert.match(text, /rate limit/);
  assert.equal(hub.state.calls.length, 3, "one try plus two attempts, each from one address");
});

test("a spent address has its lease dropped so reuse lands somewhere else", async (t) => {
  const zen = await upstream(t);
  zen.state.refuse = 1;
  const hub = await resin(t);
  const plugin = await load(
    pool(hub, { transport: workingTransport(), addresses: 2, adminToken: "dash-token" }),
    zen.origin,
  );
  await ask(plugin, zen.origin);
  // The release is started alongside the retry and never waited on.
  for (let wait = 0; wait < 100 && !hub.state.releases.length; wait += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.deepEqual(hub.state.releases, ["zen-free-1"]);
  assert.equal(hub.state.platforms, 1, "the platform is resolved once and remembered");
});

test("a request that succeeds first time never moves and never releases", async (t) => {
  const zen = await upstream(t);
  const hub = await resin(t);
  const plugin = await load(
    pool(hub, { transport: workingTransport(), addresses: 4, adminToken: "dash-token" }),
    zen.origin,
  );
  await ask(plugin, zen.origin);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(hub.state.calls.map((entry) => entry.account), ["zen-free-1"]);
  assert.deepEqual(hub.state.releases, [], "a working address is left alone");
});

test("a Resin URL that cannot be used stops the plugin instead of going direct in silence", async (t) => {
  const zen = await upstream(t);
  await assert.rejects(
    () => load({ url: "http://127.0.0.1:2260" }, zen.origin),
    /RESIN_PROXY_TOKEN, which is not the dashboard token/,
  );
  await assert.rejects(
    () => load({ url: `${zen.origin}/t`, transport: "socks5" }, zen.origin),
    /resin.transport must be forward or reverse/,
  );
  await assert.rejects(
    () => load({ url: `${zen.origin}/t`, addresses: 0 }, zen.origin),
    /resin.addresses must be a whole number from 1 to 1000/,
  );
  await assert.rejects(
    () => load({ url: `${zen.origin}/t`, account: "bad name" }, zen.origin),
    /resin.account may only hold letters, digits, dot, dash and underscore/,
  );
});
