import assert from "node:assert/strict";
import test from "node:test";
import {
  IPPool,
  ResinAdmin,
  accountNames,
  classifyResponse,
  parseResinURL,
  requireForwardSupport,
  rotate,
  transportFailure,
} from "./resin.mjs";

const reply = (status, body, type = "application/json") =>
  new Response(body, { status, headers: { "content-type": type } });

const pool = (count, prefix = "zf") => new IPPool({ accounts: accountNames(prefix, count) });

test("resin: the URL Resin hands out splits into an endpoint and a proxy token", () => {
  assert.deepEqual(parseResinURL("http://resin.example:2260/demo-proxy-token"), {
    endpoint: "http://resin.example:2260",
    token: "demo-proxy-token",
  });
  assert.deepEqual(parseResinURL("http://127.0.0.1:2260/my-token/"), {
    endpoint: "http://127.0.0.1:2260",
    token: "my-token",
  });
});

test("resin: a URL without the proxy token is refused with the reason", () => {
  assert.throws(() => parseResinURL("http://127.0.0.1:2260"), /RESIN_PROXY_TOKEN, which is not the dashboard token/);
  assert.throws(() => parseResinURL("http://user:pass@127.0.0.1:2260/t"), /must not carry credentials/);
  assert.throws(() => parseResinURL("http://127.0.0.1:2260/t?a=1"), /must not carry credentials, a query or a fragment/);
  assert.throws(() => parseResinURL("socks5://127.0.0.1:2260/t"), /must be http or https/);
  assert.throws(() => parseResinURL("http://127.0.0.1:2260/a/b"), /exactly one path segment/);
});

test("resin: account names are stable and do not repeat", () => {
  assert.deepEqual(accountNames("zen-free", 3), ["zen-free-1", "zen-free-2", "zen-free-3"]);
});

// Node's fetch accepts a proxy option and ignores it, which would send traffic
// straight out while a user believes it rotates between addresses.
test("resin: the forward transport is refused where fetch would ignore the proxy", () => {
  assert.throws(() => requireForwardSupport("forward", {}), /needs a runtime whose fetch takes a proxy option/);
  requireForwardSupport("forward", { Bun: { version: "1.4.3" } });
  requireForwardSupport("reverse", {});
});

test("pool: one address serves every request until something fails", () => {
  const subject = pool(3);
  assert.equal(subject.account(subject.pick()), "zf-1");
  subject.succeeded(0, 120);
  assert.equal(subject.account(subject.pick()), "zf-1");
  subject.succeeded(0, 130);
  assert.equal(subject.account(subject.pick()), "zf-1");
});

test("pool: a failure moves to an address never used before a measured one", () => {
  const subject = pool(4);
  subject.succeeded(0, 100);
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-2");
  subject.succeeded(1, 900);
  assert.equal(subject.account(subject.failed(1, "status 429")), "zf-3");
  assert.equal(subject.account(subject.failed(2, "status 429")), "zf-4");
});

test("pool: among measured addresses the quickest one is taken", () => {
  const subject = pool(3);
  subject.succeeded(1, 120);
  subject.succeeded(2, 800);
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-2");
  assert.equal(subject.account(), "zf-2");
});

test("pool: once every address is spent the one rested longest comes back", () => {
  let clock = 0;
  const subject = new IPPool({ accounts: accountNames("zf", 3), now: () => (clock += 1_000) });
  subject.failed(0, "status 429");
  subject.failed(1, "status 429");
  subject.failed(2, "status 429");
  assert.equal(subject.account(), "zf-1", "the address given up on longest ago is reused first");
  subject.failed(0, "status 429");
  assert.equal(subject.account(), "zf-2");
  assert.equal(subject.slots[0].samples, 0, "a reused address is measured again from scratch");
});

test("pool: concurrent failures on one address rotate the pool once", () => {
  const subject = pool(3);
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-2");
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-2");
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-2");
  assert.equal(subject.slots[0].failures, 3);
});

test("pool: when every address is spent the one rested longest comes back", () => {
  let clock = 1_000;
  const subject = new IPPool({ accounts: accountNames("zf", 2), now: () => (clock += 1_000) });
  subject.failed(0, "status 429");
  subject.failed(1, "status 429");
  assert.equal(subject.account(subject.pick()), "zf-1");
});

test("pool: a pool of one address still serves", () => {
  const subject = pool(1);
  assert.equal(subject.account(subject.failed(0, "status 429")), "zf-1");
});

test("pool: an empty pool is refused", () => {
  assert.throws(() => new IPPool({ accounts: [] }), /at least one account/);
});

test("classify: a streamed answer is never read and never moves traffic", async () => {
  const stream = reply(200, 'data: {"error":"upstream error"}\n\n', "text/event-stream");
  const verdict = await classifyResponse(stream);
  assert.equal(verdict.switch, false);
  assert.equal(verdict.response, stream, "the response object is handed on untouched");
});

test("classify: an ordinary JSON answer is handed on unchanged", async () => {
  const verdict = await classifyResponse(reply(200, JSON.stringify({ choices: [] })));
  assert.equal(verdict.switch, false);
  assert.equal(await verdict.response.text(), JSON.stringify({ choices: [] }));
});

test("classify: a 200 whose error envelope says upstream failed does move", async () => {
  const body = JSON.stringify({ type: "error", error: { message: "upstream error: do request failed" } });
  const verdict = await classifyResponse(reply(200, body));
  assert.equal(verdict.switch, true);
  assert.equal(verdict.kind, "upstream");
  assert.equal(await verdict.response.text(), body, "the caller still reads the upstream's words");
});

test("classify: a 200 carrying some other complaint does not spend an address", async () => {
  for (const message of ["model not found", "invalid request", "unsupported tool"]) {
    const body = JSON.stringify({ error: { message } });
    const verdict = await classifyResponse(reply(200, body));
    assert.equal(verdict.switch, false, `${message} is not something another address fixes`);
    assert.equal(await verdict.response.text(), body);
  }
});

test("classify: the plugin's own 403 is not a reason to move even at status 200", async () => {
  const body = JSON.stringify({ error: { type: "FreeTierError", message: "can only be used from within OpenCode" } });
  const verdict = await classifyResponse(reply(200, body));
  assert.equal(verdict.switch, false);
  assert.equal(await verdict.response.text(), body);
});

test("classify: a model writing about upstream errors in an answer does not move", async () => {
  const body = JSON.stringify({ choices: [{ message: { content: "an upstream error is what we log" } }] });
  const verdict = await classifyResponse(reply(200, body));
  assert.equal(verdict.switch, false);
});

test("classify: every failure the user named moves the request", async () => {
  const cases = [
    [429, JSON.stringify({ error: { message: "Too Many Requests" } })],
    [429, ""],
    [403, JSON.stringify({ error: { message: "Your access has been restricted due to repeated policy violations." } })],
    [403, ""],
    [500, JSON.stringify({ error: { message: "upstream error: do request failed" } })],
    [502, ""],
    [503, JSON.stringify({ error: { message: "rate limit exceeded" } })],
    [504, ""],
  ];
  for (const [status, body] of cases) {
    const verdict = await classifyResponse(reply(status, body));
    assert.equal(verdict.switch, true, `HTTP ${status} must move the request`);
  }
});

test("classify: the plugin's own 403 is handed back instead of spending the pool", async () => {
  const body = JSON.stringify({
    error: { type: "FreeTierError", message: "can only be used from within OpenCode" },
  });
  const verdict = await classifyResponse(reply(403, body));
  assert.equal(verdict.switch, false);
  assert.equal(verdict.kind, "freetier");
  assert.equal(await verdict.response.text(), body);
});

test("classify: a failing request with almost nothing to read still moves", async () => {
  const verdict = await classifyResponse(reply(403, "no"));
  assert.equal(verdict.switch, true);
  assert.equal(verdict.kind, "status 403");
});

test("classify: an answer that is not a refusal is left alone", async () => {
  for (const status of [400, 401, 404, 422]) {
    const verdict = await classifyResponse(reply(status, JSON.stringify({ error: { message: "no" } })));
    assert.equal(verdict.switch, false, `HTTP ${status} must not move the request`);
  }
});

test("classify: an oversized failing body moves without being read", async () => {
  const big = "x".repeat(1000);
  const response = new Response(big, {
    status: 500,
    headers: { "content-type": "text/plain", "content-length": String(200_000) },
  });
  const verdict = await classifyResponse(response);
  assert.equal(verdict.switch, true);
  assert.match(verdict.detail, /too large/);
});

test("transport: the caller walking away is not a failure to move on", () => {
  assert.equal(transportFailure(Object.assign(new Error("gone"), { name: "AbortError" }), undefined), undefined);
  assert.equal(transportFailure(new Error("gone"), { aborted: true }), undefined);
  assert.deepEqual(transportFailure(new Error("socket closed")), {
    kind: "transport",
    detail: "socket closed",
  });
  assert.equal(transportFailure(Object.assign(new Error("slow"), { name: "TimeoutError" })).kind, "timeout");
});

test("rotate: a rate limit is absorbed and the caller sees only the answer", async () => {
  const subject = pool(3);
  const asked = [];
  const moves = [];
  const answer = await rotate({
    pool: subject,
    attempts: 3,
    attempt: async (account) => {
      asked.push(account);
      return asked.length === 1
        ? reply(429, JSON.stringify({ error: { message: "rate limit" } }))
        : reply(200, "ok", "text/event-stream");
    },
    onMove: (move) => moves.push(move),
  });
  assert.equal(answer.status, 200);
  assert.deepEqual(asked, ["zf-1", "zf-2"], "the retry leaves from a different address");
  assert.equal(moves.length, 1);
  assert.equal(moves[0].from, "zf-1");
  assert.equal(moves[0].to, "zf-2");
  assert.equal(moves[0].kind, "rate-limit");
});

test("rotate: a request that succeeds first time never moves", async () => {
  const subject = pool(3);
  let rounds = 0;
  await rotate({
    pool: subject,
    attempts: 3,
    attempt: async () => ((rounds += 1), reply(200, "ok", "text/event-stream")),
    onMove: () => assert.fail("nothing about a working request may move"),
  });
  assert.equal(rounds, 1);
  assert.equal(subject.account(), "zf-1");
});

test("rotate: a refused request leaves the next request on a fresh address", async () => {
  const subject = pool(3);
  const asked = [];
  const attempt = async (account) => (asked.push(account), reply(429, "{}"));
  await rotate({ pool: subject, attempts: 1, attempt });
  assert.deepEqual(asked, ["zf-1", "zf-2"]);
  asked.length = 0;
  const answer = await rotate({
    pool: subject,
    attempts: 1,
    attempt: async (account) => (asked.push(account), reply(200, "ok", "text/event-stream")),
  });
  assert.equal(answer.status, 200);
  assert.deepEqual(asked, ["zf-3"], "the refused addresses are not asked again");
});

test("rotate: once the attempts are spent the upstream's own refusal is returned", async () => {
  const subject = pool(2);
  const asked = [];
  const answer = await rotate({
    pool: subject,
    attempts: 2,
    attempt: async (account) => (asked.push(account), reply(429, "Too Many Requests")),
  });
  assert.equal(answer.status, 429);
  assert.deepEqual(asked, ["zf-1", "zf-2", "zf-1"]);
  assert.equal(await answer.text(), "Too Many Requests");
});

test("rotate: a broken connection is retried from another address", async () => {
  const subject = pool(3);
  let rounds = 0;
  const answer = await rotate({
    pool: subject,
    attempts: 2,
    attempt: async () => {
      rounds += 1;
      if (rounds === 1) throw new Error("ECONNRESET");
      return reply(200, "ok", "text/event-stream");
    },
  });
  assert.equal(answer.status, 200);
  assert.equal(subject.account(), "zf-2");
});

test("rotate: a broken connection that never recovers is raised, not swallowed", async () => {
  await assert.rejects(
    () =>
      rotate({
        pool: pool(1),
        attempts: 1,
        attempt: async () => {
          throw new Error("ECONNRESET");
        },
      }),
    /ECONNRESET/,
  );
});

test("rotate: an abandoned request is raised at once and moves nothing", async () => {
  const signal = AbortSignal.abort();
  let rounds = 0;
  await assert.rejects(() =>
    rotate({
      pool: pool(3),
      attempts: 3,
      signal,
      attempt: async () => {
        rounds += 1;
        throw Object.assign(new Error("aborted"), { name: "AbortError" });
      },
      onMove: () => assert.fail("an abandoned request moves nothing"),
    }),
  );
  assert.equal(rounds, 1);
});

test("admin: the platform is looked up by name once and then remembered", async () => {
  const calls = [];
  const admin = new ResinAdmin({
    endpoint: "http://resin:2260",
    token: "dash",
    platform: "Default",
    fetch: async (url, init) => {
      calls.push([url, init.headers.authorization, init.method]);
      return new Response(
        JSON.stringify({ items: [{ id: "00000000-0000-0000-0000-000000000000", name: "Default" }] }),
        { status: 200 },
      );
    },
  });
  assert.equal(await admin.resolvePlatform(), "00000000-0000-0000-0000-000000000000");
  assert.equal(await admin.resolvePlatform(), "00000000-0000-0000-0000-000000000000");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ["http://resin:2260/api/v1/platforms?limit=200", "Bearer dash", undefined]);
});

test("admin: a stalled lookup is retried rather than given up on", async () => {
  let calls = 0;
  const admin = new ResinAdmin({
    endpoint: "http://resin:2260",
    token: "dash",
    platform: "Default",
    fetch: async () => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error("the operation timed out"), { name: "TimeoutError" });
      return new Response(JSON.stringify({ items: [{ id: "p1", name: "Default" }] }), { status: 200 });
    },
  });
  assert.equal(await admin.resolvePlatform(), "p1");
  assert.equal(calls, 2);
});

test("admin: releasing an address drops the lease of that account", async () => {
  const calls = [];
  const admin = new ResinAdmin({
    endpoint: "http://resin:2260",
    token: "dash",
    platform: "default",
    fetch: async (url, init) => {
      calls.push([url, init.method]);
      return url.includes("/platforms?")
        ? new Response(JSON.stringify({ items: [{ id: "p1", name: "Default" }] }), { status: 200 })
        : new Response("{}", { status: 200 });
    },
  });
  await admin.release("zen-free-2");
  assert.deepEqual(calls.at(-1), ["http://resin:2260/api/v1/platforms/p1/leases/zen-free-2", "DELETE"]);
});

test("admin: a missing platform is reported with the names that do exist", async () => {
  const admin = new ResinAdmin({
    endpoint: "http://resin:2260",
    token: "dash",
    platform: "Nope",
    fetch: async () =>
      new Response(JSON.stringify({ items: [{ id: "p1", name: "Default" }] }), { status: 200 }),
  });
  await assert.rejects(() => admin.resolvePlatform(), /no platform named Nope\. It has: Default/);
});

test("admin: a lease that cannot be dropped never breaks the request", async () => {
  const said = [];
  const admin = new ResinAdmin({
    endpoint: "http://resin:2260",
    token: "dash",
    platform: "Default",
    log: (line) => said.push(line),
    fetch: async () => {
      throw new Error("resin is unreachable");
    },
  });
  await admin.release("zen-free-1");
  assert.match(said.join("\n"), /could not release the lease of zen-free-1: resin is unreachable/);
});
