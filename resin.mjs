// Resin proxy pool for the Zen free plugin.
//
// OpenCode's free tier counts usage per exit IP, so one credential gets more
// room by spending it from several addresses. Resin already owns the hard
// part: it measures every node, keeps the fastest ones, and binds a business
// identity (Platform + Account) to one stable exit IP.
//
// This module adds the policy the user asked for: keep using the IP that
// works, and move to a different one only when a request comes back rate
// limited, refused, or failed upstream. Resin gives a new Account its own
// binding, so rotating the Account rotates the exit IP.

export const SWITCH_STATUSES = [403, 408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 529];

// Wording the upstream and its gateway use for the failures worth leaving.
const SWITCH_PATTERNS = [
  { kind: "upstream", pattern: /upstream error/i },
  { kind: "upstream", pattern: /do request failed/i },
  { kind: "upstream", pattern: /bad gateway|service unavailable|gateway timeout/i },
  { kind: "restricted", pattern: /access has been restricted/i },
  { kind: "restricted", pattern: /policy violation/i },
  { kind: "rate-limit", pattern: /rate ?limit|too many requests|quota exceeded/i },
];

// A refusal this plugin causes itself: Zen answers 403 FreeTierError to a
// request that does not look like OpenCode's, and no exit IP changes that.
// Moving on it would spend the whole pool and still fail, so it is handed
// back with the upstream's own words instead.
const FATAL_PATTERNS = [
  { kind: "freetier", pattern: /freetiererror/i },
  { kind: "freetier", pattern: /can only be used from within opencode/i },
];

const PEEK_LIMIT = 64 * 1024;

// Resin's forward proxy takes the identity as HTTP proxy credentials:
// Platform.Account as the user, the proxy token as the password. The URL
// users paste for Resin (http://host:2260/my-token) carries both halves.
export function parseResinURL(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error(`Resin URL must be http or https, got ${url.protocol.replace(":", "")}`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Resin URL must not carry credentials, a query or a fragment");
  }
  const token = decodeURIComponent(url.pathname.replace(/^\/+/, "").replace(/\/+$/, ""));
  if (!token) {
    throw new Error(
      "Resin URL needs the proxy token in its path, like http://host:2260/my-token. That is the value of RESIN_PROXY_TOKEN, which is not the dashboard token.",
    );
  }
  if (token.includes("/")) {
    throw new Error("Resin URL must carry exactly one path segment, the proxy token");
  }
  return { endpoint: url.origin, token };
}

export function accountNames(prefix, count) {
  return Array.from({ length: count }, (_, index) => `${prefix}-${index + 1}`);
}

// Bun's fetch takes a proxy option; Node's accepts the option and ignores it,
// which would send traffic straight out while a user believes it rotates. The
// runtime is checked rather than trusted, and the reverse transport, which is
// plain URL rewriting, is offered in its place.
export function requireForwardSupport(transport, globals = globalThis) {
  if (transport === "forward" && globals.Bun === undefined) {
    throw new Error(
      "resin.transport forward needs a runtime whose fetch takes a proxy option, which is Bun. Set resin.transport to reverse here, or run the plugin under Bun.",
    );
  }
}

function isEventStream(headers) {
  return (headers.get("content-type") ?? "").includes("text/event-stream");
}

function isJSON(headers) {
  return (headers.get("content-type") ?? "").includes("json");
}

function declaredLength(headers) {
  const value = Number.parseInt(headers.get("content-length") ?? "", 10);
  return Number.isFinite(value) ? value : undefined;
}

// A body read back from text: its length and encoding no longer describe it.
function rebuild(response, text) {
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.delete("content-encoding");
  return new Response(text, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function match(patterns, text) {
  for (const entry of patterns) {
    if (entry.pattern.test(text)) return entry;
  }
  return undefined;
}

// A 200 that is really a failure. Only a documented error envelope counts: a
// model may write "upstream error" in an answer, and an answer must never
// move traffic to another address.
function structuredError(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const error = parsed.error ?? (parsed.type === "error" ? parsed : undefined);
  if (!error) return undefined;
  const message =
    typeof error === "string"
      ? error
      : [error.message, error.type, error.code].filter(Boolean).join(" ");
  return match(SWITCH_PATTERNS, message) ?? { kind: "upstream" };
}

async function discard(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The body is already gone; nothing to release.
  }
}

// What to do with a response: keep it, or move to another exit address
// first. The response to hand on is returned either way, so a body read here
// is never lost.
export async function classifyResponse(response, { statuses = SWITCH_STATUSES } = {}) {
  const status = response.status;
  const headers = response.headers;

  if (status < 400) {
    // A streamed 200 is the model's answer: it is never read or delayed.
    if (isEventStream(headers) || !isJSON(headers)) return { switch: false, response };
    const text = await response.text();
    const structured = structuredError(text);
    const rebuilt = rebuild(response, text);
    if (!structured) return { switch: false, response: rebuilt };
    return { switch: true, kind: structured.kind, detail: text.slice(0, 300), response: rebuilt };
  }

  const length = declaredLength(headers);
  if (length !== undefined && length > PEEK_LIMIT) {
    const move = statuses.includes(status);
    if (move) await discard(response);
    return move
      ? { switch: true, kind: `status ${status}`, detail: "body too large to read", response }
      : { switch: false, response };
  }

  const text = (await response.text()).slice(0, PEEK_LIMIT);
  const rebuilt = rebuild(response, text);
  const fatal = match(FATAL_PATTERNS, text);
  if (fatal) return { switch: false, kind: fatal.kind, response: rebuilt };
  const kind = match(SWITCH_PATTERNS, text)?.kind ?? (statuses.includes(status) ? `status ${status}` : undefined);
  if (!kind) return { switch: false, response: rebuilt };
  return { switch: true, kind, detail: text.slice(0, 300), response: rebuilt };
}

// A request that never produced a response, told apart from the caller
// walking away from it.
export function transportFailure(error, signal) {
  if (signal?.aborted) return undefined;
  const name = error?.name ?? "";
  if (name === "AbortError") return undefined;
  return { kind: name === "TimeoutError" ? "timeout" : "transport", detail: error?.message ?? String(error) };
}

// Holds one exit address in use at a time and the ones it may move to.
// Moving is the caller's decision (see rotate); this remembers what happened,
// so that a move lands on a fresh address before it reuses a measured one,
// and on the fastest address once every address has been measured.
//
// A given up address is never used again while any other is available, so
// resting is an ordering rather than a timer: a request always has to be
// served, and the only question is which address serves it.
export class IPPool {
  constructor({ accounts, now = Date.now }) {
    if (!accounts?.length) throw new Error("The exit address pool needs at least one account");
    this.accounts = accounts;
    this.now = now;
    this.active = 0;
    this.slots = accounts.map(() => ({
      state: "ready",
      ttfbMs: undefined,
      samples: 0,
      failures: 0,
      lastKind: undefined,
      givenUpAt: 0,
    }));
  }

  account(index = this.active) {
    return this.accounts[index];
  }

  // The address to use now. It stays put while it is usable.
  pick() {
    if (this.slots[this.active].state === "ready") return this.active;
    return this.#moveFrom(this.active);
  }

  // Time to the response headers, which is the part of a request the exit
  // address itself decides.
  succeeded(index, ttfbMs) {
    const slot = this.slots[index];
    slot.state = "ready";
    slot.samples += 1;
    slot.lastKind = undefined;
    slot.ttfbMs = slot.ttfbMs === undefined ? ttfbMs : slot.ttfbMs * 0.7 + ttfbMs * 0.3;
  }

  // Give up on an address. A repeat call for one already given up on counts
  // the failure but never moves twice, so concurrent requests that fail
  // together rotate the pool once between them.
  failed(index, kind) {
    const slot = this.slots[index];
    slot.failures += 1;
    slot.lastKind = kind;
    slot.state = "cooling";
    slot.givenUpAt = this.now();
    if (this.active === index) this.active = this.#moveFrom(index);
    return this.active;
  }

  // An address that has never been used is taken before a measured one, so
  // each move spends a fresh address; once all are measured, the quickest one
  // is taken. When every address has been given up on, the pool takes the one
  // it gave up on longest ago, whose lease the caller drops so that reusing
  // its Account yields a different address.
  #moveFrom(exclude) {
    const candidates = [];
    for (let index = 0; index < this.slots.length; index += 1) {
      if (index === exclude) continue;
      if (this.slots[index].state === "ready") candidates.push(index);
    }
    if (candidates.length) {
      const fresh = candidates.filter((index) => this.slots[index].samples === 0);
      const chosen = fresh.length
        ? fresh[0]
        : candidates.reduce((best, index) =>
            this.slots[index].ttfbMs < this.slots[best].ttfbMs ? index : best,
          );
      return (this.active = chosen);
    }
    const resting =
      this.slots.length > 1
        ? this.slots.map((_, index) => index).filter((index) => index !== exclude)
        : [exclude];
    const chosen = resting.reduce((best, index) =>
      this.slots[index].givenUpAt < this.slots[best].givenUpAt ? index : best,
    );
    const slot = this.slots[chosen];
    slot.state = "ready";
    slot.ttfbMs = undefined;
    slot.samples = 0;
    slot.lastKind = undefined;
    return (this.active = chosen);
  }
}

// Runs one request, moving to another exit address whenever the answer says
// the current one is spent. Nothing reaches the caller before that decision,
// so a moved request stays invisible to it.
export async function rotate({ pool, attempts, attempt, onMove, signal }) {
  let lastFailure;
  for (let round = 0; round <= attempts; round += 1) {
    const index = pool.pick();
    const startedAt = Date.now();
    let response;
    try {
      response = await attempt(pool.account(index));
    } catch (error) {
      if (signal?.aborted) throw error;
      const failure = transportFailure(error, signal);
      if (!failure) throw error;
      lastFailure = error;
      const from = pool.account(index);
      pool.failed(index, failure.kind);
      onMove?.({ from, to: pool.account(), round, kind: failure.kind, detail: failure.detail });
      if (round === attempts) throw error;
      continue;
    }
    const verdict = await classifyResponse(response);
    if (!verdict.switch) {
      pool.succeeded(index, Date.now() - startedAt);
      return verdict.response;
    }
    const from = pool.account(index);
    pool.failed(index, verdict.kind);
    onMove?.({ from, to: pool.account(), round, kind: verdict.kind, detail: verdict.detail });
    if (round === attempts) return verdict.response;
  }
  throw lastFailure;
}

// The Resin dashboard API, used only to drop the lease of an address the
// pool has given up on, so that reusing its Account yields a different
// address instead of the same refused one. Deliberately kept off the request
// path: the same host answers in seconds and is sometimes unreachable.
export class ResinAdmin {
  constructor({ endpoint, token, platform, timeoutMs = 30000, fetch: fetchImpl = fetch, log }) {
    this.endpoint = endpoint;
    this.token = token;
    this.platform = platform;
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl;
    this.log = log;
    this.platformID = undefined;
  }

  async #request(path, init = {}) {
    return this.fetch(`${this.endpoint}/api/v1${path}`, {
      ...init,
      headers: { authorization: `Bearer ${this.token}`, ...init.headers },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  // Resin's own host answers the same read in two seconds or stalls past a
  // minute, so the lookup is retried rather than given up on: the address it
  // yields is what lets a reused Account come back somewhere else.
  async resolvePlatform(attempts = 3) {
    if (this.platformID) return this.platformID;
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        this.platformID = await this.#lookupPlatform();
        return this.platformID;
      } catch (error) {
        lastError = error;
        if (attempt < attempts) await new Promise((wait) => setTimeout(wait, 400 * attempt));
      }
    }
    throw lastError;
  }

  async #lookupPlatform() {
    const response = await this.#request("/platforms?limit=200");
    if (!response.ok) throw new Error(`Resin's platform list answered HTTP ${response.status}`);
    const body = await response.json();
    const wanted = this.platform.toLowerCase();
    const found = (body.items ?? []).find((item) => item.name?.toLowerCase() === wanted);
    if (!found) {
      const names = (body.items ?? []).map((item) => item.name).join(", ");
      throw new Error(`Resin has no platform named ${this.platform}. It has: ${names || "none"}`);
    }
    return found.id;
  }

  // Best effort by design: a lease that outlives its use costs one address,
  // while a failed request must never become a failed answer.
  async release(account) {
    try {
      const platformID = await this.resolvePlatform();
      const response = await this.#request(
        `/platforms/${platformID}/leases/${encodeURIComponent(account)}`,
        { method: "DELETE" },
      );
      if (!response.ok && response.status !== 404) {
        this.log?.(`could not release the lease of ${account}: HTTP ${response.status}`);
      }
    } catch (error) {
      this.log?.(`could not release the lease of ${account}: ${error?.message ?? error}`);
    }
  }
}
