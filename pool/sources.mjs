// The layer above pool/protocols.mjs: fetch the places nodes come from, work
// out what each body is, and hand the lines to the parser.
//
// Two things here are deliberate and load-bearing:
//
// 1. A subscription URL carries the token that pays for it. Fetch errors
//    routinely embed the whole URL, so every message that could reach a log is
//    passed through state.mjs's redactSubscriptionUrl first.
// 2. Accounting has to add up. `input === outbound + skipped` holds for any
//    body, so a node that disappears can always be attributed to a reason
//    rather than silently missing. Over-capacity is one of those reasons.

import { SKIP_REASONS, parseSubscription } from "./protocols.mjs";
import { nodeId, redactSubscriptionUrl } from "./state.mjs";

export const SOURCE_REASONS = Object.freeze({
  ...SKIP_REASONS,
  OVER_CAPACITY: "over-capacity",
});

export const SOURCE_FORMATS = Object.freeze(["json", "uri-lines", "plain-lines"]);

export const DEFAULT_TIMEOUT_MS = 20_000;
export const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
export const DEFAULT_USER_AGENT = "zen-free-pool/1";

// Markers that say a body is a Clash/Mihomo profile rather than something this
// module can read. The plugin has no dependencies, so a YAML profile cannot be
// parsed faithfully, and a half-understood YAML reader would quietly invent
// nodes -- worse than refusing. The subscription usually has a base64/v2ray
// spelling of the same list, so the error says so.
const YAML_MARKERS = [/^\s*proxies\s*:/m, /^\s*proxy-groups\s*:/m, /^\s*mixed-port\s*:/m, /^\s*rules\s*:/m];

export class SourceError extends Error {
  constructor(code, message, { url } = {}) {
    // A fetch error's own text routinely embeds the whole URL, token included,
    // so the message is scrubbed here rather than trusted: every URL that
    // appears in it is reduced to the form safe to log.
    const scrubbed = scrubUrls(message);
    super(url === undefined ? scrubbed : `${scrubbed} [${redactSubscriptionUrl(url)}]`);
    this.name = "SourceError";
    this.code = code;
    if (url !== undefined) this.redacted = redactSubscriptionUrl(url);
  }
}

// Any URL in a message is a URL that may carry a subscription token.
export function scrubUrls(text) {
  return String(text ?? "").replace(/https?:\/\/[^\s"')\]<>]+/g, (match) => redactSubscriptionUrl(match));
}

// ---------------------------------------------------------------- format

function looksBase64(text) {
  const compact = text.replace(/\s+/g, "");
  if (compact.length < 16 || compact.length % 4 === 1) return false;
  if (!/^[A-Za-z0-9+/\-_]+={0,2}$/.test(compact)) return false;
  const decoded = Buffer.from(compact.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  // A replacement character means the bytes were not text, so this is not a
  // wrapped list of links.
  return decoded !== "" && !decoded.includes("\uFFFD");
}

export function isClashProfile(text) {
  return YAML_MARKERS.some((pattern) => pattern.test(text));
}

// What a body is, decided by looking at it rather than at its source. Returns
// the text to parse: a base64 body is unwrapped first, because the parser reads
// lines and cannot see through the wrapper.
export function readBody(text, { url } = {}) {
  const body = String(text ?? "");
  if (body.trim() === "") {
    throw new SourceError("SOURCE_EMPTY", "the subscription returned nothing to parse", { url });
  }
  if (isClashProfile(body)) {
    throw new SourceError(
      "SOURCE_CLASH",
      "this subscription is a Clash YAML profile, which this plugin cannot parse without a YAML dependency it deliberately does not have. Use the same subscription's base64 / v2ray (plain link list) URL instead",
      { url },
    );
  }
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return { format: "json", body };
  }
  if (body.includes("://")) {
    return { format: "uri-lines", body };
  }
  if (looksBase64(body)) {
    const decoded = Buffer.from(
      body.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, ""),
      "base64",
    ).toString("utf8");
    if (decoded.includes("://")) return { format: "uri-lines", body: decoded };
    throw new SourceError("SOURCE_UNKNOWN", "the subscription is base64 but does not decode to a link list", {
      url,
    });
  }
  const lines = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length > 0 && lines.every((line) => line.length >= 3 && !line.includes(" ") && line.includes(":"))) {
    // A bare address list: host:port[:user:pass], which the parser reads too.
    return { format: "plain-lines", body };
  }
  throw new SourceError(
    "SOURCE_UNKNOWN",
    "the subscription is neither a link list, base64-wrapped links, a plain address list, nor sing-box JSON",
    { url },
  );
}

// ---------------------------------------------------------------- fetching

// The cap is enforced while reading rather than trusted from content-length, so
// a body that lies about its size (or streams forever) still cannot exhaust
// memory.
async function readCapped(response, maxBytes) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new SourceError("SOURCE_TOO_LARGE", `the subscription is larger than the ${maxBytes} byte limit`);
  }
  if (response.body === null || response.body === undefined) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        throw new SourceError("SOURCE_TOO_LARGE", `the subscription exceeded the ${maxBytes} byte limit while reading`);
      }
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return Buffer.from(joined).toString("utf8");
}

export async function fetchSubscription(
  url,
  { headers, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES, fetchImpl = globalThis.fetch } = {},
) {
  try {
    const response = await fetchImpl(url, {
      headers: { "user-agent": DEFAULT_USER_AGENT, ...headers },
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new SourceError("SOURCE_HTTP", `the subscription answered HTTP ${response.status}`, { url });
    }
    return await readCapped(response, maxBytes);
  } catch (error) {
    if (error instanceof SourceError) throw error;
    // The URL is in the message here more often than anywhere else, which is
    // exactly why this wraps rather than rethrows.
    throw new SourceError("SOURCE_FETCH", `the subscription could not be fetched: ${error?.message ?? error}`, {
      url,
    });
  }
}

// ---------------------------------------------------------------- nodes

function numberOrNull(value) {
  const port = typeof value === "string" ? Number.parseInt(value, 10) : value;
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

// A raw sing-box outbound from a JSON source. Its own `tag` is dropped: tags
// belong to core.mjs, which makes them unique across the whole pool.
function outboundFromObject(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return null;
  const type = typeof entry.type === "string" ? entry.type.trim().toLowerCase() : "";
  if (type === "" || type === "direct" || type === "block" || type === "dns" || type === "selector") return null;
  const server = typeof entry.server === "string" ? entry.server.trim() : "";
  const port = numberOrNull(entry.server_port);
  if (server === "" || port === null) return null;
  const { tag, ...outbound } = entry;
  return { protocol: type, name: typeof tag === "string" ? tag : undefined, outbound: { ...outbound, type, server, server_port: port } };
}

function keyParamsOf(outbound) {
  // Only the parameters that decide which peer is reached. Anything measured,
  // named or tagged must not move the identity; see state.mjs's nodeId.
  const keys = ["uuid", "password", "method", "auth_str", "flow", "security", "alter_id"];
  const params = {};
  for (const key of keys) {
    if (outbound[key] !== undefined) params[key] = outbound[key];
  }
  if (outbound.tls?.server_name !== undefined) params.server_name = outbound.tls.server_name;
  if (outbound.transport?.type !== undefined) params.transport = outbound.transport.type;
  return params;
}

function makeNode(entry, sourceTag) {
  const outbound = entry.outbound;
  const scheme = entry.protocol ?? outbound.type;
  return {
    id: nodeId(scheme, outbound.server, outbound.server_port, keyParamsOf(outbound)),
    scheme,
    host: outbound.server,
    port: outbound.server_port,
    name: entry.name,
    sourceTag,
    outbound,
  };
}

// ---------------------------------------------------------------- loading

function parseOneSource(text, sourceTag, { coreVersion, allowUnpinned, url }) {
  const { format, body } = readBody(text, { url });
  if (format !== "json") {
    const result = parseSubscription(body, { coreVersion, allowUnpinned });
    return {
      format,
      entries: result.outbounds.map((entry) => ({ entry, sourceTag })),
      skipped: result.skipped.map((entry) => ({ reason: entry.reason, detail: entry.detail })),
      ignoredParams: result.counts.ignoredParams ?? {},
      unpinned: result.counts.unpinned ?? 0,
      input: result.counts.input,
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new SourceError("SOURCE_JSON", `the subscription is not valid JSON: ${error?.message ?? error}`, { url });
  }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.outbounds) ? parsed.outbounds : null;
  if (list === null) {
    throw new SourceError("SOURCE_JSON", "the subscription is JSON but carries no outbounds array", { url });
  }
  const entries = [];
  const skipped = [];
  let unpinned = 0;
  for (const item of list) {
    const outbound = outboundFromObject(item);
    if (outbound === null) {
      skipped.push({ reason: SKIP_REASONS.PARSE_ERROR, detail: "the JSON entry is not a dialable outbound" });
      continue;
    }
    if (outbound.outbound.tls?.insecure === true) unpinned += 1;
    entries.push({ entry: outbound, sourceTag });
  }
  return { format, entries, skipped, ignoredParams: {}, unpinned, input: list.length };
}

// The one entry point. Every source is fetched or read, parsed through the same
// parser, then deduplicated and capped; the counts always reconcile.
export async function loadCandidates({
  subscriptions = [],
  manual = [],
  coreVersion,
  allowUnpinned = false,
  maxNodes = 300,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES,
  fetchImpl = globalThis.fetch,
} = {}) {
  const sources = [];
  const collected = [];
  const skipped = [];
  const ignoredByName = {};
  const byReason = {};
  for (const reason of Object.values(SOURCE_REASONS)) byReason[reason] = 0;
  let input = 0;
  let unpinned = 0;
  const warnings = [];

  const absorb = (parsed, sourceTag) => {
    input += parsed.input;
    for (const { entry, } of parsed.entries) collected.push({ entry, sourceTag });
    for (const entry of parsed.skipped) {
      skipped.push({ ...entry, sourceTag });
      byReason[entry.reason] = (byReason[entry.reason] ?? 0) + 1;
    }
    for (const [key, count] of Object.entries(parsed.ignoredParams)) {
      ignoredByName[key] = (ignoredByName[key] ?? 0) + count;
    }
    unpinned += parsed.unpinned;
  };

  for (const source of subscriptions) {
    const url = typeof source === "string" ? source : source?.url;
    const name = typeof source === "string" ? undefined : source?.name;
    if (typeof url !== "string" || url === "") {
      sources.push({ name, ok: false, code: "SOURCE_URL", detail: "a subscription has no url" });
      continue;
    }
    const tag = name ?? redactSubscriptionUrl(url);
    try {
      const text = await fetchSubscription(url, {
        headers: typeof source === "object" ? source?.headers : undefined,
        timeoutMs,
        maxBytes,
        fetchImpl,
      });
      const parsed = parseOneSource(text, tag, { coreVersion, allowUnpinned, url });
      absorb(parsed, tag);
      sources.push({ name, url: redactSubscriptionUrl(url), ok: true, format: parsed.format, input: parsed.input });
    } catch (error) {
      // A source that could not be read is reported, never counted as input:
      // it contributed no candidates, so `input === outbound + skipped` stays
      // true and the caller can decide whether a total failure is fatal.
      const detail = error instanceof SourceError ? error.message : scrubUrls(error?.message ?? error);
      sources.push({ name, url: redactSubscriptionUrl(url), ok: false, code: error?.code ?? "SOURCE_ERROR", detail });
      warnings.push(detail);
    }
  }

  if (manual.length > 0) {
    const lines = [];
    const objects = [];
    for (const entry of manual) {
      if (typeof entry === "string") lines.push(entry);
      else if (entry !== null && typeof entry === "object") objects.push(entry);
      else {
        skipped.push({ reason: SKIP_REASONS.PARSE_ERROR, detail: "a manual entry is neither a line nor an object", sourceTag: "manual" });
        input += 1;
        byReason[SKIP_REASONS.PARSE_ERROR] += 1;
      }
    }
    if (lines.length > 0) {
      const parsed = parseOneSource(lines.join("\n"), "manual", { coreVersion, allowUnpinned });
      absorb(parsed, "manual");
    }
    if (objects.length > 0) {
      input += objects.length;
      for (const item of objects) {
        const outbound = outboundFromObject(item);
        if (outbound === null) {
          skipped.push({ reason: SKIP_REASONS.PARSE_ERROR, detail: "the manual object is not a dialable outbound", sourceTag: "manual" });
          byReason[SKIP_REASONS.PARSE_ERROR] += 1;
          continue;
        }
        if (outbound.outbound.tls?.insecure === true) unpinned += 1;
        collected.push({ entry: outbound, sourceTag: "manual" });
      }
    }
  }

  // Deduplicate by identity, then cap. Both are accounting events, not
  // disappearances.
  const seen = new Set();
  const unique = [];
  for (const { entry, sourceTag } of collected) {
    const node = makeNode(entry, sourceTag);
    if (seen.has(node.id)) {
      skipped.push({ reason: "duplicate", detail: `the same node is already in the pool (${node.host}:${node.port})`, sourceTag });
      byReason.duplicate = (byReason.duplicate ?? 0) + 1;
      continue;
    }
    seen.add(node.id);
    unique.push(node);
  }

  const nodes = unique.slice(0, Math.max(0, maxNodes));
  for (const node of unique.slice(Math.max(0, maxNodes))) {
    skipped.push({
      reason: SOURCE_REASONS.OVER_CAPACITY,
      detail: `the pool holds at most ${maxNodes} nodes`,
      sourceTag: node.sourceTag,
    });
    byReason[SOURCE_REASONS.OVER_CAPACITY] += 1;
  }

  return {
    nodes,
    sources,
    skipped,
    warnings,
    counts: {
      input,
      outbound: nodes.length,
      skipped: skipped.length,
      byReason,
      ignoredParams: ignoredByName,
      unpinned,
    },
  };
}
