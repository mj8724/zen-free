// Subscription line -> sing-box outbound.
//
// A subscription body is a list of share links, one per line. This module turns
// each line into a sing-box outbound object, or a classified skip. It never
// guesses: a line it does not fully understand comes back as a skip reason
// instead of an outbound that might not be the node the link meant.
//
// Field names come from sing-box's outbound documentation
// (https://sing-box.sagernet.org/configuration/outbound/). The docs served
// 1.15.0-dev while the newest release was 1.14.3, so only fields that exist in
// the 1.14.3 schema are emitted; the fields deliberately left out are listed in
// FIELDS_NOT_EMITTED. The one version-dependent gate is MIN_CORE_VERSION, and
// it only lists protocols whose first release was checked.
//
// Out of scope: fetching a subscription (sources.mjs), assembling a config
// (core.mjs), tagging and deduplicating outbounds. `tag` is left to the caller
// so it can keep tags unique; the link's `#fragment` comes back as `name`.

export const SKIP_REASONS = Object.freeze({
  UNSUPPORTED_SCHEME: "unsupported-scheme",
  PARSE_ERROR: "parse-error",
  CORE_TOO_OLD: "core-too-old",
});

// The sing-box release that first shipped the outbound type, for the protocols
// whose release was checked against its release notes:
//   tuic      1.4.0   "Add TUIC support", v1.4.0 release notes
//   hysteria2 1.8.0   "Add Hysteria2 protocol", v1.8.0 release notes
//   anytls    1.12.0  "Add AnyTLS protocol", v1.12.0 release notes
// Everything else is left ungated rather than carrying a version that was not
// checked: vmess/vless/trojan/shadowsocks/http/socks are older than the oldest
// release I can point at, and hysteria 1 is ungated because its first release
// was not verified.
export const MIN_CORE_VERSION = Object.freeze({
  tuic: "1.4.0",
  hysteria2: "1.8.0",
  anytls: "1.12.0",
});

// Parameters whose sing-box field exists only in newer docs, or has no faithful
// sing-box field at all. A line carrying one is skipped rather than emitted with
// a field the core would reject or that would quietly change the node dialled:
//   hysteria2   hop_interval_max, realm, disable_chrome_parrot, bbr_profile
//   anytls      client_metadata
//   vless/tuic  pqv, pcs, vcn, ech, disable_sni
//   hysteria 1  obfs (see parseHysteria)
export const FIELDS_NOT_EMITTED = Object.freeze([
  "hysteria2.hop_interval_max",
  "hysteria2.realm",
  "hysteria2.disable_chrome_parrot",
  "hysteria2.bbr_profile",
  "anytls.client_metadata",
  "vless.pqv",
  "vless.pcs",
  "vless.vcn",
  "vless.ech",
  "tuic.disable_sni",
  "hysteria.obfs",
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^\[[0-9a-f:.]+\]$|^(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}$/i;
const HOST_RE = /^[A-Za-z0-9._-]+$/;
const PORT_RE = /^\d{1,5}$/;
const DURATION_RE = /^\d+(?:\.\d+)?(?:ms|s|m|h)$/;

// sing-box's shadowsocks method enum (option/shadowsocks.go). A method outside
// it is not a cipher the core can create, so the line is skipped.
const SS_METHODS = new Set([
  "none",
  "aes-128-gcm",
  "aes-192-gcm",
  "aes-256-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
  "aes-128-ctr",
  "aes-192-ctr",
  "aes-256-ctr",
  "aes-128-cfb",
  "aes-192-cfb",
  "aes-256-cfb",
  "rc4-md5",
  "chacha20-ietf",
  "xchacha20",
]);

// SIP003 plugins sing-box implements internally; anything else is skipped.
const SS_PLUGINS = new Set(["obfs-local", "v2ray-plugin"]);

// vmess `security` values sing-box accepts.
const VMESS_SECURITY = new Set(["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb"]);

const VMESS_NETWORKS = new Set(["", "tcp", "ws", "grpc", "h2", "http", "quic"]);
const TRANSPORT_TYPES = new Set(["ws", "grpc", "http", "httpupgrade", "quic"]);
const UTLS_FINGERPRINTS = new Set([
  "chrome",
  "firefox",
  "edge",
  "safari",
  "ios",
  "android",
  "360",
  "qq",
  "random",
  "randomized",
]);
const TUIC_CONGESTION = new Set(["cubic", "new_reno", "bbr"]);
const TUIC_UDP_RELAY_MODES = new Set(["native", "quic"]);

// ---------------------------------------------------------------- primitives

function skip(reason, detail, scheme = null) {
  return { ok: false, reason, detail, scheme };
}

function ok(protocol, name, outbound, ignored = null, unpinned = false) {
  if (!isStructurallyValid(outbound)) {
    return skip(SKIP_REASONS.PARSE_ERROR, "the outbound built from this line failed its own field check");
  }
  const result = { ok: true, protocol, name, outbound };
  if (ignored !== null && ignored.length > 0) result.ignored = ignored;
  if (unpinned) result.unpinned = true;
  return result;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value !== "";
}

function decodePercent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

// Standard or URL-safe base64, padded or not. Returns a Buffer, or null when
// the text is not base64 (a truncated blob that is still valid base64 is caught
// by whoever parses the decoded bytes).
function decodeBase64(value) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (normalized === "" || !/^[A-Za-z0-9+/]+$/.test(normalized)) return null;
  if (normalized.length % 4 === 1) return null;
  return Buffer.from(normalized, "base64");
}

// The pin these links carry is the SHA-256 of the server's *certificate*: it is
// per node (14 distinct pins over 16 nodes on one real subscription) and it does
// NOT match the key the server presents, which is why mapping it onto
// certificate_public_key_sha256 made every pinned node fail at handshake with
// "unrecognized remote public key". sing-box only grew a client-side certificate
// hash in 1.15.0, so on 1.14.3 the pin cannot be carried at all.
//
// A pin is what authenticates a node whose SNI is camouflage, so dropping it is
// not a detail that may happen quietly: by default such a node is refused with a
// reason naming the core requirement, and only an explicit opt-in uses it
// unauthenticated (tls.insecure), counted and reported as unpinned.
const CERT_PIN_SINCE = "1.15.0";

function pinToBase64(value) {
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, "hex").toString("base64");
  // A 32-byte digest is 43 base64 characters, optionally with one '=' pad.
  if (/^[A-Za-z0-9+/]{43}$/.test(value)) return `${value}=`;
  if (/^[A-Za-z0-9+/]{43}=$/.test(value)) return value;
  return null;
}

// UTF-8 text whose bytes round-trip; truncation and replacement characters both
// come back as null.
function decodeUtf8(bytes) {
  const text = bytes.toString("utf8");
  return Buffer.from(text, "utf8").equals(bytes) ? text : null;
}

function parsePort(value) {
  if (typeof value !== "string" || !PORT_RE.test(value)) return null;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : null;
}

function stripBrackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function validHost(host) {
  if (typeof host !== "string" || host === "") return false;
  if (host.includes("[") || host.includes("]")) return IPV6_RE.test(host);
  return IPV6_RE.test(host) || IPV4_RE.test(host) || HOST_RE.test(host);
}

// Query strings are parsed here rather than with URLSearchParams: `+` stays a
// literal plus (subscription passwords carry plus signs) and a repeated key
// keeps its first value.
function parseParams(search) {
  const params = new Map();
  if (typeof search !== "string" || search === "" || search === "?") return params;
  for (const chunk of search.replace(/^\?/, "").split("&")) {
    if (chunk === "") continue;
    const equals = chunk.indexOf("=");
    const rawKey = equals === -1 ? chunk : chunk.slice(0, equals);
    const rawValue = equals === -1 ? "" : chunk.slice(equals + 1);
    const key = decodePercent(rawKey);
    const value = decodePercent(rawValue);
    if (key === null || value === null) return null;
    if (!params.has(key)) params.set(key, value);
  }
  return params;
}

// undefined means "the link did not say"; null means "it said something invalid".
function readBool(params, keys) {
  for (const key of keys) {
    if (!params.has(key)) continue;
    const value = params.get(key);
    if (value === "1" || value === "true" || value === "True") return true;
    if (value === "0" || value === "false" || value === "False") return false;
    return null;
  }
  return undefined;
}

function readInt(params, keys) {
  for (const key of keys) {
    if (!params.has(key)) continue;
    if (!/^\d+$/.test(params.get(key))) return null;
    return Number(params.get(key));
  }
  return undefined;
}

function readFirst(params, keys) {
  for (const key of keys) {
    if (params.has(key)) return params.get(key);
  }
  return undefined;
}

// `ignorable` holds keys that cannot change what is dialled for this protocol:
// exporters leave them behind from a transport this protocol cannot use here
// (a vless link carrying quicSecurity has no QUIC transport to apply it to), so
// such a key is counted and reported rather than refusing the whole node.
// A key that is neither allowed nor ignorable is still an error: an
// unrecognised structure must never become a node.
function unknownParam(params, allowed, ignorable = null) {
  for (const key of params.keys()) {
    if (allowed.has(key)) continue;
    if (ignorable !== null && ignorable.has(key)) continue;
    return key;
  }
  return null;
}

function ignoredParams(params, allowed, ignorable) {
  const found = [];
  for (const key of params.keys()) {
    if (!allowed.has(key) && ignorable.has(key)) found.push(key);
  }
  return found;
}

function parseAlpn(value) {
  if (typeof value !== "string" || value === "") return null;
  const protocols = value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  return protocols.length === 0 ? null : protocols;
}

function parseFingerprint(value) {
  if (value === undefined) return undefined;
  return UTLS_FINGERPRINTS.has(value) ? value : null;
}

function buildTLS({ serverName = "", insecure = false, alpn = null, fingerprint = null, reality = null, certificateSha256 = null } = {}) {
  const tls = { enabled: true };
  if (serverName !== "") tls.server_name = serverName;
  if (insecure) tls.insecure = true;
  if (alpn) tls.alpn = alpn;
  if (fingerprint) tls.utls = { enabled: true, fingerprint };
  if (certificateSha256) tls.certificate_sha256 = certificateSha256;
  if (reality) {
    const block = { enabled: true, public_key: reality.publicKey };
    if (reality.shortId !== undefined) block.short_id = reality.shortId;
    tls.reality = block;
  }
  return tls;
}

function buildTransport(type, { path, host, serviceName } = {}) {
  if (type === "ws") {
    const transport = { type: "ws", path: path === undefined || path === "" ? "/" : path };
    if (host !== undefined && host !== "") transport.headers = { Host: host };
    return transport;
  }
  if (type === "httpupgrade") {
    const transport = { type: "httpupgrade", path: path === undefined || path === "" ? "/" : path };
    if (host !== undefined && host !== "") transport.host = host;
    return transport;
  }
  if (type === "grpc") {
    const transport = { type: "grpc" };
    if (serviceName !== undefined && serviceName !== "") transport.service_name = serviceName;
    return transport;
  }
  if (type === "http") {
    const transport = { type: "http", path: path === undefined || path === "" ? "/" : path };
    const hosts = (host ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry !== "");
    if (hosts.length > 0) transport.host = hosts;
    return transport;
  }
  if (type === "quic") return { type: "quic" };
  return null;
}

// The last structural check before an outbound is handed back.
function isStructurallyValid(outbound) {
  if (outbound === null || typeof outbound !== "object") return false;
  if (!isNonEmptyString(outbound.type)) return false;
  if (!isNonEmptyString(outbound.server) || !validHost(stripBrackets(outbound.server))) return false;
  if (!Number.isInteger(outbound.server_port) || outbound.server_port < 1 || outbound.server_port > 65535) return false;
  if (outbound.tls !== undefined) {
    if (outbound.tls === null || typeof outbound.tls !== "object") return false;
    if (outbound.tls.enabled !== true) return false;
    if (outbound.tls.reality !== undefined && !isNonEmptyString(outbound.tls.reality.public_key)) return false;
  }
  if (outbound.transport !== undefined) {
    if (outbound.transport === null || typeof outbound.transport !== "object") return false;
    if (!TRANSPORT_TYPES.has(outbound.transport.type)) return false;
  }
  switch (outbound.type) {
    case "vmess":
      return UUID_RE.test(outbound.uuid) && Number.isInteger(outbound.alter_id) && VMESS_SECURITY.has(outbound.security);
    case "vless":
      return UUID_RE.test(outbound.uuid);
    case "trojan":
    case "hysteria2":
    case "anytls":
      return isNonEmptyString(outbound.password);
    case "shadowsocks":
      return SS_METHODS.has(outbound.method) && isNonEmptyString(outbound.password);
    case "hysteria":
      return true;
    case "tuic":
      return UUID_RE.test(outbound.uuid) && isNonEmptyString(outbound.password);
    case "http":
      return true;
    case "socks":
      return outbound.version === "5";
    default:
      return false;
  }
}

// -------------------------------------------------------------- URI spelling

// `new URL` for the URI-shaped links: it rejects the shapes that cannot be a
// link at all (no host, port out of range) and gives host/port/search/hash.
// These schemes get their userinfo back percent-encoded, so it is decoded here.
function splitURI(text) {
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const user = url.username === "" ? "" : decodePercent(url.username);
  const password = url.password === "" ? "" : decodePercent(url.password);
  if (user === null || password === null) return null;
  // A query value that is not percent-encoded lands here too: the link cannot
  // be read as written, so it is skipped rather than given a mangled value.
  const params = parseParams(url.search);
  if (params === null) return null;
  return {
    user,
    password,
    host: stripBrackets(url.hostname),
    rawPort: url.port,
    params,
    name: url.hash === "" ? null : (decodePercent(url.hash.slice(1)) ?? url.hash.slice(1)),
  };
}

// `host:port`, `[v6]:port` -- for the two shapes that are not handed to
// `new URL`: bare `host:port[:user:pass]` and the fully-base64 legacy `ss://`.
function splitHostPort(text) {
  if (typeof text !== "string" || text === "") return null;
  if (text.startsWith("[")) {
    const end = text.indexOf("]");
    if (end === -1) return null;
    if (text[end + 1] !== ":") return null;
    return { host: text.slice(1, end), port: text.slice(end + 2) };
  }
  const colon = text.lastIndexOf(":");
  if (colon === -1) return null;
  return { host: text.slice(0, colon), port: text.slice(colon + 1) };
}

function versionParts(value) {
  if (typeof value !== "string" || !/^\d+(?:\.\d+)*$/.test(value)) return null;
  return value.split(".").map((part) => Number(part));
}

function compareVersions(left, right) {
  const a = versionParts(left);
  const b = versionParts(right);
  if (a === null || b === null) return null;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return 0;
}

// --------------------------------------------------------------------- vmess

// vmess shares are not URIs: everything after `vmess://` is base64 of a JSON
// object. That base64 can contain `/` and `+`, so the payload is taken from the
// raw line instead of being handed to `new URL`.
const VMESS_KEYS = new Set([
  "v",
  "ps",
  "remarks",
  "name",
  "add",
  "port",
  "id",
  "aid",
  "scy",
  "net",
  "type",
  "host",
  "path",
  "tls",
  "sni",
  "servername",
  "alpn",
  "fp",
]);

function parseVmess(text) {
  const body = text.slice("vmess://".length);
  const cut = body.search(/[#?]/);
  const payload = cut === -1 ? body : body.slice(0, cut);
  const nameFromHash = cut === -1 || body[cut] !== "#" ? null : decodePercent(body.slice(cut + 1));
  const bytes = decodeBase64(payload);
  if (bytes === null) return skip(SKIP_REASONS.PARSE_ERROR, "the vmess payload is not base64", "vmess");
  const json = decodeUtf8(bytes);
  if (json === null) return skip(SKIP_REASONS.PARSE_ERROR, "the vmess payload is not UTF-8", "vmess");
  let config;
  try {
    config = JSON.parse(json);
  } catch {
    return skip(SKIP_REASONS.PARSE_ERROR, "the vmess payload is not JSON", "vmess");
  }
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    return skip(SKIP_REASONS.PARSE_ERROR, "the vmess payload is not a JSON object", "vmess");
  }
  const unknownKey = Object.keys(config).find((key) => !VMESS_KEYS.has(key));
  if (unknownKey !== undefined) {
    return skip(SKIP_REASONS.PARSE_ERROR, `vmess field "${unknownKey}" is not known`, "vmess");
  }

  const host = String(config.add ?? "");
  const port = parsePort(String(config.port ?? ""));
  const uuid = String(config.id ?? "");
  if (!validHost(host)) return skip(SKIP_REASONS.PARSE_ERROR, "the vmess address is missing or not a host", "vmess");
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the vmess port is missing or out of range", "vmess");
  if (!UUID_RE.test(uuid)) return skip(SKIP_REASONS.PARSE_ERROR, "the vmess id is not a UUID", "vmess");

  const aid = config.aid === undefined || config.aid === "" ? 0 : Number(config.aid);
  if (!Number.isInteger(aid) || aid < 0) {
    return skip(SKIP_REASONS.PARSE_ERROR, "the vmess aid is not a whole number", "vmess");
  }
  const security = String(config.scy ?? "") === "" ? "auto" : String(config.scy);
  if (!VMESS_SECURITY.has(security)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vmess security "${security}" is not one sing-box knows`, "vmess");
  }

  const network = String(config.net ?? "").toLowerCase();
  if (!VMESS_NETWORKS.has(network)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vmess network "${network}" has no sing-box transport`, "vmess");
  }
  const headerType = String(config.type ?? "").toLowerCase();
  if (headerType !== "" && headerType !== "none" && !(headerType === "gun" && network === "grpc")) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vmess header type "${headerType}" is not supported`, "vmess");
  }

  const tlsFlag = String(config.tls ?? "").toLowerCase();
  if (tlsFlag !== "" && tlsFlag !== "none" && tlsFlag !== "tls") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vmess tls value "${tlsFlag}" is not known`, "vmess");
  }
  const fingerprint = parseFingerprint(config.fp === undefined ? undefined : String(config.fp));
  if (fingerprint === null) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vmess fingerprint "${config.fp}" is not a uTLS one`, "vmess");
  }

  const outbound = { type: "vmess", server: host, server_port: port, uuid, security, alter_id: aid };
  if (tlsFlag === "tls") {
    // The SNI comes from `sni` only. `host` is the Host header the ws/http
    // transport sends, which is a different thing on a CDN link, so it is never
    // promoted to server_name (sing-box falls back to the server address).
    outbound.tls = buildTLS({
      serverName: String(config.sni ?? config.servername ?? ""),
      alpn: parseAlpn(config.alpn === undefined ? null : String(config.alpn)),
      fingerprint: fingerprint ?? null,
    });
  }
  if (network === "ws") {
    outbound.transport = buildTransport("ws", { path: stringOrUndefined(config.path), host: stringOrUndefined(config.host) });
  } else if (network === "grpc") {
    outbound.transport = buildTransport("grpc", { serviceName: String(config.path ?? "") });
  } else if (network === "h2" || network === "http") {
    outbound.transport = buildTransport("http", { path: stringOrUndefined(config.path), host: stringOrUndefined(config.host) });
  } else if (network === "quic") {
    outbound.transport = buildTransport("quic");
  }

  const name = String(config.ps ?? config.remarks ?? config.name ?? "") || nameFromHash || null;
  return ok("vmess", name, outbound);
}

function stringOrUndefined(value) {
  return value === undefined ? undefined : String(value);
}

// --------------------------------------------------------------------- vless

const VLESS_PARAMS = new Set([
  "type",
  "security",
  "encryption",
  "flow",
  "sni",
  "fp",
  "pbk",
  "sid",
  "spx",
  "spider_x",
  "path",
  "host",
  "serviceName",
  "servicename",
  "alpn",
  "headerType",
  "allowInsecure",
  "insecure",
  "mode",
]);

const V2RAY_TRANSPORTS = new Set(["", "tcp", "ws", "grpc", "http", "h2", "httpupgrade"]);

// QUIC-only knobs an exporter leaves on a link whose transport is not QUIC.
// vless has no QUIC transport in V2RAY_TRANSPORTS, so these can never apply.
const VLESS_IGNORABLE = new Set(["quicSecurity", "quicsecurity", "quicsecuritytype"]);

function v2rayTransport(type, params, label) {
  if (type === "" || type === "tcp") return { transport: undefined };
  if (!V2RAY_TRANSPORTS.has(type)) {
    return { transport: undefined, error: `the ${label} transport "${type}" is not one sing-box offers` };
  }
  const path = params.get("path");
  const host = params.get("host");
  if (type === "ws") return { transport: buildTransport("ws", { path, host }) };
  if (type === "httpupgrade") return { transport: buildTransport("httpupgrade", { path, host }) };
  if (type === "http" || type === "h2") return { transport: buildTransport("http", { path, host }) };
  const mode = params.get("mode");
  if (mode !== undefined && mode !== "gun") {
    return { transport: undefined, error: `the ${label} grpc mode "${mode}" is not supported` };
  }
  const serviceName = readFirst(params, ["serviceName", "servicename"]) ?? params.get("path") ?? "";
  return { transport: buildTransport("grpc", { serviceName }) };
}

function parseVless(text) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, "the vless link is not a usable URL", "vless");
  const unknown = unknownParam(uri.params, VLESS_PARAMS, VLESS_IGNORABLE);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the vless parameter "${unknown}" is not known`, "vless");
  const ignored = ignoredParams(uri.params, VLESS_PARAMS, VLESS_IGNORABLE);

  if (!UUID_RE.test(uri.user)) return skip(SKIP_REASONS.PARSE_ERROR, "the vless user is not a UUID", "vless");
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, "the vless address is missing", "vless");
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the vless port is missing or out of range", "vless");

  const encryption = uri.params.get("encryption");
  if (encryption !== undefined && encryption !== "" && encryption !== "none") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vless encryption "${encryption}" is not supported`, "vless");
  }
  const flow = uri.params.get("flow") ?? "";
  if (flow !== "" && flow !== "none" && flow !== "xtls-rprx-vision") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vless flow "${flow}" is not the one sing-box implements`, "vless");
  }
  const headerType = uri.params.get("headerType") ?? "";
  if (headerType !== "" && headerType !== "none") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vless header type "${headerType}" is not supported`, "vless");
  }
  const security = uri.params.get("security") ?? "";
  if (security !== "" && security !== "none" && security !== "tls" && security !== "reality") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the vless security "${security}" is not known`, "vless");
  }

  const type = (uri.params.get("type") ?? "").toLowerCase();
  const transport = v2rayTransport(type, uri.params, "vless");
  if (transport.error) return skip(SKIP_REASONS.PARSE_ERROR, transport.error, "vless");

  const fingerprint = parseFingerprint(uri.params.get("fp"));
  if (fingerprint === null) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the uTLS fingerprint "${uri.params.get("fp")}" is not one sing-box knows`, "vless");
  }
  const insecure = readBool(uri.params, ["allowInsecure", "insecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "allowInsecure is not a boolean", "vless");

  const outbound = { type: "vless", server: uri.host, server_port: port, uuid: uri.user };
  if (flow !== "" && flow !== "none") outbound.flow = flow;

  if (security === "reality") {
    const publicKey = uri.params.get("pbk") ?? "";
    const keyBytes = decodeBase64(publicKey);
    if (keyBytes === null || keyBytes.length !== 32) {
      return skip(SKIP_REASONS.PARSE_ERROR, "the reality public key is not 32 bytes of base64", "vless");
    }
    if (fingerprint === undefined) {
      // sing-box's REALITY client is the uTLS one, so a link without `fp` has
      // no handshake to dial with; picking one here would be a guess.
      return skip(SKIP_REASONS.PARSE_ERROR, "a reality link without fp has no fingerprint to offer", "vless");
    }
    const shortId = uri.params.get("sid") ?? "";
    if (shortId !== "" && !/^(?:[0-9a-f]{2})+$/i.test(shortId)) {
      return skip(SKIP_REASONS.PARSE_ERROR, "the reality short id is not an even-length hex string", "vless");
    }
    if (shortId.length > 16) {
      return skip(SKIP_REASONS.PARSE_ERROR, "the reality short id is longer than 16 characters", "vless");
    }
    // `spx`/`spider_x` is Xray's spider path. sing-box has no such field and its
    // REALITY handshake does not use one, so it is read and dropped rather than
    // turned into a field the core would reject.
    outbound.tls = buildTLS({
      serverName: uri.params.get("sni") ?? "",
      insecure: insecure === true,
      alpn: parseAlpn(uri.params.get("alpn")),
      fingerprint,
      reality: { publicKey, shortId: shortId === "" ? undefined : shortId },
    });
  } else if (security === "tls") {
    outbound.tls = buildTLS({
      serverName: uri.params.get("sni") ?? "",
      insecure: insecure === true,
      alpn: parseAlpn(uri.params.get("alpn")),
      fingerprint: fingerprint ?? null,
    });
  }
  if (transport.transport !== undefined) outbound.transport = transport.transport;

  return ok("vless", uri.name, outbound, ignored);
}

// -------------------------------------------------------------------- trojan

const TROJAN_PARAMS = new Set([
  "type",
  "security",
  "sni",
  "peer",
  "allowInsecure",
  "insecure",
  "fp",
  "alpn",
  "path",
  "host",
  "serviceName",
  "servicename",
  "headerType",
  "mode",
]);

function parseTrojan(text) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, "the trojan link is not a usable URL", "trojan");
  const unknown = unknownParam(uri.params, TROJAN_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the trojan parameter "${unknown}" is not known`, "trojan");

  if (uri.user === "") return skip(SKIP_REASONS.PARSE_ERROR, "the trojan link has no password", "trojan");
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, "the trojan address is missing", "trojan");
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the trojan port is missing or out of range", "trojan");

  const headerType = uri.params.get("headerType") ?? "";
  if (headerType !== "" && headerType !== "none") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the trojan header type "${headerType}" is not supported`, "trojan");
  }
  const security = uri.params.get("security") ?? "";
  if (security !== "" && security !== "tls") {
    // sing-box's trojan outbound is always the TLS one, so a link that asks for
    // anything else has no faithful outbound here.
    return skip(SKIP_REASONS.PARSE_ERROR, `the trojan security "${security}" is not known`, "trojan");
  }
  const type = (uri.params.get("type") ?? "").toLowerCase();
  const transport = v2rayTransport(type, uri.params, "trojan");
  if (transport.error) return skip(SKIP_REASONS.PARSE_ERROR, transport.error, "trojan");

  const fingerprint = parseFingerprint(uri.params.get("fp"));
  if (fingerprint === null) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the uTLS fingerprint "${uri.params.get("fp")}" is not one sing-box knows`, "trojan");
  }
  const insecure = readBool(uri.params, ["allowInsecure", "insecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "allowInsecure is not a boolean", "trojan");

  const outbound = {
    type: "trojan",
    server: uri.host,
    server_port: port,
    password: uri.user,
    // Trojan is TLS on its own; without this sing-box would dial it in the clear.
    tls: buildTLS({
      serverName: readFirst(uri.params, ["sni", "peer"]) ?? "",
      insecure: insecure === true,
      alpn: parseAlpn(uri.params.get("alpn")),
      fingerprint: fingerprint ?? null,
    }),
  };
  if (transport.transport !== undefined) outbound.transport = transport.transport;

  return ok("trojan", uri.name, outbound);
}

// ------------------------------------------------------------- shadowsocks

function ssOutbound({ method, password, host, port, name, params }) {
  if (!SS_METHODS.has(method)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the shadowsocks method "${method}" is not one sing-box knows`, "ss");
  }
  if (password === "") return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks password is empty", "ss");
  if (!validHost(host)) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks address is missing", "ss");
  const parsedPort = parsePort(port);
  if (parsedPort === null) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks port is missing or out of range", "ss");

  const outbound = { type: "shadowsocks", server: host, server_port: parsedPort, method, password };
  for (const key of params.keys()) {
    if (key !== "plugin") {
      return skip(SKIP_REASONS.PARSE_ERROR, `the shadowsocks parameter "${key}" is not known`, "ss");
    }
  }
  const plugin = params.get("plugin") ?? "";
  if (plugin !== "") {
    const parts = plugin.split(";");
    const pluginName = parts.shift().trim();
    if (!SS_PLUGINS.has(pluginName)) {
      return skip(SKIP_REASONS.PARSE_ERROR, `the shadowsocks plugin "${pluginName}" is not one sing-box implements`, "ss");
    }
    outbound.plugin = pluginName;
    const opts = parts.join(";").trim();
    if (opts !== "") outbound.plugin_opts = opts;
  }
  return ok("shadowsocks", name, outbound);
}

function ssEnvelope(text) {
  const body = text.slice("ss://".length);
  const hashAt = body.indexOf("#");
  const withoutHash = hashAt === -1 ? body : body.slice(0, hashAt);
  const name = hashAt === -1 ? null : (decodePercent(body.slice(hashAt + 1)) ?? body.slice(hashAt + 1));
  const queryAt = withoutHash.indexOf("?");
  return {
    authority: queryAt === -1 ? withoutHash : withoutHash.slice(0, queryAt),
    params: parseParams(queryAt === -1 ? "" : withoutHash.slice(queryAt)),
    name,
  };
}

// SIP002: `ss://<userinfo>@host:port?plugin=...#tag`, where userinfo is either
// base64 of `method:password` or the plaintext pair.
function parseSip002(text) {
  const { authority, params, name } = ssEnvelope(text);
  if (params === null) return skip(SKIP_REASONS.PARSE_ERROR, "a shadowsocks query value is not percent-encoded", "ss");
  const at = authority.lastIndexOf("@");
  if (at === -1) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks link has no userinfo", "ss");
  const hostPort = splitHostPort(authority.slice(at + 1));
  if (hostPort === null) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks link has no host and port", "ss");
  const userinfo = decodePercent(authority.slice(0, at));
  if (userinfo === null) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks userinfo is not percent-encoded", "ss");

  // Plaintext wins when it names a method sing-box knows; otherwise the
  // userinfo is read as base64 of `method:password`.
  const colon = userinfo.indexOf(":");
  if (colon !== -1 && SS_METHODS.has(userinfo.slice(0, colon))) {
    return ssOutbound({
      method: userinfo.slice(0, colon),
      password: userinfo.slice(colon + 1),
      host: hostPort.host,
      port: hostPort.port,
      name,
      params,
    });
  }
  const bytes = decodeBase64(userinfo);
  const decoded = bytes === null ? null : decodeUtf8(bytes);
  const split = decoded === null ? -1 : decoded.indexOf(":");
  if (split === -1) {
    return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks userinfo is neither method:password nor its base64", "ss");
  }
  return ssOutbound({
    method: decoded.slice(0, split),
    password: decoded.slice(split + 1),
    host: hostPort.host,
    port: hostPort.port,
    name,
    params,
  });
}

// Legacy: `ss://<base64 of method:password@host:port>`, no `@` outside the blob.
function parseSsLegacy(text) {
  const { authority, params, name } = ssEnvelope(text);
  if (params === null) return skip(SKIP_REASONS.PARSE_ERROR, "a shadowsocks query value is not percent-encoded", "ss");
  const bytes = decodeBase64(authority);
  const decoded = bytes === null ? null : decodeUtf8(bytes);
  if (decoded === null) return skip(SKIP_REASONS.PARSE_ERROR, "the shadowsocks link is not base64", "ss");
  const at = decoded.lastIndexOf("@");
  if (at === -1) return skip(SKIP_REASONS.PARSE_ERROR, "the decoded shadowsocks link has no host", "ss");
  const credentials = decoded.slice(0, at);
  const colon = credentials.indexOf(":");
  if (colon === -1) return skip(SKIP_REASONS.PARSE_ERROR, "the decoded shadowsocks link has no method", "ss");
  const hostPort = splitHostPort(decoded.slice(at + 1));
  if (hostPort === null) return skip(SKIP_REASONS.PARSE_ERROR, "the decoded shadowsocks link has no port", "ss");
  return ssOutbound({
    method: credentials.slice(0, colon),
    password: credentials.slice(colon + 1),
    host: hostPort.host,
    port: hostPort.port,
    name,
    params,
  });
}

// The two shapes are told apart by the `@` the SIP002 form carries outside its
// base64; the legacy blob never has one.
function parseShadowsocks(text) {
  const body = text.slice("ss://".length);
  const hashAt = body.indexOf("#");
  const beforeHash = hashAt === -1 ? body : body.slice(0, hashAt);
  return beforeHash.includes("@") ? parseSip002(text) : parseSsLegacy(text);
}

// ---------------------------------------------------------- hysteria2 / hy2

const HYSTERIA2_PARAMS = new Set([
  "sni",
  "peer",
  "insecure",
  "allowInsecure",
  "pinSHA256",
  "pinsha256",
  "obfs",
  "obfs-password",
  "obfsparam",
  "alpn",
  "up",
  "upmbps",
  "down",
  "downmbps",
  "mport",
  "ports",
  "hop-interval",
  "hop_interval",
  "fp",
  "fingerprint",
  "security",
]);

// `mport=2000-3000,4000` / `ports=2000:3000` -> sing-box's ["2000:3000", "4000"].
function parseServerPorts(value) {
  const ranges = [];
  for (const entry of value.split(",")) {
    const range = entry.trim().replace("-", ":");
    if (!/^\d{1,5}(?::\d{1,5})?$/.test(range)) return null;
    const [start, end] = range.split(":");
    if (parsePort(start) === null) return null;
    if (end !== undefined && parsePort(end) === null) return null;
    ranges.push(range);
  }
  return ranges.length === 0 ? null : ranges;
}

// tls.certificate_sha256 is what a `pinSHA256=` link needs, and it arrived in
// sing-box 1.15.0. On anything older a pinned node is refused, not quietly
// weakened -- unless the caller explicitly opts in (see CERT_PIN_SINCE).
const PIN_SINCE = CERT_PIN_SINCE;

function parseHysteria2(text, scheme, options = {}) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} link is not a usable URL`, scheme);
  const unknown = unknownParam(uri.params, HYSTERIA2_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} parameter "${unknown}" is not known`, scheme);

  const pin = readFirst(uri.params, ["pinSHA256", "pinsha256"]);
  let certificateSha256 = null;
  let unpinned = false;
  if (pin !== undefined && pin !== "") {
    const base64 = pinToBase64(pin);
    if (base64 === null) {
      return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} pin is neither a hex nor a base64 SHA-256`, scheme);
    }
    const comparison = typeof options.coreVersion === "string"
      ? compareVersions(options.coreVersion, PIN_SINCE)
      : null;
    if (comparison !== null && comparison >= 0) {
      certificateSha256 = [base64];
    } else if (options.allowUnpinned === true) {
      unpinned = true;
    } else {
      return skip(
        SKIP_REASONS.CORE_TOO_OLD,
        `the ${scheme} certificate pin needs sing-box >= ${PIN_SINCE}; with an older core this node can only be used unauthenticated, which pool.allowUnpinnedNodes must opt in to`,
        scheme,
      );
    }
  }

  const security = uri.params.get("security") ?? "";
  if (security !== "" && security !== "tls") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} security "${security}" is not known`, scheme);
  }
  // `hysteria2://user:pass@` is the official client's userpass form; sing-box
  // wants the pair as one password, which is what the two halves are read as.
  const password = uri.password === "" ? uri.user : `${uri.user}:${uri.password}`;
  if (password === "") return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} link has no password`, scheme);
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} address is missing`, scheme);
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} port is missing or out of range`, scheme);

  const insecure = readBool(uri.params, ["insecure", "allowInsecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "insecure is not a boolean", scheme);
  const fingerprint = parseFingerprint(readFirst(uri.params, ["fp", "fingerprint"]));
  if (fingerprint === null) return skip(SKIP_REASONS.PARSE_ERROR, "the uTLS fingerprint is not one sing-box knows", scheme);

  const obfsType = uri.params.get("obfs") ?? "";
  // Salamander is the only obfuscation 1.14.3 has; gecko arrived after it.
  if (obfsType !== "" && obfsType !== "salamander") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} obfs "${obfsType}" is not one sing-box 1.14.3 knows`, scheme);
  }
  const obfsPassword = readFirst(uri.params, ["obfs-password", "obfsparam"]) ?? "";
  if (obfsType === "" && obfsPassword !== "") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} link has an obfs password but no obfs type`, scheme);
  }
  if (obfsType === "salamander" && obfsPassword === "") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} salamander obfs needs its password`, scheme);
  }

  const outbound = { type: "hysteria2", server: uri.host, server_port: port };
  const ports = readFirst(uri.params, ["mport", "ports"]);
  if (ports !== undefined) {
    const serverPorts = parseServerPorts(ports);
    if (serverPorts === null) {
      return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} port range "${ports}" is not usable`, scheme);
    }
    outbound.server_ports = serverPorts;
  }
  const hopInterval = readFirst(uri.params, ["hop-interval", "hop_interval"]);
  if (hopInterval !== undefined) {
    // Hysteria's own links write this in seconds; sing-box wants a duration.
    const duration = DURATION_RE.test(hopInterval)
      ? hopInterval
      : /^\d+$/.test(hopInterval)
        ? `${hopInterval}s`
        : null;
    if (duration === null) {
      return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} hop interval "${hopInterval}" is not a duration`, scheme);
    }
    outbound.hop_interval = duration;
  }
  const up = readInt(uri.params, ["up", "upmbps"]);
  if (up === null) return skip(SKIP_REASONS.PARSE_ERROR, "the upstream bandwidth is not a whole number", scheme);
  if (up !== undefined) outbound.up_mbps = up;
  const down = readInt(uri.params, ["down", "downmbps"]);
  if (down === null) return skip(SKIP_REASONS.PARSE_ERROR, "the downstream bandwidth is not a whole number", scheme);
  if (down !== undefined) outbound.down_mbps = down;

  if (obfsType === "salamander") outbound.obfs = { type: "salamander", password: obfsPassword };
  outbound.password = password;
  outbound.tls = buildTLS({
    serverName: readFirst(uri.params, ["sni", "peer"]) ?? "",
    // A camouflage SNI with the pin dropped cannot be verified at all, so the
    // opt-in path has to say so to the core as well.
    insecure: insecure === true || unpinned,
    alpn: parseAlpn(uri.params.get("alpn")),
    fingerprint: fingerprint ?? null,
    certificateSha256,
  });

  return ok("hysteria2", uri.name, outbound, null, unpinned);
}

// --------------------------------------------------------------- hysteria 1

const HYSTERIA_PARAMS = new Set([
  "protocol",
  "auth",
  "auth_str",
  "peer",
  "sni",
  "insecure",
  "allowInsecure",
  "alpn",
  "upmbps",
  "downmbps",
  "fp",
  "fingerprint",
]);

function parseHysteria(text) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, "the hysteria link is not a usable URL", "hysteria");
  const unknown = unknownParam(uri.params, HYSTERIA_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the hysteria parameter "${unknown}" is not known`, "hysteria");

  const protocol = uri.params.get("protocol") ?? "";
  if (protocol !== "" && protocol !== "udp") {
    return skip(SKIP_REASONS.PARSE_ERROR, `the hysteria protocol "${protocol}" is not one this module maps`, "hysteria");
  }
  // sing-box's hysteria `obfs` is a bare string and the 1.14.3 docs do not say
  // whether it holds the type or the password, so a link that carries obfs is
  // left to a human instead of emitted with the field half understood.
  for (const key of ["obfs", "obfsParam", "obfsparam"]) {
    if (uri.params.has(key)) {
      return skip(SKIP_REASONS.PARSE_ERROR, "hysteria obfs is not mapped: sing-box 1.14.3's field is ambiguous", "hysteria");
    }
  }
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, "the hysteria address is missing", "hysteria");
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the hysteria port is missing or out of range", "hysteria");

  const insecure = readBool(uri.params, ["insecure", "allowInsecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "insecure is not a boolean", "hysteria");
  const fingerprint = parseFingerprint(readFirst(uri.params, ["fp", "fingerprint"]));
  if (fingerprint === null) return skip(SKIP_REASONS.PARSE_ERROR, "the uTLS fingerprint is not one sing-box knows", "hysteria");

  const outbound = { type: "hysteria", server: uri.host, server_port: port };
  const up = readInt(uri.params, ["upmbps"]);
  if (up === null) return skip(SKIP_REASONS.PARSE_ERROR, "upmbps is not a whole number", "hysteria");
  if (up !== undefined) outbound.up_mbps = up;
  const down = readInt(uri.params, ["downmbps"]);
  if (down === null) return skip(SKIP_REASONS.PARSE_ERROR, "downmbps is not a whole number", "hysteria");
  if (down !== undefined) outbound.down_mbps = down;

  // The link spells the plaintext auth string `auth`; sing-box calls the
  // plaintext field `auth_str` and the base64 one `auth`.
  const auth = readFirst(uri.params, ["auth", "auth_str"]);
  if (auth !== undefined && auth !== "") outbound.auth_str = auth;
  else if (uri.user !== "") outbound.auth_str = uri.user;

  outbound.tls = buildTLS({
    serverName: readFirst(uri.params, ["peer", "sni"]) ?? "",
    insecure: insecure === true,
    alpn: parseAlpn(uri.params.get("alpn")),
    fingerprint: fingerprint ?? null,
  });

  return ok("hysteria", uri.name, outbound);
}

// ---------------------------------------------------------------------- tuic

const TUIC_PARAMS = new Set([
  "congestion_control",
  "udp_relay_mode",
  "udp_over_stream",
  "zero_rtt_handshake",
  "heartbeat",
  "sni",
  "alpn",
  "allow_insecure",
  "allowInsecure",
  "insecure",
  "fp",
  "fingerprint",
  "password",
]);

function parseTuic(text) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, "the tuic link is not a usable URL", "tuic");
  const unknown = unknownParam(uri.params, TUIC_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the tuic parameter "${unknown}" is not known`, "tuic");

  if (!UUID_RE.test(uri.user)) return skip(SKIP_REASONS.PARSE_ERROR, "the tuic user is not a UUID", "tuic");
  const password = uri.password !== "" ? uri.password : (uri.params.get("password") ?? "");
  if (password === "") return skip(SKIP_REASONS.PARSE_ERROR, "the tuic link has no password", "tuic");
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, "the tuic address is missing", "tuic");
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the tuic port is missing or out of range", "tuic");

  const congestion = uri.params.get("congestion_control");
  if (congestion !== undefined && !TUIC_CONGESTION.has(congestion)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the tuic congestion control "${congestion}" is not one sing-box knows`, "tuic");
  }
  const relayMode = uri.params.get("udp_relay_mode");
  if (relayMode !== undefined && !TUIC_UDP_RELAY_MODES.has(relayMode)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the tuic udp relay mode "${relayMode}" is not one sing-box knows`, "tuic");
  }
  const udpOverStream = readBool(uri.params, ["udp_over_stream"]);
  if (udpOverStream === null) return skip(SKIP_REASONS.PARSE_ERROR, "udp_over_stream is not a boolean", "tuic");
  const zeroRtt = readBool(uri.params, ["zero_rtt_handshake"]);
  if (zeroRtt === null) return skip(SKIP_REASONS.PARSE_ERROR, "zero_rtt_handshake is not a boolean", "tuic");
  const heartbeat = uri.params.get("heartbeat");
  if (heartbeat !== undefined && !DURATION_RE.test(heartbeat)) {
    return skip(SKIP_REASONS.PARSE_ERROR, `the tuic heartbeat "${heartbeat}" is not a duration`, "tuic");
  }
  const insecure = readBool(uri.params, ["allow_insecure", "allowInsecure", "insecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "allow_insecure is not a boolean", "tuic");
  const fingerprint = parseFingerprint(readFirst(uri.params, ["fp", "fingerprint"]));
  if (fingerprint === null) return skip(SKIP_REASONS.PARSE_ERROR, "the uTLS fingerprint is not one sing-box knows", "tuic");

  const outbound = { type: "tuic", server: uri.host, server_port: port, uuid: uri.user, password };
  if (congestion !== undefined) outbound.congestion_control = congestion;
  if (relayMode !== undefined) outbound.udp_relay_mode = relayMode;
  if (udpOverStream !== undefined) outbound.udp_over_stream = udpOverStream;
  if (zeroRtt !== undefined) outbound.zero_rtt_handshake = zeroRtt;
  if (heartbeat !== undefined) outbound.heartbeat = heartbeat;
  outbound.tls = buildTLS({
    serverName: uri.params.get("sni") ?? "",
    insecure: insecure === true,
    alpn: parseAlpn(uri.params.get("alpn")),
    fingerprint: fingerprint ?? null,
  });

  return ok("tuic", uri.name, outbound);
}

// -------------------------------------------------------------------- anytls

const ANYTLS_PARAMS = new Set([
  "sni",
  "insecure",
  "allowInsecure",
  "fp",
  "fingerprint",
  "alpn",
  "idle_session_check_interval",
  "idle_session_timeout",
  "min_idle_session",
]);

function parseAnytls(text) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, "the anytls link is not a usable URL", "anytls");
  const unknown = unknownParam(uri.params, ANYTLS_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the anytls parameter "${unknown}" is not known`, "anytls");

  if (uri.user === "") return skip(SKIP_REASONS.PARSE_ERROR, "the anytls link has no password", "anytls");
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, "the anytls address is missing", "anytls");
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the anytls port is missing or out of range", "anytls");

  const insecure = readBool(uri.params, ["insecure", "allowInsecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "insecure is not a boolean", "anytls");
  const fingerprint = parseFingerprint(readFirst(uri.params, ["fp", "fingerprint"]));
  if (fingerprint === null) return skip(SKIP_REASONS.PARSE_ERROR, "the uTLS fingerprint is not one sing-box knows", "anytls");

  const outbound = { type: "anytls", server: uri.host, server_port: port, password: uri.user };
  for (const key of ["idle_session_check_interval", "idle_session_timeout"]) {
    const value = uri.params.get(key);
    if (value === undefined) continue;
    if (!DURATION_RE.test(value)) {
      return skip(SKIP_REASONS.PARSE_ERROR, `the anytls ${key} "${value}" is not a duration`, "anytls");
    }
    outbound[key] = value;
  }
  const minIdleSession = readInt(uri.params, ["min_idle_session"]);
  if (minIdleSession === null) return skip(SKIP_REASONS.PARSE_ERROR, "min_idle_session is not a whole number", "anytls");
  if (minIdleSession !== undefined) outbound.min_idle_session = minIdleSession;
  outbound.tls = buildTLS({
    serverName: uri.params.get("sni") ?? "",
    insecure: insecure === true,
    alpn: parseAlpn(uri.params.get("alpn")),
    fingerprint: fingerprint ?? null,
  });

  return ok("anytls", uri.name, outbound);
}

// ------------------------------------------------------------- http / https

const HTTP_PARAMS = new Set(["sni", "insecure", "allowInsecure"]);

function parseHttp(text, { defaultPort, tlsEnabled, scheme }) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} link is not a usable URL`, scheme);
  const unknown = unknownParam(uri.params, HTTP_PARAMS);
  if (unknown !== null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} parameter "${unknown}" is not known`, scheme);

  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} address is missing`, scheme);
  const port = uri.rawPort === "" ? defaultPort : parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} port is out of range`, scheme);
  const insecure = readBool(uri.params, ["insecure", "allowInsecure"]);
  if (insecure === null) return skip(SKIP_REASONS.PARSE_ERROR, "insecure is not a boolean", scheme);

  const outbound = { type: "http", server: uri.host, server_port: port };
  if (uri.user !== "") outbound.username = uri.user;
  if (uri.password !== "") outbound.password = uri.password;
  if (tlsEnabled) {
    // An https URL's host is the name its certificate is checked against.
    outbound.tls = buildTLS({ serverName: uri.params.get("sni") ?? uri.host, insecure: insecure === true });
  } else if (uri.params.get("sni") !== undefined || insecure === true) {
    return skip(SKIP_REASONS.PARSE_ERROR, "an http link cannot carry TLS options", scheme);
  }
  return ok("http", uri.name, outbound);
}

// -------------------------------------------------------------------- socks

function parseSocks(text, scheme) {
  const uri = splitURI(text);
  if (uri === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} link is not a usable URL`, scheme);
  if (uri.params.size !== 0) {
    const unknown = uri.params.keys().next().value;
    return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} parameter "${unknown}" is not known`, scheme);
  }
  if (uri.user.includes(":")) return skip(SKIP_REASONS.PARSE_ERROR, "the socks user contains a colon", scheme);
  if (!validHost(uri.host)) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} address is missing`, scheme);
  const port = parsePort(uri.rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, `the ${scheme} port is missing or out of range`, scheme);

  // `socks5h://` asks the proxy to resolve names. sing-box has no field for
  // that choice -- its socks outbound hands the domain to the server unless a
  // dial field forces local resolution -- so both spellings build the same
  // outbound instead of one of them being given a field that does not exist.
  const outbound = { type: "socks", server: uri.host, server_port: port, version: "5" };
  if (uri.user !== "") outbound.username = uri.user;
  if (uri.password !== "") outbound.password = uri.password;
  return ok("socks", uri.name, outbound);
}

// ------------------------------------------- bare `host:port[:user:pass]`

// Credentials-less means http. IPv4 only: a domain could be a bare host too,
// but then a password's colon is indistinguishable from the port separator, and
// a link that might be split in the wrong place is not one to hand to a core.
function parseBareAddress(text) {
  const hashAt = text.indexOf("#");
  const body = hashAt === -1 ? text : text.slice(0, hashAt);
  const name = hashAt === -1 ? null : (decodePercent(text.slice(hashAt + 1)) ?? null);
  if (body.includes("@") || body.includes("?") || body.includes("/")) {
    return skip(SKIP_REASONS.PARSE_ERROR, "the line is neither a URI nor host:port[:user:pass]", null);
  }
  const parts = body.split(":");
  if (parts.length < 2 || parts.length > 4) {
    return skip(
      SKIP_REASONS.PARSE_ERROR,
      parts.length > 4
        ? "this form cannot carry a password with a colon; use a URI instead"
        : "the line is neither a URI nor host:port[:user:pass]",
      null,
    );
  }
  const [host, rawPort, username, password] = parts;
  if (!IPV4_RE.test(host)) return skip(SKIP_REASONS.PARSE_ERROR, "the bare form takes an IPv4 address only", null);
  const port = parsePort(rawPort);
  if (port === null) return skip(SKIP_REASONS.PARSE_ERROR, "the bare form has no usable port", null);
  if (parts.length === 3) return skip(SKIP_REASONS.PARSE_ERROR, "the bare form needs both a user and a password", null);
  if (parts.length === 4) {
    if (username === "" || password === "") {
      return skip(SKIP_REASONS.PARSE_ERROR, "the bare form needs both a user and a password", null);
    }
    return ok("http", name, { type: "http", server: host, server_port: port, username, password });
  }
  return ok("http", name, { type: "http", server: host, server_port: port });
}

// ------------------------------------------------------------- the registry

const PARSERS = new Map([
  ["vmess", { protocol: "vmess", parse: (text) => parseVmess(text) }],
  ["vless", { protocol: "vless", parse: (text, options) => parseVless(text, options) }],
  ["trojan", { protocol: "trojan", parse: (text) => parseTrojan(text) }],
  ["ss", { protocol: "shadowsocks", parse: (text) => parseShadowsocks(text) }],
  ["hysteria2", { protocol: "hysteria2", parse: (text, options) => parseHysteria2(text, "hysteria2", options) }],
  ["hy2", { protocol: "hysteria2", parse: (text, options) => parseHysteria2(text, "hy2", options) }],
  ["hysteria", { protocol: "hysteria", parse: (text) => parseHysteria(text) }],
  ["tuic", { protocol: "tuic", parse: (text) => parseTuic(text) }],
  ["anytls", { protocol: "anytls", parse: (text) => parseAnytls(text) }],
  ["http", { protocol: "http", parse: (text) => parseHttp(text, { defaultPort: 80, tlsEnabled: false, scheme: "http" }) }],
  ["https", { protocol: "http", parse: (text) => parseHttp(text, { defaultPort: 443, tlsEnabled: true, scheme: "https" }) }],
  ["socks5", { protocol: "socks", parse: (text) => parseSocks(text, "socks5") }],
  ["socks5h", { protocol: "socks", parse: (text) => parseSocks(text, "socks5h") }],
  ["socks", { protocol: "socks", parse: (text) => parseSocks(text, "socks") }],
]);

// Every scheme spelling this module reads. `hy2` is the short spelling of
// hysteria2 and builds the same outbound; socks4/ssr and the other schemes a
// subscription may carry are not listed and come back as unsupported-scheme.
export const SUPPORTED_SCHEMES = Object.freeze([...PARSERS.keys()]);

export function parseProtocolLine(line, options = {}) {
  const text = typeof line === "string" ? line.trim() : "";
  if (text === "") return skip(SKIP_REASONS.PARSE_ERROR, "the line is empty", null);

  const match = /^([A-Za-z][A-Za-z0-9+.\-]*):\/\//.exec(text);
  if (match === null) return parseBareAddress(text);

  const scheme = match[1].toLowerCase();
  const parser = PARSERS.get(scheme);
  if (parser === undefined) return skip(SKIP_REASONS.UNSUPPORTED_SCHEME, `the scheme "${scheme}" is not supported`, scheme);

  const floor = MIN_CORE_VERSION[parser.protocol];
  if (floor !== undefined && typeof options.coreVersion === "string") {
    const comparison = compareVersions(options.coreVersion, floor);
    if (comparison !== null && comparison < 0) {
      return skip(SKIP_REASONS.CORE_TOO_OLD, `${parser.protocol} needs sing-box >= ${floor}`, scheme);
    }
  }
  return parser.parse(text, options);
}

// A whole subscription body. Blank lines (including the one a trailing newline
// leaves behind) are counted as ignored, so `input === outbound + skipped`
// holds over any body.
export function parseSubscription(text, options = {}) {
  const lines = String(text).split(/\r?\n/);
  const outbounds = [];
  const skipped = [];
  const byReason = {};
  for (const reason of Object.values(SKIP_REASONS)) byReason[reason] = 0;
  // Keys a line carried that cannot change what is dialled. Counted by name so
  // a tolerant read is still a visible one.
  const ignoredParamsByName = {};
  // Nodes used without the certificate pin that authenticates them.
  let unpinned = 0;
  let ignored = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === "") {
      ignored += 1;
      continue;
    }
    const result = parseProtocolLine(line, options);
    if (result.ok) {
      outbounds.push({ protocol: result.protocol, name: result.name, outbound: result.outbound });
      for (const key of result.ignored ?? []) ignoredParamsByName[key] = (ignoredParamsByName[key] ?? 0) + 1;
      if (result.unpinned) unpinned += 1;
    } else {
      skipped.push({ line, scheme: result.scheme, reason: result.reason, detail: result.detail });
      byReason[result.reason] += 1;
    }
  }

  return {
    outbounds,
    skipped,
    counts: {
      input: lines.length - ignored,
      outbound: outbounds.length,
      skipped: skipped.length,
      ignored,
      byReason,
      ignoredParams: ignoredParamsByName,
      unpinned,
    },
  };
}
