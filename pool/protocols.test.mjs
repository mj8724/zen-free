import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  FIELDS_NOT_EMITTED,
  MIN_CORE_VERSION,
  SKIP_REASONS,
  SUPPORTED_SCHEMES,
  parseProtocolLine,
  parseSubscription,
} from "./protocols.mjs";

// The corpus is one line per shape this module claims to read. Every field
// assertion below is made against the outbound the corpus line produced, so a
// change in how a link maps shows up as a failing field, not as a passing
// "it returned an object".
const corpus = readFileSync(new URL("./fixtures/subscription.txt", import.meta.url), "utf8");
const corpusLines = corpus
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line !== "");
const parsed = parseSubscription(corpus);
const byName = new Map(parsed.outbounds.map((entry) => [entry.name, entry.outbound]));

function node(name) {
  const outbound = byName.get(name);
  assert.ok(outbound, `the fixture ${name} must have produced an outbound`);
  return outbound;
}

function byServer(server) {
  const entry = parsed.outbounds.find((item) => item.outbound.server === server);
  assert.ok(entry, `the fixture for ${server} must have produced an outbound`);
  return entry.outbound;
}

function skipOf(line) {
  const result = parseProtocolLine(line);
  assert.equal(result.ok, false, `${line} must not produce an outbound`);
  assert.ok(Object.values(SKIP_REASONS).includes(result.reason), `unclassified reason ${result.reason}`);
  return result;
}

// ---------------------------------------------------------------- counting

test("every fixture line is either an outbound or a classified skip", () => {
  assert.equal(parsed.counts.input, corpusLines.length, "input counts the lines the corpus holds");
  assert.equal(parsed.counts.ignored, 1, "only the trailing newline's empty line is ignored");
  assert.equal(parsed.counts.outbound, parsed.outbounds.length);
  assert.equal(parsed.counts.skipped, parsed.skipped.length);
  assert.equal(
    parsed.counts.outbound + parsed.counts.skipped,
    parsed.counts.input,
    "N === M + X: no line may be dropped between the two",
  );

  const reasons = Object.fromEntries(Object.values(SKIP_REASONS).map((reason) => [reason, 0]));
  for (const skip of parsed.skipped) reasons[skip.reason] += 1;
  assert.deepEqual(parsed.counts.byReason, reasons, "the per-reason counts must agree with the skip list");
  assert.deepEqual(
    Object.values(reasons).reduce((sum, count) => sum + count, 0),
    parsed.counts.skipped,
  );
  assert.equal(reasons["unsupported-scheme"], 2);
  assert.equal(reasons["core-too-old"], 0, "no line is gated unless a core version is offered");
});

test("every outbound carries the fields a sing-box outbound needs", () => {
  for (const { outbound } of parsed.outbounds) {
    assert.equal(typeof outbound.type, "string");
    assert.equal(typeof outbound.server, "string");
    assert.ok(outbound.server.length > 0);
    assert.ok(Number.isInteger(outbound.server_port), `${outbound.type} needs an integer port`);
    assert.ok(outbound.server_port >= 1 && outbound.server_port <= 65535);
    if (outbound.tls !== undefined) assert.equal(outbound.tls.enabled, true);
    if (outbound.transport !== undefined) assert.equal(typeof outbound.transport.type, "string");
  }
});

test("blank lines and CRLF are not counted as nodes", () => {
  const body = `${corpusLines[0]}\r\n\r\n  \r\n${corpusLines[25]}\n\n`;
  const result = parseSubscription(body);
  assert.equal(result.counts.outbound, 2);
  assert.equal(result.counts.skipped, 0);
  assert.equal(result.counts.input, 2);
  assert.equal(result.counts.ignored, 4);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});

// ------------------------------------------------------------------- vmess

test("vmess: base64 JSON maps to server, uuid, security, alter_id and the ws transport", () => {
  const vmess = node("fixture-vmess-ws");
  assert.equal(vmess.type, "vmess");
  assert.equal(vmess.server, "vmess.example.invalid");
  assert.equal(vmess.server_port, 443);
  assert.equal(vmess.uuid, "11111111-1111-4111-8111-111111111111");
  assert.equal(vmess.security, "auto");
  assert.equal(vmess.alter_id, 0);
  assert.deepEqual(vmess.tls, {
    enabled: true,
    server_name: "cdn.example.invalid",
    alpn: ["h2", "http/1.1"],
    utls: { enabled: true, fingerprint: "chrome" },
  });
  assert.deepEqual(vmess.transport, {
    type: "ws",
    path: "/fixture-vmess",
    headers: { Host: "cdn.example.invalid" },
  });
});

test("vmess: a tcp node keeps its cipher and carries no tls or transport block", () => {
  const vmess = node("fixture-vmess-tcp");
  assert.equal(vmess.server, "203.0.113.10");
  assert.equal(vmess.server_port, 8080);
  assert.equal(vmess.uuid, "11111111-1111-4111-8111-111111111111");
  assert.equal(vmess.security, "aes-128-gcm");
  assert.equal(vmess.alter_id, 0);
  assert.equal("tls" in vmess, false);
  assert.equal("transport" in vmess, false);
});

test("vmess: the grpc network's gun mode becomes the grpc transport's service name", () => {
  const vmess = node("fixture-vmess-grpc");
  assert.equal(vmess.server, "203.0.113.11");
  assert.equal(vmess.server_port, 443);
  assert.equal(vmess.tls.server_name, "grpc.example.invalid");
  assert.equal(vmess.tls.utls.fingerprint, "chrome");
  assert.deepEqual(vmess.transport, { type: "grpc", service_name: "fixture-gun-service" });
});

test("vmess: a payload that is not base64 JSON is a parse error, not an outbound", () => {
  assert.equal(skipOf(corpusLines[28]).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("vmess://bm90LWpzb24").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("vmess://eyJ2IjoiMiIsImFkZCI6Ii4iLCJwb3J0IjoiNDQzIiwiaWQiOiJ4In0").reason, SKIP_REASONS.PARSE_ERROR);
});

test("vmess: a JSON field this module does not know is a parse error", () => {
  const payload = Buffer.from(
    JSON.stringify({
      v: "2",
      add: "vmess.example.invalid",
      port: "443",
      id: "11111111-1111-4111-8111-111111111111",
      aid: "0",
      scy: "auto",
      net: "tcp",
      extra_field: "?",
    }),
  ).toString("base64");
  assert.equal(skipOf(`vmess://${payload}`).reason, SKIP_REASONS.PARSE_ERROR);
});

// ------------------------------------------------------------------- vless

test("vless: reality fills tls.reality with the key and short id, and utls with fp", () => {
  const vless = node("fixture-vless-reality");
  assert.equal(vless.type, "vless");
  assert.equal(vless.server, "198.51.100.10");
  assert.equal(vless.server_port, 443);
  assert.equal(vless.uuid, "11111111-1111-4111-8111-111111111111");
  assert.equal(vless.flow, "xtls-rprx-vision");
  assert.equal("transport" in vless, false, "tcp needs no transport block");
  assert.deepEqual(vless.tls, {
    enabled: true,
    server_name: "www.example.invalid",
    utls: { enabled: true, fingerprint: "chrome" },
    reality: {
      enabled: true,
      public_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE",
      short_id: "0123456789abcdef",
    },
  });
  // `spx` is Xray's spider path: read from the link, and not turned into a
  // field sing-box does not have.
  assert.equal("spx" in vless.tls, false);
  assert.equal("spider_x" in vless.tls, false);
});

test("vless: ws carries path and the Host header, and tls carries alpn", () => {
  const vless = node("fixture-vless-ws");
  assert.equal(vless.server, "198.51.100.11");
  assert.equal(vless.server_port, 8443);
  assert.equal("flow" in vless, false);
  assert.deepEqual(vless.tls, {
    enabled: true,
    server_name: "cdn.example.invalid",
    alpn: ["h2", "http/1.1"],
    utls: { enabled: true, fingerprint: "firefox" },
  });
  assert.deepEqual(vless.transport, { type: "ws", path: "/fixture-ws", headers: { Host: "cdn.example.invalid" } });
});

test("vless: an IPv6 host loses its brackets and grpc keeps its service name", () => {
  const vless = node("fixture-vless-grpc-ipv6");
  assert.equal(vless.server, "2001:db8::1");
  assert.equal(vless.server_port, 8443);
  assert.equal(vless.tls.server_name, "grpc.example.invalid");
  assert.deepEqual(vless.transport, { type: "grpc", service_name: "fixture-grpc" });
});

test("vless: httpupgrade keeps its host and path", () => {
  const vless = node("fixture-vless-httpupgrade");
  assert.equal(vless.server, "198.51.100.12");
  assert.equal(vless.server_port, 8080);
  assert.equal("tls" in vless, false, "security=none means no tls block");
  assert.deepEqual(vless.transport, {
    type: "httpupgrade",
    path: "/fixture-upgrade",
    host: "upgrade.example.invalid",
  });
});

test("vless: reality needs a 32-byte key, an even-length hex short id and a fingerprint", () => {
  const head = "vless://11111111-1111-4111-8111-111111111111@198.51.100.10:443?security=reality&type=tcp&fp=chrome";
  const key = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
  const complete = parseProtocolLine(`${head}&pbk=${key}&sid=0123456789abcdef`);
  assert.equal(complete.ok, true, "a 32-byte key with a hex short id is a node this core takes");
  assert.equal(complete.outbound.tls.reality.public_key, key);
  assert.equal(complete.outbound.tls.reality.short_id, "0123456789abcdef");
  assert.equal(skipOf(`${head}&pbk=QUFBQUFB`).reason, SKIP_REASONS.PARSE_ERROR, "six bytes is not a key");
  assert.equal(skipOf(`${head}&pbk=not-base64!`).reason, SKIP_REASONS.PARSE_ERROR);
  const noFingerprint = "vless://11111111-1111-4111-8111-111111111111@198.51.100.10:443?security=reality&type=tcp&pbk=" + key;
  assert.equal(skipOf(noFingerprint).reason, SKIP_REASONS.PARSE_ERROR);
  const oddShortId = `${head}&pbk=${key}&sid=012`;
  assert.equal(skipOf(oddShortId).reason, SKIP_REASONS.PARSE_ERROR);
  const longShortId = `${head}&pbk=${key}&sid=0123456789abcdef00`;
  assert.equal(skipOf(longShortId).reason, SKIP_REASONS.PARSE_ERROR);
});

test("vless: a transport, flow or fingerprint sing-box cannot dial is a parse error", () => {
  const base = "vless://11111111-1111-4111-8111-111111111111@198.51.100.10:443?security=none";
  assert.equal(skipOf(`${base}&type=kcp`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&type=xhttp`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&flow=xtls-rprx-direct`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&fp=fixture-browser`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&pqv=1`).reason, SKIP_REASONS.PARSE_ERROR);
});

// ------------------------------------------------------------------ trojan

test("trojan: password and tls land in their fields, with the ws transport beside them", () => {
  const trojan = node("fixture-trojan-ws");
  assert.equal(trojan.type, "trojan");
  assert.equal(trojan.server, "203.0.113.20");
  assert.equal(trojan.server_port, 443);
  assert.equal(trojan.password, "fixture-trojan-pass");
  assert.deepEqual(trojan.tls, { enabled: true, server_name: "trojan.example.invalid", insecure: true });
  assert.deepEqual(trojan.transport, {
    type: "ws",
    path: "/fixture-trojan",
    headers: { Host: "cdn.example.invalid" },
  });
});

test("trojan: a tcp node keeps tls on, with the uTLS fingerprint from fp", () => {
  const trojan = node("fixture-trojan-tcp");
  assert.equal(trojan.server, "203.0.113.21");
  assert.equal(trojan.password, "fixture-trojan-pass");
  assert.deepEqual(trojan.tls, {
    enabled: true,
    server_name: "trojan2.example.invalid",
    utls: { enabled: true, fingerprint: "chrome" },
  });
  assert.equal("transport" in trojan, false);
});

test("trojan: a link without a password is a parse error", () => {
  assert.equal(skipOf("trojan://:443?sni=t.example.invalid").reason, SKIP_REASONS.PARSE_ERROR);
});

// ------------------------------------------------------------ shadowsocks

test("shadowsocks: the SIP002 form splits method and password out of its base64 userinfo", () => {
  const sip002 = node("fixture-ss-sip002");
  assert.equal(sip002.type, "shadowsocks");
  assert.equal(sip002.server, "192.0.2.10");
  assert.equal(sip002.server_port, 8388);
  assert.equal(sip002.method, "aes-256-gcm");
  assert.equal(sip002.password, "fixture-ss-password");
});

test("shadowsocks: both spellings of one node build the same outbound", () => {
  assert.deepEqual(node("fixture-ss-sip002"), node("fixture-ss-legacy"));
  const legacy = node("fixture-ss-legacy");
  assert.equal(legacy.method, "aes-256-gcm");
  assert.equal(legacy.password, "fixture-ss-password");
  assert.equal(legacy.server, "192.0.2.10");
  assert.equal(legacy.server_port, 8388);
});

test("shadowsocks: a 2022 cipher keeps its key as the password", () => {
  const ss2022 = node("fixture-ss-2022");
  assert.equal(ss2022.method, "2022-blake3-aes-128-gcm");
  assert.equal(ss2022.password, "Zml4dHVyZS1zcy1rZXktMQ==");
  assert.equal(ss2022.server, "192.0.2.11");
  assert.equal(ss2022.server_port, 8389);
});

test("shadowsocks: a SIP003 plugin becomes plugin and plugin_opts", () => {
  const plugin = node("fixture-ss-plugin");
  assert.equal(plugin.plugin, "obfs-local");
  assert.equal(plugin.plugin_opts, "obfs=http;obfs-host=cdn.example.invalid");
  assert.equal(plugin.method, "aes-256-gcm");
});

test("shadowsocks: a method sing-box does not have, or an unknown plugin, is a parse error", () => {
  // `chacha20-poly1305` is a cipher other clients take; sing-box's enum spells
  // the one it has `chacha20-ietf-poly1305`, so this link is not this core's.
  const nearMiss = Buffer.from("chacha20-poly1305:fixture-ss-password").toString("base64url");
  assert.equal(skipOf(`ss://${nearMiss}@192.0.2.13:8391`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("ss://bm90LWJhc2U2NA@192.0.2.13:8391").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("ss://YWVzLTI1Ni1nY206cGFzcw@192.0.2.13:8391?plugin=fixture-plugin").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("ss://YWVzLTI1Ni1nY206cGFzcw@192.0.2.13:99999").reason, SKIP_REASONS.PARSE_ERROR);
});

test("scheme spellings reach the parsers they name", () => {
  for (const scheme of ["vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "hysteria", "tuic", "anytls", "http", "https", "socks5", "socks5h", "socks"]) {
    assert.ok(SUPPORTED_SCHEMES.includes(scheme), `${scheme} must be a supported scheme`);
  }
  assert.ok(!SUPPORTED_SCHEMES.includes("ssr"));
  assert.ok(!SUPPORTED_SCHEMES.includes("socks4"));
  assert.deepEqual(Object.values(MIN_CORE_VERSION), ["1.4.0", "1.8.0", "1.12.0"]);
  assert.ok(FIELDS_NOT_EMITTED.length > 0);
});

// ------------------------------------------------------------ hysteria2 / hy2

test("hysteria2: password, salamander obfs and the TLS block land in their fields", () => {
  const hy2 = node("fixture-hy2");
  assert.equal(hy2.type, "hysteria2");
  assert.equal(hy2.server, "192.0.2.20");
  assert.equal(hy2.server_port, 8443);
  assert.equal(hy2.password, "fixture-hy2-pass");
  assert.deepEqual(hy2.obfs, { type: "salamander", password: "fixture-obfs" });
  assert.deepEqual(hy2.tls, { enabled: true, server_name: "hy2.example.invalid", insecure: true });
});

test("hy2:// is the same node as hysteria2://", () => {
  const short = node("fixture-hy2-alias");
  assert.deepEqual(short, node("fixture-hy2"));
  assert.equal(short.type, "hysteria2");
  assert.equal(short.password, "fixture-hy2-pass");
  assert.equal(short.server_port, 8443);
  assert.equal(short.obfs.password, "fixture-obfs");
});

test("hysteria2: port hopping becomes server_ports, and a bare hop interval is seconds", () => {
  const hopping = node("fixture-hy2-hop");
  assert.deepEqual(hopping.server_ports, ["2000:3000", "4000"]);
  assert.equal(hopping.hop_interval, "30s");
  assert.equal(hopping.server, "192.0.2.21");
  const withUnit = parseProtocolLine(
    "hysteria2://fixture-hy2-pass@192.0.2.21:8443?sni=hy2b.example.invalid&mport=2000-3000&hop-interval=45s",
  );
  assert.equal(withUnit.ok, true);
  assert.deepEqual(withUnit.outbound.server_ports, ["2000:3000"]);
  assert.equal(withUnit.outbound.hop_interval, "45s");
});

test("hysteria2: a parameter this module cannot map, or a missing obfs password, is a parse error", () => {
  assert.equal(skipOf(corpusLines[31]).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(
    skipOf("hysteria2://fixture-hy2-pass@192.0.2.20:8443?sni=hy2.example.invalid&obfs=salamander").reason,
    SKIP_REASONS.PARSE_ERROR,
  );
  assert.equal(
    skipOf("hysteria2://fixture-hy2-pass@192.0.2.20:8443?sni=hy2.example.invalid&obfs=gecko&obfs-password=x").reason,
    SKIP_REASONS.PARSE_ERROR,
  );
  assert.equal(skipOf("hysteria2://fixture-hy2-pass@192.0.2.20:8443?sni=hy2.example.invalid&up=abc").reason, SKIP_REASONS.PARSE_ERROR);
});

// --------------------------------------------------------------- hysteria 1

test("hysteria: auth_str, the bandwidth pair and the peer name land in their fields", () => {
  const hysteria = node("fixture-hysteria");
  assert.equal(hysteria.type, "hysteria");
  assert.equal(hysteria.server, "192.0.2.30");
  assert.equal(hysteria.server_port, 8443);
  assert.equal(hysteria.auth_str, "fixture-hysteria-auth");
  assert.equal(hysteria.up_mbps, 100);
  assert.equal(hysteria.down_mbps, 100);
  assert.deepEqual(hysteria.tls, { enabled: true, server_name: "hysteria.example.invalid", insecure: true });
});

test("hysteria: obfs is left alone rather than mapped onto an ambiguous field", () => {
  const withObfs = "hysteria://192.0.2.30:8443?protocol=udp&auth=fixture-auth&peer=h.example.invalid&obfs=xplus&obfsParam=fixture-obfs";
  assert.equal(skipOf(withObfs).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(withObfs).detail.includes("obfs"), true);
});

// --------------------------------------------------------------------- tuic

test("tuic: uuid, password, congestion control, relay mode and TLS are all set", () => {
  const tuic = node("fixture-tuic");
  assert.equal(tuic.type, "tuic");
  assert.equal(tuic.server, "192.0.2.40");
  assert.equal(tuic.server_port, 443);
  assert.equal(tuic.uuid, "11111111-1111-4111-8111-111111111111");
  assert.equal(tuic.password, "fixture-tuic-pass");
  assert.equal(tuic.congestion_control, "bbr");
  assert.equal(tuic.udp_relay_mode, "quic");
  assert.equal(tuic.heartbeat, "10s");
  assert.deepEqual(tuic.tls, {
    enabled: true,
    server_name: "tuic.example.invalid",
    insecure: true,
    alpn: ["h3"],
    utls: { enabled: true, fingerprint: "chrome" },
  });
});

test("tuic: a value sing-box does not list, or a link without a password, is a parse error", () => {
  const base = "tuic://11111111-1111-4111-8111-111111111111:fixture-tuic-pass@192.0.2.40:443?sni=tuic.example.invalid";
  assert.equal(skipOf(`${base}&congestion_control=fixture`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&udp_relay_mode=fixture`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&heartbeat=soon`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf(`${base}&disable_sni=1`).reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(
    skipOf("tuic://11111111-1111-4111-8111-111111111111@192.0.2.40:443?sni=tuic.example.invalid").reason,
    SKIP_REASONS.PARSE_ERROR,
  );
});

// ------------------------------------------------------------------ anytls

test("anytls: password and its TLS block land in their fields", () => {
  const anytls = node("fixture-anytls");
  assert.equal(anytls.type, "anytls");
  assert.equal(anytls.server, "192.0.2.50");
  assert.equal(anytls.server_port, 443);
  assert.equal(anytls.password, "fixture-anytls-pass");
  assert.deepEqual(anytls.tls, {
    enabled: true,
    server_name: "anytls.example.invalid",
    insecure: true,
    utls: { enabled: true, fingerprint: "chrome" },
  });
});

test("anytls: its session fields are read when the link spells them out", () => {
  const result = parseProtocolLine(
    "anytls://fixture-anytls-pass@192.0.2.50:443?sni=anytls.example.invalid&idle_session_timeout=45s&min_idle_session=3",
  );
  assert.equal(result.ok, true);
  assert.equal(result.outbound.idle_session_timeout, "45s");
  assert.equal(result.outbound.min_idle_session, 3);
  assert.equal(skipOf("anytls://fixture-anytls-pass@192.0.2.50:443?idle_session_timeout=soon").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("anytls://fixture-anytls-pass@192.0.2.50:443?client_metadata=x").reason, SKIP_REASONS.PARSE_ERROR);
});

// ------------------------------------------------------------- http / https

test("http: credentials go in their own fields and no tls block is added", () => {
  const http = node("fixture-http");
  assert.equal(http.type, "http");
  assert.equal(http.server, "198.51.100.50");
  assert.equal(http.server_port, 8080);
  assert.equal(http.username, "fixture-http-user");
  assert.equal(http.password, "fixture-http-pass");
  assert.equal("tls" in http, false);
  assert.deepEqual(Object.keys(http).sort(), ["password", "server", "server_port", "type", "username"]);
});

test("https: the host becomes the server_name its certificate is checked against", () => {
  const https = node("fixture-https");
  assert.equal(https.type, "http");
  assert.equal(https.server, "198.51.100.51");
  assert.equal(https.server_port, 8443);
  assert.equal(https.username, "fixture-https-user");
  assert.deepEqual(https.tls, { enabled: true, server_name: "198.51.100.51" });
  const secure = parseProtocolLine("https://h.example.invalid");
  assert.equal(secure.outbound.server_port, 443, "https without a port is the scheme default");
  const plain = parseProtocolLine("http://h.example.invalid");
  assert.equal(plain.outbound.server_port, 80, "http without a port is the scheme default");
});

// -------------------------------------------------------------------- socks

test("socks5 and socks5h build the same socks 5 outbound, and socks:// is socks 5 too", () => {
  const five = node("fixture-socks5");
  const fiveH = node("fixture-socks5h");
  assert.equal(five.type, "socks");
  assert.equal(five.version, "5");
  assert.equal(five.username, "fixture-socks-user");
  assert.equal(five.password, "fixture-socks-pass");
  assert.deepEqual({ ...fiveH, server: five.server, server_port: five.server_port }, five);
  // The `h` spelling asks the proxy to resolve names; sing-box has no field for
  // that choice, so both spellings stay field-identical instead of one carrying
  // a field the core does not have.
  assert.equal("domain_strategy" in fiveH, false);
  assert.equal("resolve" in fiveH, false);
  const bare = node("fixture-socks");
  assert.equal(bare.version, "5");
  assert.equal(bare.server, "198.51.100.62");
  assert.equal("username" in bare, false);
});

// ------------------------------------------- bare `host:port[:user:pass]`

test("bare host:port is an http outbound without credentials", () => {
  assert.deepEqual(byServer("198.51.100.70"), { type: "http", server: "198.51.100.70", server_port: 8080 });
});

test("bare host:port:user:pass is an http outbound with them", () => {
  assert.deepEqual(byServer("198.51.100.71"), {
    type: "http",
    server: "198.51.100.71",
    server_port: 8080,
    username: "fixture-bare-user",
    password: "fixture-bare-pass",
  });
});

test("the bare form takes IPv4 only, and refuses a password with a colon", () => {
  const colonPassword = skipOf(corpusLines[32]);
  assert.equal(colonPassword.reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(colonPassword.detail.includes("colon"), true);
  assert.equal(skipOf(corpusLines[33]).reason, SKIP_REASONS.PARSE_ERROR, "a domain is not IPv4");
  assert.equal(skipOf("2001:db8::1:8080").reason, SKIP_REASONS.PARSE_ERROR, "IPv6 needs a URI");
  assert.equal(skipOf("198.51.100.74:0").reason, SKIP_REASONS.PARSE_ERROR, "port 0 is not a port");
});

// ------------------------------------------------- classify, never guess

test("ssr:// and an unknown scheme are unsupported-scheme, and neither becomes an outbound", () => {
  const ssr = skipOf(corpusLines[26]);
  assert.equal(ssr.reason, SKIP_REASONS.UNSUPPORTED_SCHEME);
  assert.equal(ssr.scheme, "ssr");
  assert.equal(ssr.outbound, undefined, "ssr must never be read as shadowsocks");
  const unknown = skipOf(corpusLines[27]);
  assert.equal(unknown.reason, SKIP_REASONS.UNSUPPORTED_SCHEME);
  assert.equal(unknown.scheme, "quantum");
  assert.equal(skipOf("socks4://198.51.100.1:1080").reason, SKIP_REASONS.UNSUPPORTED_SCHEME);
  assert.equal(skipOf("socks4a://198.51.100.1:1080").reason, SKIP_REASONS.UNSUPPORTED_SCHEME);
  assert.equal(parsed.skipped.filter((skip) => skip.reason === SKIP_REASONS.UNSUPPORTED_SCHEME).length, 2);
  assert.equal(parsed.outbounds.some((entry) => entry.outbound.server.includes("ssr")), false);
});

test("malformed lines come back as parse errors instead of throwing", () => {
  for (const index of [28, 29, 30, 31, 32, 33]) {
    assert.equal(skipOf(corpusLines[index]).reason, SKIP_REASONS.PARSE_ERROR, corpusLines[index]);
  }
  assert.equal(skipOf("this is not a node").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("198.51.100.73").reason, SKIP_REASONS.PARSE_ERROR);
  assert.equal(skipOf("vless://11111111-1111-4111-8111-111111111111@198.51.100.80:0?security=none").reason, SKIP_REASONS.PARSE_ERROR);
  const mixed = parseSubscription(`${corpusLines[29]}\n${corpusLines[24]}\n${corpusLines[30]}`);
  assert.equal(mixed.counts.input, 3, "a malformed line does not stop the batch");
  assert.equal(mixed.counts.outbound, 1);
  assert.equal(mixed.counts.skipped, 2);
  assert.equal(mixed.counts.input, mixed.counts.outbound + mixed.counts.skipped);
});

test("a core that is too old skips the protocols it does not have yet", () => {
  const older = parseSubscription(corpus, { coreVersion: "1.11.0" });
  assert.equal(older.counts.input, parsed.counts.input);
  assert.equal(older.counts.outbound + older.counts.skipped, older.counts.input, "N === M + X still holds");
  assert.deepEqual(
    older.skipped.filter((skip) => skip.reason === SKIP_REASONS.CORE_TOO_OLD).map((skip) => skip.scheme),
    ["anytls"],
  );
  assert.equal(older.counts.byReason[SKIP_REASONS.CORE_TOO_OLD], 1);
  assert.equal(older.counts.outbound, parsed.counts.outbound - 1, "only the anytls line moved");
  assert.deepEqual(
    older.outbounds.map((entry) => entry.outbound),
    parsed.outbounds.filter((entry) => entry.protocol !== "anytls").map((entry) => entry.outbound),
  );

  const justNewEnough = parseSubscription(corpus, { coreVersion: "1.12.0" });
  assert.equal(justNewEnough.counts.byReason[SKIP_REASONS.CORE_TOO_OLD], 0);
  const newest = parseSubscription(corpus, { coreVersion: "1.14.3" });
  assert.deepEqual(newest.counts, { ...parsed.counts, ignored: newest.counts.ignored });

  const anytlsLink = "anytls://fixture-anytls-pass@192.0.2.50:443?sni=anytls.example.invalid";
  assert.equal(parseProtocolLine(anytlsLink, { coreVersion: "1.11.9" }).reason, SKIP_REASONS.CORE_TOO_OLD);
  assert.equal(parseProtocolLine(anytlsLink, { coreVersion: "1.12.0" }).ok, true);
  assert.equal(
    parseProtocolLine("tuic://11111111-1111-4111-8111-111111111111:p@192.0.2.40:443?sni=t.example.invalid", { coreVersion: "1.3.9" }).reason,
    SKIP_REASONS.CORE_TOO_OLD,
  );
  assert.equal(
    parseProtocolLine("hy2://fixture-hy2-pass@192.0.2.20:8443?sni=hy2.example.invalid", { coreVersion: "1.7.0" }).reason,
    SKIP_REASONS.CORE_TOO_OLD,
  );
  // vmess, vless, trojan, ss, http and socks predate every gate, so an old core
  // is never offered a core-too-old for them.
  assert.equal(parseProtocolLine(corpusLines[0], { coreVersion: "1.0.0" }).ok, true);
  assert.equal(parseProtocolLine(corpusLines[9], { coreVersion: "1.0.0" }).ok, true);
});

test("no outbound carries a field this module decided not to emit", () => {
  const banned = new Map();
  for (const entry of FIELDS_NOT_EMITTED) {
    const [protocol, field] = entry.split(".");
    if (!banned.has(protocol)) banned.set(protocol, new Set());
    banned.get(protocol).add(field);
  }
  const keysOf = (value, into = new Set()) => {
    if (value === null || typeof value !== "object") return into;
    for (const [key, nested] of Object.entries(value)) {
      into.add(key);
      keysOf(nested, into);
    }
    return into;
  };
  for (const { outbound } of parsed.outbounds) {
    const bannedForType = banned.get(outbound.type);
    if (bannedForType === undefined) continue;
    for (const key of keysOf(outbound)) {
      assert.equal(bannedForType.has(key), false, `${outbound.type} must not carry ${key}`);
    }
  }
});

// ------------------------------------------------- certificate pins (pinSHA256)

// The pin a real subscription carries is the SHA-256 of the server's
// CERTIFICATE, not of its public key: measured against the live node, the pin
// (bc53205c...) does not equal the key the server presents (51c25870...), and
// mapping it onto certificate_public_key_sha256 made every pinned node fail at
// handshake with "unrecognized remote public key". sing-box only grew a
// client-side certificate hash in 1.15.0, so on 1.14.3 the pin cannot be
// carried, and a node whose SNI is camouflage cannot be authenticated without
// it. Refusing loudly is therefore the default, and using it unauthenticated
// has to be asked for.
const PIN = "bc53205c6e9d025262e60890d9f342480444ca5b753eb1009e15cfc7ee211399";
const PIN_B64 = "vFMgXG6dAlJi5giQ2fNCSAREylt1PrEAnhXPx+4hE5k=";
const pinned = (extra = "") =>
  `hysteria2://pw@node.invalid:443?insecure=false&sni=www.apple.com&pinSHA256=${PIN}${extra}`;

test("hysteria2: a pin on an older core is refused, naming what would carry it", () => {
  const result = parseProtocolLine(pinned(), { coreVersion: "1.14.3" });
  assert.equal(result.ok, false);
  assert.equal(result.reason, SKIP_REASONS.CORE_TOO_OLD);
  assert.match(result.detail, /1\.15\.0/);
});

test("hysteria2: the hex pin is converted to the base64 a certificate hash needs", () => {
  const result = parseProtocolLine(pinned(), { coreVersion: "1.15.0" });
  assert.equal(result.ok, true);
  assert.deepEqual(result.outbound.tls.certificate_sha256, [PIN_B64]);
});

test("hysteria2: a base64 pin is accepted as written", () => {
  const line = `hysteria2://pw@node.invalid:443?sni=www.apple.com&pinSHA256=${encodeURIComponent(PIN_B64)}`;
  const result = parseProtocolLine(line, { coreVersion: "1.15.0" });
  assert.equal(result.ok, true);
  assert.deepEqual(result.outbound.tls.certificate_sha256, [PIN_B64]);
});

test("hysteria2: a pin that is neither hex nor base64 is a parse error", () => {
  const result = parseProtocolLine("hysteria2://pw@node.invalid:443?pinSHA256=not-a-hash", {
    coreVersion: "1.15.0",
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, SKIP_REASONS.PARSE_ERROR);
});

test("hysteria2: using a pinned node without its pin needs the explicit opt-in", () => {
  const strict = parseProtocolLine(pinned(), { coreVersion: "1.14.3" });
  assert.equal(strict.ok, false, "the pin is not dropped unless asked");

  const allowed = parseProtocolLine(pinned(), { coreVersion: "1.14.3", allowUnpinned: true });
  assert.equal(allowed.ok, true);
  assert.equal(allowed.unpinned, true, "the caller can count what it gave up");
  assert.equal(allowed.outbound.tls.certificate_sha256, undefined);
  assert.equal(allowed.outbound.tls.insecure, true, "an unverifiable node must say so to the core");
});

test("hysteria2: an opt-in does not apply to a core that can carry the pin", () => {
  const result = parseProtocolLine(pinned(), { coreVersion: "1.15.0", allowUnpinned: true });
  assert.equal(result.ok, true);
  assert.equal(result.unpinned, undefined, "the pin is used when the core can hold it");
  assert.deepEqual(result.outbound.tls.certificate_sha256, [PIN_B64]);
});

test("vless: a leftover QUIC-only knob is counted, not refused", () => {
  const line =
    "vless://11111111-1111-4111-8111-111111111111@example.invalid:443?type=ws&encryption=none&quicSecurity=none&security=tls";
  const result = parseProtocolLine(line, { coreVersion: "1.14.3" });
  assert.equal(result.ok, true, "a real exporter leaves this key on a non-QUIC link");
  assert.deepEqual(result.ignored, ["quicSecurity"]);
});

test("a subscription reports what it ignored and what it left unauthenticated", () => {
  const body = [
    "vless://11111111-1111-4111-8111-111111111111@example.invalid:443?type=ws&quicSecurity=none",
    pinned(),
    "ssr://unsupported",
  ].join("\n");
  const result = parseSubscription(body, { coreVersion: "1.14.3", allowUnpinned: true });
  assert.deepEqual(result.counts.ignoredParams, { quicSecurity: 1 });
  assert.equal(result.counts.unpinned, 1);
  assert.equal(result.counts.input, result.counts.outbound + result.counts.skipped);
});
