import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { deflateRawSync, gzipSync } from "node:zlib";
import {
  CoreError,
  DEFAULT_CONNECT_TIMEOUT,
  LOOPBACK,
  binaryName,
  buildConfig,
  checkConfig,
  compareVersions,
  coreCount,
  downloadAsset,
  extractArchiveEntry,
  findOnPath,
  healthy,
  lastError,
  managedBinaryPath,
  normalizeVersion,
  parseVersionOutput,
  pickReleaseAsset,
  portStates,
  provisionBinary,
  readCoreVersion,
  startCore,
  stopAll,
} from "./core.mjs";
import { parseSubscription } from "./protocols.mjs";

// The real core this pool is built for, at the path it was handed for this task
// or wherever ZEN_FREE_SING_BOX points. It is not vendored: the tests that need
// a process skip cleanly when it is not on this machine, and everything that
// does not need one runs either way.
const REAL_BINARY = process.env.ZEN_FREE_SING_BOX ?? "G:/tmp/sing-box.exe";
const hasRealBinary = fs.existsSync(REAL_BINARY);
const realTest = hasRealBinary ? test : test.skip;
const UUID = "11111111-1111-4111-8111-111111111111";
const REAL_VERSION_OUTPUT = `sing-box version 1.14.3

Environment: go1.26.8 windows/amd64
Tags: with_gvisor,with_quic,with_dhcp
Revision: 7054cac5124465ffdb145870d7c01885566711b1
CGO: disabled
`;

// --------------------------------------------------------------- fixtures

// One node per index, all pointing at TEST-NET-2: buildConfig never dials, so
// the address only has to be a valid one.
function nodes(count) {
  return Array.from({ length: count }, (_, index) => ({
    protocol: "vless",
    name: `node-${index}`,
    outbound: { type: "vless", server: `198.51.100.${10 + index}`, server_port: 443, uuid: UUID },
  }));
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object") return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

function sandbox(label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `zen-free-${label}-`));
  return {
    dir,
    path: (...parts) => path.join(dir, ...parts),
    write(name, data) {
      const target = path.join(dir, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, data);
      return target;
    },
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

// Ports are arithmetic in buildConfig, so the tests pick a base whose whole run
// is free and hand it over: the same scan the supervisor refuses to do.
async function freeBase(count, host = LOOPBACK) {
  const start = 30_000 + ((process.pid % 400) * 4);
  for (let base = start; base < 39_000; base += 1) {
    const states = await portStates(
      Array.from({ length: count }, (_, index) => base + index),
      { host },
    );
    if (states.every((state) => state === "free")) return base;
  }
  throw new Error("no free contiguous port base for the test");
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, LOOPBACK, () => resolve(server.address().port));
  });
}

function close(server) {
  // server.close() only completes once every connection has ended, and a
  // keep-alive socket left behind by a proxied request or by the core itself
  // never ends on its own. Without this the teardown waits forever: the test's
  // assertions all pass and the file still never exits, which is why this only
  // ever showed up as a hang on the Node baseline.
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(() => resolve()));
}

function occupied(port) {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host: LOOPBACK, exclusive: true }, () => resolve(server));
  });
}

// What curl does through an HTTP proxy, without depending on curl: an
// absolute-form request on the inbound port.
function proxyGet(port, target = "http://example.invalid/x", timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: LOOPBACK, port });
    let received = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`nothing came back from the proxy on ${port}`));
    }, timeoutMs);
    socket.on("connect", () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n`);
    });
    socket.on("data", (chunk) => {
      received += chunk;
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      resolve(received);
    });
  });
}

async function eventually(check, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

// ------------------------------------------------- archive builders (tests)

function crc32(buffer) {
  let crc = 0xffff_ffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb8_8320 & -(crc & 1));
  }
  return (crc ^ 0xffff_ffff) >>> 0;
}

// A minimal writer for the two shapes the reader has to read. `deflate` picks
// the compression method per entry, so both paths are exercised.
function makeZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const raw = Buffer.from(entry.data);
    const body = entry.deflate === true ? deflateRawSync(raw) : raw;
    const method = entry.deflate === true ? 8 : 0;
    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x0403_4b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc32(raw), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    locals.push(local, body);

    const header = Buffer.alloc(46 + name.length);
    header.writeUInt32LE(0x0201_4b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(0, 12);
    header.writeUInt16LE(0, 14);
    header.writeUInt32LE(crc32(raw), 16);
    header.writeUInt32LE(body.length, 20);
    header.writeUInt32LE(raw.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt16LE(0, 30);
    header.writeUInt16LE(0, 32);
    header.writeUInt16LE(0, 34);
    header.writeUInt16LE(0, 36);
    header.writeUInt32LE(0, 38);
    header.writeUInt32LE(offset, 42);
    name.copy(header, 46);
    central.push(header);
    offset += local.length + body.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x0605_4b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

function makeTarGz(entries) {
  const blocks = [];
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const raw = Buffer.from(entry.data);
    const header = Buffer.alloc(512);
    name.copy(header, 0);
    header.write("0000644\0", 100, 8);
    header.write("0000000\0", 108, 8);
    header.write("0000000\0", 116, 8);
    header.write(`${raw.length.toString(8).padStart(11, "0")}\0`, 124, 12);
    header.write("00000000000\0", 136, 12);
    header.fill(0x20, 148, 156);
    header.write("0", 156, 1);
    header.write("ustar\0", 257, 6);
    header.write("00", 263, 2);
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);
    const padding = Buffer.alloc((512 - (raw.length % 512)) % 512);
    blocks.push(header, raw, padding);
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

const FAKE_BINARY = Buffer.concat([Buffer.from("MZ fake sing-box 1.14.3 "), Buffer.alloc(4096, 7)]);

// --------------------------------------------------------- version reading

test("the release line a real sing-box prints is read as its version", () => {
  assert.equal(parseVersionOutput(REAL_VERSION_OUTPUT), "1.14.3");
  assert.equal(parseVersionOutput("sing-box version 1.15.0-beta.5\n"), "1.15.0");
  assert.equal(parseVersionOutput("1.12.0"), "1.12.0");
  assert.equal(parseVersionOutput("not a version"), null);
  assert.equal(normalizeVersion("1.9"), "1.9.0");
  assert.equal(normalizeVersion("v1.14.3"), null);
});

test("1.9 sorts below 1.10, and the gates read as versions, not strings", () => {
  assert.equal(compareVersions("1.9.0", "1.10.0"), -1);
  assert.equal(compareVersions("1.14.3", "1.14.3"), 0);
  assert.equal(compareVersions("1.12.0", "1.11.9"), 1);
  assert.equal(compareVersions("nope", "1.11.0"), null);
});

realTest("the real binary names its own version", { timeout: 60_000 }, () => {
  assert.match(readCoreVersion(REAL_BINARY), /^\d+\.\d+\.\d+$/);
});

// ------------------------------------------------------------ the config

test("one inbound, outbound and rule per node, whatever maxNodes says", () => {
  const built = buildConfig(nodes(5), { coreVersion: "1.14.3", portBase: 28_100, maxNodes: 300 });
  assert.equal(built.counts.inbound, 5, "the actual node count, not maxNodes");
  assert.equal(built.counts.outbound, 6, "one outbound per node plus direct");
  assert.equal(built.config.route.rules.length, 5);
  assert.deepEqual(built.ports, [28_100, 28_101, 28_102, 28_103, 28_104]);
  assert.deepEqual(built.config.inbounds.map((inbound) => inbound.tag), ["in-0", "in-1", "in-2", "in-3", "in-4"]);
  assert.deepEqual(built.config.outbounds.map((outbound) => outbound.tag), [
    "out-0",
    "out-1",
    "out-2",
    "out-3",
    "out-4",
    "direct",
  ]);
});

test("every inbound listens on loopback only", () => {
  const built = buildConfig(nodes(4), { coreVersion: "1.14.3", portBase: 28_200 });
  const loopback = (address) => address === "127.0.0.1" || address === "::1" || /^127\./.test(address);
  for (const inbound of built.config.inbounds) {
    assert.equal(inbound.type, "http");
    assert.equal(typeof inbound.listen, "string", `${inbound.tag} must name its listen address`);
    assert.ok(loopback(inbound.listen), `${inbound.tag} binds ${inbound.listen}, which is not loopback`);
    assert.ok(Number.isInteger(inbound.listen_port), `${inbound.tag} has no port`);
  }
  assert.deepEqual([...new Set(built.config.inbounds.map((inbound) => inbound.listen))], [LOOPBACK]);
  assert.equal(JSON.stringify(built.config).includes("0.0.0.0"), false, "no address in this config is a wildcard");
});

test("each rule routes its own inbound to an outbound that exists", () => {
  const built = buildConfig(nodes(3), { coreVersion: "1.14.3", portBase: 28_300 });
  const inboundTags = new Set(built.config.inbounds.map((inbound) => inbound.tag));
  const outboundTags = new Set(built.config.outbounds.map((outbound) => outbound.tag));
  const allTags = [...inboundTags, ...outboundTags];
  assert.equal(new Set(allTags).size, allTags.length, "tags are unique");
  assert.equal(built.config.route.rules.length, 3);
  for (const [index, rule] of built.config.route.rules.entries()) {
    assert.deepEqual(rule.inbound, [`in-${index}`]);
    assert.ok(outboundTags.has(rule.outbound), `rule ${index} names outbound ${rule.outbound}, which is not in the config`);
    assert.equal(rule.outbound, `out-${index}`);
  }
});

test("traffic that matches no rule goes out direct", () => {
  const built = buildConfig(nodes(2), { coreVersion: "1.14.3", portBase: 28_400 });
  assert.equal(built.config.route.final, "direct");
  assert.deepEqual(built.config.outbounds.at(-1), {
    type: "direct",
    tag: "direct",
    connect_timeout: DEFAULT_CONNECT_TIMEOUT,
  });
});

test("every outbound carries a connect_timeout, because the 5s default dial failed reachable nodes", () => {
  const built = buildConfig(nodes(2), { coreVersion: "1.14.3", portBase: 28_410 });
  for (const outbound of built.config.outbounds) {
    assert.match(outbound.connect_timeout ?? "", /^\d+(?:\.\d+)?(?:ms|s|m|h|d)$/, `${outbound.tag} has no connect_timeout`);
  }
  assert.equal(built.config.outbounds[0].connect_timeout, DEFAULT_CONNECT_TIMEOUT);
  const custom = buildConfig(nodes(1), { coreVersion: "1.14.3", portBase: 28_420, connectTimeout: "7s" });
  assert.equal(custom.config.outbounds[0].connect_timeout, "7s");
  assert.equal(custom.config.outbounds.at(-1).connect_timeout, "7s", "direct is dialled too");
});

test("tags are added to copies: the caller's nodes come back untouched", () => {
  const input = deepFreeze(nodes(3));
  const first = buildConfig(input, { coreVersion: "1.14.3", portBase: 28_430 });
  const second = buildConfig(input, { coreVersion: "1.14.3", portBase: 28_430 });
  assert.deepEqual(first, second, "the same input must give the same config");
  for (const node of input) {
    assert.equal("tag" in node.outbound, false, "a tag was written into the caller's outbound");
    assert.equal("connect_timeout" in node.outbound, false, "a timeout was written into the caller's outbound");
  }
  assert.notEqual(first.config.outbounds[0], input[0].outbound, "the outbound must be a copy");
});

test("the config follows the core: a rule action from 1.11, the new DNS form from 1.12", () => {
  const ten = buildConfig(nodes(1), { coreVersion: "1.10.0", portBase: 28_440 }).config;
  assert.equal("action" in ten.route.rules[0], false, "1.10 has no rule actions");
  assert.equal("default_domain_resolver" in ten.route, false);
  assert.equal("type" in ten.dns.servers[0], false, "1.10 reads the legacy dns server form");
  assert.equal(ten.dns.servers[0].address, "local");
  assert.equal(ten.dns.final, "local");
  assert.ok(ten.dns.servers[1].address.startsWith("https://"), "the DoH server keeps its legacy address");

  const eleven = buildConfig(nodes(1), { coreVersion: "1.11.0", portBase: 28_450 }).config;
  assert.equal(eleven.route.rules[0].action, "route");
  assert.equal(eleven.route.rules[0].outbound, "out-0");
  assert.equal("default_domain_resolver" in eleven.route, false);
  assert.equal("type" in eleven.dns.servers[0], false);

  const twelve = buildConfig(nodes(1), { coreVersion: "1.12.0", portBase: 28_460 }).config;
  assert.equal(twelve.route.rules[0].action, "route");
  assert.deepEqual(twelve.route.default_domain_resolver, { server: "local" });
  assert.equal(twelve.dns.servers[0].type, "local");
  assert.equal(twelve.dns.servers[1].type, "https");
  assert.equal(twelve.dns.servers[1].server, "1.1.1.1");
  assert.equal("address" in twelve.dns.servers[0], false, "1.12 reads the new dns server form");
  assert.equal(twelve.dns.final, "local");

  const newest = buildConfig(nodes(1), { coreVersion: "1.14.3", portBase: 28_470 }).config;
  assert.deepEqual(newest.dns, twelve.dns);
  assert.equal(newest.route.rules[0].action, "route");
  assert.equal(newest.log.level, "warn");
});

test("a node whose protocol the core is too old for is counted, not emitted", () => {
  const input = [
    ...nodes(1),
    { protocol: "anytls", name: "anytls-1", outbound: { type: "anytls", server: "198.51.100.99", server_port: 443, password: "pw" } },
  ];
  const old = buildConfig(input, { coreVersion: "1.11.0", portBase: 28_480 });
  assert.equal(old.counts.byReason["core-too-old"], 1);
  assert.equal(old.counts.inbound, 1);
  assert.equal(old.config.outbounds.some((outbound) => outbound.type === "anytls"), false);
  const skipped = old.skipped.find((entry) => entry.reason === "core-too-old");
  assert.match(skipped.detail, /1\.12\.0/, "the skip must name the release the protocol needs");
  assert.equal(skipped.scheme, "anytls");
  assert.equal(old.config.route.rules[0].outbound, "out-0", "the node that stayed keeps tag 0");
  assert.deepEqual(old.ports, [28_480]);
  assert.equal(buildConfig(input, { coreVersion: "1.12.0", portBase: 28_490 }).counts.inbound, 2);
});

test("a portBase whose run would pass 65535 is refused before anything binds", () => {
  assert.throws(
    () => buildConfig(nodes(3), { coreVersion: "1.14.3", portBase: 65_534 }),
    (error) => error instanceof CoreError && error.code === "CORE_PORT_RANGE" && /65535/.test(error.message),
  );
  assert.deepEqual(buildConfig(nodes(3), { coreVersion: "1.14.3", portBase: 65_533 }).ports, [65_533, 65_534, 65_535]);
});

test("bad options are refused instead of being written into the config", () => {
  assert.throws(() => buildConfig(nodes(1), { portBase: 28_100 }), (error) => error.code === "CORE_VERSION_REQUIRED");
  assert.throws(() => buildConfig(nodes(1), { coreVersion: "1.14.3", portBase: 0 }), (error) => error.code === "CORE_PORT_RANGE");
  assert.throws(() => buildConfig(nodes(1), { coreVersion: "1.14.3", connectTimeout: "20" }), (error) => error.code === "CORE_OPTIONS");
  assert.throws(() => buildConfig(nodes(1), { coreVersion: "1.14.3", logLevel: "loud" }), (error) => error.code === "CORE_OPTIONS");
  assert.throws(() => buildConfig(null, { coreVersion: "1.14.3" }), (error) => error.code === "CORE_NODE_INVALID");
  assert.throws(() => buildConfig([{ name: "no outbound" }], { coreVersion: "1.14.3" }), (error) => error.code === "CORE_NODE_INVALID");
});

test("a parseSubscription result can be handed straight in, skips and all", () => {
  const parsed = parseSubscription(["socks5://127.0.0.1:1080#one", "ssr://not-read-here", "socks5://127.0.0.1:1081#two"].join("\n"));
  assert.equal(parsed.counts.outbound, 2);
  const built = buildConfig(parsed, { coreVersion: "1.14.3", portBase: 28_500 });
  assert.equal(built.counts.inbound, 2);
  assert.equal(built.counts.input, 3);
  assert.equal(built.counts.byReason["unsupported-scheme"], 1, "parse skips are carried into the config's counts");
  assert.equal(built.config.outbounds[0].type, "socks");
  assert.equal(built.config.outbounds[0].tag, "out-0");
});

// ------------------------------------------------------------- sing-box check

realTest("check accepts the config this module generates", { timeout: 60_000 }, async (t) => {
  const box = sandbox("check");
  t.after(() => box.cleanup());
  const built = buildConfig(nodes(2), { coreVersion: readCoreVersion(REAL_BINARY), portBase: await freeBase(2), logLevel: "info" });
  const configPath = box.write("config.json", JSON.stringify(built.config));
  const result = checkConfig(REAL_BINARY, configPath);
  assert.equal(result.ok, true, result.detail);
  assert.equal(result.status, 0);
  assert.match(result.command, /check -c /);
});

realTest("check refuses a config sing-box cannot read, and says so in its own words", { timeout: 60_000 }, async (t) => {
  const box = sandbox("check-bad");
  t.after(() => box.cleanup());
  const built = buildConfig(nodes(1), { coreVersion: readCoreVersion(REAL_BINARY), portBase: await freeBase(1) });
  const broken = { ...built.config, bogus: 1 };
  const result = checkConfig(REAL_BINARY, box.write("config.json", JSON.stringify(broken)));
  assert.equal(result.ok, false);
  assert.notEqual(result.status, 0);
  assert.match(result.detail, /unknown field "bogus"/, "sing-box's own message must reach the caller");
});

// -------------------------------------------------------------------- ports

test("a bound port reads busy and a free one reads free", async (t) => {
  const base = await freeBase(2);
  const server = await occupied(base);
  t.after(() => close(server));
  assert.deepEqual(await portStates([base, base + 1]), ["busy", "free"]);
});

// ------------------------------------------------------- binary provisioning

test("core.binary is used as given, and a path that is not a file is refused", async (t) => {
  const box = sandbox("binary");
  t.after(() => box.cleanup());
  const fake = box.write(binaryName(), "not really sing-box");
  const chosen = await provisionBinary({ binary: fake, stateDir: box.path("state") });
  assert.equal(chosen.path, fake);
  assert.equal(chosen.source, "option");
  await assert.rejects(
    () => provisionBinary({ binary: box.path("missing", binaryName()), stateDir: box.path("state") }),
    (error) => error.code === "CORE_BINARY_MISSING" && /not a file/.test(error.message),
  );
});

test("PATH is searched, then the managed copy under the state dir", async (t) => {
  const box = sandbox("path");
  t.after(() => box.cleanup());
  const onPath = box.write(path.join("bin", binaryName()), "on path");
  const found = await provisionBinary({ stateDir: box.path("state"), env: { PATH: box.path("bin") } });
  assert.equal(found.path, onPath);
  assert.equal(found.source, "path");

  const managed = box.write(path.join("state", "bin", binaryName()), "managed");
  const reused = await provisionBinary({ stateDir: box.path("state"), env: { PATH: box.path("empty") } });
  assert.equal(reused.path, managed);
  assert.equal(reused.source, "managed");

  // findOnPath is what both of those go through, so it is asserted on its own.
  assert.equal(findOnPath("sing-box", { env: { PATH: box.path("bin") } }), onPath);
  assert.equal(findOnPath("sing-box", { env: { PATH: box.path("empty") } }), null);
});

test("with nothing local and downloading off, the failure names every place it looked", async (t) => {
  const box = sandbox("nodownload");
  t.after(() => box.cleanup());
  await assert.rejects(
    () => provisionBinary({ stateDir: box.path("state"), env: { PATH: box.path("empty") }, download: false }),
    (error) =>
      error.code === "CORE_BINARY_MISSING" &&
      error.message.includes("core.binary") &&
      error.message.includes("PATH") &&
      error.message.includes(managedBinaryPath(box.path("state"))),
  );
});

test("the release asset is picked by platform and architecture, not by luck", () => {
  const release = {
    tag_name: "v1.14.3",
    assets: [
      { name: "sing-box-1.14.3-linux-amd64.tar.gz", size: 11, url: "https://api.github.com/repos/SagerNet/sing-box/releases/assets/1" },
      { name: "sing-box-1.14.3-darwin-arm64.tar.gz", size: 12, id: 2 },
      { name: "sing-box-1.14.3-windows-amd64.zip", size: 13, url: "https://api.github.com/repos/SagerNet/sing-box/releases/assets/3" },
    ],
  };
  const windows = pickReleaseAsset(release, { platform: "win32", arch: "x64" });
  assert.equal(windows.name, "sing-box-1.14.3-windows-amd64.zip");
  assert.equal(windows.format, "zip");
  assert.equal(windows.size, 13);
  const linux = pickReleaseAsset(release, { platform: "linux", arch: "x64" });
  assert.equal(linux.name, "sing-box-1.14.3-linux-amd64.tar.gz");
  assert.equal(linux.format, "tar.gz");
  const darwin = pickReleaseAsset(release, { platform: "darwin", arch: "arm64" });
  assert.equal(darwin.name, "sing-box-1.14.3-darwin-arm64.tar.gz");
  assert.equal(darwin.url, "https://api.github.com/repos/SagerNet/sing-box/releases/assets/2", "the API asset endpoint is built from the id");
  assert.throws(() => pickReleaseAsset(release, { platform: "sunos", arch: "x64" }), (error) => error.code === "CORE_PLATFORM_UNSUPPORTED");
  assert.throws(
    () => pickReleaseAsset({ tag_name: "v1.14.3", assets: [] }, { platform: "win32", arch: "x64" }),
    (error) => error.code === "CORE_ASSET_MISSING",
  );
});

// ------------------------------------------------------------- the download

// A release server that behaves like this environment's: it answers, then cuts
// the connection long before the last byte. `cuts` is the payload length each
// round is allowed to deliver, in order.
function flakyServer(body, cuts, { repeatLast = false } = {}) {
  const ranges = [];
  let round = 0;
  const server = http.createServer((req, res) => {
    const range = req.headers.range ?? null;
    ranges.push(range);
    round += 1;
    const from = range === null ? 0 : Number(/bytes=(\d+)-/.exec(range)[1]);
    const rest = body.subarray(from);
    if (from === 0) res.writeHead(200, { "content-length": String(body.length) });
    else res.writeHead(206, { "content-length": String(rest.length), "content-range": `bytes ${from}-${body.length - 1}/${body.length}` });
    const allowed = cuts.length === 0 ? undefined : cuts[repeatLast ? Math.min(round - 1, cuts.length - 1) : round - 1];
    const piece = allowed === undefined ? rest : rest.subarray(0, allowed);
    res.write(piece);
    if (allowed === undefined) res.end();
    else setTimeout(() => res.destroy(), 10);
  });
  return { server, ranges };
}

const ARCHIVE = makeZip([
  { name: `sing-box-1.14.3-x/${binaryName()}`, data: FAKE_BINARY, deflate: true },
  { name: "sing-box-1.14.3-x/LICENSE", data: "license text" },
]);

test("a download cut short resumes from what is already on disk, and only then is accepted", async (t) => {
  const box = sandbox("resume");
  t.after(() => box.cleanup());
  const dest = box.path("sing-box.zip");
  const { server, ranges } = flakyServer(ARCHIVE, [Math.floor(ARCHIVE.length / 3), Math.floor(ARCHIVE.length / 2)]);
  const port = await listen(server);
  t.after(() => close(server));
  const digest = `sha256:${createHash("sha256").update(ARCHIVE).digest("hex")}`;
  const result = await downloadAsset({
    url: `http://127.0.0.1:${port}/asset`,
    dest,
    size: ARCHIVE.length,
    digest,
    stallMs: 5_000,
    progressBytes: 1_024,
    sleep: () => Promise.resolve(),
  });
  assert.equal(result.bytes, ARCHIVE.length);
  assert.ok(ranges.length >= 3, `every round should have been retried (saw ${JSON.stringify(ranges)})`);
  assert.equal(ranges[0], null, "the first round has nothing to resume from");
  for (const range of ranges.slice(1)) {
    const from = Number(/^bytes=(\d+)-$/.exec(range ?? "")?.[1] ?? Number.NaN);
    assert.ok(Number.isInteger(from) && from > 0, `a resumed round must say where to continue from, got ${range}`);
    assert.ok(from < ARCHIVE.length, `a resumed round must ask for the remainder, got ${range}`);
  }
  assert.equal(fs.readFileSync(dest).equals(ARCHIVE), true, "the resumed file must be the whole archive, byte for byte");
});

test("a download that never finishes is refused, and keeps its partial file for the next run", async (t) => {
  const box = sandbox("partial");
  t.after(() => box.cleanup());
  const dest = box.path("sing-box.zip");
  const { server } = flakyServer(ARCHIVE, [Math.floor(ARCHIVE.length / 4)], { repeatLast: true });
  const port = await listen(server);
  t.after(() => close(server));
  await assert.rejects(
    () => downloadAsset({ url: `http://127.0.0.1:${port}/asset`, dest, size: ARCHIVE.length, attempts: 2, stallMs: 5_000, sleep: () => Promise.resolve() }),
    (error) => error.code === "CORE_DOWNLOAD_FAILED" && /stopped at/.test(error.message),
  );
  const partial = fs.statSync(dest).size;
  assert.ok(partial > 0 && partial < ARCHIVE.length, `the partial file must be kept (${partial} of ${ARCHIVE.length})`);

  // The next run continues from those bytes instead of starting over.
  const second = flakyServer(ARCHIVE, []);
  const secondPort = await listen(second.server);
  t.after(() => close(second.server));
  const result = await downloadAsset({
    url: `http://127.0.0.1:${secondPort}/asset`,
    dest,
    size: ARCHIVE.length,
    stallMs: 5_000,
    sleep: () => Promise.resolve(),
  });
  assert.equal(result.bytes, ARCHIVE.length);
  assert.equal(second.ranges[0], `bytes=${partial}-`, "the second run must ask for what it already has");
  assert.equal(fs.readFileSync(dest).equals(ARCHIVE), true);
});

test("a silent socket is a failed round, not a hang", async (t) => {
  const box = sandbox("stall");
  t.after(() => box.cleanup());
  const dest = box.path("sing-box.zip");
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests += 1;
    res.writeHead(200, { "content-length": String(ARCHIVE.length) });
    res.write(ARCHIVE.subarray(0, 10));
  });
  const port = await listen(server);
  t.after(() => close(server));
  await assert.rejects(
    () => downloadAsset({ url: `http://127.0.0.1:${port}/asset`, dest, size: ARCHIVE.length, attempts: 2, stallMs: 400, sleep: () => Promise.resolve() }),
    (error) => error.code === "CORE_DOWNLOAD_FAILED" && /no data for 400 ms/.test(error.message),
  );
  assert.equal(requests, 2, "a stalled round is retried, up to the attempt limit");
});

test("a digest that does not match the release is refused and the file removed", async (t) => {
  const box = sandbox("digest");
  t.after(() => box.cleanup());
  const dest = box.path("sing-box.zip");
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-length": String(ARCHIVE.length) });
    res.end(ARCHIVE);
  });
  const port = await listen(server);
  t.after(() => close(server));
  await assert.rejects(
    () => downloadAsset({ url: `http://127.0.0.1:${port}/asset`, dest, size: ARCHIVE.length, digest: `sha256:${"0".repeat(64)}`, stallMs: 5_000 }),
    (error) => error.code === "CORE_DOWNLOAD_CORRUPT",
  );
  assert.equal(fs.existsSync(dest), false, "a corrupt copy must not be left behind to be reused");
});

// --------------------------------------------------- provisioning, end to end

const PLATFORM_OS = { win32: "windows", darwin: "darwin", linux: "linux", freebsd: "freebsd", openbsd: "openbsd" }[process.platform];
const PLATFORM_ARCH = { x64: "amd64", arm64: "arm64", ia32: "386", arm: "armv7" }[process.arch];
const assetName = `sing-box-1.14.3-${PLATFORM_OS}-${PLATFORM_ARCH}.zip`;

test("provisioning asks the release API, resumes the asset, unpacks the binary and keeps it", { skip: PLATFORM_OS === undefined || PLATFORM_ARCH === undefined }, async (t) => {
  const box = sandbox("provision");
  t.after(() => box.cleanup());
  const archive = makeZip([
    { name: `sing-box-1.14.3-${PLATFORM_OS}-${PLATFORM_ARCH}/LICENSE`, data: "license text", deflate: true },
    { name: `sing-box-1.14.3-${PLATFORM_OS}-${PLATFORM_ARCH}/${binaryName()}`, data: FAKE_BINARY, deflate: true },
  ]);
  const { server } = flakyServer(archive, [Math.floor(archive.length / 2)]);
  const port = await listen(server);
  t.after(() => close(server));
  const stateDir = box.path("state");
  const seen = [];
  const fetchImpl = async (url, init = {}) => {
    seen.push({ url, accept: init.headers?.accept, agent: init.headers?.["user-agent"] });
    if (url.includes("/releases/latest")) {
      return new Response(
        JSON.stringify({
          tag_name: "v1.14.3",
          assets: [
            { name: "sing-box-1.14.3-solaris-sparc.tar.gz", size: 1, url: "http://127.0.0.1:1/wrong" },
            {
              name: assetName,
              size: archive.length,
              digest: `sha256:${createHash("sha256").update(archive).digest("hex")}`,
              url: `http://127.0.0.1:${port}/asset`,
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return fetch(url, init);
  };

  const result = await provisionBinary({
    stateDir,
    env: { PATH: box.path("empty") },
    platform: process.platform,
    arch: process.arch,
    fetchImpl,
    stallMs: 5_000,
    sleep: () => Promise.resolve(),
  });

  assert.equal(result.source, "downloaded");
  assert.equal(result.path, managedBinaryPath(stateDir, process.platform));
  assert.equal(fs.readFileSync(result.path).equals(FAKE_BINARY), true, "the unpacked file must be the binary, not the archive");
  assert.equal(fs.existsSync(`${result.path}.download`), false, "the partial archive is removed once the binary is in place");
  assert.equal(seen[0].url, "https://api.github.com/repos/SagerNet/sing-box/releases/latest");
  assert.equal(seen[1].accept, "application/octet-stream", "the asset endpoint is asked for the bytes, as the API requires");
  assert.ok(seen.length >= 3, "the cut body must have been fetched again");

  // The managed copy is what the next run uses: no second release request.
  const again = await provisionBinary({
    stateDir,
    env: { PATH: box.path("empty") },
    platform: process.platform,
    arch: process.arch,
    fetchImpl: async () => {
      throw new Error("provisioning must not go back to the network while the managed copy is there");
    },
  });
  assert.equal(again.source, "managed");
});

test("the archive reader finds the binary in a zip and in a tar.gz", () => {
  const zip = makeZip([
    { name: "sing-box-1.14.3-windows-amd64/LICENSE", data: "license text" },
    { name: "sing-box-1.14.3-windows-amd64/sing-box.exe", data: FAKE_BINARY, deflate: true },
  ]);
  const fromZip = extractArchiveEntry(zip, { format: "zip", name: "sing-box.exe" });
  assert.equal(fromZip.name, "sing-box-1.14.3-windows-amd64/sing-box.exe");
  assert.equal(fromZip.data.equals(FAKE_BINARY), true);
  assert.equal(extractArchiveEntry(zip, { format: "zip", name: "sing-box" }), null, "a name the archive does not hold is null, not a throw");

  const tar = makeTarGz([
    { name: "sing-box-1.14.3-linux-amd64/LICENSE", data: "license text" },
    { name: "sing-box-1.14.3-linux-amd64/sing-box", data: FAKE_BINARY },
  ]);
  assert.equal(extractArchiveEntry(tar, { format: "tar.gz", name: "sing-box" }).data.equals(FAKE_BINARY), true);

  assert.throws(() => extractArchiveEntry(zip, { format: "rar", name: "sing-box" }), (error) => error.code === "CORE_ARCHIVE_UNSUPPORTED");
  assert.throws(() => extractArchiveEntry(Buffer.from("not an archive"), { format: "zip", name: "sing-box" }), (error) => error.code === "CORE_ARCHIVE_UNSUPPORTED");
});

// -------------------------------------------------------------- the process

// A stand-in upstream HTTP proxy: it answers every request with its own name,
// which is how a test can tell which outbound a request left through. sing-box's
// http outbound tunnels even a plain :80 target with CONNECT, so the CONNECT
// path is what has to answer.
function fakeProxy(label) {
  const body = `i am proxy ${label}`;
  const answer = (res) => {
    res.writeHead(200, { "content-type": "text/plain", "content-length": String(body.length), connection: "close" });
    res.end(body);
  };
  const server = http.createServer((req, res) => answer(res));
  server.on("connect", (req, socket) => {
    socket.write(`HTTP/1.1 200 Connection Established\r\n\r\n`);
    socket.write(`HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`);
    socket.end();
  });
  return server;
}

realTest("the generated config runs, and each inbound proxies through its own outbound", { timeout: 60_000 }, async (t) => {
  const box = sandbox("run");
  t.after(() => box.cleanup());
  const proxyA = fakeProxy("A");
  const proxyB = fakeProxy("B");
  const portA = await listen(proxyA);
  const portB = await listen(proxyB);
  t.after(() => close(proxyA));
  t.after(() => close(proxyB));
  const parsed = parseSubscription([`http://${LOOPBACK}:${portA}#proxy-a`, `http://${LOOPBACK}:${portB}#proxy-b`].join("\n"));
  assert.equal(parsed.counts.outbound, 2);
  const base = await freeBase(2);
  const lines = [];

  const handle = await startCore({
    nodes: parsed,
    core: { binary: REAL_BINARY, portBase: base, logLevel: "info", stateDir: box.path("state") },
    log: (line) => lines.push(line),
    startTimeoutMs: 15_000,
  });
  t.after(async () => {
    await handle.stop();
  });

  assert.equal(handle.healthy(), true, JSON.stringify(handle.lastError));
  assert.equal(handle.phase, "running");
  assert.equal(handle.coreVersion, readCoreVersion(REAL_BINARY));
  assert.deepEqual(handle.ports, [base, base + 1]);
  assert.deepEqual(await portStates([base, base + 1]), ["busy", "busy"], "both loopback proxies must be listening");
  assert.equal(handle.config.inbounds[0].listen, LOOPBACK);
  assert.ok(handle.pid > 0);

  // A real request through the inbound: the answer can only come from the proxy
  // that outbound 0 points at, so this is the routing being asserted, not the
  // config's shape.
  const first = await proxyGet(handle.ports[0]);
  assert.match(first, /i am proxy A/, `in-0 must route through out-0, got ${first.slice(0, 160)}`);
  const second = await proxyGet(handle.ports[1]);
  assert.match(second, /i am proxy B/, `in-1 must route through out-1, got ${second.slice(0, 160)}`);
  assert.match(handle.stderr, /inbound\/http\[in-0\]/, "the core's own log must name the inbound");
  assert.match(handle.stderr, /outbound\/http\[out-1\]/, "the core's own log must name the outbound it used");
  assert.ok(lines.some((line) => line.includes("sing-box is up")), "the caller is told when the core is up");
  // The whole-process gates agree with this handle while it is the only core.
  assert.equal(coreCount(), 1);
  assert.equal(healthy(), true);
  assert.equal(lastError(), null);

  await handle.stop();
  assert.equal(handle.phase, "stopped");
  assert.equal(handle.healthy(), false);
  assert.equal(healthy(), false, "no core is supervised after the last stop");
  assert.equal(coreCount(), 0);
  assert.deepEqual(await portStates([base, base + 1]), ["free", "free"], "stop must give the ports back");
  assert.equal(fs.existsSync(handle.configPath), false, "the temp config is removed on stop");
  await assert.rejects(() => proxyGet(handle.ports[0], "http://example.invalid/x", 2_000), "nothing may listen after stop");

  // The same ports come back, and stopAll() tears a core down without a handle.
  const restarted = await startCore({
    nodes: parsed,
    core: { binary: REAL_BINARY, portBase: base, stateDir: box.path("state") },
    startTimeoutMs: 15_000,
  });
  assert.equal(restarted.healthy(), true, JSON.stringify(restarted.lastError));
  assert.equal(coreCount(), 1);
  assert.equal(await stopAll(), 1);
  assert.equal(coreCount(), 0);
  assert.deepEqual(await portStates([base, base + 1]), ["free", "free"]);
  // stopAll() killed the process from the outside. Under Node a ChildProcess
  // whose stdio was piped keeps the event loop alive until those streams are
  // closed, so the handle is released here too. Without this the file passes
  // its assertions and then never exits, which reads as a hang rather than as
  // the harness bug it is. Bun happens to exit regardless, which is exactly why
  // this only ever showed up on the Node baseline.
  await restarted.stop();
});

realTest("a config sing-box refuses is never started, and its stderr is what the caller sees", { timeout: 60_000 }, async (t) => {
  const box = sandbox("refuse");
  t.after(() => box.cleanup());
  const base = await freeBase(1);
  await assert.rejects(
    () =>
      startCore({
        nodes: [{ protocol: "nope", outbound: { type: "nope", server: "198.51.100.10", server_port: 443 } }],
        core: { binary: REAL_BINARY, portBase: base, stateDir: box.path("state") },
      }),
    (error) => {
      assert.equal(error.code, "CORE_CHECK_FAILED");
      assert.match(error.detail.stderr, /unknown outbound type: nope/, "sing-box's own stderr must survive");
      assert.equal(error.detail.config.outbounds[0].type, "nope", "the config that was refused comes back with it");
      return true;
    },
  );
  assert.deepEqual(await portStates([base]), ["free"], "a refused config must not have bound anything");
});

realTest("a busy port is reported as EADDRINUSE instead of being moved", { timeout: 60_000 }, async (t) => {
  const box = sandbox("busy");
  t.after(() => box.cleanup());
  const base = await freeBase(2);
  const blocker = await occupied(base + 1);
  t.after(() => close(blocker));
  await assert.rejects(
    () =>
      startCore({
        nodes: nodes(2),
        core: { binary: REAL_BINARY, portBase: base, stateDir: box.path("state") },
      }),
    (error) => {
      assert.equal(error.code, "CORE_PORT_IN_USE");
      assert.match(error.message, /EADDRINUSE/);
      assert.match(error.message, new RegExp(String(base + 1)), "the occupied port must be named");
      assert.deepEqual(error.detail.ports, [base + 1]);
      return true;
    },
  );
});

realTest("after five consecutive failures it stops restarting and only reports", { timeout: 60_000 }, async (t) => {
  const box = sandbox("restart");
  t.after(() => box.cleanup());
  const base = await freeBase(1);
  const lines = [];
  // The config is built and checked by the real core, and a process that dies at
  // once is run in its place: the readiness window has to be shorter than the
  // process's own start-up, and a cold start of the 82 MB binary (or of the
  // test runtime itself) on this machine can take longer than that, which made
  // this test race the runtime instead of the policy it is about. A shell that
  // exits with a code is as instant as a process gets on either platform.
  const dying = process.platform === "win32" ? ["cmd.exe", "/c", "exit", "7"] : ["/bin/sh", "-c", "exit 7"];
  const handle = await startCore({
    nodes: nodes(1),
    core: { binary: REAL_BINARY, portBase: base, stateDir: box.path("state"), maxRestarts: 2 },
    command: dying,
    log: (line) => lines.push(line),
    restartDelays: [20, 20],
    startTimeoutMs: 1_500,
    pollMs: 50,
    healthIntervalMs: 5_000,
  });
  t.after(async () => {
    await handle.stop();
  });

  assert.equal(handle.phase, "failed");
  assert.equal(handle.healthy(), false);
  assert.equal(handle.lastError.code, "CORE_EXITED");
  assert.match(handle.lastError.message, /code 7/, "the exit code must reach the caller");
  assert.equal(handle.stats().starts, 3, "one start and two restarts");
  assert.equal(handle.stats().restarts, 2);
  assert.equal(handle.stats().failures, 3);
  assert.ok(lines.some((line) => /not restarting again/.test(line)), "giving up is reported, not silent");
  assert.equal(lastError()?.code, "CORE_EXITED", "the whole-process gate sees the same failure");

  // Nothing is restarted after giving up.
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(handle.stats().starts, 3, "the supervisor must not keep trying");
  assert.equal(handle.healthy(), false);
});

realTest("a core is reclaimed when the process that started it exits, without stop()", { timeout: 60_000 }, async (t) => {
  const box = sandbox("reclaim");
  t.after(() => box.cleanup());
  const base = await freeBase(1);
  const script = box.write(
    "child.mjs",
    [
      `import { startCore } from ${JSON.stringify(new URL("./core.mjs", import.meta.url).href)};`,
      "const handle = await startCore({",
      `  nodes: [{ protocol: "vless", name: "n", outbound: { type: "vless", server: "198.51.100.10", server_port: 443, uuid: ${JSON.stringify(UUID)} } }],`,
      `  core: { binary: ${JSON.stringify(REAL_BINARY)}, portBase: ${base}, stateDir: ${JSON.stringify(box.path("state"))}, handleSignals: false },`,
      "  startTimeoutMs: 15000,",
      "});",
      'if (!handle.healthy()) { console.error(`not healthy: ${JSON.stringify(handle.lastError)}`); process.exit(1); }',
      'console.log("READY");',
      'console.log(`CONFIG ${handle.configPath}`);',
      "process.exit(0);",
      "",
    ].join("\n"),
  );

  const child = spawn(process.execPath, [script], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  const code = await new Promise((resolve) => child.on("exit", resolve));
  assert.equal(code, 0, `the child agent did not get as far as READY: ${output}`);
  assert.match(output, /READY/);

  // process.exit() cannot await anything, so this only holds if the 'exit'
  // handler killed the child and removed its config synchronously.
  const released = await eventually(async () => (await portStates([base]))[0] === "free", 5_000);
  assert.equal(released, true, "sing-box outlived the process that started it: an orphan");
  const configPath = /CONFIG (.+)/.exec(output)?.[1]?.trim();
  assert.ok(configPath, "the child must report the config it wrote");
  assert.equal(await eventually(() => !fs.existsSync(configPath), 5_000), true, "the temp config outlived its process");
});

test("a body with no length is accepted once it ends, and one with a length must match it", async (t) => {
  const box = sandbox("nolength");
  t.after(() => box.cleanup());
  const dest = box.path("sing-box.zip");
  // Node's http server chunks a response that sets no content-length, so this
  // is the case where the only thing that says "finished" is the end of body.
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/octet-stream" });
    res.end(ARCHIVE);
  });
  const port = await listen(server);
  t.after(() => close(server));
  const result = await downloadAsset({ url: `http://127.0.0.1:${port}/asset`, dest, size: null, stallMs: 5_000 });
  assert.equal(result.bytes, ARCHIVE.length);
  assert.equal(fs.readFileSync(dest).equals(ARCHIVE), true);
});

realTest("a pool with no nodes still runs, because there is nothing to bind", { timeout: 60_000 }, async (t) => {
  const box = sandbox("empty");
  t.after(() => box.cleanup());
  const handle = await startCore({
    nodes: [],
    core: { binary: REAL_BINARY, stateDir: box.path("state") },
    startTimeoutMs: 10_000,
  });
  t.after(async () => {
    await handle.stop();
  });
  assert.equal(handle.healthy(), true, JSON.stringify(handle.lastError));
  assert.deepEqual(handle.ports, []);
  assert.equal(handle.config.inbounds.length, 0);
  assert.equal(handle.config.route.final, "direct");
  await handle.stop();
  assert.equal(handle.healthy(), false);
  assert.equal(coreCount(), 0);
});
