// The sing-box core: the binary, the config it is given, and the process.
//
// A pool is N nodes and each node is a sing-box outbound. This module owns the
// four things the other pool modules deliberately leave alone: tags, ports, the
// version gates that decide which config fields are legal, and the process
// lifetime. It builds one config with one loopback HTTP proxy per node, has
// sing-box itself validate that config, and only then runs it.
//
// Every field choice below was checked against a real sing-box 1.14.3 core --
// `sing-box check` plus a live run and a proxied request, not the docs alone:
//
//   * `listen` is written explicitly as 127.0.0.1 on every inbound, and a test
//     asserts that nothing but loopback is ever bound. An HTTP inbound takes no
//     credentials, so a wildcard listen publishes N open proxies to the LAN.
//     1.14.3's http inbound happens to default to 127.0.0.1 when the field is
//     left out (measured), which is exactly why the field is written out: the
//     safety of an unauthenticated proxy should not rest on a default.
//   * `connect_timeout` is set on every outbound (and on `direct`). On this
//     deployment a real node host takes 3s+ just to finish a TCP connect, and
//     sing-box's 5s default dial timeout made reachable nodes fail with
//     "i/o timeout" -- measured at exactly 5.0s, twice, on one live config.
//   * The DNS block uses the new server format (`type: "local"`) from 1.12 and
//     the legacy `address` spelling below it. 1.14.3 refuses the legacy form
//     outright ("removed in sing-box 1.14.0"), and a config with new-format
//     servers but no `route.default_domain_resolver` is refused as well
//     ("deprecated in sing-box 1.12.0 and will be removed").
//   * A DNS server must not carry `detour: "direct"`: a live 1.14.3 run failed
//     with "start dns/https[doh]: detour to an empty direct outbound makes no
//     sense", so the DoH server names no detour.
//   * `route.rules[].action` exists since 1.11 (checked against the rule docs
//     at tag v1.11.0); the `outbound`-only spelling is what 1.10 reads.
//   * `route.final: "direct"` plus a `direct` outbound, so traffic that matches
//     no rule never leaves through a node.
//
// Out of scope: fetching a subscription (sources.mjs), parsing share links
// (protocols.mjs), and reading the running config back (v1 rebuilds nothing).

import { spawn as spawnProcess, spawnSync as spawnSyncProcess } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { MIN_CORE_VERSION, SKIP_REASONS } from "./protocols.mjs";

export const LOOPBACK = "127.0.0.1";
export const DIRECT_TAG = "direct";
export const LOCAL_DNS_TAG = "local";
export const DOH_DNS_TAG = "doh";
export const DEFAULT_PORT_BASE = 28100;
export const DEFAULT_DNS_SERVER = "1.1.1.1";
// 20s, not 15s: the slowest connect measured on this deployment was ~5.3s of
// TCP to a Cloudflare-fronted node, and a node that answers late is still a
// node that answers.
export const DEFAULT_CONNECT_TIMEOUT = "20s";
export const DEFAULT_LOG_LEVEL = "warn";
// Rule actions (`action: "route"`) and the new DNS server formats.
export const MIN_ACTION_VERSION = "1.11.0";
export const MIN_DNS_FORMAT_VERSION = "1.12.0";
export const MAX_RESTARTS = 5;
export const DEFAULT_RESTART_DELAYS = [250, 500, 1000, 2000, 4000];
export const DEFAULT_START_TIMEOUT_MS = 15_000;
export const DEFAULT_HEALTH_INTERVAL_MS = 2_000;
export const DEFAULT_PROBE_TIMEOUT_MS = 2_000;
export const STDERR_LINES = 200;

const RELEASE_LATEST = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";
const RELEASE_TAG = (version) => `https://api.github.com/repos/SagerNet/sing-box/releases/tags/${version}`;
const RELEASE_ASSET = (id) => `https://api.github.com/repos/SagerNet/sing-box/releases/assets/${id}`;
// The release is the only thing this module ever fetches, and the API asset
// endpoint is the only address that works here: direct
// github.com/.../releases/download/... URLs are blocked in this environment,
// while the asset endpoint returns the same bytes with an octet-stream Accept.
const USER_AGENT = "zen-free-pool-core";
const LOG_LEVELS = new Set(["trace", "debug", "info", "warn", "error", "fatal"]);
const DURATION_RE = /^\d+(?:\.\d+)?(?:ms|s|m|h|d)$/;
const ANSI_RE = /\u001b\[[0-9;]*m/g;
const OS_NAMES = { win32: "windows", windows: "windows", darwin: "darwin", linux: "linux", freebsd: "freebsd", openbsd: "openbsd" };
const ARCH_NAMES = {
  x64: "amd64",
  amd64: "amd64",
  arm64: "arm64",
  ia32: "386",
  386: "386",
  arm: "armv7",
  armv7: "armv7",
  s390x: "s390x",
  riscv64: "riscv64",
};

export class CoreError extends Error {
  constructor(code, message, detail = null) {
    super(message);
    this.name = "CoreError";
    this.code = code;
    this.detail = detail;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stripAnsi(text) {
  return String(text).replace(ANSI_RE, "");
}

function lastLines(text, count) {
  const lines = stripAnsi(text)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  return lines.slice(-count).join(" | ");
}

function isFile(target) {
  try {
    return fs.statSync(target).isFile();
  } catch {
    return false;
  }
}

function fileSize(target) {
  try {
    return fs.statSync(target).size;
  } catch {
    return 0;
  }
}

function wait(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function formatBytes(bytes) {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(0)} KiB`;
  return `${bytes} B`;
}

// ------------------------------------------------------------------ versions

export function versionParts(value) {
  if (isPlainObject(value) && Number.isInteger(value.major) && Number.isInteger(value.minor)) {
    return { major: value.major, minor: value.minor, patch: Number.isInteger(value.patch) ? value.patch : 0 };
  }
  if (typeof value !== "string") return null;
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(value.trim());
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3] ?? 0) };
}

export function normalizeVersion(value) {
  const parts = versionParts(value);
  return parts === null ? null : `${parts.major}.${parts.minor}.${parts.patch}`;
}

// -1, 0 or 1, and null when either side is not a version.
export function compareVersions(left, right) {
  const a = versionParts(left);
  const b = versionParts(right);
  if (a === null || b === null) return null;
  for (const key of ["major", "minor", "patch"]) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  return 0;
}

// `sing-box version 1.14.3` is the whole first line of the real output; a
// pre-release suffix is dropped, since the gated fields are gated by
// major.minor.
export function parseVersionOutput(text) {
  if (typeof text !== "string") return null;
  const named = /sing-box version\s+([0-9][0-9A-Za-z.\-+]*)/i.exec(text);
  const bare = named === null ? /^\s*([0-9][0-9A-Za-z.\-+]*)/.exec(text) : null;
  return normalizeVersion(named !== null ? named[1] : (bare === null ? "" : bare[1]));
}

export function readCoreVersion(binary, { spawnSync: run = spawnSyncProcess, timeoutMs = 30_000 } = {}) {
  let result;
  try {
    result = run(binary, ["version"], { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  } catch (error) {
    throw new CoreError("CORE_UNUSABLE", `cannot run ${binary}: ${error.message}`);
  }
  if (result.error) {
    throw new CoreError("CORE_UNUSABLE", `cannot run ${binary} version: ${result.error.message}`);
  }
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    throw new CoreError("CORE_UNUSABLE", `${binary} version exited ${result.status}: ${lastLines(output, 3)}`, { stderr: result.stderr ?? "" });
  }
  const version = parseVersionOutput(output);
  if (version === null) {
    throw new CoreError("CORE_UNUSABLE", `${binary} version did not name a sing-box release: ${lastLines(output, 3)}`, { stdout: output });
  }
  return version;
}

// -------------------------------------------------------------------- config

function nodeEntry(entry, index) {
  if (!isPlainObject(entry)) {
    throw new CoreError("CORE_NODE_INVALID", `nodes[${index}] is not an object`);
  }
  // `{protocol, name, outbound}` is what parseSubscription emits; a bare
  // outbound object is accepted too, so a caller can hand over an outbound it
  // built itself. protocols.mjs emits no tag, which is why every outbound here
  // is copied rather than mutated.
  const outbound = isPlainObject(entry.outbound) ? entry.outbound : entry;
  if (typeof outbound.type !== "string" || outbound.type === "") {
    throw new CoreError("CORE_NODE_INVALID", `nodes[${index}] has no outbound type`);
  }
  return {
    outbound,
    protocol: typeof entry.protocol === "string" ? entry.protocol : outbound.type,
    name: typeof entry.name === "string" ? entry.name : null,
  };
}

function dnsBlock(modern, { dohServer, localTag, dohTag }) {
  if (modern) {
    return {
      servers: [
        { tag: localTag, type: "local" },
        { tag: dohTag, type: "https", server: dohServer },
      ],
      final: localTag,
    };
  }
  // The legacy spelling, for cores older than 1.12. `detour` is left out on
  // purpose: the 1.11 docs call it optional ("default outbound will be used if
  // empty") and 1.14.3 rejects a detour to the direct outbound.
  return {
    servers: [
      { tag: localTag, address: "local" },
      { tag: dohTag, address: `https://${dohServer}/dns-query` },
    ],
    final: localTag,
  };
}

// The pure half of the module: nodes plus a core version in, one config plus
// the ports it binds out. It touches nothing -- no filesystem, no clock, no
// process -- so the tests can assert the exact shape without spawning anything.
export function buildConfig(nodes, options = {}) {
  const coreVersion = normalizeVersion(options.coreVersion);
  if (coreVersion === null) {
    throw new CoreError(
      "CORE_VERSION_REQUIRED",
      "buildConfig needs coreVersion (the release read from `sing-box version`): which config fields are legal depends on it",
    );
  }
  const portBase = options.portBase ?? DEFAULT_PORT_BASE;
  if (!Number.isInteger(portBase) || portBase < 1 || portBase > 65_535) {
    throw new CoreError("CORE_PORT_RANGE", `portBase must be a whole number from 1 to 65535, got ${options.portBase}`);
  }
  const connectTimeout = options.connectTimeout ?? DEFAULT_CONNECT_TIMEOUT;
  if (typeof connectTimeout !== "string" || !DURATION_RE.test(connectTimeout)) {
    throw new CoreError("CORE_OPTIONS", `connectTimeout must be a duration with a unit like "20s", got ${JSON.stringify(options.connectTimeout)}`);
  }
  const logLevel = options.logLevel ?? DEFAULT_LOG_LEVEL;
  if (!LOG_LEVELS.has(logLevel)) {
    throw new CoreError("CORE_OPTIONS", `logLevel must be one of ${[...LOG_LEVELS].join(", ")}, got ${JSON.stringify(options.logLevel)}`);
  }
  const localTag = options.localTag ?? LOCAL_DNS_TAG;
  const dohTag = options.dohTag ?? DOH_DNS_TAG;
  const dohServer = options.dohServer ?? DEFAULT_DNS_SERVER;
  // Which server resolves outbound domain names. `local` keeps the pre-1.12
  // behaviour (the system resolver) and still works when DoH is unreachable; a
  // caller that would rather not hand node hostnames to the local resolver
  // points this at the DoH server instead.
  const resolverTag = options.resolverTag ?? localTag;

  const source = Array.isArray(nodes) ? nodes : (Array.isArray(nodes?.outbounds) ? nodes.outbounds : null);
  if (source === null) {
    throw new CoreError("CORE_NODE_INVALID", "nodes must be an array of outbounds (parseSubscription(...).outbounds)");
  }
  const carried = Array.isArray(nodes?.skipped) ? nodes.skipped : [];

  const byReason = {};
  for (const reason of Object.values(SKIP_REASONS)) byReason[reason] = 0;
  for (const entry of carried) {
    if (entry?.reason in byReason) byReason[entry.reason] += 1;
  }

  const accepted = [];
  const skipped = [...carried];
  for (const [index, entry] of source.entries()) {
    const node = nodeEntry(entry, index);
    // The floor is applied again here even though parseProtocolLine applies it
    // too: a caller may hand over outbounds it parsed without a version, and a
    // field the core cannot read is worse than a node that is left out.
    const floor = MIN_CORE_VERSION[node.protocol];
    if (floor !== undefined && compareVersions(coreVersion, floor) < 0) {
      skipped.push({
        line: null,
        scheme: node.protocol,
        name: node.name,
        reason: SKIP_REASONS.CORE_TOO_OLD,
        detail: `${node.protocol} needs sing-box >= ${floor}, this core is ${coreVersion}`,
      });
      byReason[SKIP_REASONS.CORE_TOO_OLD] += 1;
      continue;
    }
    accepted.push(node);
  }

  const count = accepted.length;
  const lastPort = portBase + count - 1;
  if (lastPort > 65_535) {
    throw new CoreError(
      "CORE_PORT_RANGE",
      `portBase ${portBase} with ${count} nodes needs port ${lastPort}, past the last usable port 65535: move the pool with core.portBase`,
    );
  }

  // One inbound per node, at portBase + i. Deliberately not "find a free run of
  // ports": the ports are chosen by arithmetic so a node keeps its port across
  // restarts, and an occupied one is reported as EADDRINUSE by whoever can
  // actually see the sockets instead of being moved in silence.
  const inbounds = accepted.map((node, index) => ({
    type: "http",
    tag: `in-${index}`,
    listen: LOOPBACK,
    listen_port: portBase + index,
  }));
  const outbounds = accepted.map((node, index) => ({
    ...node.outbound,
    tag: `out-${index}`,
    connect_timeout: connectTimeout,
  }));
  outbounds.push({ type: "direct", tag: DIRECT_TAG, connect_timeout: connectTimeout });

  const supportsAction = compareVersions(coreVersion, MIN_ACTION_VERSION) >= 0;
  const rules = accepted.map((node, index) =>
    supportsAction
      ? { inbound: [`in-${index}`], action: "route", outbound: `out-${index}` }
      : { inbound: [`in-${index}`], outbound: `out-${index}` },
  );

  const modernDns = compareVersions(coreVersion, MIN_DNS_FORMAT_VERSION) >= 0;
  const route = { rules, final: DIRECT_TAG };
  if (modernDns) route.default_domain_resolver = { server: resolverTag };

  const config = {
    log: { level: logLevel },
    dns: dnsBlock(modernDns, { dohServer, localTag, dohTag }),
    inbounds,
    outbounds,
    route,
  };

  return {
    config,
    coreVersion,
    portBase,
    connectTimeout,
    ports: inbounds.map((inbound) => inbound.listen_port),
    skipped,
    counts: {
      input: source.length + carried.length,
      inbound: inbounds.length,
      outbound: outbounds.length,
      skipped: skipped.length,
      byReason,
    },
  };
}

// `sing-box check` is the authority on whether a config is usable, so it is run
// before anything is spawned and its exit code is never overridden.
export function checkConfig(binary, configPath, { spawnSync: run = spawnSyncProcess, timeoutMs = 60_000 } = {}) {
  const command = `${binary} check -c ${configPath}`;
  let result;
  try {
    result = run(binary, ["check", "-c", configPath], { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  } catch (error) {
    return { ok: false, status: null, command, stdout: "", stderr: error.message, detail: `cannot run sing-box check: ${error.message}` };
  }
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  let detail = lastLines(`${stderr}${stdout}`, 4);
  if (detail === "" && result.error) detail = `sing-box check could not be run: ${result.error.message}`;
  if (detail === "") detail = `sing-box check exited ${result.status} without a message`;
  return { ok: result.status === 0, status: result.status ?? null, command, stdout, stderr, detail };
}

// --------------------------------------------------------------------- ports

// A port is "busy" when binding it fails with EADDRINUSE, which is exactly the
// question "is somebody already listening here" -- measured against a real
// sing-box on this platform, where binding a bound loopback port does fail.
export function portState(port, { host = LOOPBACK, timeoutMs = DEFAULT_PROBE_TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    const server = net.createServer();
    let settled = false;
    const finish = (state) => {
      if (settled) return;
      settled = true;
      resolve(state);
    };
    const timer = setTimeout(() => {
      try {
        server.close();
      } catch {
        // A server that never listened has nothing to release.
      }
      finish("error");
    }, timeoutMs);
    timer.unref?.();
    server.once("error", (error) => {
      clearTimeout(timer);
      finish(error.code === "EADDRINUSE" ? "busy" : "error");
    });
    server.listen({ port, host, exclusive: true }, () => {
      clearTimeout(timer);
      server.close(() => finish("free"));
    });
  });
}

export async function portStates(ports, options = {}) {
  const states = [];
  for (const port of ports) states.push(await portState(port, options));
  return states;
}

export async function busyPorts(ports, probe = portStates, timeoutMs) {
  if (ports.length === 0) return [];
  const states = await probe(ports, { timeoutMs });
  return ports.filter((port, index) => states[index] === "busy");
}

// ------------------------------------------------------------------ binaries

// Where the managed copy lives. Both overridable so a user can point the pool
// at a directory of their own (ZEN_FREE_STATE_DIR) or name the binary outright
// (ZEN_FREE_SING_BOX, the same thing as the core.binary option).
export function defaultStateDir(env = process.env, platform = process.platform) {
  if (env.ZEN_FREE_STATE_DIR) return env.ZEN_FREE_STATE_DIR;
  if (platform === "win32") {
    const local = env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
    return path.join(local, "zen-free");
  }
  return path.join(env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache"), "zen-free");
}

export function binaryName(platform = process.platform) {
  return platform === "win32" ? "sing-box.exe" : "sing-box";
}

export function managedBinaryPath(stateDir, platform = process.platform) {
  return path.join(stateDir, "bin", binaryName(platform));
}

// Walks the PATH entries and returns the first file that exists.
export function findOnPath(name, { env = process.env, platform = process.platform, access = isFile } = {}) {
  const pathValue = env.PATH ?? env.Path ?? env.path ?? "";
  const separator = platform === "win32" ? ";" : ":";
  const candidates = platform === "win32" && !name.includes(".") ? [`${name}.exe`, name] : [name];
  for (const directory of pathValue.split(separator)) {
    const cleaned = directory.trim().replace(/^"|"$/g, "");
    if (cleaned === "") continue;
    for (const candidate of candidates) {
      const full = path.join(cleaned, candidate);
      if (access(full)) return full;
    }
  }
  return null;
}

export function archiveFormat(name) {
  const value = String(name ?? "");
  if (value.endsWith(".zip")) return "zip";
  if (value.endsWith(".tar.gz") || value.endsWith(".tgz")) return "tar.gz";
  return null;
}

export function pickReleaseAsset(release, { platform = process.platform, arch = process.arch } = {}) {
  const osName = OS_NAMES[platform];
  const archName = ARCH_NAMES[arch];
  if (osName === undefined || archName === undefined) {
    throw new CoreError("CORE_PLATFORM_UNSUPPORTED", `no sing-box release is built for ${platform}/${arch}`);
  }
  const tag = String(release?.tag_name ?? "");
  const version = tag.replace(/^v/, "");
  if (version === "") {
    throw new CoreError("CORE_RELEASE_UNKNOWN", "the release metadata has no tag_name");
  }
  const assets = Array.isArray(release.assets) ? release.assets.filter(isPlainObject) : [];
  const wanted = `sing-box-${version}-${osName}-${archName}`;
  const asset =
    assets.find((entry) => entry.name === `${wanted}.zip`) ??
    assets.find((entry) => entry.name === `${wanted}.tar.gz`) ??
    assets.find((entry) => new RegExp(`^sing-box-[0-9][0-9A-Za-z.\\-]*?-${osName}-${archName}\\.(?:zip|tar\\.gz)$`).test(String(entry.name ?? "")));
  if (asset === undefined) {
    throw new CoreError(
      "CORE_ASSET_MISSING",
      `the ${tag} release has no ${osName}/${archName} asset; it offers ${assets.map((entry) => entry.name).join(", ") || "nothing"}`,
    );
  }
  const format = archiveFormat(asset.name);
  if (format === null) {
    throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `the ${tag} ${osName}/${archName} asset is ${asset.name}, which is neither a zip nor a tar.gz`);
  }
  return {
    name: asset.name,
    format,
    version,
    release: tag,
    size: Number.isInteger(asset.size) && asset.size > 0 ? asset.size : null,
    digest: typeof asset.digest === "string" ? asset.digest : null,
    url: typeof asset.url === "string" && asset.url !== "" ? asset.url : RELEASE_ASSET(asset.id),
  };
}

export async function fetchRelease({ release = "latest", fetchImpl = globalThis.fetch, timeoutMs = 30_000 } = {}) {
  const url = release === "latest" ? RELEASE_LATEST : RELEASE_TAG(release);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("the release request timed out")), timeoutMs);
  timer.unref?.();
  try {
    const response = await fetchImpl(url, {
      headers: { accept: "application/vnd.github+json", "user-agent": USER_AGENT },
      signal: controller.signal,
      redirect: "follow",
    });
    if (!response.ok) {
      throw new CoreError("CORE_RELEASE_UNKNOWN", `GitHub answered HTTP ${response.status} for ${url}`, { url, status: response.status });
    }
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

// -------------------------------------------------------------- the archive

// A zip reader rather than a dependency: the release ships one file inside one
// small zip, and the two structures a central directory needs are stable.
function readZipEntry(bytes, name) {
  let eocd = -1;
  const floor = Math.max(0, bytes.length - 65_557);
  for (let at = bytes.length - 22; at >= floor; at -= 1) {
    if (bytes.readUInt32LE(at) === 0x0605_4b50) {
      eocd = at;
      break;
    }
  }
  if (eocd === -1) throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", "the downloaded archive is not a zip: no end of central directory");
  const total = bytes.readUInt16LE(eocd + 10);
  let offset = bytes.readUInt32LE(eocd + 16);
  for (let index = 0; index < total; index += 1) {
    if (bytes.readUInt32LE(offset) !== 0x0201_4b50) {
      throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `zip entry ${index} does not start where the central directory says it does`);
    }
    const method = bytes.readUInt16LE(offset + 10);
    const compressedSize = bytes.readUInt32LE(offset + 20);
    const uncompressedSize = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    const localOffset = bytes.readUInt32LE(offset + 42);
    const entryName = bytes.toString("utf8", offset + 46, offset + 46 + nameLength);
    if ([compressedSize, uncompressedSize, localOffset].includes(0xffff_ffff)) {
      throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", "the downloaded archive is a zip64 archive, which this reader does not implement");
    }
    if (path.posix.basename(entryName) === name) {
      if (bytes.readUInt32LE(localOffset) !== 0x0403_4b50) {
        throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `${entryName} has no local zip header`);
      }
      const localNameLength = bytes.readUInt16LE(localOffset + 26);
      const localExtraLength = bytes.readUInt16LE(localOffset + 28);
      const dataStart = localOffset + 30 + localNameLength + localExtraLength;
      const raw = bytes.subarray(dataStart, dataStart + compressedSize);
      let data;
      if (method === 0) data = raw;
      else if (method === 8) data = inflateRawSync(raw);
      else throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `${entryName} uses zip compression method ${method}`);
      if (data.length !== uncompressedSize) {
        throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `${entryName} unpacked to ${data.length} bytes, not the ${uncompressedSize} the archive declares`);
      }
      return { name: entryName, data };
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return null;
}

function tarText(block, start, length) {
  const end = block.indexOf(0, start);
  const stop = end === -1 || end > start + length ? start + length : end;
  return block.toString("utf8", start, stop);
}

// tar.gz for the platforms whose release is not a zip. Only plain files are
// read: a GNU long name ('L') or a pax header ('x') is skipped by its own size,
// and the sing-box archives carry neither.
function readTarEntry(bytes, name) {
  const tar = bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes) : bytes;
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const fileName = tarText(header, 0, 100);
    const prefix = tarText(header, 345, 155);
    const sizeText = tarText(header, 124, 12).trim();
    const size = sizeText === "" ? 0 : Number.parseInt(sizeText, 8);
    const type = String.fromCharCode(header[156] === 0 ? 0x30 : header[156]);
    const full = prefix === "" ? fileName : `${prefix}/${fileName}`;
    if (Number.isNaN(size)) throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `${full} has a tar size this reader cannot read`);
    if (["0", " ", "7"].includes(type) && path.posix.basename(full) === name) {
      return { name: full, data: tar.subarray(offset + 512, offset + 512 + size) };
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}

// Returns the named file's bytes, or null when the archive holds no such file.
export function extractArchiveEntry(bytes, { format, name }) {
  if (format === "zip") return readZipEntry(bytes, name);
  if (format === "tar.gz") return readTarEntry(bytes, name);
  throw new CoreError("CORE_ARCHIVE_UNSUPPORTED", `cannot read a ${format} archive: only zip and tar.gz are implemented`);
}

// ------------------------------------------------------------- the download

async function writeChunks({ response, dest, have, expected, stallMs, progressBytes, log }) {
  const reader = typeof response.body?.getReader === "function" ? response.body.getReader() : null;
  if (reader === null) {
    const chunk = Buffer.from(await response.arrayBuffer());
    fs.appendFileSync(dest, chunk);
    const next = have + chunk.length;
    return { have: next, complete: expected === null || next >= expected };
  }
  const fd = fs.openSync(dest, "a");
  let stallTimer = null;
  let stalled = false;
  let ended = false;
  let logged = Math.floor(have / progressBytes);
  const armStall = () => {
    if (stallTimer) clearTimeout(stallTimer);
    stallTimer = setTimeout(() => {
      stalled = true;
      reader.cancel().catch(() => {});
    }, stallMs);
    stallTimer.unref?.();
  };
  try {
    armStall();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        ended = true;
        break;
      }
      if (!value || value.length === 0) continue;
      fs.writeSync(fd, value);
      have += value.length;
      armStall();
      const step = Math.floor(have / progressBytes);
      if (step > logged) {
        logged = step;
        log(`sing-box download ${formatBytes(have)} of ${expected === null ? "?" : formatBytes(expected)} (partial file kept for resume)`);
      }
      if (expected !== null && have >= expected) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
  } finally {
    if (stallTimer) clearTimeout(stallTimer);
    fs.closeSync(fd);
  }
  if (stalled) {
    throw new CoreError("CORE_DOWNLOAD_STALLED", `no data for ${stallMs} ms; the ${formatBytes(have)} already on disk will be resumed`, { have });
  }
  return { have, complete: expected === null ? ended : have >= expected };
}

// Why this is not one plain fetch: on this network the asset endpoint was
// measured at ~34 KB/s for this 31.3 MiB release, with the connection dropped
// before the end, and a later run took the same asset at a steady ~200 KB/s in
// a single round. Both are handled the same way: the file on disk is the state
// (every round asks for `Range: bytes=<have>-` and appends), a stalled socket
// costs one round, and nothing is accepted until the size -- and the sha256,
// which GitHub reports for the asset -- matches the release. A run that exhausts
// its attempts leaves the partial file behind, so the next one continues it.
export async function downloadAsset({
  url,
  dest,
  size = null,
  digest = null,
  headers = {},
  fetchImpl = globalThis.fetch,
  log = () => {},
  stallMs = 60_000,
  attempts = 8,
  progressBytes = 5 << 20,
  sleep = wait,
}) {
  let expected = Number.isInteger(size) && size > 0 ? size : null;
  let have = fileSize(dest);
  if (expected !== null && have > expected) {
    fs.truncateSync(dest, 0);
    have = 0;
  }
  if (have > 0) log(`resuming the sing-box download at ${formatBytes(have)}${expected === null ? "" : ` of ${formatBytes(expected)}`}`);
  let lastError = null;
  let complete = false;

  for (let round = 1; round <= attempts; round += 1) {
    // The file is the state, not a counter: a round that dies mid-body has
    // already appended the bytes it received, and the next round has to ask
    // for the remainder of what is really on disk or the file gets a second
    // copy of its own prefix.
    have = fileSize(dest);
    if (expected !== null && have >= expected) {
      complete = true;
      break;
    }
    if (round > 1) {
      log(`sing-box download attempt ${round}/${attempts} from byte ${have}${lastError === null ? "" : ` after: ${lastError.message}`}`);
      await sleep(Math.min(30_000, 500 * round));
    }
    const controller = new AbortController();
    const requestHeaders = {
      "user-agent": USER_AGENT,
      accept: "application/octet-stream",
      ...headers,
    };
    if (have > 0) requestHeaders.range = `bytes=${have}-`;
    let response = null;
    try {
      response = await fetchImpl(url, { headers: requestHeaders, signal: controller.signal, redirect: "follow" });
      if (!response.ok) {
        const retryable = response.status >= 500 || [408, 425, 429].includes(response.status);
        const failure = new CoreError(
          "CORE_DOWNLOAD_FAILED",
          `HTTP ${response.status} ${response.statusText ?? ""} for ${url}`.trim(),
          { url, status: response.status, retryable },
        );
        if (!retryable) throw failure;
        lastError = failure;
        controller.abort();
        continue;
      }
      // A server that ignores the Range header would restart the body; the
      // bytes on disk would then be the tail of a full copy, not a prefix, so
      // the file is truncated and the round starts over.
      if (have > 0 && response.status !== 206) {
        log("the release server ignored the Range header, restarting the download from zero");
        fs.truncateSync(dest, 0);
        have = 0;
      }
      if (expected === null) {
        const length = Number(response.headers.get("content-length"));
        if (Number.isFinite(length) && length > 0) expected = response.status === 206 ? have + length : length;
      }
      const pumped = await writeChunks({ response, dest, have, expected, stallMs, progressBytes, log });
      have = pumped.have;
      complete = pumped.complete;
      lastError = null;
    } catch (error) {
      if (error instanceof CoreError && error.code === "CORE_DOWNLOAD_FAILED" && error.detail?.retryable !== true) {
        throw error;
      }
      lastError = error instanceof CoreError ? error : new CoreError("CORE_DOWNLOAD_FAILED", `the download failed: ${error.message}`, { retryable: true });
    } finally {
      try {
        controller.abort();
      } catch {
        // aborting an already finished request is a no-op.
      }
    }
    if (complete) break;
  }

  const written = fileSize(dest);
  if (expected !== null && written !== expected) {
    // A file longer than the release means a resumed round wrote past the end;
    // keeping it would make every later run fail the same way.
    if (written > expected) fs.truncateSync(dest, 0);
    throw new CoreError(
      "CORE_DOWNLOAD_FAILED",
      `the sing-box release download stopped at ${formatBytes(written)} of ${formatBytes(expected)} after ${attempts} attempts${lastError === null ? "" : `: ${lastError.message}`}`,
      { url, have: written, expected, attempts },
    );
  }
  if (!complete) {
    throw new CoreError(
      "CORE_DOWNLOAD_FAILED",
      `the sing-box release download ended after ${formatBytes(written)} and the server named no length to check it against${lastError === null ? "" : `: ${lastError.message}`}`,
      { url, have: written, expected, attempts },
    );
  }
  if (digest !== null) {
    const [algorithm, value] = String(digest).split(":");
    if (algorithm === "sha256" && value) {
      const actual = createHash("sha256").update(fs.readFileSync(dest)).digest("hex");
      if (actual !== value) {
        fs.rmSync(dest, { force: true });
        throw new CoreError("CORE_DOWNLOAD_CORRUPT", `the downloaded archive is not the release's sha256: expected ${value}, got ${actual}`, { url, expected: value, actual });
      }
    }
  }
  log(`sing-box release downloaded: ${formatBytes(written)} at ${dest}`);
  return { path: dest, bytes: written, expected };
}

// --------------------------------------------------------------------------
// Self-provisioning. The order is the caller's: an explicit core.binary, then
// whatever is on PATH, then the managed copy under the state dir, and only then
// the network. Nothing but the sing-box release is ever fetched, and only the
// platform asset of the requested (or latest) release.

export async function provisionBinary(options = {}) {
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? process.arch;
  const log = options.log ?? (() => {});
  const env = options.env ?? process.env;
  const name = binaryName(platform);
  const stateDir = options.stateDir ?? defaultStateDir(env, platform);
  const managed = managedBinaryPath(stateDir, platform);

  const configured = options.binary ?? env.ZEN_FREE_SING_BOX;
  if (configured !== undefined && configured !== null && configured !== "") {
    const given = String(configured);
    if (!isFile(given)) {
      throw new CoreError("CORE_BINARY_MISSING", `the configured sing-box binary ${given} is not a file`, { path: given });
    }
    return { path: given, source: "option", stateDir, version: null, asset: null };
  }

  const onPath = findOnPath("sing-box", { env, platform });
  if (onPath !== null) return { path: onPath, source: "path", stateDir, version: null, asset: null };

  if (isFile(managed)) {
    log(`using the managed sing-box at ${managed}`);
    return { path: managed, source: "managed", stateDir, version: null, asset: null };
  }

  if (options.download === false) {
    throw new CoreError(
      "CORE_BINARY_MISSING",
      `no sing-box found: no core.binary, nothing on PATH, and nothing at ${managed}; downloading is switched off (core.download: false)`,
      { stateDir, managed },
    );
  }

  const release = await fetchRelease({
    release: options.release ?? "latest",
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    timeoutMs: options.releaseTimeoutMs,
  });
  const asset = pickReleaseAsset(release, { platform, arch });
  log(`no local sing-box; fetching ${asset.name} from the GitHub release asset API (${asset.size === null ? "size unknown" : formatBytes(asset.size)})`);
  fs.mkdirSync(path.dirname(managed), { recursive: true });
  const archivePath = `${managed}.download`;
  await downloadAsset({
    url: asset.url,
    dest: archivePath,
    size: asset.size,
    digest: asset.digest,
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    log,
    stallMs: options.stallMs ?? 60_000,
    attempts: options.attempts ?? 8,
    sleep: options.sleep,
  });
  const entry = extractArchiveEntry(fs.readFileSync(archivePath), { format: asset.format, name });
  if (entry === null) {
    throw new CoreError("CORE_ARCHIVE_NO_BINARY", `the ${asset.name} archive holds no ${name}`, { asset: asset.name });
  }
  const staging = `${managed}.new`;
  fs.writeFileSync(staging, entry.data);
  if (platform !== "win32") fs.chmodSync(staging, 0o755);
  fs.renameSync(staging, managed);
  fs.rmSync(archivePath, { force: true });
  log(`sing-box ${asset.version} installed at ${managed}`);
  return { path: managed, source: "downloaded", stateDir, version: asset.version, asset: asset.name, bytes: entry.data.length, release: asset.release };
}

// ------------------------------------------------------------- the process

// `process.on("exit")` runs after the event loop has stopped, so only
// synchronous work is possible there -- and killing a child (TerminateProcess on
// Windows) and removing a directory are both synchronous. One shared handler
// services every live core, so a second core does not stack listeners.
const live = new Set();
let exitHandlerInstalled = false;
let signalHandlersInstalled = false;

function killSync(child) {
  if (child === null || child === undefined) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill("SIGKILL");
  } catch {
    // A child that is already gone throws here; there is nothing to reclaim.
  }
}

// What the process has to give back when it leaves: the child, and the temp
// config it was started with. Nothing here may await anything.
function reclaimAll() {
  for (const entry of live) {
    killSync(entry.child);
    try {
      fs.rmSync(entry.tempDir, { recursive: true, force: true });
    } catch {
      // A temp dir that is already gone, or that something else holds, is not
      // worth failing an exit over.
    }
  }
}

function installProcessHandlers(signals) {
  if (!exitHandlerInstalled) {
    exitHandlerInstalled = true;
    process.on("exit", reclaimAll);
  }
  if (signals && !signalHandlersInstalled) {
    signalHandlersInstalled = true;
    for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
      process.on(signal, () => {
        reclaimAll();
        process.exit(code);
      });
    }
  }
}

/**
 * Provision the binary, build and check the config, then spawn and supervise
 * sing-box. The returned handle is live: `healthy()` and `lastError` are what
 * the caller gates on, `stop()` gives the child back.
 *
 * options.nodes  the outbounds to route through (parseSubscription(...) works)
 * options.core   the plugin's own options: binary, stateDir, portBase,
 *                connectTimeout, logLevel, maxRestarts, download, handleSignals
 *
 * The handle is the gate for this core; the module-level healthy()/lastError()
 * are the same gate across every core this process supervises.
 */
export async function startCore(options = {}) {
  const core = isPlainObject(options.core) ? options.core : {};
  const log = typeof options.log === "function" ? options.log : () => {};
  const platform = options.platform ?? process.platform;
  const runSync = options.spawnSync ?? spawnSyncProcess;
  const doSpawn = options.spawn ?? spawnProcess;
  const probe = options.probe ?? portStates;
  const sleep = options.sleep ?? wait;

  const provisioned = await provisionBinary({
    binary: core.binary ?? options.binary,
    stateDir: core.stateDir ?? options.stateDir,
    download: core.download !== false,
    release: core.release,
    env: options.env ?? process.env,
    platform,
    arch: options.arch ?? process.arch,
    fetchImpl: options.fetchImpl,
    log,
  });
  const binary = provisioned.path;
  const coreVersion = readCoreVersion(binary, { spawnSync: runSync, timeoutMs: options.versionTimeoutMs });
  const built = buildConfig(options.nodes, {
    coreVersion,
    portBase: core.portBase,
    connectTimeout: core.connectTimeout,
    logLevel: core.logLevel,
    dohServer: core.dohServer,
    resolverTag: core.resolverTag,
  });

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zen-free-core-"));
  const configPath = path.join(tempDir, "config.json");
  fs.writeFileSync(configPath, `${JSON.stringify(built.config, null, 2)}\n`, "utf8");

  const check = checkConfig(binary, configPath, { spawnSync: runSync, timeoutMs: options.checkTimeoutMs });
  if (!check.ok) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw new CoreError(
      "CORE_CHECK_FAILED",
      `sing-box ${coreVersion} refused the generated config, so it was not started: ${check.detail}`,
      { command: check.command, stderr: check.stderr, stdout: check.stdout, config: built.config },
    );
  }
  log(`sing-box ${coreVersion} accepted the config: ${built.counts.inbound} inbound, ${built.counts.outbound} outbound, ports ${built.ports[0] ?? "-"}..${built.ports.at(-1) ?? "-"}`);

  const busy = await busyPorts(built.ports, probe, options.probeTimeoutMs);
  if (busy.length > 0) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw new CoreError(
      "CORE_PORT_IN_USE",
      `EADDRINUSE: ${busy.join(", ")} ${busy.length === 1 ? "is" : "are"} already in use on ${LOOPBACK}, so the pool cannot listen there; another core or an unrelated program holds ${busy.length === 1 ? "it" : "them"} (move the pool with core.portBase, or stop that process)`,
      { ports: busy, portBase: built.portBase },
    );
  }
  const maxRestarts = core.maxRestarts ?? MAX_RESTARTS;
  const restartDelays = options.restartDelays ?? DEFAULT_RESTART_DELAYS;
  const startTimeoutMs = options.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS;
  const pollMs = options.pollMs ?? 100;
  const healthIntervalMs = options.healthIntervalMs ?? DEFAULT_HEALTH_INTERVAL_MS;
  const argv = options.command ?? [binary, "run", "-c", configPath];

  installProcessHandlers(core.handleSignals !== false);

  const state = {
    ports: built.ports,
    child: null,
    attempt: null,
    phase: "starting",
    failures: 0,
    starts: 0,
    restarts: 0,
    lastError: null,
    lastExit: null,
    lines: [],
    partial: { out: "", err: "" },
    stopping: false,
    restartTimer: null,
    watcher: null,
  };

  // stderr (and stdout, which this build leaves empty) is kept as a rolling
  // tail: it is what a restart and a refusal are diagnosed from.
  function record(chunk, stream) {
    const parts = (state.partial[stream] + String(chunk)).split(/\r?\n/);
    state.partial[stream] = parts.pop() ?? "";
    for (const line of parts) {
      state.lines.push(line);
      if (state.lines.length > STDERR_LINES) state.lines.shift();
      const readable = stripAnsi(line).trim();
      if (readable !== "") log(`sing-box: ${readable}`);
    }
  }

  function failure(code, message, detail = null) {
    return { code, message, detail, at: Date.now() };
  }

  function isAlive() {
    const child = state.child;
    return child !== null && child.exitCode === null && child.signalCode === null;
  }

  function healthy() {
    return state.phase === "running" && isAlive();
  }

  function beginAttempt() {
    if (state.stopping || state.phase === "failed") return;
    const attempt = { id: state.starts + 1, settled: false, child: null };
    state.starts += 1;
    state.attempt = attempt;
    state.phase = "starting";
    let child;
    try {
      child = doSpawn(argv[0], argv.slice(1), { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    } catch (error) {
      settle(attempt, failure("CORE_SPAWN_FAILED", `cannot run ${argv.join(" ")}: ${error.message}`));
      return;
    }
    attempt.child = child;
    state.child = child;
    live.add({ child, tempDir });
    child.stdout?.on("data", (chunk) => record(chunk, "out"));
    child.stderr?.on("data", (chunk) => record(chunk, "err"));
    child.on("error", (error) => settle(attempt, failure("CORE_SPAWN_FAILED", `sing-box could not be started: ${error.message}`)));
    child.on("exit", (code, signal) => {
      for (const entry of live) {
        if (entry.child === child) live.delete(entry);
      }
      state.lastExit = { code, signal, at: Date.now() };
      const tail = lastLines(state.lines.slice(-6).join("\n"), 2);
      settle(
        attempt,
        failure(
          /address already in use|EADDRINUSE/i.test(tail) ? "CORE_PORT_IN_USE" : "CORE_EXITED",
          `sing-box exited with code ${code}${signal === null ? "" : ` (${signal})`}${tail === "" ? "" : `: ${tail}`}`,
        ),
      );
    });
    void watchStart(attempt);
  }

  // Readiness is "the ports I assigned answer as busy", not "the process has
  // not exited yet": a core that is running but never bound its inbounds is
  // useless to the caller, and probing the ports is the portable way to ask
  // (reading another process's command line is not).
  async function watchStart(attempt) {
    const startedAt = Date.now();
    for (;;) {
      if (attempt.settled || state.stopping) return;
      if (state.ports.length === 0) {
        if (isAlive() && Date.now() - startedAt >= 300) {
          markRunning(attempt);
          return;
        }
      } else {
        const states = await probe(state.ports, { timeoutMs: options.probeTimeoutMs });
        if (attempt.settled || state.stopping) return;
        if (states.every((entry) => entry === "busy")) {
          markRunning(attempt);
          return;
        }
      }
      if (Date.now() - startedAt >= startTimeoutMs) {
        const tail = lastLines(state.lines.slice(-6).join("\n"), 2);
        settle(
          attempt,
          failure(
            "CORE_NOT_LISTENING",
            `sing-box did not listen on ${state.ports.join(", ") || "any port"} within ${startTimeoutMs} ms${tail === "" ? "" : `: ${tail}`}`,
          ),
        );
        return;
      }
      await sleep(pollMs);
    }
  }

  function markRunning(attempt) {
    if (attempt.settled) return;
    attempt.settled = true;
    const recovered = state.failures;
    state.failures = 0;
    state.lastError = null;
    state.phase = "running";
    if (recovered > 0) log(`sing-box recovered after ${recovered} failed ${recovered === 1 ? "start" : "starts"}`);
    log(`sing-box is up (pid ${attempt.child.pid}) on ${state.ports.length} loopback ${state.ports.length === 1 ? "port" : "ports"}`);
  }

  function settle(attempt, problem) {
    if (attempt.settled) return;
    attempt.settled = true;
    killSync(attempt.child);
    if (state.stopping) return;
    state.failures += 1;
    state.lastError = problem;
    if (state.failures > maxRestarts) {
      state.phase = "failed";
      if (state.watcher !== null) {
        clearInterval(state.watcher);
        state.watcher = null;
      }
      log(`sing-box failed ${state.failures} times in a row (last: ${problem.message}); not restarting again. The config it ran is ${configPath}`);
      return;
    }
    const delay = restartDelays[Math.min(state.failures - 1, restartDelays.length - 1)];
    state.phase = "restarting";
    log(`sing-box is down (${problem.message}); restart ${state.failures}/${maxRestarts} in ${delay} ms`);
    state.restartTimer = setTimeout(() => {
      state.restartTimer = null;
      state.restarts += 1;
      beginAttempt();
    }, delay);
  }
  // Aliveness is probed, not inferred: the process is asked whether its ports
  // are still occupied, and a core that stopped serving is restarted even if
  // its process is technically still there.
  async function healthCheck() {
    if (state.stopping || state.phase !== "running") return;
    const attempt = state.attempt;
    if (attempt === null || attempt.settled) return;
    if (!isAlive()) {
      settle(attempt, failure("CORE_EXITED", "sing-box is gone without an exit event"));
      return;
    }
    if (state.ports.length === 0) return;
    const busy = await busyPorts(state.ports, probe, options.probeTimeoutMs);
    if (state.stopping || attempt.settled) return;
    if (busy.length === 0) {
      settle(attempt, failure("CORE_NOT_LISTENING", `sing-box stopped listening on every assigned port (${state.ports.join(", ")}), probed by binding each one`));
    }
  }

  async function stop({ timeoutMs = options.stopTimeoutMs ?? 5_000 } = {}) {
    state.stopping = true;
    if (state.restartTimer !== null) {
      clearTimeout(state.restartTimer);
      state.restartTimer = null;
    }
    if (state.watcher !== null) {
      clearInterval(state.watcher);
      state.watcher = null;
    }
    const child = state.child;
    for (const entry of live) {
      if (entry.child === child) live.delete(entry);
    }
    killSync(child);
    if (child !== null) {
      const deadline = Date.now() + timeoutMs;
      while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) await sleep(25);
      killSync(child);
    }
    // The OS releases the listening sockets a moment after the process dies, so
    // the ports are waited for rather than assumed.
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const busy = await busyPorts(state.ports, probe, options.probeTimeoutMs);
      if (busy.length === 0 || Date.now() >= deadline) break;
      await sleep(50);
    }
    state.phase = "stopped";
    owned.delete(handle);
    fs.rmSync(tempDir, { recursive: true, force: true });
    log(`sing-box stopped; ${state.ports.join(", ") || "no ports"} released and the temp config removed`);
  }

  const handle = {
    binary,
    coreVersion,
    source: provisioned.source,
    stateDir: provisioned.stateDir,
    configPath,
    config: built.config,
    ports: [...state.ports],
    counts: built.counts,
    skipped: built.skipped,
    get pid() {
      return state.child?.pid ?? null;
    },
    get phase() {
      return state.phase;
    },
    get lastError() {
      return state.lastError;
    },
    get stderr() {
      return state.lines.join("\n");
    },
    healthy,
    stats() {
      return {
        phase: state.phase,
        pid: state.child?.pid ?? null,
        starts: state.starts,
        restarts: state.restarts,
        failures: state.failures,
        lastExit: state.lastExit,
        lastError: state.lastError,
        ports: [...state.ports],
      };
    },
    async waitForReady({ timeoutMs = startTimeoutMs } = {}) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        if (state.phase === "running") return true;
        if (state.phase === "failed" || state.phase === "stopped" || Date.now() >= deadline) return false;
        await sleep(50);
      }
    },
    stop,
  };

  state.watcher = setInterval(() => {
    void healthCheck();
  }, healthIntervalMs);
  state.watcher.unref?.();
  owned.add(handle);
  beginAttempt();
  await handle.waitForReady({ timeoutMs: startTimeoutMs + 1_000 });
  return handle;
}

// -------------------------------------------------------------------- the set
// A handle is what a caller who started one core needs. These are for a caller
// that wants a single gate over everything this process runs, and for tearing
// the pool down when a handle has been lost.

const owned = new Set();

/** True when every core this process supervises is up. False when there is none. */
export function healthy() {
  return owned.size > 0 && [...owned].every((core) => core.healthy());
}

/** The most recent failure any supervised core reported, or null. */
export function lastError() {
  const failures = [...owned].map((core) => core.lastError).filter(Boolean);
  if (failures.length === 0) return null;
  return failures.reduce((newest, failure) => (failure.at > newest.at ? failure : newest));
}

/** How many cores this process is supervising. */
export function coreCount() {
  return owned.size;
}

/** Stop every supervised core, and answer how many were stopped. */
export async function stopAll(options) {
  const cores = [...owned];
  await Promise.all(cores.map((core) => core.stop(options)));
  return cores.length;
}
