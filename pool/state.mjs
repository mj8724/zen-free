// Durable pool state: the one place the pool remembers what it learned.
//
// The pool is rebuilt from this file on every plugin load, so the contract has
// to survive the three things that will really happen: a half-written file
// (the process died mid-save), a file written by an older release, and a path
// the user cannot write. None of them may throw — a plugin that cannot persist
// still has to start — so every failure comes back as a warning next to a
// usable state and the caller never needs a try/catch.
//
// What "usable" means depends on the failure:
//   * the recorded file is junk, or carries another schema version -> the pool
//     starts empty, because nothing in that file can be trusted;
//   * the path or the directory cannot be written -> the pool keeps running in
//     memory, which is all a read-only install can offer.
//
// Those two are deliberately separate warnings. "The path could not be
// expanded" is a configuration mistake and needs a different value; "the
// directory is not writable" is an environment that will not persist. Sending
// the user to fix the wrong one is worse than saying nothing, so the codes
// never overlap and a path that cannot be expanded is never reported as an
// unwritable directory.
//
// This module is data and fs only: no network, no process control.

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Bumped whenever the shape below changes incompatibly. A file under another
// version is discarded whole rather than migrated: the pool rebuilds itself
// from the subscriptions in seconds, and a half-migrated node table is a
// debugging session.
export const STATE_VERSION = 1;

// First port handed to a node. Nodes are addressed by a local listener each,
// so the range starts here and the allocator, not this module, decides what
// happens after it.
export const DEFAULT_PORT_BASE = 28100;

export const WARNING_CODES = Object.freeze({
  PATH_UNEXPANDABLE: "state-path-unexpandable",
  DIR_UNWRITABLE: "state-dir-unwritable",
  FILE_CORRUPT: "state-file-corrupt",
  STATE_INVALID: "state-invalid",
  VERSION_MISMATCH: "state-version-mismatch",
  READ_FAILED: "state-read-failed",
});

// A node's life, not its health: `ready` may be dialled, `cooling` is being
// left alone for a while after failures, `retired` is never dialled again
// (replaced in the config or gone from every subscription).
export const NODE_STATUSES = Object.freeze(["ready", "cooling", "retired"]);

// Thrown by resolveStatePath only. load/save turn it into a warning, so this
// escapes to callers that resolve a path themselves, to be shown verbatim.
export class StatePathError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "StatePathError";
    this.code = code;
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// State is JSON by contract, so a JSON round trip is both the clone and the
// proof that nothing non-serialisable was smuggled in.
function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function deepFreeze(value) {
  if (isPlainObject(value) || Array.isArray(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

function asText(value) {
  return typeof value === "string" ? value : "";
}

function asCount(value, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

// The canonical empty record, frozen: it is exported so callers can compare
// against it, and handed out as a fresh copy so they can also mutate it.
export const DEFAULT_STATE = deepFreeze({
  version: STATE_VERSION,
  writtenAt: "",
  subscriptions: [],
  nodes: [],
  portAssignment: { base: DEFAULT_PORT_BASE },
});

export function emptyState() {
  return deepClone(DEFAULT_STATE);
}

// ------------------------------------------------------------ path expansion

// Node's and Bun's fs do not expand `~`: passing "~/pool/state.json" through
// gives a directory literally named "~" that always happens to be creatable,
// so a user's configured path would silently persist somewhere they never
// look. The expansion is done here instead, with the home directory
// injectable so it can be tested without touching the real one.
export function resolveStatePath(value, { homedir = os.homedir() } = {}) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new StatePathError(
      WARNING_CODES.PATH_UNEXPANDABLE,
      `state path must be a non-empty string, got ${value === "" ? "an empty string" : String(value)}`,
    );
  }
  const raw = value.trim();
  if (raw.startsWith("~")) {
    if (raw !== "~" && !raw.startsWith("~/") && !raw.startsWith("~\\")) {
      throw new StatePathError(
        WARNING_CODES.PATH_UNEXPANDABLE,
        `state path "${raw}" names another user's home directory, which this module does not expand`,
      );
    }
    const home = typeof homedir === "string" ? homedir.trim() : "";
    if (home === "") {
      throw new StatePathError(
        WARNING_CODES.PATH_UNEXPANDABLE,
        `state path "${raw}" needs a home directory and none could be found`,
      );
    }
    return path.resolve(home, raw === "~" ? "" : raw.slice(2));
  }
  return path.resolve(raw);
}

// --------------------------------------------------------------- record shape

function subscriptionRecord(raw) {
  const source = isPlainObject(raw) ? raw : {};
  return {
    ...deepClone(source),
    url: asText(source.url),
    name: asText(source.name),
    lastFetchedAt: asCount(source.lastFetchedAt),
    lastError: asText(source.lastError),
  };
}

function nodeRecord(raw) {
  const source = isPlainObject(raw) ? raw : {};
  const ewma = isPlainObject(source.probeEwmaMs) ? source.probeEwmaMs : {};
  const status = NODE_STATUSES.includes(source.status) ? source.status : "ready";
  return {
    ...deepClone(source),
    id: asText(source.id),
    scheme: asText(source.scheme),
    host: asText(source.host),
    port: asCount(source.port),
    sourceTag: asText(source.sourceTag),
    outbound: isPlainObject(source.outbound) ? deepClone(source.outbound) : {},
    lastExitIp: asText(source.lastExitIp),
    exitIpAt: asCount(source.exitIpAt),
    probeEwmaMs: { ...deepClone(ewma), zen: asCount(ewma.zen), neutral: asCount(ewma.neutral) },
    lastProbedAt: asCount(source.lastProbedAt),
    status,
    lastKind: asText(source.lastKind),
    failures: asCount(source.failures),
    skipReason: asText(source.skipReason),
  };
}

// Fills every documented field from the defaults, keeps anything else the file
// carried (a newer writer's extra columns survive a load here), and reports
// what could not be repaired as issues rather than dropping the file.
function normalizeState(raw) {
  const source = isPlainObject(raw) ? raw : {};
  const issues = [];
  if (!Array.isArray(source.subscriptions) && source.subscriptions !== undefined) {
    issues.push("subscriptions is not an array, so it was reset");
  }
  if (!Array.isArray(source.nodes) && source.nodes !== undefined) {
    issues.push("nodes is not an array, so it was reset");
  }
  const nodes = asArray(source.nodes).map(nodeRecord);
  const seen = new Set();
  nodes.forEach((node, index) => {
    if (node.id === "") {
      issues.push(`node ${index} has no id, so it cannot be keyed by slot`);
    } else if (seen.has(node.id)) {
      issues.push(`node id ${node.id} appears twice`);
    }
    seen.add(node.id);
  });
  const assignment = isPlainObject(source.portAssignment) ? source.portAssignment : {};
  return {
    state: {
      version: STATE_VERSION,
      writtenAt: asText(source.writtenAt),
      subscriptions: asArray(source.subscriptions).map(subscriptionRecord),
      nodes,
      portAssignment: { ...deepClone(assignment), base: asCount(assignment.base, DEFAULT_PORT_BASE) },
    },
    issues,
  };
}

// The record as it goes to disk: normalized, stamped, and ordered like the
// documented schema so a human reading the file sees the same field order
// every time.
function toRecord(state, now) {
  const { state: normalized } = normalizeState(state);
  return { ...normalized, version: STATE_VERSION, writtenAt: new Date(now).toISOString() };
}

// ------------------------------------------------------------------- node id

// Stable identity for one node: the same subscription line parsed on any
// machine, at any time, yields the same id, and the id changes when the node
// that would be dialled changes. It deliberately excludes the subscription's
// name and tag, so a node carried by two subscriptions is one slot, and
// excludes anything measured (`probeEwmaMs`, `port`, `status`), so measurement
// never moves a slot.
//
// keyParams are the protocol parameters that decide which peer you actually
// reach — vmess/vless `id`, shadowsocks `method`+`password`, trojan `password`
// and so on. Key order is irrelevant; pass only what changes the dial.
export function nodeId(scheme, host, port, keyParams = {}) {
  return createHash("sha256").update(canonicalIdentity(scheme, host, port, keyParams)).digest("hex").slice(0, 16);
}

function canonicalIdentity(scheme, host, port, keyParams) {
  const lines = [
    `scheme=${asText(scheme).trim().toLowerCase()}`,
    `host=${asText(host).trim().toLowerCase()}`,
    `port=${asCount(port)}`,
  ];
  const params = isPlainObject(keyParams) ? keyParams : {};
  for (const key of Object.keys(params).sort()) {
    const rendered = canonicalValue(params[key]);
    if (rendered !== null) lines.push(`${key}=${rendered}`);
  }
  return lines.join("\n");
}

// JSON-shaped rendering with sorted object keys, so two equal parameter sets
// hash alike no matter how the parser built them. undefined is the one value
// that disappears: it means "this node has no such parameter".
function canonicalValue(value) {
  if (value === undefined) return null;
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalValue(item) ?? "null").join(",")}]`;
  }
  if (isPlainObject(value)) {
    const entries = Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  const text = JSON.stringify(value);
  return text === undefined ? `${typeof value}` : text;
}

// ------------------------------------------------------------------- logging

// Subscription URLs carry the token that pays for them, so a URL that reaches
// a log is worth stripping to its origin and path. The recorded state keeps
// the URL verbatim because it is the only copy the pool has to re-fetch with;
// this helper exists for everything that prints.
export function redactSubscriptionUrl(value) {
  try {
    const url = new URL(String(value));
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "";
  }
}

// ------------------------------------------------------------------ load/save

// Names the temp file written next to the target. Only one save runs at a
// time per process, so a counter is enough to keep a stale leftover from a
// killed process out of the way.
let temporaryCounter = 0;

function warning(code, message) {
  return { code, message };
}

function unwritableWarning(target, error) {
  return warning(
    WARNING_CODES.DIR_UNWRITABLE,
    `cannot write ${target} (${error.code ?? error.message}); the pool keeps its state in memory only`,
  );
}

// Reads the recorded state. Always returns a state to run with plus the
// warnings explaining anything that had to be given up, so a caller can log
// them and start regardless.
//
// A missing file is not a warning: it is the first run.
export function load(statePath, { homedir = os.homedir() } = {}) {
  let resolved = null;
  try {
    resolved = resolveStatePath(statePath, { homedir });
  } catch (error) {
    return {
      state: emptyState(),
      warnings: [warning(error.code ?? WARNING_CODES.PATH_UNEXPANDABLE, error.message)],
      path: null,
    };
  }

  let text;
  try {
    text = fs.readFileSync(resolved, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return { state: emptyState(), warnings: [], path: resolved };
    return {
      state: emptyState(),
      warnings: [warning(WARNING_CODES.READ_FAILED, `cannot read ${resolved} (${error.code ?? error.message}); starting from defaults`)],
      path: resolved,
    };
  }

  let raw;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    return {
      state: emptyState(),
      warnings: [warning(WARNING_CODES.FILE_CORRUPT, `${resolved} is not valid JSON (${error.message}); starting from defaults`)],
      path: resolved,
    };
  }
  if (!isPlainObject(raw)) {
    return {
      state: emptyState(),
      warnings: [warning(WARNING_CODES.FILE_CORRUPT, `${resolved} does not hold a state object; starting from defaults`)],
      path: resolved,
    };
  }
  if (raw.version !== STATE_VERSION) {
    return {
      state: emptyState(),
      warnings: [
        warning(
          WARNING_CODES.VERSION_MISMATCH,
          `${resolved} is state version ${raw.version}, this module records version ${STATE_VERSION}; starting from defaults`,
        ),
      ],
      path: resolved,
    };
  }

  const { state, issues } = normalizeState(raw);
  const warnings = issues.length === 0
    ? []
    : [warning(WARNING_CODES.STATE_INVALID, `${resolved} was repaired: ${issues.join("; ")}`)];
  return { state, warnings, path: resolved };
}

// Replaces the recorded state atomically: a temp file in the same directory,
// then a rename over the target. A reader either sees the previous complete
// file or this one, and a crash mid-write leaves the target untouched.
//
// Returns the record that was written (or would have been, when the write was
// refused) so the caller's in-memory copy always matches what it asked to
// persist — including `writtenAt`, which is stamped here.
export function save(statePath, state, { homedir = os.homedir(), now = Date.now() } = {}) {
  let record;
  try {
    record = toRecord(state, now);
  } catch (error) {
    // State is JSON by contract; a caller that handed over something that
    // cannot be rendered (a cycle, a function holding one) gets a warning
    // rather than an exception out of a persistence call.
    return {
      state: isPlainObject(state) ? state : emptyState(),
      saved: false,
      path: null,
      warnings: [warning(WARNING_CODES.STATE_INVALID, `state cannot be recorded as JSON (${error.message}); nothing was written`)],
    };
  }

  let resolved = null;
  try {
    resolved = resolveStatePath(statePath, { homedir });
  } catch (error) {
    return {
      state: record,
      saved: false,
      path: null,
      warnings: [warning(error.code ?? WARNING_CODES.PATH_UNEXPANDABLE, error.message)],
    };
  }

  const directory = path.dirname(resolved);
  try {
    fs.mkdirSync(directory, { recursive: true });
  } catch (error) {
    return { state: record, saved: false, path: resolved, warnings: [unwritableWarning(resolved, error)] };
  }

  const temporary = `${resolved}.${process.pid}.${++temporaryCounter}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, resolved);
  } catch (error) {
    try {
      fs.rmSync(temporary, { force: true });
    } catch {
      // The temp file is already gone or unreachable; the warning below is the
      // one the user needs, not this.
    }
    return { state: record, saved: false, path: resolved, warnings: [unwritableWarning(resolved, error)] };
  }

  return { state: record, saved: true, path: resolved, warnings: [] };
}
