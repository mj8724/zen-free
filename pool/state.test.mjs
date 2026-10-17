import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  DEFAULT_PORT_BASE,
  DEFAULT_STATE,
  NODE_STATUSES,
  STATE_VERSION,
  StatePathError,
  WARNING_CODES,
  emptyState,
  load,
  nodeId,
  redactSubscriptionUrl,
  resolveStatePath,
  save,
} from "./state.mjs";

// Every test that touches the disk gets its own scratch directory, removed
// whichever way the test ends. Nothing here reads or writes the user's real
// home: the home directory is injected everywhere it matters.
function withScratch(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zen-pool-state-"));
  try {
    return run(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function codes(result) {
  return result.warnings.map((entry) => entry.code);
}

function entries(dir) {
  return fs.readdirSync(dir).sort();
}

const SAMPLE_NODE = {
  id: "aaaaaaaaaaaaaaaa",
  scheme: "vless",
  host: "edge.example.com",
  port: 443,
  sourceTag: "sub-a",
  outbound: { type: "vless", server: "edge.example.com", server_port: 443, uuid: "u" },
  port: 28100,
  lastExitIp: "203.0.113.7",
  exitIpAt: 1700000000000,
  probeEwmaMs: { zen: 120.5, neutral: 90 },
  lastProbedAt: 1700000000000,
  status: "cooling",
  lastKind: "timeout",
  failures: 2,
  skipReason: "",
};

// ------------------------------------------------------------- path expansion

test("a ~ path is expanded through the injected home directory", () => {
  const home = path.join(path.sep, "fake", "home");
  assert.equal(resolveStatePath("~/pool/state.json", { homedir: home }), path.resolve(home, "pool", "state.json"));
  assert.equal(resolveStatePath("~", { homedir: home }), path.resolve(home));
  assert.equal(resolveStatePath("~\\pool\\state.json", { homedir: home }), path.resolve(home, "pool", "state.json"));
  assert.ok(path.isAbsolute(resolveStatePath("pool/state.json", { homedir: home })), "a relative path resolves to an absolute one");
  assert.equal(resolveStatePath("/abs/state.json", { homedir: home }), path.resolve("/abs/state.json"));
});

test("load reads through an injected ~ without touching the real home", () => {
  withScratch((dir) => {
    const written = save("~/pool/state.json", { ...emptyState(), nodes: [SAMPLE_NODE] }, { homedir: dir });
    assert.equal(written.saved, true);
    assert.equal(written.path, path.resolve(dir, "pool", "state.json"));

    const result = load("~/pool/state.json", { homedir: dir });
    assert.deepEqual(result.warnings, []);
    assert.equal(result.path, path.resolve(dir, "pool", "state.json"));
    assert.deepEqual(result.state.nodes, [SAMPLE_NODE]);
  });
});

test("a path that cannot be expanded is refused by name, not silently mangled", () => {
  const cases = [
    ["", { homedir: "/home/u" }],
    ["   ", { homedir: "/home/u" }],
    ["~someone/state.json", { homedir: "/home/u" }],
    ["~/state.json", { homedir: "" }],
    [null, { homedir: "/home/u" }],
    [undefined, { homedir: "/home/u" }],
    [42, { homedir: "/home/u" }],
  ];
  for (const [value, options] of cases) {
    assert.throws(
      () => resolveStatePath(value, options),
      (error) => error instanceof StatePathError && error.code === WARNING_CODES.PATH_UNEXPANDABLE,
      `${String(value)} must not be expanded into a path`,
    );
  }
});

// ----------------------------------------------------------------- load/save

test("saving creates the directory it was pointed at", () => {
  withScratch((dir) => {
    const target = path.join(dir, "nested", "deeper", "state.json");
    assert.equal(fs.existsSync(path.dirname(target)), false, "the directory must not exist yet");
    const result = save(target, emptyState());
    assert.equal(result.saved, true);
    assert.equal(fs.existsSync(target), true);
  });
});

test("a write is atomic: no temp file survives and the file holds the whole last record", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    save(target, { ...emptyState(), nodes: [SAMPLE_NODE] });
    const second = save(target, { ...emptyState(), nodes: [], portAssignment: { base: 29000 } });

    assert.equal(second.saved, true);
    assert.deepEqual(entries(dir), ["state.json"], "the temp file must have been renamed away, not left behind");
    assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), second.state, "the file must hold exactly the returned record");

    const reloaded = load(target);
    assert.deepEqual(reloaded.warnings, []);
    assert.equal(reloaded.state.portAssignment.base, 29000);
    assert.deepEqual(reloaded.state.nodes, []);
  });
});

test("a refused write still leaves no temp file behind", () => {
  withScratch((dir) => {
    // A read-only directory is not portable (Windows does not enforce the mode
    // bit), so unwritability is produced the portable way: a file where the
    // directory should be. mkdir then fails and so does the write.
    const blocker = path.join(dir, "blocker");
    fs.writeFileSync(blocker, "not a directory");
    const before = entries(dir);

    const result = save(path.join(blocker, "state.json"), { ...emptyState(), nodes: [SAMPLE_NODE] });

    assert.equal(result.saved, false);
    assert.deepEqual(codes(result), [WARNING_CODES.DIR_UNWRITABLE]);
    assert.deepEqual(entries(dir), before, "no temp file may be left in the parent either");
  });
});

test("a write that fails after the temp file exists still cleans it up", () => {
  withScratch((dir) => {
    // The directory exists and the temp file can be written, but the rename
    // cannot land: the target is a directory. This is the one path where a
    // temp file is created and the write still fails.
    const target = path.join(dir, "state.json");
    fs.mkdirSync(target);

    const result = save(target, emptyState());

    assert.equal(result.saved, false);
    assert.deepEqual(codes(result), [WARNING_CODES.DIR_UNWRITABLE]);
    assert.deepEqual(entries(dir), ["state.json"], "the temp file must be removed when the rename fails");
  });
});

test("an unwritable target degrades to memory instead of failing", () => {
  withScratch((dir) => {
    const blocker = path.join(dir, "blocker");
    fs.writeFileSync(blocker, "not a directory");

    const result = save(path.join(blocker, "state.json"), { ...emptyState(), nodes: [SAMPLE_NODE] });

    assert.equal(result.saved, false, "the caller learns the write did not happen");
    assert.equal(result.state.version, STATE_VERSION);
    assert.deepEqual(result.state.nodes, [SAMPLE_NODE], "the in-memory state is still the caller's");
    assert.ok(Number.isFinite(Date.parse(result.state.writtenAt)), "the record the caller keeps is a stamped one");
    assert.match(result.warnings[0].message, /memory only/);
  });
});

test("a state that cannot be written as JSON warns instead of throwing", () => {
  withScratch((dir) => {
    const circular = emptyState();
    circular.nodes = [{ ...SAMPLE_NODE, outbound: {} }];
    circular.nodes[0].outbound = { self: circular };

    const result = save(path.join(dir, "state.json"), circular);

    assert.equal(result.saved, false);
    assert.deepEqual(codes(result), [WARNING_CODES.STATE_INVALID]);
    assert.deepEqual(entries(dir), [], "nothing may be written, temp file included");
  });
});

test("a missing file is the first run, not a warning", () => {
  withScratch((dir) => {
    const result = load(path.join(dir, "state.json"));
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.state, emptyState());
    assert.deepEqual(result.state, DEFAULT_STATE);
    assert.equal(fs.existsSync(path.join(dir, "state.json")), false, "loading must not create anything");
  });
});

test("corrupt JSON starts from defaults with exactly one warning and no throw", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    fs.writeFileSync(target, "{ this is not json");

    const result = load(target);

    assert.deepEqual(result.state, emptyState());
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0].code, WARNING_CODES.FILE_CORRUPT);
  });
});

test("a version from another release starts from defaults with exactly one warning", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    fs.writeFileSync(target, JSON.stringify({ version: STATE_VERSION + 1, nodes: [SAMPLE_NODE] }));
    const newer = load(target);
    assert.deepEqual(newer.state, emptyState(), "a newer record must not be half-read");
    assert.equal(newer.warnings.length, 1);
    assert.equal(newer.warnings[0].code, WARNING_CODES.VERSION_MISMATCH);

    fs.writeFileSync(target, JSON.stringify({ version: 0, nodes: [SAMPLE_NODE] }));
    const older = load(target);
    assert.deepEqual(older.state, emptyState());
    assert.deepEqual(codes(older), [WARNING_CODES.VERSION_MISMATCH]);
  });
});

test("an unexpandable path and an unwritable directory are two different warnings", () => {
  withScratch((dir) => {
    const unexpandable = save("~someone/state.json", emptyState(), { homedir: dir });
    fs.writeFileSync(path.join(dir, "a-file"), "not a directory");
    const blocked = save(path.join(dir, "a-file", "state.json"), emptyState());

    assert.deepEqual(codes(unexpandable), [WARNING_CODES.PATH_UNEXPANDABLE]);
    assert.equal(unexpandable.path, null, "a path that could not be expanded has no resolved path");
    assert.deepEqual(codes(blocked), [WARNING_CODES.DIR_UNWRITABLE]);
    assert.notEqual(codes(unexpandable)[0], codes(blocked)[0], "a configuration mistake must not read as a read-only environment");
    assert.ok(!codes(unexpandable).includes(WARNING_CODES.DIR_UNWRITABLE));
    assert.ok(!codes(blocked).includes(WARNING_CODES.PATH_UNEXPANDABLE));
  });
});

// -------------------------------------------------------------- record shape

test("a full node record survives a round trip field for field", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    const state = {
      ...emptyState(),
      subscriptions: [{ url: "https://example.com/sub?token=secret", name: "sub-a", lastFetchedAt: 1700000000000, lastError: "timeout" }],
      nodes: [SAMPLE_NODE],
      portAssignment: { base: 28200 },
    };
    const written = save(target, state);
    assert.equal(written.saved, true);
    assert.equal(written.state.version, STATE_VERSION);
    assert.ok(Number.isFinite(Date.parse(written.state.writtenAt)));

    const { state: reloaded, warnings } = load(target);
    assert.deepEqual(warnings, []);
    assert.deepEqual(reloaded, written.state);
    assert.deepEqual(reloaded.subscriptions, state.subscriptions);
    assert.deepEqual(reloaded.nodes, [SAMPLE_NODE]);
  });
});

test("an unrepairable record is repaired with a warning rather than dropped", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    fs.writeFileSync(
      target,
      JSON.stringify({ version: STATE_VERSION, nodes: [{ ...SAMPLE_NODE, id: "" }], futureColumn: 7 }),
    );

    const result = load(target);

    assert.deepEqual(codes(result), [WARNING_CODES.STATE_INVALID]);
    assert.equal(result.state.nodes.length, 1, "the node is kept, minus what could not be keyed");
    assert.equal(result.state.nodes[0].status, NODE_STATUSES[1]);
  });
});

test("an empty state is a fresh copy every time", () => {
  const first = emptyState();
  const second = emptyState();
  assert.deepEqual(first, DEFAULT_STATE);
  assert.equal(first.portAssignment.base, DEFAULT_PORT_BASE);
  assert.notEqual(first, second);
  assert.notEqual(first.nodes, second.nodes);
  first.nodes.push(SAMPLE_NODE);
  first.portAssignment.base = 1;
  assert.deepEqual(DEFAULT_STATE.nodes, []);
  assert.equal(DEFAULT_STATE.portAssignment.base, DEFAULT_PORT_BASE);
  assert.equal(Object.isFrozen(DEFAULT_STATE), true);
  assert.equal(Object.isFrozen(DEFAULT_STATE.portAssignment), true);
});

// ------------------------------------------------------------------- node id

test("nodeId is stable across restarts and moves only with the dialled peer", () => {
  const params = { id: "11111111-2222-3333-4444-555555555555", security: "tls" };
  const id = nodeId("vless", "edge.example.com", 443, params);

  // Pinned: the pool keys its slot state by this value, so a change here would
  // silently orphan every recorded measurement.
  assert.equal(id, "5b53baf287fbe0ab");
  assert.match(id, /^[0-9a-f]{16}$/);
  assert.equal(nodeId("vless", "edge.example.com", 443, { security: "tls", id: params.id }), id, "key order must not matter");
  assert.equal(nodeId("VLESS", "Edge.Example.com", 443, params), id, "case must not matter");

  assert.notEqual(nodeId("vless", "other.example.com", 443, params), id);
  assert.notEqual(nodeId("vless", "edge.example.com", 8443, params), id);
  assert.notEqual(nodeId("vmess", "edge.example.com", 443, params), id);
  assert.notEqual(nodeId("vless", "edge.example.com", 443, { ...params, flow: "xtls-rprx-vision" }), id);
  assert.notEqual(nodeId("vless", "edge.example.com", 443, { ...params, id: "other-uuid" }), id);
  assert.equal(nodeId("vless", "edge.example.com", 443, { ...params, flow: undefined }), id, "an absent parameter is not a parameter");
});

test("a subscription URL is redacted for logs but recorded verbatim", () => {
  withScratch((dir) => {
    const target = path.join(dir, "state.json");
    const url = "https://user:pw@example.com/sub/abc?token=secret#frag";
    save(target, { ...emptyState(), subscriptions: [{ url, name: "s" }] });
    assert.equal(load(target).state.subscriptions[0].url, url, "the refetch source must be stored whole");
    assert.equal(redactSubscriptionUrl(url), "https://example.com/sub/abc");
  });
});
