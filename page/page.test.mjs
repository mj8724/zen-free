import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The page is the only part of the plugin a user touches without a terminal,
// and it can fail in ways nothing else notices: a page asset the `files`
// whitelist drops (the tab then breaks on a real install), a field whose key
// does not match the option the plugin reads (the value is written and then
// silently ignored), or a save that writes `pool: {}` (which is truthy, so the
// plugin refuses to load instead of falling back to Resin).
//
// The last of those is why the save path is run for real below rather than
// pattern-matched: a small DOM stub is enough for this page, which only ever
// creates elements, sets properties and listens on the form, so the object
// handed to magpie.options.set() can be asserted directly.

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const pageSource = fs.readFileSync(path.join(here, "app.js"), "utf8");
const html = fs.readFileSync(path.join(here, "index.html"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

// ------------------------------------------------------------------ packaging

test("every page asset is one the package actually ships", () => {
  const shipped = new Set(manifest.files);
  const assets = fs.readdirSync(here).filter((name) => !name.endsWith(".test.mjs"));
  assert.ok(assets.length >= 4, `expected the page's assets, found ${assets.join(", ")}`);
  for (const asset of assets) {
    assert.ok(
      shipped.has(`page/${asset}`),
      `page/${asset} is not in package.json "files", so it would be missing from an installed copy`,
    );
  }
});

test("the page magpie is told to open is one that exists", () => {
  const page = manifest.magpie?.page;
  assert.ok(page, 'package.json has no magpie.page, so magpie shows no tab for this plugin');
  for (const key of ["file", "icon"]) {
    const relative = page[key];
    assert.ok(relative, `magpie.page.${key} is missing`);
    assert.ok(fs.existsSync(path.join(root, relative)), `magpie.page.${key} points at a missing ${relative}`);
  }
  assert.ok(page.title, "magpie.page.title is missing");
});

test("the page's own test does not ship", () => {
  assert.ok(
    !manifest.files.some((entry) => entry.includes("test")),
    "a test file is in package.json files; the whitelist must name shipped files only",
  );
});

// ------------------------------------------------------------------ html shape

test("index.html loads its scripts in the order they depend on", () => {
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((match) => match[1]);
  const at = (needle) => scripts.findIndex((src) => src.includes(needle));
  const guardAt = at("guard.js");
  const bridgeAt = at("_magpie/bridge.js");
  const appAt = at("app.js");
  assert.ok(guardAt !== -1, "index.html does not load guard.js");
  assert.ok(bridgeAt !== -1, "index.html does not load the bridge");
  assert.ok(appAt !== -1, "index.html does not load app.js");
  // The order is load-bearing: guard.js can only filter errors if it registers
  // its listener before the bridge registers its own (both are on the window).
  assert.ok(guardAt < bridgeAt, "guard.js must be loaded before the bridge");
  assert.ok(bridgeAt < appAt, "app.js is loaded before the bridge that installs `magpie`");

  // The page's policy allows its own files only: an inline script, or an
  // attribute that is one, is refused outright.
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    assert.match(match[1], /\bsrc=/, `<script${match[1]}> has no src`);
    assert.equal(match[2].trim(), "", "index.html has an inline script");
  }
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "index.html uses an inline event handler");
  assert.match(html, /rel="stylesheet"\s+href="style\.css"/, "index.html does not load style.css");
});

// ------------------------------------------------------- the option contract

test("the keys the page writes are the options the plugin reads", () => {
  const keys = [...pageSource.matchAll(/\bkey:\s*"([^"]+)"/g)].map((match) => match[1]);
  assert.ok(keys.length >= 25, `expected the full form, found ${keys.length} fields`);

  const sources = ["provider.mjs", "pool/exits.mjs", "pool/core.mjs", "pool/probe.mjs", "pool/sources.mjs"]
    .map((file) => fs.readFileSync(path.join(root, file), "utf8"))
    .join("\n");

  for (const key of keys) {
    const leaf = key.split(".").pop();
    // The plugin reads these as property accesses on `raw`, `coreConfig`,
    // `probeConfig` or `options`; any spelling that appears at all is a key
    // that reaches it, and a typo here is a field that silently does nothing.
    assert.ok(
      new RegExp(`\\b${leaf}\\b`).test(sources),
      `the page writes ${key}, which no plugin module reads`,
    );
  }
});

test("the page offers the options that decide which exit the traffic leaves from", () => {
  for (const key of [
    "pool.subscriptions",
    "pool.manual",
    "pool.maxNodes",
    "pool.distinctIps",
    "pool.allowUnpinnedNodes",
    "pool.attempts",
    "pool.core.binary",
    "pool.core.portBase",
    "pool.probe.zenUrl",
    "pool.probe.neutralUrls",
    "pool.probe.minDistinctIps",
    "resin.url",
    "resin.transport",
  ]) {
    assert.match(pageSource, new RegExp(`key: "${key.replace(/\./g, "\\.")}"`), `the page has no field for ${key}`);
  }
});

// ------------------------------------------------- errors that are not ours

// magpie's bridge forwards every error event in the frame to the window, which
// then replaces the page with "this page stopped working". guard.js has to stop
// that for errors that are not this page's without hiding this page's own. It is
// run here the same way the browser runs it: as a classic script in the global
// scope, against a stubbed window.
const guardSource = fs.readFileSync(path.join(here, "guard.js"), "utf8");
const PAGE = "https://magpie.test/_magpie/plugin/tok/index.html";
const OWN_SCRIPTS = [
  "https://magpie.test/_magpie/plugin/tok/guard.js",
  "https://magpie.test/_magpie/plugin/tok/app.js",
];

// Runs guard.js against a stubbed window and returns a firer per event, each
// reporting whether guard.js stopped that event from being forwarded.
function installGuard(scripts = OWN_SCRIPTS, href = PAGE) {
  const registered = [];
  globalThis.location = { href };
  globalThis.document = { scripts: scripts.map((src) => ({ src })) };
  globalThis.addEventListener = (type, listener, capture) => registered.push({ type, listener, capture });
  new Function(guardSource)();

  // The bridge forwards on both of these, so the guard has to sit in front of
  // both. Capture phase, and registered first, because an error event is
  // dispatched at the window itself and listeners there run in that order.
  function firer(type) {
    const entry = registered.find((item) => item.type === type);
    assert.ok(entry, `guard.js registered no ${type} listener`);
    assert.equal(entry.capture, true, `guard.js must listen in the capture phase for ${type}`);
    return (event) => {
      let stopped = false;
      entry.listener({
        message: "",
        filename: "",
        error: undefined,
        reason: undefined,
        stopImmediatePropagation() {
          stopped = true;
        },
        ...event,
      });
      return stopped;
    };
  }

  return { error: firer("error"), rejection: firer("unhandledrejection") };
}

test("an injected script's error is not passed off as this page's", () => {
  const { error } = installGuard();
  // Injected code runs as the frame's own origin, so its message survives; a
  // file magpie serves is cross-origin to that opaque origin and does not.
  assert.equal(error({ message: "Uncaught Error: Failed to connect to MetaMask" }), true);
  assert.equal(error({ message: "boom", filename: "chrome-extension://abcdef/inpage.js" }), true);
});

test("this page's own errors are still forwarded", () => {
  const { error } = installGuard();
  assert.equal(error({ message: "Script error." }), false, "a sanitized file error is this page's");
  assert.equal(error({ message: "" }), false, "an empty message is this page's");
  assert.equal(
    error({ message: "boom", filename: "https://magpie.test/_magpie/plugin/tok/app.js" }),
    false,
    "an error naming a declared script is this page's",
  );
  assert.equal(
    error({ message: "boom", error: { fileName: "https://magpie.test/_magpie/plugin/tok/guard.js" } }),
    false,
    "the error object's fileName counts too",
  );
});

test("an error that cannot name a declared script is not this page's", () => {
  const { error } = installGuard();
  assert.equal(error({ message: "boom", filename: "weird source" }), true);
  assert.equal(error({ message: "boom", filename: "https://elsewhere.test/x.js" }), true);
});

// MetaMask reaches the bridge through the rejection path, not the error one,
// and it does so with either an Error or a bare string. Measured in the same
// sandboxed frame magpie uses: a rejection raised by the page's own code does
// not raise this event at all, so an unattributable one here is injected.
test("an injected rejection is not passed off as this page's", () => {
  const { rejection } = installGuard();
  assert.equal(rejection({ reason: new Error("Failed to connect to MetaMask") }), true);
  assert.equal(rejection({ reason: "Failed to connect to MetaMask" }), true);
  // a stack that leads elsewhere is no more this page's than no stack at all
  const elsewhere = new Error("boom");
  elsewhere.stack = "Error: boom\n    at https://elsewhere.test/x.js:1:1";
  assert.equal(rejection({ reason: elsewhere }), true);
});

test("a rejection that names one of this page's scripts is still forwarded", () => {
  const { rejection } = installGuard();
  const owned = new Error("boom in our own code");
  owned.stack = "Error: boom\n    at https://magpie.test/_magpie/plugin/tok/app.js:42:7";
  assert.equal(rejection({ reason: owned }), false);
});

// ------------------------------------------------------- the save path, run

class StubNode {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.className = "";
    this.text = undefined;
    this.listeners = new Map();
    this.style = { setProperty() {} };
    this.classList = {
      add: (name) => {
        this.className = `${this.className} ${name}`.trim();
      },
    };
  }
  set id(value) {
    this._id = value;
    registry.set(value, this);
  }
  get id() {
    return this._id;
  }
  set textContent(value) {
    this.childNodes = [];
    this.text = value;
  }
  get textContent() {
    if (this.childNodes.length) return this.childNodes.map((child) => child.textContent).join("");
    return this.text ?? "";
  }
  append(...nodes) {
    this.childNodes.push(...nodes);
  }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  async fire(type) {
    for (const listener of this.listeners.get(type) ?? []) await listener();
  }
}

const registry = new Map();

function installDom() {
  registry.clear();
  for (const id of ["form", "save", "revert", "status", "notice"]) {
    const node = new StubNode("div");
    node.id = id;
  }
  globalThis.document = {
    createElement: (tag) => new StubNode(tag),
    getElementById: (id) => registry.get(id) ?? null,
  };
}

// Runs the page against `options`, returns { saved, control } where control
// reaches a field by its dotted key.
async function runPage(options) {
  installDom();
  let saved;
  globalThis.magpie = {
    ready: Promise.resolve({ dark: false, lang: "en", tokens: {} }),
    options: {
      get: async () => options,
      set: async (next) => {
        saved = next;
        return next;
      },
    },
  };
  // The page is a classic script: compiling it in the global scope is exactly
  // how the browser runs it.
  new Function(pageSource)();
  await new Promise((resolve) => setTimeout(resolve, 0));

  return {
    control: (key) => {
      const node = registry.get(`f-${key}`);
      assert.ok(node, `the page has no control for ${key}`);
      return node;
    },
    save: () => registry.get("save").fire("click"),
    get saved() {
      return saved;
    },
  };
}

test("an untouched empty form saves almost nothing", async () => {
  const page = await runPage({});
  await page.save();
  // The rule that matters: no nodes means no pool at all, because `pool: {}`
  // is truthy and makes the plugin refuse to load.
  assert.equal(page.saved.pool, undefined, "an empty form must not save a pool");
  assert.equal(page.saved.resin, undefined, "an empty form must not save resin settings");
});

test("a pool with settings but no nodes is dropped, not saved", async () => {
  const page = await runPage({});
  page.control("pool.core.binary").value = "/opt/sing-box";
  page.control("pool.maxNodes").value = "20";
  await page.save();
  assert.equal(
    page.saved.pool,
    undefined,
    "pool settings without a single node would make the plugin refuse to load",
  );
});

test("subscription lines become the shape pool/sources.mjs reads", async () => {
  const page = await runPage({});
  page.control("pool.subscriptions").value =
    "https://one.example/sub?token=a\n机场A | https://two.example/api/v1/client/subscribe?token=b\n\n";
  page.control("pool.maxNodes").value = "12";
  await page.save();

  assert.deepEqual(page.saved.pool.subscriptions, [
    "https://one.example/sub?token=a",
    { name: "机场A", url: "https://two.example/api/v1/client/subscribe?token=b" },
  ]);
  assert.equal(page.saved.pool.maxNodes, 12, "a number field must not save a string");
});

test("hand-typed nodes keep an object line intact", async () => {
  const page = await runPage({});
  page.control("pool.manual").value =
    '1.2.3.4:8080\nvless://uuid@host:443?type=ws\n{"type":"socks","server":"5.6.7.8","server_port":1080}';
  await page.save();
  assert.deepEqual(page.saved.pool.manual, [
    "1.2.3.4:8080",
    "vless://uuid@host:443?type=ws",
    { type: "socks", server: "5.6.7.8", server_port: 1080 },
  ]);
});

test("an empty field is left out so the plugin's own default applies", async () => {
  const page = await runPage({});
  page.control("pool.subscriptions").value = "https://one.example/sub";
  await page.save();
  assert.equal(page.saved.pool.maxNodes, undefined, "an empty number field must not be written");
  assert.equal(
    page.saved.pool.allowUnpinnedNodes,
    true,
    "a switch is always written: it is on by default and its off state has to be expressible",
  );
});

test("a save keeps everything the page does not know about", async () => {
  const page = await runPage({
    pool: { subscriptions: ["https://one.example/sub"], futureOption: "kept" },
    somethingNew: { nested: true },
    headerTimeoutMs: 30000,
  });
  page.control("headerTimeoutMs").value = "45000";
  await page.save();

  assert.equal(page.saved.somethingNew.nested, true, "an unknown top-level key must survive a save");
  assert.equal(page.saved.pool.futureOption, "kept", "an unknown pool key must survive a save");
  assert.equal(page.saved.headerTimeoutMs, 45000);
});

test("resin is only saved with the address it needs", async () => {
  const page = await runPage({});
  page.control("resin.adminToken").value = "admin-secret";
  page.control("resin.addresses").value = "4";
  await page.save();
  assert.equal(page.saved.resin, undefined, "resin without a url is dropped");

  const page2 = await runPage({});
  page2.control("resin.url").value = "http://192.0.2.1:2260/token";
  page2.control("resin.transport").value = "reverse";
  await page2.save();
  assert.deepEqual(page2.saved.resin, { url: "http://192.0.2.1:2260/token", transport: "reverse" });
});
