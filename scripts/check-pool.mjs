// Real-machine check for the self-hosted pool, run by hand against a real
// sing-box and the user's own nodes.
//
//   bun scripts/check-pool.mjs --binary /path/to/sing-box \
//     --subscription 'https://provider/sub?token=...' \
//     [--manual 'ip:port,http://user:pass@host:port'] [--max-nodes 8]
//
// It answers the question unit tests cannot: on THIS machine, with THESE
// nodes, does the core come up from the generated config and does a completion
// actually come back through an exit address?
//
// What it deliberately does not claim: that rotation works. Forcing a real
// 403/429/500 from a target that is reachable through a remote exit address
// needs a target we control on the public internet, and a loopback stand-in
// cannot be reached through a remote node at all. Rotation on those statuses is
// covered instead by provider-resin.test.mjs and pool/exits.test.mjs against a
// real proxy test double, and was observed live against Resin (a 429, a 403
// policy refusal and a 500 upstream error each answered from a different exit
// IP). This script reports the rotation budget so the run is interpretable.

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZenFreePlugin } from "../index.mjs";

function options(argv) {
  const found = { flags: new Set() };
  for (let index = 0; index < argv.length; index += 1) {
    const match = /^--([a-z-]+)(?:=(.*))?$/.exec(argv[index]);
    if (!match) throw new Error(`Unexpected argument ${argv[index]}`);
    if (match[2] === undefined && (argv[index + 1] === undefined || argv[index + 1].startsWith("--"))) {
      found.flags.add(match[1]);
      continue;
    }
    found[match[1]] = match[2] ?? argv[++index];
  }
  return found;
}

const args = options(process.argv.slice(2));
if (args.flags.has("help")) {
  console.log(`Usage: bun scripts/check-pool.mjs --binary <sing-box> [--subscription <url>] [--manual 'a,b']
       [--max-nodes 8] [--attempts 3] [--model <id>] [--timeout-ms 90000]

  --binary        the sing-box to run (omit to let the plugin provision one)
  --subscription  a subscription URL to take nodes from
  --manual        comma-separated node lines: host:port, http://user:pass@host:port, vless://..., ...
  --max-nodes     how many nodes to take (default 8)
  --model         which free model to ask for; the first discovered one by default`);
  process.exit(0);
}
if (!args["binary"] && !args["subscription"] && !args["manual"]) {
  console.error(
    "Nothing to check: pass --binary (the core) and at least one of --subscription or --manual (the nodes).\n" +
      "Run with --help for the full list.",
  );
  process.exit(2);
}

const failures = [];
function check(condition, description) {
  console.log(`${condition ? "✓" : "✗"} ${description}`);
  if (!condition) failures.push(description);
}

const statePath = join(mkdtempSync(join(tmpdir(), "zen-pool-check-")), "state.json");
const attempts = Number(args["attempts"] ?? 3);
console.log(`pool check · core: ${args["binary"] ?? "(provisioned)"} · up to ${args["max-nodes"] ?? 8} nodes · ${attempts} retr${attempts === 1 ? "y" : "ies"} per request\n`);

const auth = async () => ({ type: "api", key: "public" });
let hooks;
try {
  hooks = await ZenFreePlugin(
    { project: {} },
    {
      headerTimeoutMs: Number(args["timeout-ms"] ?? 90_000),
      pool: {
        subscriptions: args["subscription"] ? [{ url: args["subscription"] }] : [],
        manual: args["manual"] ? args["manual"].split(",").map((line) => line.trim()).filter(Boolean) : [],
        core: args["binary"] ? { binary: args["binary"] } : {},
        maxNodes: Number(args["max-nodes"] ?? 8),
        attempts,
        probe: { timeoutMs: 15_000, concurrency: 8 },
        statePath,
      },
    },
  );
  check(true, "the plugin loaded with a pool (a pool that cannot work throws here instead)");
} catch (error) {
  check(false, `the plugin refused to load: ${error?.message ?? error}`);
  process.exit(1);
}

try {
  const models = await hooks.provider.models({ models: {} }, { auth: await auth() });
  const ids = Object.keys(models ?? {});
  check(ids.length > 0, `Zen's free models were discovered (${ids.length})`);
  const model = args["model"] ?? ids[0];
  console.log(`  asking for ${model}\n`);

  const loader = await hooks.auth.loader(auth);
  const started = Date.now();
  const response = await loader.fetch("https://opencode.ai/inference/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Reply with the single word OK" }],
      stream: true,
    }),
  });
  const text = await response.text();
  const answer = [...text.matchAll(/"content":"([^"]*)"/g)].map((match) => match[1]).join("");
  check(response.status === 200, `a completion came back through the pool (HTTP ${response.status}, ${Date.now() - started}ms)`);
  check(text.includes("[DONE]"), "it was a whole stream, [DONE] and all");
  check(answer.trim() !== "", `it carried an answer: ${JSON.stringify(answer.slice(0, 60))}`);

  // What the pool measured about the addresses it was given. This is the number
  // the user actually cares about: nodes are not IPs.
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  try {
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    const measured = state.nodes.filter((node) => node.lastExitIp);
    const distinct = new Set(measured.map((node) => node.lastExitIp));
    console.log(
      `\n  ${state.nodes.length} node(s) in the pool; ${measured.length} measured an exit address; ${distinct.size} distinct IP(s)`,
    );
    for (const node of measured.slice(0, 10)) {
      console.log(`    ${node.id}  ${node.scheme.padEnd(10)} ${String(node.lastExitIp).padEnd(30)} ${node.probeEwmaMs?.zen ?? "-"}ms`);
    }
    if (measured.length > 0) {
      check(distinct.size > 1 || measured.length === 1, `the pool leaves from ${distinct.size} distinct address(es)`);
    } else {
      console.log("  · no address measured yet (probing had not finished); run again to see it");
    }
  } catch (error) {
    console.log(`  · could not read the state file yet: ${error?.message ?? error}`);
  }
} catch (error) {
  check(false, `the request failed: ${error?.message ?? error}`);
} finally {
  // The core reclaims its child synchronously when this process exits, which
  // is the same path magpie relies on.
}

console.log(failures.length ? `\nFAILED: ${failures.length} check(s) did not hold` : "\nall checks held");
process.exit(failures.length ? 1 : 0);
