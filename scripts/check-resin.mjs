// Live check of the Resin side, run by hand against a real Resin.
//
// It answers the one question the plugin's own tests cannot: does a second
// Account really leave from a different exit address? Everything it creates,
// it removes.
//
//   bun scripts/check-resin.mjs --url http://host:2260/PROXY_TOKEN \
//     [--admin-token ADMIN_TOKEN] [--platform Default] [--addresses 3]
//     [--timeout-ms 120000] [--tries 3]
//
// The proxy token is Resin's RESIN_PROXY_TOKEN, which is not the dashboard
// token. The admin token is optional: without it the leases this creates are
// left behind for Resin to expire on its own.
//
// Give it room. Resin binds a new Account to a node on that Account's first
// request, and on this deployment that first bind measured 37 seconds. The
// same deployment also drops a good share of connections outright, so each
// address is asked several times before it is called a failure.
import { randomBytes } from "node:crypto";
import { ResinAdmin, parseResinURL, requireForwardSupport } from "../resin.mjs";
import { forwardProxyURL } from "../provider.mjs";

const ECHO = "https://api.ipify.org";
const ZEN = "https://opencode.ai/inference/v1/chat/completions";

function options(argv) {
  const found = {};
  for (let index = 0; index < argv.length; index += 1) {
    const match = /^--([a-z-]+)(?:=(.*))?$/.exec(argv[index]);
    if (!match) throw new Error(`Unexpected argument ${argv[index]}`);
    found[match[1]] = match[2] ?? argv[++index];
  }
  return found;
}

const args = options(process.argv.slice(2));
if (!args.url) throw new Error("--url is required, like http://host:2260/PROXY_TOKEN");
requireForwardSupport("forward");
const { endpoint, token } = parseResinURL(args.url);
const platform = args.platform ?? "Default";
const addresses = Number(args.addresses ?? 3);
const prefix = `zfcheck-${randomBytes(4).toString("hex")}`;
const timeoutMs = Number(args["timeout-ms"] ?? 120000);
const tries = Number(args.tries ?? 3);
const adminToken = args["admin-token"];
const admin = adminToken
  ? new ResinAdmin({
      endpoint,
      token: adminToken,
      platform,
      log: (line) => console.log(`  ! ${line}`),
    })
  : undefined;

const failures = [];
function check(condition, description) {
  console.log(`${condition ? "✓" : "✗"} ${description}`);
  if (!condition) failures.push(description);
}

// The address a request left from, as the far end sees it: this is the
// address Zen would count the request against. A proxy that refuses the
// tunnel reports it here, with Resin's own reason header, rather than as a
// status code. A connection Resin drops is asked again, because a dropped
// connection says nothing about the exit address behind it.
async function once(account, target) {
  try {
    const response = await fetch(target, {
      proxy: forwardProxyURL({ endpoint, token, platform }, account),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const body = (await response.text()).trim();
    return { status: response.status, body, ip: target === ECHO ? body : undefined };
  } catch (error) {
    const reason = error?.headers?.get?.("x-resin-error") ?? error?.cause?.headers?.get?.("x-resin-error");
    return {
      status: error?.status ?? 0,
      reason,
      body: `${reason ? `${reason}: ` : ""}${error?.message ?? error}`,
    };
  }
}

async function egress(account, target = ECHO) {
  let result = await once(account, target);
  for (let attempt = 2; attempt <= tries && result.status !== 200; attempt += 1) {
    console.log(`  ${account}  retrying (${attempt}/${tries}): ${result.body.slice(0, 70)}`);
    result = await once(account, target);
  }
  return result;
}

const created = [];
try {
  console.log(`Resin ${endpoint} · platform ${platform} · ${addresses} addresses · prefix ${prefix}\n`);

  if (admin) {
    check(!!(await admin.resolvePlatform()), `platform ${platform} resolved through the dashboard API`);
  } else {
    console.log("· no --admin-token, so leases are neither released nor cleaned up\n");
  }

  const seen = [];
  for (let index = 1; index <= addresses; index += 1) {
    const account = `${prefix}-${index}`;
    created.push(account);
    const result = await egress(account);
    seen.push({ account, ...result });
    const note = result.ip ? "" : `  (${result.body.slice(0, 90)})`;
    console.log(`  ${account}  HTTP ${result.status}  exit ${result.ip ?? "-"}${note}`);
  }

  console.log("");
  const reached = seen.filter((entry) => entry.status === 200 && entry.ip);
  check(
    reached.length === seen.length,
    "every request went through Resin (the proxy token is the right one)",
  );
  if (reached.length === seen.length) {
    const distinct = new Set(seen.map((entry) => entry.ip)).size;
    check(
      distinct === seen.length,
      `each Account left from its own address (${distinct}/${seen.length} distinct)`,
    );
  } else {
    console.log("· addresses are not compared until every request reaches Resin");
  }

  if (admin && reached.length === seen.length) {
    const first = created[0];
    const before = seen[0].ip;
    await admin.release(first);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const after = await egress(first);
    // Reported, not asserted: dropping the lease frees the binding, and Resin
    // then picks a node again, which may be the same quickest one.
    console.log(
      `\n  ${first}: lease dropped, ${before} -> ${after.ip ?? "-"}${after.ip === before ? " (Resin picked the same address again)" : ""}`,
    );
    check(after.status === 200, "the reused Account still answers after its lease was dropped");
  } else if (admin) {
    console.log("· the lease release is not exercised until every request reaches Resin");
  }

  if (!reached.length) {
    console.log("\n· Zen is not asked until Resin accepts the proxy token");
  } else {
    const zen = await egress(`${prefix}-1`, ZEN);
    console.log(`\n  opencode.ai through Resin: HTTP ${zen.status} ${zen.body.slice(0, 160)}`);
    check(
      zen.status === 200 || /freetier|restricted|policy|upstream|rate ?limit|model/i.test(zen.body),
      "Zen answered as Zen does, so the tunnel carried a real request",
    );
  }
} finally {
  if (admin) {
    for (const account of created) await admin.release(account);
    console.log(`\nreleased ${created.length} check lease(s)`);
  } else {
    console.log(`\nleft ${created.length} lease(s) for Resin to expire: ${created.join(", ")}`);
  }
}

console.log(failures.length ? `\nFAILED: ${failures.length} check(s) did not hold` : "\nall checks held");
process.exit(failures.length ? 1 : 0);
