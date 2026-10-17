// The pool's settings, as a page in magpie's own window.
//
// A page has almost no powers: its policy is connect-src 'none', so there is
// no network, and there are no files and no magpie API behind it either. The
// one thing it reads and writes is the plugin's own options — the object
// magpie keeps in plugins.json and hands the plugin as its second argument.
// So this page is a form over that object, and nothing else.
//
// Two rules it has to keep, both about not breaking the plugin it configures:
//
//   1. options.set() replaces the whole object. What is saved is therefore the
//      form's values applied over the object that was already there, never a
//      fresh object built from the form alone: a key this page does not know
//      about must survive a save.
//   2. `pool: {}` is truthy, and the pool refuses to start with no nodes
//      ("no usable node ... refusing to start rather than sending traffic out
//      directly"), so an empty pool is worse than no pool: it takes the Resin
//      fallback away and breaks the plugin. An empty pool is dropped, not
//      saved, and the page says so.
(async () => {
  await magpie.ready;

  const original = (await magpie.options.get()) ?? {};

  // Containers this page owns. Pruned deepest first: pool.core and pool.probe
  // going away can leave pool empty in the same save.
  const CONTAINERS = ["pool.core", "pool.probe", "pool", "resin"];

  const SCHEMA = [
    {
      title: "出口源",
      open: true,
      note: "请求从哪个 IP 出去。两处都留空就是直连 —— 而 Zen 免费层对不像 OpenCode 发来的请求一律回 403 FreeTierError，插件等于用不了。",
      fields: [
        {
          key: "pool.subscriptions",
          kind: "urls",
          label: "订阅链接",
          hint: "每行一个。可以写成「名称 | 链接」，日志和告警里就用这个名字。支持 base64 包裹的 URI 行、明文 URI 行、sing-box JSON、host:port 列表；Clash YAML 不支持，遇到会明确报错。",
          placeholder: "https://provider.example/sub?token=…\n机场A | https://another.example/api/v1/client/subscribe?token=…",
        },
        {
          key: "pool.manual",
          kind: "lines",
          label: "手填节点",
          hint: "每行一个：host:port、http://user:pass@host:port、socks5://…、vless://…、trojan://…、hysteria2://…，也可以直接粘一个 sing-box outbound JSON 对象。",
          placeholder: "1.2.3.4:8080\nsocks5://user:pass@5.6.7.8:1080\nvless://uuid@host:443?type=ws&security=tls",
        },
      ],
    },
    {
      title: "sing-box 内核",
      note: "默认自动安装：本机没有 sing-box 时自己下载、校验、解压到状态目录。",
      fields: [
        {
          key: "pool.core.binary",
          kind: "text",
          label: "内核路径",
          hint: "留空 = 先在 PATH 里找 sing-box，找不到就自动下载。",
          placeholder: "sing-box",
        },
        {
          key: "pool.core.download",
          kind: "bool",
          label: "允许自动下载内核",
          def: true,
          hint: "关掉之后内核必须已经在 PATH 上或由上面指定。",
        },
        {
          key: "pool.core.portBase",
          kind: "number",
          label: "本地端口起点",
          def: 28100,
          min: 1,
          max: 65535,
          hint: "第 i 个节点用 portBase + i。节点多的时候会占一段连续端口。",
        },
        {
          key: "pool.core.stateDir",
          kind: "text",
          label: "状态目录",
          hint: "内核与池状态（节点表、延迟、出口 IP）放这里，留空 = magpie 配置目录下的 zen-free。",
        },
        {
          key: "pool.statePath",
          kind: "text",
          label: "状态文件路径",
          hint: "留空 = 状态目录下的 zen-free-pool.json。",
        },
      ],
    },
    {
      title: "池子与换 IP",
      note: "只在出错时换，不出错就一直用同一个 IP。",
      fields: [
        {
          key: "pool.maxNodes",
          kind: "number",
          label: "最多托管节点数",
          def: 300,
          min: 1,
          max: 1000,
          hint: "每个节点占一个本地监听端口。",
        },
        {
          key: "pool.distinctIps",
          kind: "bool",
          label: "按真实出口 IP 去重排序",
          def: true,
          hint: "同出口 IP 的节点排到后面（不删，所以不会动到已经生成的配置）。",
        },
        {
          key: "pool.allowUnpinnedNodes",
          kind: "bool",
          label: "允许没有证书 pin 的节点",
          def: true,
          hint: "SNI 是伪装的时候，pin 才是认证节点的东西，而 sing-box 1.14.3 带不了证书 hash（要 1.15.0）。关掉会损失相当一部分节点。开着这些节点走 tls.insecure。",
        },
        {
          key: "pool.attempts",
          kind: "number",
          label: "每次请求最多额外重试",
          def: 3,
          min: 0,
          max: 10,
          hint: "换 IP 在响应交出去之前完成，对 agent 透明；流式回复开始吐内容之后不重试。",
        },
        {
          key: "pool.refreshTickMs",
          kind: "number",
          label: "后台复查间隔（毫秒）",
          def: 60000,
          min: 1000,
          hint: "定时唤醒去看有没有节点该重新测延迟，默认 60000（1 分钟）。它只决定「什么时候看一眼」，不决定测哪些节点。",
        },
      ],
    },
    {
      title: "延迟测试",
      note: "两个目标分开存：到 Zen 的真实延迟，和中立目标。中立目标同时用来解析真实出口 IP。",
      fields: [
        {
          key: "pool.probe.zenUrl",
          kind: "text",
          label: "Zen 延迟目标",
          placeholder: "https://opencode.ai/inference/v1/models",
          hint: "默认打 /models，不耗额度。",
        },
        {
          key: "pool.probe.neutralUrls",
          kind: "lines",
          label: "中立延迟目标",
          hint: "每行一个，按顺序回退。留空用默认：ifconfig.me/ip → www.cloudflare.com/cdn-cgi/trace → api.ip.sb/ip。",
          placeholder: "https://ifconfig.me/ip\nhttps://www.cloudflare.com/cdn-cgi/trace",
        },
        {
          key: "pool.probe.timeoutMs",
          kind: "number",
          label: "探测超时（毫秒）",
          def: 8000,
          min: 1,
        },
        {
          key: "pool.probe.concurrency",
          kind: "number",
          label: "探测并发",
          def: 16,
          min: 1,
          max: 256,
        },
        {
          key: "pool.probe.minDistinctIps",
          kind: "number",
          label: "最少出口 IP 数",
          def: 10,
          min: 1,
          hint: "低于这个数就在日志里告警：节点可能共用出口，限流不会像节点数看起来那样分散。",
        },
        {
          key: "pool.probe.activeRefreshMs",
          kind: "number",
          label: "在用节点复测间隔（毫秒）",
          def: 600000,
          min: 1000,
          hint: "正在用的那个地址多久重测一次，默认 600000（10 分钟），也就是约 6 次/小时。",
        },
        {
          key: "pool.probe.staleMs",
          kind: "number",
          label: "备用节点复测间隔（毫秒）",
          def: 3600000,
          min: 1000,
          hint: "实测最快的几个备用地址多久重测一次，默认 3600000（1 小时），也就是约 8 次/小时。探测要花掉出口 IP，所以这两个数是真实成本。",
        },
      ],
    },
    {
      title: "Resin 降级",
      note: "只在没有配置 pool 的时候生效。pool 和 resin 同时有值时走 pool。",
      fields: [
        {
          key: "resin.url",
          kind: "text",
          label: "Resin 代理地址",
          placeholder: "http://host:2260/<代理令牌>",
          hint: "这里要的是代理令牌（RESIN_PROXY_TOKEN），不是面板令牌。",
        },
        {
          key: "resin.adminToken",
          kind: "secret",
          label: "Resin 管理令牌",
          hint: "面板令牌，用来在固定 IP 用尽时释放地址。",
        },
        {
          key: "resin.platform",
          kind: "text",
          label: "平台",
          placeholder: "Default",
        },
        {
          key: "resin.account",
          kind: "text",
          label: "账号前缀",
          def: "zen-free",
          hint: "用来在 Resin 上区分这批地址的账号名，只能用字母、数字、点、减号、下划线。留空则用 zen-free。",
        },
        {
          key: "resin.addresses",
          kind: "number",
          label: "并发地址数",
          def: 8,
          min: 1,
        },
        {
          key: "resin.transport",
          kind: "select",
          label: "传输方式",
          options: ["forward", "reverse"],
          emptyLabel: "（默认 forward）",
        },
      ],
    },
    {
      title: "高级",
      note: "一般不用改。",
      fields: [
        {
          key: "headerTimeoutMs",
          kind: "number",
          label: "响应头超时（毫秒）",
          def: 120000,
          min: 1,
          hint: "只约束等响应头的时间；一旦开始收正文，就交给调用方自己的超时。",
        },
        {
          key: "baseURL",
          kind: "text",
          label: "Zen API 地址",
          placeholder: "https://opencode.ai/inference/v1",
        },
        {
          key: "catalogURL",
          kind: "text",
          label: "模型目录地址",
          placeholder: "https://models.opencode.ai/api.json",
        },
        {
          key: "docsURL",
          kind: "text",
          label: "文档地址（取候选模型用）",
        },
      ],
    },
  ];

  // ------------------------------------------------------------------ helpers

  const getPath = (root, path) =>
    path.split(".").reduce((node, key) => (node == null ? undefined : node[key]), root);

  function setPath(root, path, value) {
    const keys = path.split(".");
    const last = keys.pop();
    let node = root;
    for (const key of keys) {
      if (node[key] == null || typeof node[key] !== "object") node[key] = {};
      node = node[key];
    }
    node[last] = value;
  }

  function deletePath(root, path) {
    const keys = path.split(".");
    const last = keys.pop();
    let node = root;
    for (const key of keys) {
      if (node == null || typeof node[key] !== "object") return;
      node = node[key];
    }
    if (node && typeof node === "object") delete node[last];
  }

  const isEmptyObject = (value) =>
    !!value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;

  // Options are plain JSON, so this is enough and works everywhere.
  const clone = (value) => (value === undefined ? {} : JSON.parse(JSON.stringify(value)));

  function parseLines(text) {
    const out = [];
    for (const line of String(text).split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("{")) {
        try {
          out.push(JSON.parse(trimmed));
          continue;
        } catch {
          // not an object after all; keep it as a node line to be reported
        }
      }
      out.push(trimmed);
    }
    return out.length ? out : undefined;
  }

  const formatLines = (value) =>
    (Array.isArray(value) ? value : [])
      .map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry)))
      .join("\n");

  function parseUrls(text) {
    const out = [];
    for (const line of String(text).split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const at = trimmed.indexOf(" | ");
      if (at > 0) {
        const name = trimmed.slice(0, at).trim();
        const url = trimmed.slice(at + 3).trim();
        if (name && url) {
          out.push({ name, url });
          continue;
        }
      }
      out.push(trimmed);
    }
    return out.length ? out : undefined;
  }

  const formatUrls = (value) =>
    (Array.isArray(value) ? value : [])
      .map((entry) => {
        if (typeof entry === "string") return entry;
        const url = entry?.url ?? "";
        if (!url) return "";
        return entry?.name ? `${entry.name} | ${url}` : url;
      })
      .filter(Boolean)
      .join("\n");

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  // ------------------------------------------------------------------ render

  const controls = new Map();

  function buildField(field) {
    const wrap = el("div", "field");
    const input = document.createElement(
      field.kind === "lines" || field.kind === "urls"
        ? "textarea"
        : field.kind === "select"
          ? "select"
          : field.kind === "bool"
            ? "input"
            : "input",
    );

    const current = getPath(original, field.key);

    if (field.kind === "bool") {
      wrap.classList.add("check");
      input.type = "checkbox";
      input.checked = typeof current === "boolean" ? current : field.def === true;
      input.id = `f-${field.key}`;
      const text = el("div", "text");
      const label = el("label", "label", field.label);
      label.htmlFor = input.id;
      text.append(label);
      if (field.hint) text.append(el("span", "hint", field.hint));
      wrap.append(input, text);
      controls.set(field.key, input);
      return wrap;
    }

    const label = el("label", "label", field.label);
    label.htmlFor = `f-${field.key}`;
    wrap.append(label);
    if (field.hint) wrap.append(el("span", "hint", field.hint));

    if (field.kind === "lines" || field.kind === "urls") {
      input.value = field.kind === "urls" ? formatUrls(current) : formatLines(current);
      input.rows = 4;
      input.placeholder = field.placeholder ?? "";
      input.spellcheck = false;
    } else if (field.kind === "select") {
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = field.emptyLabel ?? "（默认）";
      input.append(empty);
      for (const option of field.options ?? []) {
        const node = document.createElement("option");
        node.value = option;
        node.textContent = option;
        input.append(node);
      }
      input.value = typeof current === "string" ? current : "";
    } else {
      input.type = field.kind === "secret" ? "password" : field.kind === "number" ? "number" : "text";
      if (field.kind === "number") {
        if (field.min !== undefined) input.min = String(field.min);
        if (field.max !== undefined) input.max = String(field.max);
        input.value = typeof current === "number" ? String(current) : "";
        // The effective default, shown rather than written: leaving it empty
        // keeps the option out of plugins.json and lets the plugin's own
        // default apply.
        input.placeholder = field.def === undefined ? "" : `${field.def}（默认）`;
      } else {
        input.value = typeof current === "string" ? current : "";
        input.placeholder = field.placeholder ?? "";
        input.spellcheck = false;
      }
    }

    input.id = `f-${field.key}`;
    wrap.append(input);
    controls.set(field.key, input);
    return wrap;
  }

  function render() {
    const form = document.getElementById("form");
    form.textContent = "";
    controls.clear();
    for (const group of SCHEMA) {
      const details = el("details", "sec");
      if (group.open) details.open = true;
      const summary = document.createElement("summary");
      summary.append(el("h2", null, group.title));
      details.append(summary);
      const body = el("div", "body");
      if (group.note) body.append(el("p", "note", group.note));
      for (const field of group.fields) body.append(buildField(field));
      details.append(body);
      form.append(details);
    }
    refreshNotice();
  }

  // ------------------------------------------------------------------ collect

  function readField(field) {
    const input = controls.get(field.key);
    if (field.kind === "bool") return input.checked;
    if (field.kind === "number") {
      const text = input.value.trim();
      if (!text) return undefined;
      const value = Number(text);
      return Number.isFinite(value) ? value : undefined;
    }
    if (field.kind === "lines") return parseLines(input.value);
    if (field.kind === "urls") return parseUrls(input.value);
    const text = input.value.trim();
    return text === "" ? undefined : text;
  }

  function collect() {
    const next = clone(original);
    const dropped = [];

    for (const group of SCHEMA) {
      for (const field of group.fields) {
        const value = readField(field);
        if (value === undefined) deletePath(next, field.key);
        else setPath(next, field.key, value);
      }
    }

    for (const path of CONTAINERS) {
      if (isEmptyObject(getPath(next, path))) deletePath(next, path);
    }

    // A configured-but-empty pool is the one shape that breaks the plugin, so
    // it is dropped rather than saved.
    const pool = getPath(next, "pool");
    if (pool) {
      const sources = (getPath(next, "pool.subscriptions")?.length ?? 0) + (getPath(next, "pool.manual")?.length ?? 0);
      if (sources === 0) {
        deletePath(next, "pool");
        dropped.push("没有节点，pool 配置没有保存（留着它插件会拒绝加载）");
      }
    }

    if (getPath(next, "resin") && !getPath(next, "resin.url")) {
      deletePath(next, "resin");
      dropped.push("没有代理地址，resin 配置没有保存");
    }

    return { next, dropped };
  }

  // ------------------------------------------------------------------ notice

  function describe(next) {
    const sources = (getPath(next, "pool.subscriptions")?.length ?? 0) + (getPath(next, "pool.manual")?.length ?? 0);
    const resin = getPath(next, "resin.url");
    if (sources > 0) {
      return { tone: "", text: `出口：自建代理池，${sources} 个来源条目。` };
    }
    if (resin) {
      return { tone: "", text: "出口：Resin（降级路径）。" };
    }
    return {
      tone: "bad",
      text: "出口：直连 —— Zen 免费层会回 403 FreeTierError，插件用不了。填订阅链接或手填节点。",
    };
  }

  function refreshNotice() {
    const { next, dropped } = collect();
    const box = document.getElementById("notice");
    box.textContent = "";
    const why = describe(next);
    const line = el("div", `notice${why.tone ? ` ${why.tone}` : ""}`);
    line.append(el("b", null, why.text));
    box.append(line);
    for (const message of dropped) {
      const note = el("div", "notice warn");
      note.append(el("b", null, message));
      box.append(note);
    }
  }

  // ------------------------------------------------------------------ save

  const status = document.getElementById("status");
  function say(message, tone) {
    status.textContent = message;
    status.className = `status${tone ? ` ${tone}` : ""}`;
  }

  document.getElementById("save").addEventListener("click", async () => {
    const button = document.getElementById("save");
    button.disabled = true;
    say("保存中…");
    try {
      const { next, dropped } = collect();
      const saved = await magpie.options.set(next);
      // set() answers with what it kept: make that the new starting point so a
      // second save does not resurrect a key magpie dropped.
      const fresh = clone(saved ?? next);
      for (const key of Object.keys(original)) delete original[key];
      Object.assign(original, fresh);
      render();
      say(dropped.length ? "已保存（有配置被忽略，见上方）" : "已保存，插件会重新加载", dropped.length ? "err" : "ok");
    } catch (error) {
      say(`保存失败：${error?.message ?? error}`, "err");
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("revert").addEventListener("click", () => {
    render();
    say("已放弃修改");
  });

  // Attached once, on the form itself: render() replaces the form's children,
  // not the form, so this survives every re-render without stacking up.
  const form = document.getElementById("form");
  form.addEventListener("input", refreshNotice);
  form.addEventListener("change", refreshNotice);

  render();
  say("");
})();
