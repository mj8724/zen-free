# OpenCode Zen Free · 自建代理池

在 [magpie](https://usemagpie.ai) 和 OpenCode 里使用 OpenCode Zen 的免费模型，**出口 IP 由插件自己管理的代理池提供**（sing-box 内核）。

供应商 id 仍是 `opencode-zen-free`，所以 `opencode-zen-free/<模型>` 的用法不变。

为什么要这样：Zen 免费额度按**出口 IP** 计算，一个凭证换着 IP 用就能绕开单 IP 限制。而坑在于——**订阅里「一个节点」不等于「一个 IP」**。实测你那份订阅：16 个节点探活后 8 个可达，8 个出口 IP 全不同；5 个 hysteria2 节点 → 5 个不同 IP。所以池子必须测延迟、必须解析真实出口 IP，否则你以为有 300 个 IP，其实可能只有几个。

## 架构

```
Zen 请求
  └─ rotate()                     失败分类 + 透明重试 + 池状态机（已测）
       └─ http://127.0.0.1:<port>         每个节点一个本地端口
            └─ sing-box（1 个进程，N×http inbound → N×outbound → 各协议节点）
                 └─ 订阅节点 / 手填代理
```

**为什么每节点一个本地 http inbound**：实测 Bun 的 `fetch` 代理选项**只认 HTTP(S)，SOCKS5 直接抛 `UnsupportedProxyProtocol`**。让 sing-box 吐 http inbound，Bun 走 `http://127.0.0.1:port` 就完成了 CONNECT + TLS + SSE，**不用写一行隧道代码**。

## 装 sing-box

插件**默认自动装**：发现本机没有 `sing-box` 时，自己从 GitHub 官方 release 下载、校验、解压到 magpie 配置目录并缓存。

两点实测提醒：
- 直连 `github.com/.../releases/download/...` 在受限网络会被挡，所以走的是 **GitHub API 的 asset 端点**，并且**支持断点续传**（下载会中断，实测约 34 KB/s，32MB 的包）
- 想省掉这次下载：自己装好后用 `core.binary` 指过去，或关掉自动安装（`core.download: false`）

## 在 magpie 界面里配置（推荐）

装好之后，magpie 的**设置 → 插件**里会多出一个**属于这个插件自己的页面**（侧边栏「插件」组里的**代理池**标签）。订阅链接、手填节点、内核、延迟测试、Resin 降级、高级项都在那里填，改完点保存 —— 不需要命令行。

界面分 6 组：

| 组 | 管什么 |
|---|---|
| 出口源 | 订阅链接、手填节点 |
| sing-box 内核 | 内核路径、是否自动下载、端口起点、状态目录 |
| 池子与换 IP | 节点上限、出口 IP 去重、证书 pin 取舍、重试次数、后台复查间隔 |
| 延迟测试 | 两个延迟目标、超时、并发、最少出口 IP 数、复测间隔 |
| Resin 降级 | 只在没有 pool 时生效 |
| 高级 | 响应头超时、Zen API 地址等 |

空白项**不会写进配置**，继续用插件自己的默认值，所以想恢复默认只要把那个框清空。默认值显示在输入框的灰色提示里。

四个必须知道的行为：
1. **保存是覆盖在已有配置之上**：界面把它认识的字段写进去，它不认识的键原样保留，所以界面和命令行可以混着用。
2. **界面不会去抓订阅**：页面的安全策略是 `connect-src 'none'`，它没有任何网络能力 —— 它只把链接存进配置，真正的抓取由插件在 Bun 里做。所以填完要**重载插件**（或重新开关一次插件）才开始工作。
3. **一个节点都没填就是直连，而直连必然 403**：Zen 免费层对不像 OpenCode 发来的请求一律回 `403 FreeTierError`。界面会在这种情况下标红。还有一处小心：只填了池子的其它设置、却一个节点都没有时，界面会**丢掉 pool 配置而不保存它** —— 因为 `pool: {}` 是真值，留着它插件会拒绝加载（`no usable node`），连 Resin 降级都没了。
4. **浏览器扩展弄不坏这个页面**：magpie 的 bridge 有**两条**转发路径 —— `error` 和 `unhandledrejection` —— 命中任一条，窗口就会把页面换成「此页面已停止工作」。钱包扩展（比如 MetaMask）会往每个 frame 注入脚本，它在沙箱 frame 里抛错**或者**产生未处理的 rejection 都会触发（MetaMask 走的是后者：实测四种注入方式里，只盖住 `throw` 的那一版对它无效）。`page/guard.js` 只在报错确实来自本页声明的脚本时才放行 —— 判据不是猜的：沙箱 frame 是不透明源，magpie 提供的**文件**对它都是跨源，浏览器会把它们的报错洗成 `Script error.`；**注入的代码**跑在 frame 自己的源上，报错会保留原文。所以一个保留着消息、又没有来源的报错只可能来自注入的代码。rejection 没有来源，就用 reason 的 stack 归因 —— 而且在这个沙箱里**本页自己的 rejection 根本不会触发这个事件**（`Promise.reject(Error)`、`Promise.reject(字符串)`、executor、async throw 四种都实测无事件），所以能到达 bridge 的 rejection 只可能是注入的。

> 为什么选项不放在 magpie 那一块「插件选项」里：magpie 给 provider 插件的选项界面（`auth.options`，见 `internal/plugin/providers.go` 的 `Option`）**只有开关**——`Default bool`，UI 提交的是 `{provider, key, on}`。一个订阅链接放不进去。所以这个插件自带一个页面。

## 配置（命令行）

```sh
magpie plugin add /path/to/zen-free
magpie plugin login opencode-zen-free      # 密钥填 public
magpie plugin options opencode-zen-free-resin '{
  "pool": {
    "subscriptions": [{ "url": "https://provider.example/sub?token=xxx", "name": "providerA" }],
    "manual": [
      "http://user:pass@1.2.3.4:8080",
      "socks5://user:pass@5.6.7.8:1080",
      "9.9.9.9:3128",
      "vless://uuid@host:443?type=ws&security=tls"
    ],
    "core": { "binary": "sing-box", "portBase": 28100 },
    "maxNodes": 300,
    "distinctIps": true,
    "allowUnpinnedNodes": true,
    "attempts": 3,
    "probe": {
      "neutralUrls": ["https://ifconfig.me/ip", "https://www.cloudflare.com/cdn-cgi/trace"],
      "zenUrl": "https://opencode.ai/inference/v1/models",
      "timeoutMs": 8000, "concurrency": 16, "minDistinctIps": 10
    }
  }
}'
```

| 选项 | 含义 |
|---|---|
| `subscriptions[]` | 订阅链接。支持 base64 包裹的 URI 行、明文 URI 行、sing-box JSON、`host:port` 列表 |
| `manual[]` | 手填：同样的行格式，或直接给 sing-box outbound 对象 |
| `core.binary` | sing-box 路径；不给就找 PATH，再不给就自动下载 |
| `core.portBase` | 本地端口起始（第 i 个节点用 `portBase + i`） |
| `core.download` | 设为 `false` 则禁止自动下载内核 |
| `core.stateDir` / `statePath` | 内核与池状态（节点表、延迟、出口 IP）的存放位置，默认在 magpie 配置目录下 |
| `maxNodes` | 最多托管多少节点（1-1000，默认 300） |
| `distinctIps` | 按**真实出口 IP** 去重排序（默认开） |
| `allowUnpinnedNodes` | 见下面「证书 pin」 |
| `attempts` | 每次请求最多额外重试几次 |
| `probe.neutralUrls` | 中立延迟目标回退数组，**同时用来解析真实出口 IP** |
| `probe.zenUrl` | 到 Zen 的真实延迟目标（用 `GET /models`，不耗额度） |
| `probe.minDistinctIps` | 不同出口 IP 少于这个数就告警 |
| `probe.activeRefreshMs` | 在用地址的复测间隔（默认 600000，10 分钟，约 6 次/小时） |
| `probe.staleMs` | 备用地址的复测间隔（默认 3600000，1 小时，约 8 次/小时） |
| `refreshTickMs` | 后台复查的唤醒间隔（默认 60000）。它只决定「什么时候看一眼」 |

### 支持哪些协议

`vmess` `vless`（含 reality 与 ws/grpc/httpupgrade）`trojan` `shadowsocks`（SIP002 与 legacy）`hysteria2`/`hy2` `hysteria` `tuic` `anytls` `http` `https` `socks5` `socks`，以及裸 `host:port[:user:pass]`（无凭据按 http，仅 IPv4）。

**不支持的会计数报出**，不会静默丢弃：`unsupported-scheme`（如 `ssr://`）、`parse-error`、`core-too-old`、`over-capacity`、`duplicate`。

**Clash YAML 不做**：插件零依赖，而一个半懂的 YAML 读取器会静默造出错误节点。遇到 Clash 订阅会**明确报错**并让你改用同一订阅的 base64/v2ray 链接。

## 换 IP 的行为

**只在出错时换，不出错就一直用同一个 IP。**

触发：`403` `408` `429` `500/502/503/504/520-524/529`、正文含 `upstream error` / `do request failed` / `access has been restricted` / `policy violations` / `rate limit` 等、以及连接层报错。

**故意不换**：
- `400/401/404/422` —— 换 IP 没用
- **`403 FreeTierError`**（"can only be used from within OpenCode"）—— 请求形状问题，换 IP 会把整池 IP 白耗光
- 流式回复**已经开始吐内容之后**的问题 —— 重试会让内容重复（所以探测/重试都只覆盖响应头之前）

换的顺序：**没用过的节点优先，且按探测延迟从快到慢**；全部用过之后用**实测最快**的；同出口 IP 的节点**排到后面**（不删，所以不会动到已生成的配置）。换 IP 在响应交出去之前完成，对 agent 透明。

## 延迟测试（两个目标分开存）

| 目标 | 用途 | 实测 |
|---|---|---|
| `zenUrl` = `GET /models` | 到 Zen 的真实路径 | ~1.1–1.9s |
| `neutralUrls` | 中立端点，**同时解析真实出口 IP** | ~0.44–0.68s |

两个数分别存进 `probeEwmaMs.zen` 和 `probeEwmaMs.neutral`，选路用 zen 优先。

**探测是花钱的** —— 它消耗的正是你要保住的那些 IP。所以预算是收着的：正在用的地址每 10 分钟重测一次（6 次/小时），最快的 8 个备选每小时一次（8 次/小时），加上从没测过的。

**探测失败不等于节点坏**：Zen 对"不像 OpenCode 发来的"请求一律回 403，中立端点也可能自己不可达。这两种都归为**端点问题，不淘汰节点**。只有 `5xx/429/连接错误` 才算节点的。

## 证书 pin（需要你知情的一个取舍）

部分 hysteria2 节点用 `pinSHA256` 认证，SNI 是伪装的（如 `www.apple.com`），**没有 pin 就无法验证服务器身份**。

实测：这个 pin 是**证书**哈希（16 个节点 14 个不同 pin），而 sing-box 的 `certificate_sha256` **要 1.15.0 才有**（1.14.3 直接拒绝该字段）。把它当公钥哈希用会让节点在握手时报 `unrecognized remote public key`。

所以：

| 情况 | 行为 |
|---|---|
| sing-box >= 1.15.0 | pin 走 `certificate_sha256`，**正常认证** |
| sing-box < 1.15.0 + `allowUnpinnedNodes: true`（**默认**） | 节点**能用**，但标记为 `unpinned` 且 `tls.insecure` —— **等于不验证服务器身份**，理论上可被中间人冒充。加载时会告警告诉你几个节点是这样 |
| sing-box < 1.15.0 + `allowUnpinnedNodes: false` | 这些节点被拒（`core-too-old`），最安全 |

默认开着，是因为实测里你那些 hysteria2 节点**恰好是可用性最好的那批**（6/6 可用，而 vless 只有 2/10）。想更严就把它设成 `false`。

## 怎么确认它在工作

1. **magpie 日志**：加载时会打
   ```
   [zen-free-pool] sing-box 1.14.3 accepted the config: 5 inbound, 6 outbound, ports 28100..28104
   [zen-free-pool] pool: 5 node(s) on ports 28100..28104, core 1.14.3, 0 duplicate(s) dropped
   [zen-free-pool] pool: measured 5 node(s); 5 distinct exit IP(s) over 5 node(s)
   ```
   换 IP 时打 `<from> -> <to> after <原因>`。
2. **真机体检**：
   ```sh
   bun scripts/check-pool.mjs --binary /path/to/sing-box \
     --subscription 'https://provider/sub?token=...' --max-nodes 8
   ```
   它会起真内核、发一次真实流式 completion、并列出每个节点测到的出口 IP。
3. **magpie 的 Providers 页 / `magpie quota`**：账号那一行会显示池子的实时状态
   ```
   代理池节点      存活 12 / 共 167，失效 155
   独立出口 IP     12 个
   ```
   每个数的口径：

   | 数字 | 含义 |
   |---|---|
   | 共 N | 池子托管的节点数（去重、并受 `maxNodes` 限制之后） |
   | 存活 | **真的测到过出口 IP** 的节点数 |
   | 失效 | 共 − 存活（包括从没答过的，以及已退役的） |
   | 独立出口 IP | 去重、去退役之后的**真实出口 IP** 个数 —— 这才是限流能分散到的宽度 |

   内核没在跑的时候，第一行会附上 `（sing-box 1.14.3 未运行）`。那是一个**从节点数看不出来**的故障：请求全失败，而节点数看着一切正常。

   > **为什么不做在插件自己的页面里**：magpie 不给插件页面任何数据通道。页面只能问四件事 —— `hello`、`options.get`、`options.set`、`read` —— 而 `read` 只允许 `providers:list` 和 `usage:summary`（见 magpie 的 `internal/gui/pluginpage.go`），页面的 CSP 又是 `connect-src 'none'`，连网络都没有。所以「账号的用量行」是插件唯一能被 UI 展示的状态出口，节点状态就放在那里。

## 局限

- **v1 不做运行期订阅刷新**：节点表在插件加载时定下来，刷新靠重载插件。理由：新增节点要新 inbound → 要重生成配置 → 要重启内核 → **会打断在途 SSE 流**
- 流式回复**中途**失败不重试（内容已经发出去了）
- 订阅链接默认直连抓取；订阅域名本身需要翻墙的话 v1 不支持
- 池子**只能在 Bun 下工作**（Node 的 `fetch` 接受 `proxy` 选项但**会忽略**它 —— 插件会直接报错，而不是静默直连）
- 300 个本地监听端口在 Windows 可能触发防火墙/杀软提示
- 需要本机有 `sing-box`（默认自动装）

## 备选：Resin

原来的 Resin 后端保留着，作为池子不可用时的降级路径，配置方式不变：

```jsonc
{ "resin": { "url": "http://host:2260/<代理令牌>", "adminToken": "<管理令牌>", "platform": "Default", "account": "zen-free", "addresses": 8, "transport": "forward" } }
```

`pool` 和 `resin` 同时配置时**优先走 pool**。注意 Resin 有**两个不同的令牌**：`url` 里要的是**代理令牌**（`RESIN_PROXY_TOKEN`），`adminToken` 才是面板令牌。填错会得到 `403 Proxy authentication failed`，所以插件对没有令牌的 `url` 直接报错而不是静默失效。

`scripts/check-resin.mjs` 是它对应的体检脚本。

## 测试

```sh
bun test          # 396 个用例
node --test       # Node 下 3 个已知失败：Node 的 fetch 多带一个 accept-language 头，是原版就有的运行时差异
```

## 原有说明（Zen 免费额度本身）

Zen 免费层从 2026-10-13 起只回答「看起来像 OpenCode 发来的」请求，否则 `403 FreeTierError`。插件按 OpenCode 1.19.0 实际发送的头和 session id 形状发请求。

模型列表自动发现（启动时和每小时），退役模型与 SystemOne 模型排除；请求走 `https://opencode.ai/inference/v1`，按模型各自的 Chat Completions / Responses / Anthropic Messages 原生协议发送，流式与非流式都支持。

agent 的工具会保留：Zen 的模型常调 OpenCode 自己的工具名，只在大小写不同、或只在大小写与 `_`/`-` 上不同且恰好只有一个匹配时，会换成 agent 自己的工具。

Zen 有时会在 `[DONE]` 之前关掉流：如果已经说了话且没有未完成的工具调用，就当作正常回答结束并加一句说明；断在有未完成工具调用、什么都没说、或客户端非流式的情况下则报错并说明收到多少。
