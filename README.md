# OpenCode Zen Free + Resin 代理池

在 [magpie](https://usemagpie.ai) 和 OpenCode 里使用 OpenCode Zen 的免费模型，出口 IP 交给
[Resin](https://github.com/Resinat/Resin) 代理池管理。

供应商 id 仍是 `opencode-zen-free`，所以 `opencode-zen-free/<模型>` 的用法不变。
本仓库是 magpie 社区 [zen-free 插件](https://github.com/magpie-community/plugins/tree/main/packages/zen-free)
的一个改造版，改动只有一处：**上游请求从 Resin 的某个出口 IP 发出，被限流或拒绝时自动换成另一个 IP。**

之所以要这么做：Zen 免费额度按出口 IP 计算，一个凭证换着 IP 用就能绕开单 IP 的限制。

## 安装

```sh
magpie plugin add /path/to/zen-free      # 目录就地加载
magpie plugin login opencode-zen-free    # 密钥填 public
magpie plugin options opencode-zen-free-resin '这里是下面的 JSON'
```

配置完后 `magpie provider test opencode-zen-free` 可以发一个最小请求试一下。

## 先搞清楚两个令牌

这是最容易踩的坑。Resin 有两个不同的令牌：

| 令牌 | 环境变量 | 用在哪 |
| --- | --- | --- |
| **代理令牌** | `RESIN_PROXY_TOKEN` | 走代理时用，拼进 `resin.url` 的路径里 |
| **管理令牌** | `RESIN_ADMIN_TOKEN` | 登录 Resin 面板、调用 `/api/v1`，填进 `resin.adminToken` |

`resin.url` 里的那个路径段必须是**代理令牌**。填成管理令牌的话，Resin 会返回
`403 Proxy authentication failed`。这就是为什么 `resin.url` 不接受没有路径的形式
（那样插件会直接报错，而不是静默失效）。

`resin.adminToken` 可以不给：不给的话换 IP 仍然有效，只是被换掉的 IP 不会释放租约，
下次轮回到它时还会拿到同一个 IP。

## 选项

```jsonc
{
  "resin": {
    "url": "http://resin.example:2260/你的代理令牌",  // 必填，没有就是直连
    "adminToken": "你的管理令牌",                        // 选填，用于释放租约
    "platform": "Default",                              // Resin 里的平台名
    "account": "zen-free",                              // Account 前缀，决定 IP 的归属身份
    "addresses": 8,                                     // 可用出口 IP 的上限（1-1000）
    "transport": "forward",                             // forward 或 reverse
    "attempts": 3                                       // 每次请求最多额外重试几次（0-10）
  }
}
```

`addresses` 决定 Resin 里会占用多少个 Account（`zen-free-1` .. `zen-free-N`），
也就是你可以轮换多少个出口 IP。Resin 的 `allocation_policy: PREFER_LOW_LATENCY` 会给
每个 Account 绑一个它认为最快的节点，所以这里填多少，就等于有多少个「服务器到它最快」的 IP。
你提到有 300 个 IP，那就填 300。

## 换 IP 的行为

**只在出错时换，不出错就一直用同一个 IP。** 这正是需求里说的：不报错就不换。

触发换 IP 的情况：

| 类别 | 具体 |
| --- | --- |
| 状态码 | 403、408、429、500、502、503、504、520-524、529 |
| 正文关键词 | `upstream error`、`do request failed`、`bad gateway`、`service unavailable`、`gateway timeout`、`access has been restricted`、`policy violation`、`rate limit`、`too many requests`、`quota exceeded` |
| 连接层 | 连接被重置、超时等 fetch 抛错 |

不触发换 IP 的情况：

- `400`、`401`、`404`、`422` —— 换 IP 解决不了。
- **`403 FreeTierError`（"can only be used from within OpenCode"）** —— 这是请求形状不对，
  换 IP 不但没用，还会把整池 IP 白白耗光。所以这条会连同上游原文一起交回给 agent。
- 流式回复**已经开始吐出内容之后**才出的问题 —— 这时换 IP 重试会让内容重复，
  所以不做（见下面「局限」）。

换 IP 的选择顺序：

1. 优先换成**没用过的** Account —— 保证每次都花掉一个新 IP；
2. 全都用过之后，换成**实测最快**的那个（按响应头到达时间 TTFB 排序，不掺生成耗时）；
3. 全都换过一遍之后，换成**最久没被换掉**的那个，并释放它的租约让它重新绑定。

注意第 3 步：释放租约只是解除绑定，Resin 会重新挑一次节点，**可能又挑回同一个 IP**（如果它仍是最快的）。
所以真正避免用完的关键是 `addresses` 给够（你说有 300 个，那就填 300），而不是靠释放租约。

换 IP 对 agent 是透明的：插件在把响应交出去之前就重试完了。`attempts` 用完还没成功，
就把上游自己的报错原样交回。

## 两种传输方式

| | forward（默认） | reverse |
| --- | --- | --- |
| 身份 | `Platform.Account:令牌` 作为代理认证 | 路径里带 Platform，`X-Resin-Account` 头带 Account |
| TLS | 端到端（CONNECT 隧道） | 到 Resin 这一段是明文 HTTP |
| 要求 | 需要 Bun | 任何运行时都行 |

forward 是默认值，因为它靠 CONNECT 隧道穿过去，SSE 流一个字节都不会被改动。

**forward 需要 Bun**（`fetch` 支持 `proxy` 选项）。Node 的 `fetch` 会接受 `proxy` 选项然后
**默默忽略它** —— 那样请求会直接发出去而你以为在换 IP。所以插件在加载时检查：没有 Bun 就直接报错，
让你改 `transport: "reverse"`，而不是悄悄失效。magpie 用 Bun 跑插件，正常不需要管这件事。

## 怎么确认它在工作

1. **magpie 日志**：每次换 IP 会打一行
   `[zen-free-resin] zen-free-1 -> zen-free-2 after rate-limit: {"error":...}`。
2. **Resin 面板** `Leases` 页：能看到每个 Account 绑到了哪个节点、出口 IP 是多少。
   换过的 Account 会换到新的 `egress_ip`。
3. **Resin 面板** `Requests` 页：按 Platform / Account 查请求记录和状态码。

## 局限

- 流式回复**中途**失败不会重试（内容已经发出去了）。上面列的触发条件都是带状态码的，
  也就是在流开始之前就能判断，能覆盖你遇到的 `status_code=403/429/500` 这几类。
- 模型发现（`/models`、catalog、docs）走直连，不经过代理池。读不到时会退回上一次的列表，
  不影响已有模型的使用。
- 换 IP 解决的是「按 IP 限流」。如果账号本身被限制，换 IP 无效。

## 与原版的差异

改动集中在 `resin.mjs`（新增）和 `provider.mjs` 的 `send()`；其余文件与原版一致。

- `resin.mjs` —— 出口 IP 池、失败分类、透明重试、Resin 管理 API 客户端。
- `provider.mjs` —— `options.resin` 的解析与校验；`send()` 把上游请求包进池子里。
- `models.mjs`、`stream.mjs`、`tool-response.mjs` —— 未改动。

测试：`bun test`（219 个用例）。另外 `bun test` 之外，也可以在 Node 下跑
`node --test`，其中 3 个上游自带用例会因为 Node 的 fetch 多带一个 `accept-language` 头而失败，
这是原版就有的运行时差异，与本次改动无关。

## Zen 免费额度本身的注意事项（原版说明）

Zen 免费层从 2026-10-13 起只回答「看起来像 OpenCode 发来的」请求：不是 OpenCode 发来的会得到
`403 FreeTierError`。插件按 OpenCode 1.19.0 实际发送的头和 session id 形状来发请求。
旧版本插件会拿到 403，需要更新。

模型列表会自动发现（启动时和每小时），退役模型和 SystemOne 模型会被排除；请求走
`https://opencode.ai/inference/v1`，按模型各自的 Chat Completions / Responses / Anthropic
Messages 原生协议发送，流式与非流式都支持。

agent 的工具会被保留：Zen 的模型常调 OpenCode 自己的工具名，只在大小写不同（`bash` → `Bash`）、
或只在大小写与 `_`/`-` 上不同（`todowrite` → `todo_write`）且恰好只有一个匹配时，会换成 agent 自己的工具。

Zen 有时会在 `[DONE]` 之前就关掉流：如果已经说了话且没有未完成的工具调用，就当作正常回答结束并加一句说明；
如果流断在有未完成工具调用、什么都没说、或客户端非流式的情况下，则报错并说明收到多少。
