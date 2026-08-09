# gfwlist → 多目标分流规则集

[![daily build](https://github.com/gfwlist-srs/gfwlist-srs/actions/workflows/daily.yml/badge.svg)](https://github.com/gfwlist-srs/gfwlist-srs/actions/workflows/daily.yml)
[![jsdelivr](https://data.jsdelivr.com/v1/package/gh/gfwlist-srs/gfwlist-srs/badge)](https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/)

> **使命：只有国内无法访问的域名/IP 才走代理，其余全部走本地网络 ——
> 以最小的代理节点消耗，换取最好的访问体验。**

以官方 [gfwlist](https://github.com/gfwlist/gfwlist) 为唯一数据源，每日自动构建，
为 **sing-box / Shadowrocket / Surge / Loon / Clash(Mihomo) / Xray(v2rayN) / Quantumult X**
交付语义一致的分流规则集。工程目标：**语义等价 · 高性能 · 可审计**。
设计与映射推导见 [docs/DESIGN.md](docs/DESIGN.md)。

## 使命如何在设计中兑现

| 使命要求 | 项目机制 |
|---|---|
| 该走代理的**一个不漏** | gfwlist 全集忠实转换，双引擎 oracle 对拍门禁：**0 未申报偏差**才允许发布；任何"漏代理"(narrowed) 都不允许出现在 block 侧 |
| 可访问的**不被误代理** | 上游 `@@` 例外（白名单）完整保留且**永远先于阻断规则求值**——被 block 覆盖但国内可访问的域名（如 `cn.investing.com`）直连；这是 gfwlist 内置的"国内可访问"裁注意图，我们系统性兑现 |
| 多代理的**必须申报** | 对拍是**双向**的：未申报的 widened（多走代理）同样使构建失败；仅存的 widened（280 条 URL 前缀规则整域走代理）逐条审计可查 |
| 其余流量**默认直连** | 全部产物只含 block/exception 两类规则；各工具参考配置统一 `final:direct` / `FINAL,DIRECT` / `MATCH,DIRECT` 兜底 |
| 规则本身**不成为瓶颈** | 域名树 + 集合级单条正则，匹配 ~µs/域名；4260 条正则合并为 1 条 |
| 国内域名**DNS 不绕路** | sing-box 专用 `gfwlist-block-domain` 纯域名集：仅被墙域名单走加密远端解析，其余本地 DNS（避免国内站点被绕到远端 CDN 节点） |

**一条诚实的边界**：gfwlist 是社区维护的"受影响名单"，不是墙内实时可达性清单。
"按当前可访问性再裁剪"被明确否决（DESIGN §8：CI 在墙外无法探测、GFW 阻断是动态的、
上游维护本身即裁剪、裁剪会破坏可复现与可审计）——因此本项目保证的是
**忠实于 gfwlist 的最小代理集**，而非实时精确的最小集；`@@` 例外机制 +
用户本地直连叠加层承载剩余的裁剪需求。

## 多目标架构（IR 管线）

```
gfwlist.txt → 解析 (parse_line) → 保义清洗 (去重/子集消除) → gfwlist-ir.json
                                                                │
              ┌───────────┬───────────────┬─────────┬─────────┼─────────┐
              ▼           ▼               ▼         ▼         ▼         ▼
          sing-box   Shadowrocket     Surge系    Clash系   Xray系   Quantumult X
          .json/.srs   .conf          .list      .yaml     .json     .list
```

- **IR 层**（`src/gfwparse.py`）目标无关：逐行 ABP 语义解析、降级决策、精度标签申报、
  去重与子集消除、集合级 gap 正则。语义决策只存在这一层。
- **目标适配器**只做"词汇表 + 方言"翻译（如 Shadowrocket 的 URL-REGEX 语境重写），
  不做语义决策 —— 新增一个 VPN 工具 ≈ 新增一个薄适配器 + 一个对拍模拟器。
- 对拍门禁（双引擎 oracle + 样本生成）全部目标共享。

## 产物（dist/）

| 文件 | 说明 |
|------|------|
| `gfwlist-ir.json` | **公共中间表示 (IR)**：全部目标的公共数据源（规范化规则集 + 逐行决策 + 精度标签），第三方可据此二次转换到任意工具 |
| `gfwlist-block.srs` / `.json` | 阻断规则集（编译后 / source） |
| `gfwlist-block-domain.srs` / `.json` | 阻断规则集的纯域名变体（去掉唯一的 1 条 `ip_cidr`，供 **DNS 规则**引用，见下） |
| `gfwlist-exception.srs` / `.json` | 例外（白名单）规则集 |
| `gfwlist-shadowrocket.conf` | Shadowrocket 完整配置（例外 DIRECT 在前，阻断 PROXY 在后） |
| `gfwlist-exception.list` / `gfwlist-block.list` | Surge 系裸规则集（无策略列）：Surge/Loon RULE-SET、Shadowrocket 规则分组 |
| `gfwlist-clash-exception.yaml` / `gfwlist-clash-block.yaml` | Clash 系 classical rule-provider（mihomo/Clash Premium/Stash/FlClash） |
| `gfwlist-xray.json` | Xray 系路由规则（Xray/v2ray/v2rayN/v2rayNG/NekoBox/Passwall） |
| `gfwlist-quantumultx.list` | Quantumult X（无域正则能力，正则/gap 已丢弃并申报 narrowed） |
| `audit-targets.json` | 多目标审计（逐规则溯源 + 精度标签 + 产物一致性校验基准） |
| `audit.md` / `audit.json` | 逐行转换审计（分类、决策、精度标签） |
| `audit-shadowrocket.md` / `.json` | Shadowrocket 目标侧审计（含 conf↔审计逐行一致性校验） |
| `mismatches.json` / `mismatches-shadowrocket.json` | 最近一次全量对拍的偏差明细（全部已申报） |

## 本地构建与验证

```bash
# 依赖: sing-box >= 1.11, python >= 3.10, pip install -r requirements.txt
curl -fsSL -o gfwlist.b64 https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
python3 tools/validate_input.py gfwlist.b64          # 输入结构验证
base64 -d -i gfwlist.b64 -o gfwlist.txt              # Windows: certutil -decode
python3 src/gfwlist2srs.py gfwlist.txt dist          # 转换 + 审计
python3 src/gfwlist2shadowrocket.py gfwlist.txt dist # Shadowrocket 目标转换 + 审计
sing-box rule-set compile dist/gfwlist-block.json -o dist/gfwlist-block.srs
sing-box rule-set compile dist/gfwlist-block-domain.json -o dist/gfwlist-block-domain.srs
sing-box rule-set compile dist/gfwlist-exception.json -o dist/gfwlist-exception.srs
python3 tests/differential_test.py gfwlist.txt dist  # sing-box 全量对拍（门禁）
python3 tests/differential_shadowrocket.py gfwlist.txt dist  # Shadowrocket 全量对拍（门禁）
sing-box check -c examples/config.local.json         # 真实 sing-box 验证配置
```

## 等价性验证方法

- **双引擎 Oracle**：
  - 规范引擎 `adblockparser`（忠实实现 ABP/AutoProxy 参考语义 = gfwlist 原始消费端语义），未申报偏差即失败；
  - 交叉验证引擎 `python-adblock`（Brave adblock-rust / uBO 系工业引擎，~5 倍速）。实测其 token 化实现在本清单上有 quirk（2 字符标签中缀匹配错位、`@@||www.gov.tw` 例外过度覆盖整个 gov.tw 等），故仅作交叉验证：与规范引擎的偏离计入"引擎分歧"白名单，避免把上游引擎 bug 复制进产物。
- **被测**：内置 sing-box 匹配语义模拟器（`domain`/`domain_suffix`/`domain_keyword`/`domain_regex`/`ip_cidr` + 例外优先路由），加载**最终 ruleset JSON**（含集合级 gap 正则），命中可溯源到原始行号。
- **样本**：每条原始规则派生正例/近邻负例/变异（子域、scheme、路径、端口、前缀粘连、中缀、通配实例化、IP 邻址）+ 随机背景域，当前版 36645 个 URL，每条线均被覆盖。
- **判定**：不一致样本定位责任规则；仅当责任规则精度 ∈ {widened, narrowed, approximated}（审计已申报）或属已声明引擎分歧才允许通过。当前结果：**0 未申报偏差**（双引擎）。
- **真实性**：`.srs` 由真实 `sing-box rule-set compile` 编译（兼作 RE2 校验），`sing-box check` 验证完整引用配置。

## 使用方式

双规则集：例外集必须放在阻断集**之前**（先命中先放行 = AutoProxy `@@` 否决语义）。
产物通过 jsDelivr CDN 分发（国内访问友好），完整示例见 [examples/config.json](examples/config.json)：

```jsonc
"route": {
  "rules": [
    { "rule_set": "gfwlist-exception", "action": "route", "outbound": "direct" },
    { "rule_set": "gfwlist-block",     "action": "route", "outbound": "proxy"  }
  ],
  "rule_set": [
    { "type": "remote", "tag": "gfwlist-exception", "format": "binary",
      "url": "https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-exception.srs",
      "update_interval": "24h" },
    { "type": "remote", "tag": "gfwlist-block", "format": "binary",
      "url": "https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-block.srs",
      "update_interval": "24h" }
  ]
}
```

> CDN 说明：jsDelivr 对 `@main` 分支引用有缓存（通常数分钟至数小时）。
> 本仓库的每日工作流在每次更新 dist 后会主动 purge 这些文件的 CDN 缓存，
> 因此客户端按 `update_interval` 拉取即可拿到当日最新版。
> 备用直链（无 CDN）：`https://raw.githubusercontent.com/gfwlist-srs/gfwlist-srs/main/dist/gfwlist-block.srs`

### DNS 规则请引用 `gfwlist-block-domain`

`gfwlist-block` 内含 1 条 `ip_cidr`（`85.17.73.31/32`）。在 **DNS rules** 里直接引用它会让
sing-box 1.14 进入 legacy address-filter 模式（弃用警告，1.16 将拒绝）；而配套的
`rule_set_ip_cidr_match_source: true` 会把规则集变成对**查询来源 IP** 的条件，导致规则永不命中
（表现为 Google 等域名走本地 DNS 被 GFW 投毒）。因此：

- **DNS rules** 引用 `gfwlist-block-domain`（纯域名变体，对 DNS 查询无语义损失 ——
  DNS 查询本来就没有目标 IP 可匹配 `ip_cidr`）；
- **route rules** 仍引用完整的 `gfwlist-block`（保留 `ip_cidr`，让对该 IP 的直连连接也走代理）。

```jsonc
"dns": {
  "rules": [
    { "rule_set": "gfwlist-exception",     "action": "route", "server": "local-dns"  },
    { "rule_set": "gfwlist-block-domain",  "action": "route", "server": "remote-dns" }
  ],
  "ruleset": "..." // rule_set 声明与 route 中相同，仅 url 换成 gfwlist-block-domain.srs
}
```

## Shadowrocket 使用方式

`dist/gfwlist-shadowrocket.conf` 是完整配置（`[General]` + `[Rule]` + `[Host]`），
与 sing-box 版共用同一解析/优化管线和同一套等价性验证：

- **例外语义**：例外（`@@`）规则以 `DIRECT` 置于全部 `PROXY` 规则之前，
  Shadowrocket 按序先命中先生效 —— 与 AutoProxy `@@` 否决语义等价；
- **映射**：`domain_suffix → DOMAIN-SUFFIX`、`domain_keyword → DOMAIN-KEYWORD`、
  `ip_cidr → IP-CIDR,…,no-resolve`、域正则 → `URL-REGEX`（目标侧重写见下）；
- **URL 语境重写**：`URL-REGEX` 匹配整条 URL 而非 host。block 侧域正则/gap 的
  `(^|\.)` 前缀扩展为 `(?:^|://|\.)`，URL path 中的 `.` 也会构成边界
  （path 含 `suffix.` 片段的 URL 可能误命中 → 放宽，block 安全方向，已申报）；
  exception 侧前缀为 `(?:^|://)` 且 `.* → [^/]*`，不会跨入 path（例外宁窄，host 内等价）；
- **性能**：两条集合级 gap `URL-REGEX`（4200+ 分支的超长正则）排在各自集合末尾，
  仅当全部 `DOMAIN-SUFFIX` 未命中时才求值。若实测介意其开销可整行删除，
  代价是 `||host` 的延续形态（`host.evil.com`）退回标签边界语义（收窄）。

Shadowrocket：配置 → 添加配置 → 从 URL 下载，填入：

```
https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-shadowrocket.conf
```

备用直链：`https://raw.githubusercontent.com/gfwlist-srs/gfwlist-srs/main/dist/gfwlist-shadowrocket.conf`
已建有主配置时，也可只复制该文件的 `[Rule]` 段合并进自己的配置（务必保持例外规则在阻断规则之前）。

## Surge / Loon 使用方式

引用两个 RULE-SET（**例外必须在阻断之前**，策略分别在引用行指定）：

```ini
[Rule]
RULE-SET,https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-exception.list,DIRECT
RULE-SET,https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-block.list,PROXY
FINAL,DIRECT
```

Shadowrocket 也可用「配置 → 规则分组」按同样顺序订阅这两个 URL（例外组选 DIRECT）。

## Clash / Mihomo 使用方式（Stash / ClashVerge / FlClash 等通用）

```yaml
rule-providers:
  gfwlist-exception:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-clash-exception.yaml
    interval: 86400
    path: ./rule-providers/gfwlist-exception.yaml
  gfwlist-block:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/dist/gfwlist-clash-block.yaml
    interval: 86400
    path: ./rule-providers/gfwlist-block.yaml

rules:
  - RULE-SET,gfwlist-exception,DIRECT   # 例外必须在阻断之前
  - RULE-SET,gfwlist-block,PROXY
  - MATCH,DIRECT
```

classical 行为保留全部 `DOMAIN-REGEX`（host 语境 RE2，与 sing-box 同方言），无精度损失。

## Xray / v2rayN 使用方式（v2rayNG / NekoBox / Passwall 通用）

`gfwlist-xray.json` 是 v2rayN 自定义路由规则文件（rules 为标准 Xray RuleObject，
例外 `direct` 在前、阻断 `proxy` 在后）。v2rayN：设置 → 自定义路由规则 → 导入 URL
或粘贴文件内容；原生 Xray 则把 `rules` 数组合并进 `routing.rules` 开头。
domain 令牌全部显式带 `domain:`/`regexp:` 前缀（Xray 裸字符串是 keyword 子串语义，
无前缀会严重误伤）。

## Quantumult X 使用方式

`gfwlist-quantumultx.list` 追加到 `[filter_local]`，或作为 `[filter_remote]` 订阅
（例外 `direct` 在前）。注意：Quantumult X **没有域正则能力**，10 条域正则与
集合级 gap 规则已丢弃（narrowed，审计已申报）——影响仅为 `||host` 延续形态
（`host.evil.com`）与 9 条特殊正则域名的覆盖，对拍门禁按"能力收窄"白名单验证。

## 已知语义偏差（全部审计申报，详见 dist/audit.md）

| 方向 | 来源 | 影响 |
|------|------|------|
| widened | 280 条 URL 前缀规则的 scheme/path 条件在连接级模型中不存在 | 被墙站全协议走代理（无害） |
| approximated | 2 条裸子串规则 → 域后缀；247 条无尾斜杠 URL 前缀规则的"向右延续"语义 | 仅理论边界差异 |
| narrowed | 1 条畸形正则（L314，缺收尾 `/`） | 按 ABP 规范该规则本就永不命中，丢弃等价 |
| widened（Shadowrocket 目标侧） | 10 条域正则 → `URL-REGEX` 的 `(^|\.) → (?:^|://|\.)` 前缀扩展 + 2 条 gap 正则 | URL path 中 `.` 边界可能误命中（多走代理，无害） |

## GitHub Actions

`.github/workflows/daily.yml`：每日 01:17 UTC（北京 09:17）自动构建。三段式并行流水线：
`build`（下载→验证→六目标转换→编译）→ `gate`（**六路对拍门禁矩阵并行**）→ `publish`
（全部门禁通过才提交 dist 并 purge CDN）。任一门禁失败则不发布。

## Shadowrocket 目标设计（与 sing-box 目标的关系）

Shadowrocket 版与 sing-box 版**共用同一解析/优化管线**（`parse_line` + `optimize`），
只做目标侧翻译（`src/gfwlist2shadowrocket.py`），因此逐行决策天然一致。
对拍门禁（`tests/differential_shadowrocket.py`）共用同一样本生成与双引擎 oracle；
当前全量 36645 样本下，Shadowrocket 模拟器与 sing-box 模拟器**逐样本行为完全一致**
（偏差集合相同，仅 6 条责任溯源标签位移），0 未申报偏差。详见 docs/DESIGN.md §11。
