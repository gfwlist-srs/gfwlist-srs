# gfwlist → sing-box headless-rule (.srs) 转换设计

目标：**语义等价 · 高性能 · 可审计**。转换器对任意行做通用语法处理，不写死任何具体规则。

## 1. gfwlist 语法清单（基于 2026-08-06 版全量普查，4465 行）

gfwlist 是 Adblock Plus (ABP) filter list 的一个子集，由 AutoProxy 消费。全量语法形态：

| # | 语法形态 | 数量 | 原始语义（对 URL 匹配） |
|---|---------|-----:|------------------------|
| 1 | `!` 注释 / `[AutoProxy]` 头 / 空行 | 115 | 元数据，无匹配语义 |
| 2 | `\|\|host` 主机锚定 | 4033 | host 等于 host 或其任意子域 |
| 3 | `@@\|\|host` 例外（白名单） | 33 | 命中时**否决**所有 block 规则 |
| 4 | `\|http(s)://host/path` URL 前缀锚定 | 280 | URL 以该前缀开头（含 scheme、可选路径） |
| 5 | `/regex/` 正则 | 1 | URL 匹配正则 |
| 6 | `@@/regex/` 例外正则 | 1 | 同上，且为例外 |
| 7 | 裸子串（无锚定） | 2 | 子串出现在 URL 任意位置即命中 |

形态 2–7 中可能出现 ABP 元字符：`*` 任意字符序列、`^` 分隔符、行尾 `|` 结尾锚定、行内路径。

关键语义事实：
- **例外优先**：`@@` 规则命中即否决 block（AutoProxy/ABP 语义）。
- **匹配对象是整条 URL**（含 scheme 与路径），而 sing-box headless rule 只能匹配连接级目标（domain / IP / port，无 scheme、无 path）。这是两种模型的根本差异，等价性按第 3 节的降级策略处理并全部审计。

## 2. sing-box headless rule 能力面（sing-box 1.13）

规则集 JSON（version 3）→ `sing-box rule-set compile` → `.srs` 二进制。headless rule 与域名相关的字段：

- `domain`：精确匹配某域名
- `domain_suffix`：域名后缀，**按标签边界**匹配（`example.com` 命中 `www.example.com`，不命中 `notexample.com`）
- `domain_keyword`：域名子串
- `domain_regex`：域名正则（Go RE2，**不支持 lookahead/lookbehind**）
- `ip_cidr`：目标 IP 网段

## 3. 等价映射表（核心设计）

### 3.0 关键语义发现（对拍测试实证）

1. **ABP `\|\|host` 无右边界**：`\|\|example.com` 在真实 ABP 匹配器（adblockparser 实证）下命中 `example.com.evil.com`、`example.com.cn` —— 模式只锚定左边界（域名起始或 `.` 之后），右侧不要求边界。sing-box `domain_suffix` 要求右侧标签边界，二者**不等价**。
   **编码方案**：`domain_suffix(host)` ∪ 集合级合并正则 `(^|\.)(h1|h2|…|hn)\.`（补齐"host 后还有标签"的缺口）。两者合取与 ABP `\|\|host` 精确等价，且只需 **1 条** 合并正则（Go RE2，实测 sing-box 编译 0.134s，srs 51KB）。
2. **例外同样无右边界**：`\@\|\|*.x` 等例外模式的 `$` 锚定同样要去掉（partial match），否则漏放。
3. **畸形正则**：上游 L314 `@@/^https?:…` 缺收尾 `/`，按 ABP 规范是永不命中的字面量 filter，丢弃即等价（已在审计标注）。
4. **`Checksum` 算法**：与 ABP/AutoProxy 全部公开变体（UTF-8/UTF-16LE、去行/去空白等）均不匹配，判定为 gfwlist 私有变体；CI 改用结构校验（base64 可解码 + `[AutoProxy]` 头 + `Last Modified` 可解析 + 行数下限）。
5. **基准引擎分轨（实测发现）**：python-adblock（Brave adblock-rust 绑定）速度约快 5 倍，但其 token 化实现在本清单上有多处可观测 quirk：
   - 含 2 字符标签（io/cn/tw 等）的 `\|\|host` 规则：中缀延续匹配行为错位（如 `\|\|ai.studio` 不命中 `www.ai.studio.evil.com`，而 `\|\|bbc.com` 命中 `www.bbc.com.evil.com`）；
   - 带 2 字符 TLD 的例外规则过度应用：`@@||www.gov.tw` 在其引擎中错误豁免整个 `gov.tw`（`mail.gov.tw`、apex 全被豁免），ABP 规范只豁免 www.gov.tw 及其子域。
   因此采用**双引擎对拍**：adblockparser（忠实实现 ABP/AutoProxy 参考语义 = gfwlist 原始消费者的语义）为**规范引擎**，未申报偏差即失败；adblock-rust 为**交叉验证引擎**，其与规范引擎的偏离计入"引擎分歧"白名单（只报告、不修 gate），防止把上游引擎 bug 复制进产物。
6. **gap 正则的双侧差异化**：block 集 gap = `(^|\.)(alts)\.`（中缀延续也命中，安全方向放宽）；exception 集 gap = `^(alts)\.`（仅起始延续，例外宁窄，且与基准引擎行为一致）。

降级原则：**block 规则宁宽勿窄**（放宽 = 多走代理，不影响可达性）；**例外规则宁窄勿宽**（放宽 = 该走代理的被直连，会断）。无法保义的转换全部进入审计报告，标注精度类别。

| 原始形态 | 转换 | 精度 | 说明 |
|---------|------|------|------|
| `\|\|example.com` | block 集 `domain_suffix: example.com` + 集合级 gap 正则 | **精确** | gap 正则补齐 ABP 无右边界语义（见 §3.0） |
| `\|\|single`（如 goog/gle/google，单标签/TLD） | block 集 `domain_suffix: single` + gap 正则 | **精确** | 命中该 TLD 下全部域 |
| `\|\|*.example.com` | block → `domain_suffix: example.com`；exception → `domain_regex: (^|\.).*\.example\.com`（无 `$`） | block 微宽（多含 apex）；exception **精确** | block 方向放宽符合"宁宽"原则 |
| `\|\|cdn*.example.com`（标签内通配） | `domain_regex: (^|\.)cdn.*\.example\.com`（无 `$`） | **精确** | `||` 锚定 = 任意子域边界起始；ABP `*` 可跨标签；无右边界 |
| `\|http(s)://host/`（纯 scheme+host+尾斜杠） | `domain_suffix: host` + gap 正则 | **放宽**（scheme 条件消失 + 子域） | 连接级模型无 scheme；被墙站点本就全协议应代理 |
| `\|http(s)://host`（无尾斜杠/路径） | `domain_suffix: host` + gap 正则 | **近似** | ABP URL 前缀可向右延续（`hostX` 命中），suffix 边界语义与之双向近似，审计标注 |
| `\|http://host/path` | `domain_suffix: host` | **放宽**（path 条件消失） | 审计逐条列出 |
| `\|http://1.2.3.4/` | `ip_cidr: 1.2.3.4/32` | **精确**（IP 目标直连匹配） | |
| `\|http://cdn*.x.y/` | `domain_regex: (^|\.)cdn.*\.x\.y` | **精确** | 同标签内通配处理 |
| 裸子串 `www.foo.com` | `domain_suffix: www.foo.com` | **近似**（子串→域后缀） | 双向理论差异（如 `xwww.foo.com`），审计标注 |
| `/^https?:\/\/[^\/]+blogspot\.(.*)/` 类 URL 正则 | 通用翻译：剥 `^https?://`、剥 `$`、URL 字符类→域字符类 → `domain_regex` | **近似** | 翻译管线见 §4；翻译产物经 RE2 校验 |
| 例外正则含 lookahead（RE2 不支持） | 通用模板重写 `(?=.*?(a\|b))[X]+\.tail$` → `[X]*(a\|b)[X]*\.tail$`；失败则例外**丢弃**（收窄） | **收窄** | 符合例外"宁窄"原则 |
| 畸形正则（缺收尾 `/`） | 丢弃 | block **精确** / exception **收窄** | 按 ABP 规范是永不命中的字面量 filter |
| `@@\|\|host` | 例外集 `domain_suffix` + 例外集 gap 正则 | **精确** | 独立例外规则集，路由中置于 block 之前 |

### 双规则集架构（例外语义的系统级等价）

sing-box rule-set 是无序集合，集合内无法表达"例外否决"。因此在**系统层面**保义：

- 产物一 `gfwlist-block.srs`：全部 block 规则
- 产物二 `gfwlist-exception.srs`：全部例外规则
- 产物三 `gfwlist-block-domain.srs`：`gfwlist-block` 的**纯域名变体**（去掉唯一的 1 条 `ip_cidr`）。
  专供 **DNS rules** 引用：DNS 查询没有目标 IP，`ip_cidr` 在 DNS 语境本无语义；
  而引用含 `ip_cidr` 的规则集会让 sing-box 1.14 进入 legacy address-filter 模式
  （弃用警告，1.16 拒绝），其配套字段 `rule_set_ip_cidr_match_source: true` 会把
  `ip_cidr` 项变成对**查询来源 IP** 的必要条件，导致整条 DNS 规则永不命中（实测 Google 等
  域名因此落回 local DNS 被投毒）。route rules 仍引用完整的 `gfwlist-block`。
- 参考配置中例外集规则放在 block 集规则**之前**，先命中先放行 —— 与 AutoProxy 的 `@@` 否决语义等价。

## 4. 正则翻译管线（通用，不写死）

对 `/.../ ` 与含 `*`/`^` 的规则统一走翻译管线：

1. 剥外层 `/.../`；剥 URL scheme 前缀 `^https?://`；剥结尾 `$`。
2. `^`（ABP 分隔符）→ `[^A-Za-z0-9_\-.]`；`*` → `.*`；转义 `.`。
3. 若结果只含域名字符与 RE2 元字符 → `domain_regex`，首尾锚定。
4. lookahead/lookbehind/反向引用等 RE2 不支持结构 → 尝试通用重写（如 `(?=.*?(a|b))X` → 含即匹配合并）；失败则按 §3 降级策略取保守方向，审计记录 `regex-fallback`。
5. 产物一律经 Go RE2（由 `sing-box rule-set compile` 实际编译）验证。

## 5. 性能设计

- **去重**：同一 (field, value) 只保留一条。
- **子集消除**：`domain_suffix` 中若 `a` 是 `b` 的后缀且同集合，则 `b` 冗余（`example.com` 存在时 `sub.example.com` 删除）。该消除对 gap 正则同样成立（`sub.example.com` 的连续标签出现必然蕴含 `example.com` 出现）。block 与 exception 分别消除。
- **例外-阻断冲突消解**：exception 完全覆盖某 block 后缀时，审计提示（不静默删除，保持与上游语义一致由路由顺序保证）。
- **集合基数最小化**：优先 `domain_suffix`（sing-box 内部走高效域名树）；右边界缺口用**单条合并正则**补齐而非每行一条 regex（4260 条 regex → 1 条）；特殊 regex 仅 ~10 条。
- 输出 JSON 排序稳定，保证**构建可复现**（同输入同输出，GitHub diff 可审）。
- 实测（M 系列 Mac，sing-box 1.13.16）：block 集编译 0.134s，srs 51KB；exception 集 0.011s，619B。

## 6. 可审计设计

每次转换产出 `audit.json` + `audit.md`，逐行记录：

- 原始行号、原始行文本
- 分类（语法形态）、决策（转成哪条规则）
- 精度标签：`exact` / `widened` / `narrowed` / `approximated` / `dropped`（dropped 仅注释等无语义行）
- 汇总统计与精度分布
- 上游 checksum、`Last Modified`、输入行数、输出规则数

## 7. 全量对拍测试（等价性验证）

- **双引擎 Oracle**：
  - 规范引擎 `adblockparser`（纯 Python，忠实实现 ABP/AutoProxy 参考语义 = gfwlist 原始消费端语义）——未申报偏差即失败；
  - 交叉验证引擎 `python-adblock`（Brave adblock-rust 绑定，uBO 系语义，速度快 ~5 倍）——与规范引擎的偏离计入"引擎分歧"白名单（见 §3.0-5，只报告不修 gate）。
  两个引擎与转换器均零共享代码。
- **被测**：sing-box 规则语义模拟器（精确实现 sing-box `domain`/`domain_suffix`/`domain_keyword`/`domain_regex`/`ip_cidr` 匹配语义 + 例外否决顺序），加载最终 ruleset JSON（含集合级 gap 正则），命中可溯源到原始行号。
- **样本空间**：全量覆盖 ——
  1. 每条规则派生的正例（应命中）与近邻负例（差一个标签/字符）；
  2. 全部规则域名的子域/超域变异（加/删前缀标签、scheme、路径、端口）；
  3. 公共后缀表热门域 + 随机域名（背景负例）；
  4. 例外规则专门构造的对抗样本（例外域名 × block 父域）。
- **判定**：oracle 判定（考虑例外否决）与模拟器判定（exception 集优先）不一致即失败，输出差异清单。
- **真实性校验**：最终 `.srs` 由真实 `sing-box rule-set compile` 编译，`sing-box check` 验证引用该 srs 的完整配置，确保产物被 sing-box 真实接受（含 RE2 兼容性）。
- 允许差异白名单：仅允许审计中已声明的 `widened/approximated` 方向差异，测试逐条核对差异是否都在已声明集合内 —— 即"**没有未申报的语义偏差**"。

## 8. 设计取舍：为什么不按"国内可访问性"裁剪规则

目标决定了规则集的职责：**被 GFW 拦截的域名/IP 走代理，其余直连**。但"按当前可访问性裁剪 block 集"被明确否决，理由：

1. **CI 无法判定可访问性**：GitHub runner 在 GFW 之外，探测结果为全通；只有在墙内探测才有意义，而每日 CI 做不到。
2. **GFW 阻断是动态的**：SNI 重置、IP 封禁随时间波动，一次性探测结论会过期；4200+ 域名逐日探测慢且不可靠。上游 gfwlist 维护者本身就在做规则的入库/剔除，跟踪上游即获得该维护成果。
3. **破坏可复现性与可审计性**：输出不再是上游的纯函数，每日 diff 噪声巨大，审计失真。
4. **用户的裁剪意图已由例外集承载**：`@@` 例外正是"被 block 规则覆盖但国内可访问"的域名（如 `@@||cn.investing.com`），全部保留即实现了"可访问的直连"。
5. **widened 规则（280 条 URL 前缀）去留**：sing-box 连接级模型无法匹配 URL 路径，选择只有"整域走代理"或"整条丢弃"。丢弃 = 被墙路径也直连（违背目标）；保留 = 多代理少量流量（无害）。故全部保留并审计标注。

若未来确需精简，可加**本地一次性探测脚本**（墙内运行，产出补充直连名单），作为可选叠加层，不进入 CI 主线。

## 9. GitHub Actions 每日构建

- `schedule: cron` 每日一次（避开整点，选 07:17 UTC 之类），`workflow_dispatch` 手动触发。
- 步骤：下载 gfwlist → 校验 checksum → 转换 → 编译 srs → 跑对拍测试（失败则中止发布）→ 提交 `dist/` 到仓库（仅在有变化时）→ 打 daily tag / release。
- 产物：`gfwlist-block.srs`、`gfwlist-block-domain.srs`（DNS 专用纯域名变体）、`gfwlist-exception.srs`、对应 `.json`（source）、`gfwlist-shadowrocket.conf`、`audit.md`、`sing-box 参考配置片段`。
- 使用方通过 raw 直链 + `rule_set` type `remote` 自动更新。

## 10. 目录结构

```
gfwlist-srs/
├── docs/DESIGN.md            # 本文档
├── src/gfwlist2srs.py        # 转换器（通用，无写死）
├── src/gfwlist2shadowrocket.py  # Shadowrocket 目标翻译（复用同一解析/优化管线）
├── tests/
│   ├── oracle_abp.py         # adblockparser 封装（独立 oracle）
│   ├── singbox_sim.py        # sing-box 匹配语义模拟器
│   ├── differential_test.py  # sing-box 全量对拍 + 未申报偏差检测
│   └── differential_shadowrocket.py  # Shadowrocket 全量对拍（共用样本/oracle）
├── tools/census.py           # 上游语法普查（设计验证用）
├── dist/                     # 构建产物（json/srs/conf/audit）
└── .github/workflows/daily.yml
```

## 11. Shadowrocket 目标（2026-08-09 扩展）

同一策略的第二目标。`src/gfwlist2shadowrocket.py` 复用 §3–§5 的解析与优化管线
（逐行决策与 sing-box 版逐字一致），仅做目标侧翻译。

### 11.1 Shadowrocket 规则能力面

- 规则按 conf 文件顺序逐条求值，**先命中先生效**；
- `DOMAIN` / `DOMAIN-SUFFIX`（标签边界，与 sing-box `domain_suffix` 同语义）/ `DOMAIN-KEYWORD`；
- `IP-CIDR,x/32,POLICY,no-resolve`（no-resolve：仅匹配 IP 字面量目标，不触发解析）；
- `URL-REGEX` —— 匹配对象是**整条 URL**（非 host），正则 search 语义；
- 内置策略 `PROXY`（当前选中节点）/ `DIRECT` / `REJECT`。

### 11.2 映射表（目标侧翻译）

| sing-box 中间形态 | Shadowrocket | 精度 | 说明 |
|------------------|--------------|------|------|
| `domain_suffix` | `DOMAIN-SUFFIX` | 不变 | 标签边界语义相同 |
| `domain_keyword` | `DOMAIN-KEYWORD` | 不变 | |
| `ip_cidr` | `IP-CIDR,…,no-resolve` | 不变 | |
| 域正则（block） | `URL-REGEX`：`(^|\.)` → `(?:^|://|\.)` | exact→**widened** | `://` 补 apex 起始边界；代价：path 中 `.` 也构成边界（path 含 `suffix.` 片段误命中，放宽=block 安全方向） |
| 域正则（exception） | `URL-REGEX`：`(^|\.)` → `(?:^|://)`，`.*` → `[^/]*` | 不变（exact） | host 内等价，且禁止跨越 path（例外宁窄） |
| block gap 正则 | `(?:^|://|\.)(alts)\.` | exact→**widened** | 同上 path 边界放宽，已申报 |
| exception gap 正则 | `(?:^|://)(alts)\.` | 不变（exact） | 仅 host 起始延续，与 sing-box `^(alts)\.` 同语义 |
| 例外否决语义 | 例外规则以 `DIRECT` 置于全部 `PROXY` 规则之前 | 系统级等价 | 与双规则集架构同理，用文件内顺序表达 |

### 11.3 性能设计

- 4305 条规则中 4292 条是 `DOMAIN-SUFFIX`（Shadowrocket 走高效域匹配）；
- 12 条 `URL-REGEX` 全部排在各自集合**末尾**，仅当 `DOMAIN-SUFFIX` 全部未命中时才求值；
- 两条集合级 gap 超长正则（4200+ 分支）可整行删除，代价：`||host` 延续形态
  （`host.evil.com`）退回标签边界语义（收窄，即放弃 ABP 无右边界语义）。

### 11.4 验证

- 对拍复用同一样本生成与双引擎 oracle；模拟器按 conf 顺序求值，
  并**校验 conf 文件与审计 sr_rules 逐行一致**（防生成器/写出 drift）；
- 当前全量 36645 样本：Shadowrocket 模拟器与 sing-box 模拟器逐样本行为**完全一致**
  （偏差集合相同，仅 6 条责任溯源标签位移），0 未申报偏差；
- 产物：`dist/gfwlist-shadowrocket.conf`（完整配置：[General] + [Rule] + [Host]）、
  `audit-shadowrocket.{json,md}`、`mismatches-shadowrocket.json`。
