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

- **Oracle**：第三方独立实现 `adblockparser`（真实 ABP 匹配器，与转换器零共享代码）。
- **被测**：sing-box 规则语义模拟器（精确实现 sing-box `domain`/`domain_suffix`/`domain_keyword`/`domain_regex`/`ip_cidr` 匹配语义 + 例外否决顺序）。
- **样本空间**：全量覆盖 ——
  1. 每条规则派生的正例（应命中）与近邻负例（差一个标签/字符）；
  2. 全部规则域名的子域/超域变异（加/删前缀标签、scheme、路径、端口）；
  3. 公共后缀表热门域 + 随机域名（背景负例）；
  4. 例外规则专门构造的对抗样本（例外域名 × block 父域）。
- **判定**：oracle 判定（考虑例外否决）与模拟器判定（exception 集优先）不一致即失败，输出差异清单。
- **真实性校验**：最终 `.srs` 由真实 `sing-box rule-set compile` 编译，`sing-box check` 验证引用该 srs 的完整配置，确保产物被 sing-box 真实接受（含 RE2 兼容性）。
- 允许差异白名单：仅允许审计中已声明的 `widened/approximated` 方向差异，测试逐条核对差异是否都在已声明集合内 —— 即"**没有未申报的语义偏差**"。

## 8. GitHub Actions 每日构建

- `schedule: cron` 每日一次（避开整点，选 07:17 UTC 之类），`workflow_dispatch` 手动触发。
- 步骤：下载 gfwlist → 校验 checksum → 转换 → 编译 srs → 跑对拍测试（失败则中止发布）→ 提交 `dist/` 到仓库（仅在有变化时）→ 打 daily tag / release。
- 产物：`gfwlist-block.srs`、`gfwlist-exception.srs`、`gfwlist-block.json`（source）、`gfwlist-exception.json`（source）、`audit.md`、`sing-box 参考配置片段`。
- 使用方通过 raw 直链 + `rule_set` type `remote` 自动更新。

## 9. 目录结构

```
gfwlist-srs/
├── docs/DESIGN.md            # 本文档
├── src/gfwlist2srs.py        # 转换器（通用，无写死）
├── tests/
│   ├── oracle_abp.py         # adblockparser 封装（独立 oracle）
│   ├── singbox_sim.py        # sing-box 匹配语义模拟器
│   └── differential_test.py  # 全量对拍 + 未申报偏差检测
├── tools/census.py           # 上游语法普查（设计验证用）
├── dist/                     # 构建产物（json/srs/audit）
└── .github/workflows/daily.yml
```
