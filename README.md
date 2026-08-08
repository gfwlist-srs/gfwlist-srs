# gfwlist → sing-box headless-rule (.srs)

[![daily build](https://github.com/gfwlist-srs/gfwlist-srs/actions/workflows/daily.yml/badge.svg)](https://github.com/gfwlist-srs/gfwlist-srs/actions/workflows/daily.yml)
[![jsdelivr](https://data.jsdelivr.com/v1/package/gh/gfwlist-srs/gfwlist-srs/badge)](https://cdn.jsdelivr.net/gh/gfwlist-srs/gfwlist-srs@main/)

将官方 [gfwlist](https://github.com/gfwlist/gfwlist) 转换为 sing-box 标准 headless rule-set
（`.srs` 二进制 + JSON source），目标：**语义等价 · 高性能 · 可审计**。
设计与映射推导见 [docs/DESIGN.md](docs/DESIGN.md)。

## 产物（dist/）

| 文件 | 说明 |
|------|------|
| `gfwlist-block.srs` / `.json` | 阻断规则集（编译后 / source） |
| `gfwlist-exception.srs` / `.json` | 例外（白名单）规则集 |
| `audit.md` / `audit.json` | 逐行转换审计（分类、决策、精度标签） |
| `mismatches.json` | 最近一次全量对拍的偏差明细（全部已申报） |

## 本地构建与验证

```bash
# 依赖: sing-box >= 1.11, python >= 3.10, pip install -r requirements.txt
curl -fsSL -o gfwlist.b64 https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
python3 tools/validate_input.py gfwlist.b64          # 输入结构验证
base64 -d -i gfwlist.b64 -o gfwlist.txt              # Windows: certutil -decode
python3 src/gfwlist2srs.py gfwlist.txt dist          # 转换 + 审计
sing-box rule-set compile dist/gfwlist-block.json -o dist/gfwlist-block.srs
sing-box rule-set compile dist/gfwlist-exception.json -o dist/gfwlist-exception.srs
python3 tests/differential_test.py gfwlist.txt dist  # 全量对拍（门禁）
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
> 本仓库的每日工作流在每次更新 dist 后会主动 purge 这两个文件的 CDN 缓存，
> 因此客户端按 `update_interval` 拉取即可拿到当日最新版。
> 备用直链（无 CDN）：`https://raw.githubusercontent.com/gfwlist-srs/gfwlist-srs/main/dist/gfwlist-block.srs`

## 已知语义偏差（全部审计申报，详见 dist/audit.md）

| 方向 | 来源 | 影响 |
|------|------|------|
| widened | 280 条 URL 前缀规则的 scheme/path 条件在连接级模型中不存在 | 被墙站全协议走代理（无害） |
| approximated | 2 条裸子串规则 → 域后缀；247 条无尾斜杠 URL 前缀规则的"向右延续"语义 | 仅理论边界差异 |
| narrowed | 1 条畸形正则（L314，缺收尾 `/`） | 按 ABP 规范该规则本就永不命中，丢弃等价 |

## GitHub Actions

`.github/workflows/daily.yml`：每日 01:17 UTC（北京 09:17）自动 下载→验证→转换→编译→**对拍门禁**→提交 dist。对拍失败则不发布。
