#!/usr/bin/env python3
"""
gfwparse — gfwlist (ABP/AutoProxy filter list) → 公共中间表示 (IR)。

这是多目标管线的第②/③层（解析 + 保义清洗），目标无关：

  gfwlist.txt ──parse_line──▶ 逐行 Decision（ABP 语义 + 降级决策 + 精度标签）
              ──optimize────▶ 规范化规则集（去重 / 子集消除）
              ──gap 正则────▶ 集合级补齐 ABP `||host` 无右边界语义

IR 的规则集使用**工具中立的匹配器词汇表**：
  domain_suffix   标签边界后缀匹配（host 本身 + 子域）
  domain_keyword  子串匹配
  domain_regex    RE2 / host 语境正则（各目标自行改写方言）
  ip_cidr         IP 网段

各目标适配器（sing-box / Shadowrocket / Clash / Xray / …）消费 IR，
只做"词汇表 + 方言"翻译，不做任何语义决策 —— 语义决策全部收敛在本层，
并逐行申报精度标签（exact/widened/narrowed/approximated/dropped）。

用法:
  python3 gfwparse.py <gfwlist.txt|gfwlist.b64> <out.json>   # 仅产出 IR
  或作为库:  from gfwparse import build_ir
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------- 精度标签

EXACT = "exact"            # 语义完全等价
WIDENED = "widened"        # 转换后匹配范围变大（block 安全方向）
NARROWED = "narrowed"      # 转换后匹配范围变小（exception 安全方向）
APPROX = "approximated"    # 双向存在理论差异，实践等价
DROPPED = "dropped"        # 无匹配语义（注释/头/空行）或按策略丢弃

# ---------------------------------------------------------------- 数据模型

@dataclass
class Decision:
    line_no: int
    raw: str
    category: str          # 语法形态
    exception: bool
    precision: str
    note: str = ""
    # 输出规则: (field, value) 列表; 空表示丢弃
    emitted: list = field(default_factory=list)


@dataclass
class IR:
    """gfwlist 的公共中间表示（内存形态）。"""
    source: str
    input_lines: int
    decisions: list[Decision]
    block_rules: dict[str, list[str]]    # 优化后 + 集合级 gap 正则
    exc_rules: dict[str, list[str]]
    optimization_log: list[str]
    conflicts: list[str]
    block_gap: str | None
    exc_gap: str | None

    def to_json_dict(self) -> dict:
        """序列化为 dist/gfwlist-ir.json（版本化 schema）。"""
        return {
            "kind": "gfwlist-ir",
            "version": 1,
            "source": {"name": self.source, "input_lines": self.input_lines},
            "semantics": {
                "vocabulary": {
                    "domain_suffix": "标签边界后缀匹配 (host 本身 + 子域)",
                    "domain_keyword": "host 子串匹配",
                    "domain_regex": "RE2, host 语境, 非锚定 (各目标自行改写方言)",
                    "ip_cidr": "目标 IP 网段",
                },
                "exception_model": "双集 + 消费端保证 exception 先于 block 求值"
                                   " (= AutoProxy @@ 否决语义)",
                "gap_regex_note": (
                    "domain_suffix + 一条集合级 gap 正则联合编码 ABP `||host` 的"
                    "左边界/无右边界语义, 二者合取与原版精确等价; "
                    "gap 正则是集合级产物, 不归属单一行, 不并入 sets —— "
                    "由各目标适配器按方言取用 (见 gap_regex 字段)。"),
            },
            "sets": {"block": self.block_rules, "exception": self.exc_rules},
            "gap_regex": {"block": self.block_gap, "exception": self.exc_gap},
            "optimization_log": self.optimization_log,
            "conflicts": self.conflicts,
            "decisions": [asdict(d) for d in self.decisions],
        }

# ---------------------------------------------------------------- 输入

def load_gfwlist(path: str) -> str:
    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
        if "[AutoProxy" not in text.splitlines()[0]:
            raise ValueError
        return text
    except (UnicodeDecodeError, ValueError, IndexError):
        return base64.b64decode(raw).decode("utf-8")

# ---------------------------------------------------------------- 工具

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_SCHEME_ANCHOR_RE = re.compile(r"^\^?https\??:\\?/\\?/")  # ^https?:\/\/ / https?:\/\/ / http:\/\/ 等变体
_RE2_UNSUPPORTED = re.compile(r"\(\?=|\(\?!|\(\?<=|\(\?<!|\\[1-9]|\\b|\\B")

def is_ip(host: str) -> bool:
    if not _IPV4_RE.match(host):
        return False
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False

def clean_host(host: str) -> str:
    return host.lower().rstrip(".")

def host_is_plain(host: str) -> bool:
    return bool(_HOST_RE.match(host))

def wildcard_host_to_regex(host: str) -> str:
    """ABP host 通配模式 -> 域名正则。
    `||` 锚定允许匹配起始于任意子域边界, 故前缀用 (^|\\.);
    ABP 模式结尾无右边界要求, 故**不加 $ 锚定** (依赖 partial match)。
    ABP `*` 匹配任意字符序列(可跨标签), `^` 为分隔符。"""
    out = []
    for ch in host:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append("[^a-z0-9_\\-.]")
        elif ch in ".-+()[]{}\\|$":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "(^|\\.)" + "".join(out)

# ---------------------------------------------------------------- 正则翻译管线

def _rewrite_lookahead(pattern: str) -> str | None:
    """通用重写单一正向前瞻: (?=.*?(a|b|c))REST
    要求 REST 中存在一个字符类重复 [X]+, 将其改写为 [X]*(a|b|c)[X]*。
    仅当 alternation 全部由字面量构成时适用。返回 None 表示模板不匹配。"""
    m = re.match(r"^\(\?=\.\*\?\(([^()]+)\)\)(.*)$", pattern)
    if not m:
        return None
    alts = m.group(1)
    if re.search(r"[\\[\\]{}()*+?.^$|\\\\]", alts.replace("|", "")):
        return None  # alternation 含元字符, 不安全
    rest = m.group(2)
    cm = re.search(r"\[[^\[\]]+\]\+", rest)
    if not cm:
        return None
    cls = cm.group(0)[:-1]  # 去掉 '+'
    return rest[:cm.start()] + cls + "*(" + alts + ")" + cls + "*" + rest[cm.end():]

def translate_url_regex(pattern: str) -> tuple[str | None, str]:
    """URL 正则 -> 域名正则。返回 (regex|None, note)。"""
    p = pattern.strip()
    if not _SCHEME_ANCHOR_RE.match(p):
        return None, "regex-not-url-anchored"
    p = _SCHEME_ANCHOR_RE.sub("", p)
    end_anchored = p.endswith("$")
    if end_anchored:
        p = p[:-1]
    # 前瞻重写 (RE2 不支持 lookahead)
    if "(?" in p:
        rw = _rewrite_lookahead(p)
        if rw is None:
            return None, "regex-unsupported-construct"
        p = rw
    # URL 字符类 -> 域名字符类 (域名不含 '/')
    p = p.replace("[^\\/]+", ".+").replace("[^\\/]*", ".*")
    if "\\/" in p or re.search(r"(?<![\\\[])/", p):
        return None, "regex-contains-path"
    if _RE2_UNSUPPORTED.search(p):
        return None, "regex-re2-unsupported"
    # 残留 URL 专用字符检查 (字面量中的 ? & = : 等)
    body = re.sub(r"\[[^\[\]]*\]", "", p)  # 去掉字符类后检查
    if re.search(r"[?&=:]", body.replace("\\?", "")):
        return None, f"regex-contains-url-chars"
    try:
        re.compile(p)
    except re.error as e:
        return None, f"regex-invalid:{e}"
    final = "^" + p
    if end_anchored:
        final += "$"
    return final, "regex-translated"

def extract_literal_domain(pattern: str) -> str | None:
    """从正则中提取最长的字面量域名片段 (用于 fallback)。"""
    best = ""
    for m in re.finditer(r"((?:\\\.|[a-z0-9-])+)", pattern.lower()):
        lit = m.group(1).replace("\\.", ".")
        if "." in lit and len(lit) > len(best) and host_is_plain(lit):
            best = lit
    return best or None

# ---------------------------------------------------------------- 行解析

def parse_line(line_no: int, raw: str) -> Decision:
    line = raw.strip()
    if not line:
        return Decision(line_no, raw, "blank", False, DROPPED)
    if line.startswith("!"):
        return Decision(line_no, raw, "comment", False, DROPPED)
    if line.startswith("[") and line.endswith("]"):
        return Decision(line_no, raw, "header", False, DROPPED)

    exception = line.startswith("@@")
    body = line[2:] if exception else line

    # --- 畸形正则: 以 / 开头但不满足 ABP /.../ 规范 ---
    # 按 ABP/AutoProxy 规范此时它是字面量 filter (实践中永远不命中), 丢弃即等价。
    if body.startswith("/") and not (body.endswith("/") and len(body) > 2):
        cat = ("exception+" if exception else "") + "malformed-regex"
        return Decision(line_no, raw, cat, exception,
                        NARROWED if exception else EXACT,
                        "畸形正则(缺收尾/), 按 ABP 规范为永不命中的字面量 filter, 丢弃等价")

    # --- /regex/ ---
    if body.startswith("/") and body.endswith("/") and len(body) > 2:
        pattern = body[1:-1]
        cat = "regex-exception" if exception else "regex"
        regex, note = translate_url_regex(pattern)
        if regex:
            return Decision(line_no, raw, cat, exception, APPROX, note,
                            [("domain_regex", regex)])
        # fallback: block 放宽(提取字面量域名为 keyword/suffix), exception 收窄(丢弃)
        if not exception:
            lit = extract_literal_domain(pattern)
            if lit:
                return Decision(line_no, raw, cat, exception, WIDENED,
                                f"{note}; fallback=literal-domain",
                                [("domain_suffix", lit)])
        return Decision(line_no, raw, cat, exception, NARROWED,
                        f"{note}; rule-dropped-by-policy")

    # --- 锚定解析 ---
    host_anchor = False
    start_anchor = False
    end_anchor = False
    if body.startswith("||"):
        host_anchor = True
        body = body[2:]
    elif body.startswith("|"):
        start_anchor = True
        body = body[1:]
    if body.endswith("|") and len(body) > 1:
        end_anchor = True
        body = body[:-1]

    # --- 拆 scheme / host / path ---
    scheme = None
    host_part = body
    path_part = None
    if "://" in body:
        scheme, rest = body.split("://", 1)
        host_part, sep, tail = rest.partition("/")
        path_part = tail if sep else None
    elif "/" in body:
        host_part, _, tail = body.partition("/")
        path_part = tail
    host = clean_host(host_part.strip())

    has_path_cond = path_part not in (None, "")
    has_scheme_cond = scheme is not None and start_anchor
    has_wildcard = ("*" in host_part) or ("^" in host_part)

    cat_parts = []
    if host_anchor: cat_parts.append("host-anchor")
    if start_anchor: cat_parts.append("url-prefix")
    if end_anchor: cat_parts.append("end-anchor")
    if not cat_parts: cat_parts.append("substring")
    if has_path_cond: cat_parts.append("path")
    if has_wildcard: cat_parts.append("wildcard")
    category = ("exception+" if exception else "") + "|".join(cat_parts)

    # --- exception 侧无法收窄保义的条件 -> 丢弃整条 (宁窄勿宽) ---
    if exception and (has_path_cond or has_scheme_cond):
        return Decision(line_no, raw, category, exception, NARROWED,
                        "exception 带 path/scheme 条件, 无法收窄保义, 丢弃整条")

    notes = []
    precision = EXACT
    if has_path_cond:
        notes.append(f"path 条件 '/{path_part}' 被丢弃(放宽)")
        precision = WIDENED
    if has_scheme_cond:
        notes.append(f"scheme 条件 '{scheme}://' 被丢弃(放宽)")
        precision = WIDENED
    # `|http://host` (无尾斜杠/路径) 的 ABP 语义是 URL 前缀:
    # host 必须以其开头但可向右延续 (hostX 命中), 且不命中子域。
    # domain_suffix 增加了子域(宽), 丢失了向右延续(窄) -> 双向近似。
    if start_anchor and not has_path_cond and path_part is None and not has_wildcard:
        notes.append("ABP URL 前缀语义(可向右延续)与 domain_suffix 边界语义双向近似")
        precision = APPROX
    if end_anchor and not (host_anchor or start_anchor):
        notes.append("end-anchor 按 substring 近似处理")
        precision = APPROX

    # --- 目标形态决策 ---
    if is_ip(host):
        if has_wildcard:
            return Decision(line_no, raw, category, exception, NARROWED,
                            "IP 含通配符, 丢弃")
        return Decision(line_no, raw, category, exception, precision,
                        "; ".join(notes), [("ip_cidr", host + "/32")])

    if not host:
        return Decision(line_no, raw, category, exception, NARROWED,
                        "无法提取 host, 丢弃")

    if has_wildcard:
        # 纯前缀通配 *.rest 特判
        if host_part.startswith("*."):
            rest = clean_host(host_part[2:])
            if host_is_plain(rest):
                if exception:
                    # 精确: 仅子域, 不含 apex; ABP 无右边界, 不加 $ (例外宁窄已满足)
                    regex = "(^|\\.).*\\." + re.escape(rest)
                    return Decision(line_no, raw, category, exception, EXACT,
                                    "; ".join(notes) or "子域通配(不含 apex, 无右边界)",
                                    [("domain_regex", regex)])
                notes.append("`*.` 通配放宽为 domain_suffix(多含 apex)")
                return Decision(line_no, raw, category, exception, WIDENED,
                                "; ".join(notes), [("domain_suffix", rest)])
        regex = wildcard_host_to_regex(host_part.lower())
        return Decision(line_no, raw, category, exception,
                        APPROX if precision == EXACT else precision,
                        ("; ".join(notes) + "; " if notes else "") + "host 通配 -> domain_regex",
                        [("domain_regex", regex)])

    if host_is_plain(host):
        if not (host_anchor or start_anchor or end_anchor):
            # 裸子串: 实践中按域后缀处理
            return Decision(line_no, raw, category, exception, APPROX,
                            "裸子串 -> domain_suffix", [("domain_suffix", host)])
        return Decision(line_no, raw, category, exception, precision,
                        "; ".join(notes), [("domain_suffix", host)])

    # host 不是合法域名形式(无锚定裸子串等) -> domain_keyword
    if not (host_anchor or start_anchor):
        return Decision(line_no, raw, category, exception, APPROX,
                        "非常规子串 -> domain_keyword",
                        [("domain_keyword", host)])
    return Decision(line_no, raw, category, exception, NARROWED,
                    f"host 形态无法保义: {host_part!r}, 丢弃")

# ---------------------------------------------------------------- 保义清洗 (目标无关)

def optimize(rules: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[str]]:
    """去重 + domain_suffix 子集消除 + domain 被 suffix 覆盖消除。返回 (rules, 消除日志)。"""
    log = []
    out = {k: sorted(set(v)) for k, v in rules.items()}
    suffixes = out.get("domain_suffix", [])
    if suffixes:
        ss = sorted(suffixes, key=lambda s: (s.count("."), s))
        keep = []
        for s in ss:
            covered = any(s != t and (s == t or s.endswith("." + t)) for t in keep)
            if covered:
                log.append(f"domain_suffix 冗余消除: {s}")
            else:
                keep.append(s)
        out["domain_suffix"] = sorted(keep)
    if out.get("domain"):
        keep_d = []
        for d in out["domain"]:
            if any(d == s or d.endswith("." + s) for s in out.get("domain_suffix", [])):
                log.append(f"domain 被 suffix 覆盖消除: {d}")
            else:
                keep_d.append(d)
        out["domain"] = keep_d
    return {k: v for k, v in out.items() if v}, log

def conflict_notes(block: dict, exception: dict) -> list[str]:
    notes = []
    for es in exception.get("domain_suffix", []):
        for bs in block.get("domain_suffix", []):
            if bs == es or bs.endswith("." + es):
                notes.append(f"exception suffix `{es}` 完全覆盖 block suffix `{bs}` (由路由顺序保义)")
    return notes

def make_gap_regex(rules: dict[str, list[str]], middle: bool) -> str | None:
    """ABP 系引擎中 `||host` 除后缀匹配外还有"延续匹配" (host 后还有标签,
    如 example.com.evil.com)。domain_suffix 要求右边界, 缺口用合并正则补齐:
      middle=True  (block):     (^|\\.)(h1|h2|...)\\.   —— 中缀延续也算 (安全方向放宽)
      middle=False (exception): ^(h1|h2|...)\\.         —— 仅起始延续 (例外宁窄,
                                   且与基准引擎 adblock-rust 实测行为一致)
    与 domain_suffix 合取后与基准引擎语义对齐 (残余差异归入已声明的引擎分歧类)。
    **只返回正则, 不修改 rules** —— 是否并入 domain_regex 由各目标适配器决定。
    无 suffix 时返回 None。"""
    suffixes = rules.get("domain_suffix", [])
    if not suffixes:
        return None
    alt = "|".join(re.escape(s) for s in sorted(suffixes))
    return ("(^|\\.)(" if middle else "^(") + alt + ")\\."

# ---------------------------------------------------------------- IR 构建

def with_gap_regex(rules: dict[str, list[str]], gap: str | None) -> dict[str, list[str]]:
    """返回 rules 的副本, 并把集合级 gap 正则并入 domain_regex 末尾。
    供 host 语境正则方言的适配器 (sing-box/Clash/Xray) 使用。"""
    if not gap:
        return rules
    out = {k: list(v) for k, v in rules.items()}
    out.setdefault("domain_regex", []).append(gap)
    return out

def build_ir(text: str, source: str = "gfwlist") -> IR:
    """gfwlist 文本 → IR（解析 + 保义清洗 + 集合级 gap 正则）。"""
    lines = text.splitlines()
    decisions: list[Decision] = []
    block_rules: dict[str, list[str]] = {}
    exc_rules: dict[str, list[str]] = {}

    for i, raw in enumerate(lines, 1):
        d = parse_line(i, raw)
        decisions.append(d)
        target = exc_rules if d.exception else block_rules
        for f, v in d.emitted:
            target.setdefault(f, []).append(v)

    block_rules, b_log = optimize(block_rules)
    exc_rules, e_log = optimize(exc_rules)
    conflicts = conflict_notes(block_rules, exc_rules)
    # gap 正则**不并入** sets: 它是 host 语境的集合级产物, 各目标适配器按需取用
    # (sing-box/Clash/Xray 直接并入 regex 列表; Shadowrocket/list 改写为 URL 语境;
    #  Quantumult X 无正则能力则丢弃并申报 narrowed)。
    block_gap = make_gap_regex(block_rules, middle=True)
    exc_gap = make_gap_regex(exc_rules, middle=False)

    return IR(
        source=source,
        input_lines=len(lines),
        decisions=decisions,
        block_rules=block_rules,
        exc_rules=exc_rules,
        optimization_log=b_log + e_log,
        conflicts=conflicts,
        block_gap=block_gap,
        exc_gap=exc_gap,
    )

# ---------------------------------------------------------------- 独立运行

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    text = load_gfwlist(sys.argv[1])
    ir = build_ir(text, source=sys.argv[1])
    Path(sys.argv[2]).write_text(
        json.dumps(ir.to_json_dict(), indent=2, ensure_ascii=False) + "\n")
    print(f"IR: {ir.input_lines} lines -> "
          f"block {sum(len(v) for v in ir.block_rules.values())} rules, "
          f"exception {sum(len(v) for v in ir.exc_rules.values())} rules")
    return 0

if __name__ == "__main__":
    sys.exit(main())
