#!/usr/bin/env python3
"""
gfwlist2shadowrocket — 将 gfwlist 转换为 Shadowrocket 规则配置 (.conf)。

与 sing-box 等所有目标共用同一 IR (src/gfwparse.py 构建)，保证各目标
的逐行决策一致；本脚本只负责"目标侧翻译"：

  sing-box 字段            Shadowrocket 规则
  ---------------------    ---------------------------------------------
  domain_suffix v          DOMAIN-SUFFIX,v,POLICY      (同为标签边界语义, 精确)
  domain_keyword v         DOMAIN-KEYWORD,v,POLICY
  ip_cidr v                IP-CIDR,v,POLICY,no-resolve
  domain_regex (block)     URL-REGEX: 前缀 (^|\\.) -> (?:^|://|\\.)
                           URL 语境下 path 中的 `.` 也可能构成边界(放宽, 已申报)
  domain_regex (exception) URL-REGEX: 前缀 (^|\\.) -> (?:^|://), .* -> [^/]*
                           host 内等价, 且不会跨入 path (例外宁窄)
  block gap 正则           URL-REGEX (?:^|://|\\.)(alts)\\.   (放宽, 已申报)
  exception gap 正则       URL-REGEX (?:^|://)(alts)\\.       (仅起始延续, 精确)

例外语义: Shadowrocket 规则按序先命中先生效, 因此例外(@@)规则以 DIRECT 置于
全部 PROXY 规则之前 —— 与 AutoProxy `@@` 否决语义系统级等价 (同 sing-box 的
双规则集架构, 只是用文件内顺序表达)。

产物: dist/gfwlist-shadowrocket.conf + dist/audit-shadowrocket.{json,md}

用法: python3 gfwlist2shadowrocket.py <gfwlist.txt|gfwlist.b64> <outdir>
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gfwparse import (  # noqa: E402
    APPROX, DROPPED, EXACT, NARROWED, WIDENED,
    Decision, build_ir, load_gfwlist,
)

# ---------------------------------------------------------------- 目标侧翻译

_PREFIX = "(^|\\.)"


def sr_regex_block(pattern: str) -> tuple[str, str]:
    """block 域正则 -> URL 正则。前缀 (^|\\.) 扩展为 (?:^|://|\\.):
    `://` 补齐 apex 在 scheme 之后的起始边界; 代价是 URL path 中的 `.`
    同样构成边界 (path 内出现 suffix. 片段会误命中 -> 放宽, block 安全方向)。"""
    if pattern.startswith(_PREFIX):
        return "(?:^|://|\\.)" + pattern[len(_PREFIX):], \
            "(^|\\.) -> (?:^|://|\\.); path 中 `.` 边界可能误命中(放宽)"
    return pattern, "原样保留(URL 语境)"


def sr_regex_exception(pattern: str) -> tuple[str, str]:
    """exception 域正则 -> URL 正则。前缀 (^|\\.) -> (?:^|://): 仅匹配 host
    起始边界; 内部 .* -> [^/]* 禁止跨越 path —— host 内与原语义等价,
    且不会产生 path 误命中 (例外宁窄)。"""
    out = pattern
    note = []
    if out.startswith(_PREFIX):
        out = "(?:^|://)" + out[len(_PREFIX):]
        note.append("(^|\\.) -> (?:^|://)")
    if ".*" in out or ".+" in out:
        out = out.replace(".*", "[^/]*").replace(".+", "[^/]+")
        note.append(".* -> [^/]* (禁跨 path)")
    return out, "; ".join(note) or "原样保留"


def sr_gap_regex(suffixes: list[str], exception: bool) -> str:
    """集合级 gap 正则的 URL 语境版本:
      exception: (?:^|://)(alts)\\.   —— 仅 host 起始延续 (例外宁窄, 精确)
      block:     (?:^|://|\\.)(alts)\\. —— 中缀延续也命中; path 中 `.` 边界
                                          可能误命中 (放宽, 已申报)"""
    alt = "|".join(re.escape(s) for s in sorted(suffixes))
    head = "(?:^|://)" if exception else "(?:^|://|\\.)"
    return f"{head}({alt})\\."


# ---------------------------------------------------------------- 主流程

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    text = load_gfwlist(src)
    lines = text.splitlines()

    # 上游元数据 (供 conf 头注释与审计)
    last_modified = ""
    for raw in lines[:20]:
        m = re.match(r"!\s*Last Modified:\s*(.+)", raw.strip())
        if m:
            last_modified = m.group(1).strip()
            break

    # --- 消费 IR (解析/清洗/决策全部在 gfwparse 完成) ---
    # 注意: Shadowrocket 使用 URL 语境正则方言, 集合级 gap 由 sr_gap_regex 自行
    # 重写, 因此这里取**不含** host 语境 gap 的 sets。
    ir = build_ir(text, source=src)
    decisions: list[Decision] = ir.decisions
    block_rules: dict[str, list[str]] = ir.block_rules
    exc_rules: dict[str, list[str]] = ir.exc_rules

    # --- 翻译成 Shadowrocket 规则 (带溯源与精度标签) ---
    # sr_rule: dict(type, value, policy, suffix, src_line, precision, note)
    sr_rules: list[dict] = []

    def emit(rtype: str, value: str, exception: bool, src_line: int,
             precision: str, note: str, suffix: str = ""):
        sr_rules.append({
            "type": rtype, "value": value,
            "policy": "DIRECT" if exception else "PROXY",
            "suffix": suffix,          # 行尾附加 (如 no-resolve)
            "src_line": src_line,      # 原始 gfwlist 行号; gap 为负数
            "precision": precision, "note": note,
            "set": "exception" if exception else "block",
        })

    # 逐行决策 -> 逐条规则 (按优化后的最终集合输出, 消除日志共享)
    decision_by_fv: dict[tuple[str, str], Decision] = {}
    for d in decisions:
        for f, v in d.emitted:
            decision_by_fv.setdefault((f, v), d)

    per_rule_notes: dict[int, str] = {}   # src_line -> 目标侧补充说明

    for exception, rules in ((True, exc_rules), (False, block_rules)):
        for f, values in rules.items():
            for v in values:
                d = decision_by_fv.get((f, v))
                src_line = d.line_no if d else -9
                prec = d.precision if d else EXACT
                note = ""
                if f == "domain_suffix":
                    emit("DOMAIN-SUFFIX", v, exception, src_line, prec, note)
                elif f == "domain_keyword":
                    emit("DOMAIN-KEYWORD", v, exception, src_line, prec, note)
                elif f == "ip_cidr":
                    emit("IP-CIDR", v, exception, src_line, prec,
                         "no-resolve: 仅匹配 IP 字面量目标", suffix=",no-resolve")
                elif f == "domain_regex":
                    if exception:
                        url_re, note = sr_regex_exception(v)
                    else:
                        url_re, note = sr_regex_block(v)
                        if prec == EXACT:
                            prec = WIDENED   # URL 语境 path `.` 边界(放宽)
                        elif prec == APPROX:
                            prec = WIDENED   # `.+` 等可跨 path(放宽)
                        if d:
                            per_rule_notes[d.line_no] = note
                    emit("URL-REGEX", url_re, exception, src_line, prec, note)

    # 集合级 gap 正则 (URL 语境)
    if exc_rules.get("domain_suffix"):
        emit("URL-REGEX", sr_gap_regex(exc_rules["domain_suffix"], True),
             True, -2, EXACT,
             "集合级 gap: ABP 例外无右边界, 补 host 起始延续 (与 sing-box 版同语义)")
    if block_rules.get("domain_suffix"):
        emit("URL-REGEX", sr_gap_regex(block_rules["domain_suffix"], False),
             False, -1, WIDENED,
             "集合级 gap: ABP ||host 无右边界, 补中缀/起始延续; "
             "path 中 `.` 边界可能误命中(放宽)")

    # --- 排序: 例外(DIRECT)全部在前, block(PROXY)在后; 集合内稳定 ---
    def sort_key(r: dict):
        set_rank = 0 if r["set"] == "exception" else 1
        type_rank = {"DOMAIN-SUFFIX": 0, "DOMAIN-KEYWORD": 1, "DOMAIN": 2,
                     "IP-CIDR": 3, "URL-REGEX": 4}[r["type"]]
        return (set_rank, type_rank, r["value"])

    sr_rules.sort(key=sort_key)

    def conf_line(r: dict) -> str:
        return f"{r['type']},{r['value']},{r['policy']}{r['suffix']}"

    # --- 生成 conf ---
    n_exc = sum(1 for r in sr_rules if r["set"] == "exception")
    n_blk = len(sr_rules) - n_exc
    header = [
        "# gfwlist-shadowrocket.conf — 自动生成, 请勿手改",
        f"# Source: gfwlist (Last Modified: {last_modified or 'unknown'})",
        "# Generator: src/gfwlist2shadowrocket.py (语义等价 · 高性能 · 可审计)",
        "# 例外(@@)规则以 DIRECT 置于全部 PROXY 规则之前, 先命中先生效,",
        "# 与 AutoProxy @@ 否决语义等价。审计: audit-shadowrocket.md",
        f"# Rules: exception {n_exc} + block {n_blk} = {len(sr_rules)}",
        "",
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "dns-server = system",
        "",
        "[Rule]",
        "# ===== 例外 (@@) — DIRECT, 必须先于 block 命中 =====",
    ]
    body = []
    prev_set = "exception"
    for r in sr_rules:
        if r["set"] != prev_set:
            body += ["", "# ===== 阻断 — PROXY ====="]
            prev_set = r["set"]
        body.append(conf_line(r))
    body += ["", "# 其余直连", "FINAL,DIRECT", "", "[Host]", "localhost = 127.0.0.1", ""]
    conf_text = "\n".join(header + body)
    (outdir / "gfwlist-shadowrocket.conf").write_text(conf_text)

    # --- 审计 ---
    sr_precision_dist: dict[str, int] = {}
    for r in sr_rules:
        key = f"{r['set']}:{r['precision']}"
        sr_precision_dist[key] = sr_precision_dist.get(key, 0) + 1

    summary = {
        "input_lines": len(lines),
        "upstream_last_modified": last_modified,
        "shadowrocket_rules": {
            "exception": n_exc, "block": n_blk, "total": len(sr_rules),
            "by_type": {
                t: sum(1 for r in sr_rules if r["type"] == t)
                for t in ("DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "URL-REGEX")
            },
        },
        "sr_precision_distribution": sr_precision_dist,
        "optimization_log_shared": ir.optimization_log,
        "target_notes": [
            "URL-REGEX 匹配对象为整条 URL; DOMAIN-* 匹配对象为 host。",
            "block 侧域正则/gap 的 (^|\\.) 前缀扩展为 (?:^|://|\\.), "
            "URL path 中的 `.` 也会构成边界 -> 可能误命中 path 含 suffix. 片段的 URL"
            " (放宽, block 安全方向, 已在逐条精度中申报)。",
            "exception 侧域正则前缀为 (?:^|://) 且 .* -> [^/]*, 不会跨入 path"
            " (host 内等价, 例外宁窄)。",
            "两条集合级 gap URL-REGEX 位于各自集合末尾, 仅当所有 DOMAIN-SUFFIX "
            "未命中时才会求值; 若介意超长正则的运行开销可整行删除, 代价是 "
            "`||host` 的延续形态 (host.evil.com) 退回与 DOMAIN-SUFFIX 相同的"
            "标签边界语义 (收窄, 相当于放弃 ABP 无右边界语义)。",
        ],
    }

    decisions_out = []
    for d in decisions:
        dd = asdict(d)
        if d.line_no in per_rule_notes:
            dd["sr_note"] = per_rule_notes[d.line_no]
        decisions_out.append(dd)

    audit = {
        "source": str(src),
        "target": "shadowrocket",
        "conf_file": "gfwlist-shadowrocket.conf",
        "sr_rules": sr_rules,
        "decisions": decisions_out,
        "summary": summary,
    }
    (outdir / "audit-shadowrocket.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n")

    md = ["# gfwlist→Shadowrocket 审计报告\n",
          f"- 上游 Last Modified: {last_modified or 'unknown'}",
          f"- 输入行数: {summary['input_lines']}",
          f"- Shadowrocket 规则: {json.dumps(summary['shadowrocket_rules'], ensure_ascii=False)}",
          f"- 目标侧精度分布: {json.dumps(sr_precision_dist, ensure_ascii=False)}",
          "",
          "## 目标侧说明",
          ] + [f"- {n}" for n in summary["target_notes"]] + [
          "",
          "## 非精确规则明细 (widened / narrowed / approximated)",
          "",
          "| 规则 | 集合 | 精度 | 源行 | 说明 |",
          "|---|---|---|---|---|",
    ]
    for r in sr_rules:
        if r["precision"] in (WIDENED, NARROWED, APPROX):
            rule_esc = conf_line(r).replace("|", "\\|")
            if len(rule_esc) > 90:
                rule_esc = rule_esc[:87] + "..."
            md.append(f"| `{rule_esc}` | {r['set']} | {r['precision']} | "
                      f"{r['src_line']} | {r['note']} |")
    (outdir / "audit-shadowrocket.md").write_text("\n".join(md) + "\n")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
