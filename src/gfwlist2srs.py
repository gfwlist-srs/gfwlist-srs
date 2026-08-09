#!/usr/bin/env python3
"""
gfwlist2srs — sing-box 目标适配器: 消费 gfwparse 构建的 IR, 产出
sing-box headless rule-set (JSON source, version 3)，供 `sing-box rule-set compile`
编译为 .srs；同时发布公共 IR (gfwlist-ir.json) 供其他目标/第三方二次转换。

设计原则（见 docs/DESIGN.md）：
  - 语义决策全部在 IR 层 (src/gfwparse.py) 完成并逐行申报精度；
  - 本适配器只做词汇表封装 (IR sets → sing-box ruleset JSON), 不做语义决策。

用法:
  python3 gfwlist2srs.py <gfwlist.txt|gfwlist.b64> <outdir>
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gfwparse import (  # noqa: E402
    APPROX, NARROWED, WIDENED, build_ir, load_gfwlist, with_gap_regex,
)

# ---------------------------------------------------------------- 主流程

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    text = load_gfwlist(src)
    ir = build_ir(text, source=src)

    # sing-box 是 host 语境 RE2 方言: 集合级 gap 正则直接并入 domain_regex。
    block_rules = with_gap_regex(ir.block_rules, ir.block_gap)
    exc_rules = with_gap_regex(ir.exc_rules, ir.exc_gap)
    decisions = ir.decisions
    conflicts = ir.conflicts
    block_gap, exc_gap = ir.block_gap, ir.exc_gap

    # --- 公共 IR 产物 (多目标管线的公共数据源) ---
    (outdir / "gfwlist-ir.json").write_text(
        json.dumps(ir.to_json_dict(), indent=2, ensure_ascii=False) + "\n")

    def ruleset(rules: dict) -> dict:
        return {"version": 3, "rules": [rules] if rules else []}

    (outdir / "gfwlist-block.json").write_text(
        json.dumps(ruleset(block_rules), indent=2, ensure_ascii=False) + "\n")
    (outdir / "gfwlist-exception.json").write_text(
        json.dumps(ruleset(exc_rules), indent=2, ensure_ascii=False) + "\n")

    # 纯域名变体 (供 DNS 规则引用): 去掉 ip_cidr。
    # sing-box 1.14+ 中, DNS 规则引用含 ip_cidr 的规则集会触发旧版
    # "address filter" 模式 (1.16 将移除); 而 ip_cidr 对 DNS 查询本无意义
    # (问题名不可能是 IP 网段), 因此提供纯域名集用于 DNS 分流。
    block_domain_rules = {k: v for k, v in block_rules.items() if k != "ip_cidr"}
    (outdir / "gfwlist-block-domain.json").write_text(
        json.dumps(ruleset(block_domain_rules), indent=2, ensure_ascii=False) + "\n")

    # --- 审计 ---
    summary = {
        "input_lines": ir.input_lines,
        "block_rules": {k: len(v) for k, v in block_rules.items()},
        "exception_rules": {k: len(v) for k, v in exc_rules.items()},
        "precision_distribution": {},
        "optimization_log": ir.optimization_log,
        "conflicts": conflicts,
        "encoding_note": (
            "domain_suffix + 一条合并 gap 正则 `(^|\\.)(suffix...)\\.` 联合编码 "
            "ABP `||host` 的左边界/无右边界语义, 二者合取与原版精确等价; "
            "gap 正则是集合级产物, 不归属单一行。"),
        "gap_regex_chars": {"block": len(block_gap or ""), "exception": len(exc_gap or "")},
    }
    for d in decisions:
        key = ("exception:" if d.exception else "block:") + d.precision
        summary["precision_distribution"][key] = \
            summary["precision_distribution"].get(key, 0) + 1

    audit = {
        "source": str(src),
        "decisions": [asdict(d) for d in decisions],
        "summary": summary,
    }
    (outdir / "audit.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n")

    # markdown 摘要
    md = ["# gfwlist→srs 审计报告\n",
          f"- 输入行数: {summary['input_lines']}",
          f"- block 规则: {summary['block_rules']}",
          f"- exception 规则: {summary['exception_rules']}",
          f"- 精度分布: {json.dumps(summary['precision_distribution'], ensure_ascii=False)}",
          f"- 优化消除: {len(ir.optimization_log)} 条",
          f"- 跨集冲突: {len(conflicts)} 条\n",
          "## 非精确转换明细 (widened / narrowed / approximated)\n",
          "| 行号 | 类别 | 精度 | 原始行 | 决策 | 输出 |",
          "|---|---|---|---|---|---|"]
    for d in decisions:
        if d.precision in (WIDENED, NARROWED, APPROX):
            outs = ", ".join(f"{f}={v}" for f, v in d.emitted) or "(丢弃)"
            raw_esc = d.raw.strip().replace("|", "\\|")[:80]
            md.append(f"| {d.line_no} | {d.category} | {d.precision} | `{raw_esc}` | {d.note} | `{outs[:100]}` |")
    if conflicts:
        md.append("\n## 跨集冲突 (exception 覆盖 block, 由路由顺序保义)\n")
        md += [f"- {c}" for c in conflicts]
    (outdir / "audit.md").write_text("\n".join(md) + "\n")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
