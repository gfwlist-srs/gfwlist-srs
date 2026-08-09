#!/usr/bin/env python3
"""
gfwlist2targets — 多目标适配器: 消费 IR (src/gfwparse.py), 产出
Surge 系 / Clash 系 / Xray 系 / Quantumult X 规则产物。

与 sing-box/Shadowrocket 适配器一样, 本脚本不做任何语义决策 —— 只做
词汇表翻译与正则方言改写; 逐行溯源 (src_line) 与精度标签随规则携带,
写入 audit-targets.json 供对拍门禁 (tests/differential_targets.py) 使用。

目标与产物:
  surge  → gfwlist-exception.list / gfwlist-block.list
           裸规则行 (无策略列), URL-REGEX 方言 (同 Shadowrocket 重写逻辑)。
           供 Surge RULE-SET / Loon RULE-SET / Shadowrocket 规则分组引用:
           先 RULE-SET 例外 (DIRECT) 后 RULE-SET 阻断 (PROXY)。
  clash  → gfwlist-clash-exception.yaml / gfwlist-clash-block.yaml
           classical rule-provider (yaml), DOMAIN-REGEX = host 语境 RE2
           (与 sing-box 同方言, gap 正则直接并入)。mihomo/Clash Premium/
           Stash/FlClash 通用。
  xray   → gfwlist-xray.json
           v2rayN 自定义路由格式 (JSON 数组, rules 为标准 Xray RuleObject):
           例外规则 (direct) 在前, 阻断规则 (proxy) 在后。
           domain 令牌显式带 domain:/keyword:/regexp: 前缀 —— Xray 裸字符串
           是 keyword 子串语义, 无前缀会严重误伤。Xray/v2ray/v2rayN/v2rayNG
           /NekoBox(xray 内核)/Passwall 通用。
  qx     → gfwlist-quantumultx.list
           host-suffix/host-keyword/ip-cidr 行 (带策略列, 例外 direct 在前)。
           Quantumult X 无域正则能力: 10 条域正则与集合级 gap 丢弃
           (narrowed, 审计申报, 门禁按"能力收窄"白名单处理)。

用法: python3 gfwlist2targets.py <gfwlist.txt|gfwlist.b64> <outdir>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gfwparse import (  # noqa: E402
    APPROX, EXACT, NARROWED, WIDENED, build_ir, load_gfwlist,
)
from gfwlist2shadowrocket import (  # noqa: E402  (URL 语境正则方言重写)
    sr_gap_regex, sr_regex_block, sr_regex_exception,
)

# ---------------------------------------------------------------- 通用规则生成

def gen_base_rules(ir) -> list[dict]:
    """IR sets → 归一化中间规则列表 (不含集合级 gap)。
    每条: {field, value, set, src_line, precision}。"""
    decision_by_fv: dict[tuple[str, str], object] = {}
    for d in ir.decisions:
        for f, v in d.emitted:
            decision_by_fv.setdefault((f, v), d)

    out = []
    for set_name, rules in (("exception", ir.exc_rules), ("block", ir.block_rules)):
        for f, values in rules.items():
            for v in values:
                d = decision_by_fv.get((f, v))
                out.append({
                    "field": f, "value": v, "set": set_name,
                    "src_line": d.line_no if d else -9,
                    "precision": d.precision if d else EXACT,
                })
    return out


def sort_rules(rules: list[dict], type_rank: dict[str, int]) -> list[dict]:
    return sorted(rules, key=lambda r: (
        0 if r["set"] == "exception" else 1,
        type_rank.get(r.get("ntype", ""), 9),
        r["value"]))


# ---------------------------------------------------------------- 目标: surge

def gen_surge(ir) -> dict:
    """URL-REGEX 方言 (复用 Shadowrocket 重写), 裸规则行, 例外/阻断分文件。"""
    rules = []
    for r in gen_base_rules(ir):
        f, v = r["field"], r["value"]
        exc = r["set"] == "exception"
        if f == "domain_suffix":
            rules.append({**r, "ntype": "suffix", "rendered": f"DOMAIN-SUFFIX,{v}"})
        elif f == "domain_keyword":
            rules.append({**r, "ntype": "keyword", "rendered": f"DOMAIN-KEYWORD,{v}"})
        elif f == "ip_cidr":
            rules.append({**r, "ntype": "ip",
                          "rendered": f"IP-CIDR,{v},no-resolve"})
        elif f == "domain_regex":
            if exc:
                url_re, note = sr_regex_exception(v)
            else:
                url_re, note = sr_regex_block(v)
                if r["precision"] in (EXACT, APPROX):
                    r["precision"] = WIDENED  # URL 语境 path `.` 边界(放宽)
            rules.append({**r, "value": url_re, "ntype": "url_regex",
                          "rendered": f"URL-REGEX,{url_re}", "note": note})
    # 集合级 gap (URL 语境)
    if ir.exc_rules.get("domain_suffix"):
        rules.append({"field": "gap", "value": sr_gap_regex(ir.exc_rules["domain_suffix"], True),
                      "set": "exception", "src_line": -2, "precision": EXACT,
                      "ntype": "url_regex",
                      "rendered": f"URL-REGEX,{sr_gap_regex(ir.exc_rules['domain_suffix'], True)}",
                      "note": "集合级 gap: 例外无右边界, 补 host 起始延续"})
    if ir.block_rules.get("domain_suffix"):
        gap = sr_gap_regex(ir.block_rules["domain_suffix"], False)
        rules.append({"field": "gap", "value": gap, "set": "block", "src_line": -1,
                      "precision": WIDENED, "ntype": "url_regex",
                      "rendered": f"URL-REGEX,{gap}",
                      "note": "集合级 gap: ||host 无右边界, 补中缀/起始延续; path `.` 边界可能误命中(放宽)"})

    rank = {"suffix": 0, "keyword": 1, "ip": 2, "url_regex": 3}
    rules = sort_rules(rules, rank)
    exc_lines = [r["rendered"] for r in rules if r["set"] == "exception"]
    blk_lines = [r["rendered"] for r in rules if r["set"] == "block"]
    return {"rules": rules, "files": {
        "gfwlist-exception.list": exc_lines,
        "gfwlist-block.list": blk_lines,
    }}


# ---------------------------------------------------------------- 目标: clash

def gen_clash(ir) -> dict:
    """classical rule-provider (yaml)。DOMAIN-REGEX 为 host 语境 RE2,
    与 sing-box 同方言 —— 正则与 gap 原样使用, 无精度损失。"""
    rules = []
    for r in gen_base_rules(ir):
        f, v = r["field"], r["value"]
        if f == "domain_suffix":
            rules.append({**r, "ntype": "suffix", "rendered": f"DOMAIN-SUFFIX,{v}"})
        elif f == "domain_keyword":
            rules.append({**r, "ntype": "keyword", "rendered": f"DOMAIN-KEYWORD,{v}"})
        elif f == "ip_cidr":
            rules.append({**r, "ntype": "ip", "rendered": f"IP-CIDR,{v},no-resolve"})
        elif f == "domain_regex":
            rules.append({**r, "ntype": "host_regex", "rendered": f"DOMAIN-REGEX,{v}"})
    # 集合级 gap (host 语境, 原样)
    if ir.exc_gap:
        rules.append({"field": "gap", "value": ir.exc_gap, "set": "exception",
                      "src_line": -2, "precision": EXACT, "ntype": "host_regex",
                      "rendered": f"DOMAIN-REGEX,{ir.exc_gap}",
                      "note": "集合级 gap: 例外无右边界, 补 host 起始延续"})
    if ir.block_gap:
        rules.append({"field": "gap", "value": ir.block_gap, "set": "block",
                      "src_line": -1, "precision": EXACT, "ntype": "host_regex",
                      "rendered": f"DOMAIN-REGEX,{ir.block_gap}",
                      "note": "集合级 gap: ||host 无右边界, 补中缀/起始延续"})

    rank = {"suffix": 0, "keyword": 1, "ip": 2, "host_regex": 3}
    rules = sort_rules(rules, rank)

    def yaml_payload(lines: list[str], title: str) -> str:
        body = [f"# {title} — 自动生成, 请勿手改",
                "# gfwlist → Clash/Mihomo classical rule-provider",
                "# 用法见 README; 审计: audit-targets.json", "payload:"]
        body += [f"  - '{l}'" for l in lines]
        return "\n".join(body) + "\n"

    exc_lines = [r["rendered"] for r in rules if r["set"] == "exception"]
    blk_lines = [r["rendered"] for r in rules if r["set"] == "block"]
    return {"rules": rules, "files": {
        "gfwlist-clash-exception.yaml": yaml_payload(exc_lines, "gfwlist-clash-exception.yaml"),
        "gfwlist-clash-block.yaml": yaml_payload(blk_lines, "gfwlist-clash-block.yaml"),
    }}


# ---------------------------------------------------------------- 目标: xray

def gen_xray(ir) -> dict:
    """v2rayN 自定义路由 JSON (rules 为标准 Xray RuleObject)。
    domain 令牌必须显式前缀: Xray 裸字符串 = keyword 子串语义。
    regexp: 为 host 语境 RE2, 与 sing-box 同方言, gap 原样并入。"""
    rules = []
    for r in gen_base_rules(ir):
        f, v = r["field"], r["value"]
        if f == "domain_suffix":
            rules.append({**r, "ntype": "suffix", "rendered": f"domain:{v}"})
        elif f == "domain_keyword":
            rules.append({**r, "ntype": "keyword", "rendered": f"keyword:{v}"})
        elif f == "ip_cidr":
            rules.append({**r, "ntype": "ip", "rendered": v})
        elif f == "domain_regex":
            rules.append({**r, "ntype": "host_regex", "rendered": f"regexp:{v}"})
    if ir.exc_gap:
        rules.append({"field": "gap", "value": ir.exc_gap, "set": "exception",
                      "src_line": -2, "precision": EXACT, "ntype": "host_regex",
                      "rendered": f"regexp:{ir.exc_gap}", "note": "集合级 gap (host 起始延续)"})
    if ir.block_gap:
        rules.append({"field": "gap", "value": ir.block_gap, "set": "block",
                      "src_line": -1, "precision": EXACT, "ntype": "host_regex",
                      "rendered": f"regexp:{ir.block_gap}", "note": "集合级 gap (中缀/起始延续)"})

    rank = {"suffix": 0, "keyword": 1, "host_regex": 2, "ip": 3}
    rules = sort_rules(rules, rank)

    def rule_obj(set_name: str, outbound: str) -> dict:
        sel = [r for r in rules if r["set"] == set_name]
        obj = {"type": "field", "ruleTag": f"gfwlist-{set_name}",
               "domain": [r["rendered"] for r in sel if r["ntype"] != "ip"],
               "outboundTag": outbound}
        ips = [r["rendered"] for r in sel if r["ntype"] == "ip"]
        if ips:
            obj["ip"] = ips
        if not obj["domain"]:
            obj.pop("domain")
        return obj

    doc = [{
        "remarks": "gfwlist (auto-generated, 例外 direct 在前, 先命中先生效)",
        "rules": [rule_obj("exception", "direct"), rule_obj("block", "proxy")],
    }]
    return {"rules": rules,
            "files": {"gfwlist-xray.json":
                      json.dumps(doc, indent=2, ensure_ascii=False) + "\n"}}


# ---------------------------------------------------------------- 目标: quantumultx

def gen_qx(ir) -> dict:
    """host-suffix/host-keyword/ip-cidr 行 (带策略列)。
    无域正则能力: 域正则与 gap 丢弃, 逐条申报 narrowed (能力收窄)。"""
    rules = []
    dropped = []
    for r in gen_base_rules(ir):
        f, v = r["field"], r["value"]
        policy = "direct" if r["set"] == "exception" else "proxy"
        if f == "domain_suffix":
            rules.append({**r, "ntype": "suffix",
                          "rendered": f"host-suffix, {v}, {policy}", "policy": policy})
        elif f == "domain_keyword":
            rules.append({**r, "ntype": "keyword",
                          "rendered": f"host-keyword, {v}, {policy}", "policy": policy})
        elif f == "ip_cidr":
            rules.append({**r, "ntype": "ip",
                          "rendered": f"ip-cidr, {v}, {policy}", "policy": policy})
        elif f == "domain_regex":
            dropped.append({**r, "drop_reason": "Quantumult X 无域正则能力, 丢弃(narrowed)"})
    # gap 无法表达 -> 能力收窄 (集合级, 溯源 -1/-2)
    for set_name, gap, src in (("exception", ir.exc_gap, -2), ("block", ir.block_gap, -1)):
        if gap:
            dropped.append({"field": "gap", "value": gap, "set": set_name,
                            "src_line": src, "precision": NARROWED,
                            "drop_reason": "Quantumult X 无域正则能力, 集合级 gap 丢弃; "
                                           "`||host` 延续形态 (host.evil.com) 退回标签边界语义"})

    rank = {"suffix": 0, "keyword": 1, "ip": 2}
    rules = sort_rules(rules, rank)
    header = ["# gfwlist-quantumultx.list — 自动生成, 请勿手改",
              "# gfwlist → Quantumult X (例外 direct 在前, 先命中先生效)",
              "# 注意: Quantumult X 无域正则能力, 域正则/gap 规则已丢弃",
              "# (narrowed, 详见 audit-targets.json); 追加于 [filter_local] 或作 filter_remote 引用"]
    lines = header + [r["rendered"] for r in rules]
    return {"rules": rules, "dropped": dropped,
            "files": {"gfwlist-quantumultx.list": "\n".join(lines) + "\n"}}


# ---------------------------------------------------------------- 主流程

GENERATORS = {"surge": gen_surge, "clash": gen_clash, "xray": gen_xray, "qx": gen_qx}

def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    text = load_gfwlist(src)
    ir = build_ir(text, source=src)

    audit_targets = {}
    summary_all = {}
    for name, gen in GENERATORS.items():
        result = gen(ir)
        for fname, content in result["files"].items():
            if isinstance(content, list):      # surge: 行列表 + 头注释
                header = [f"# {fname} — 自动生成, 请勿手改",
                          "# gfwlist → Surge/Loon RULE-SET 或 Shadowrocket 规则分组",
                          "# 例外集须先于阻断集引用 (先命中先生效 = AutoProxy @@ 否决语义);",
                          "# 审计: audit-targets.json"]
                content = "\n".join(header + content) + "\n"
            (outdir / fname).write_text(content)
        n_exc = sum(1 for r in result["rules"] if r["set"] == "exception")
        summary = {
            "rules": {"exception": n_exc, "block": len(result["rules"]) - n_exc,
                      "total": len(result["rules"])},
            "files": sorted(result["files"]),
        }
        if result.get("dropped"):
            summary["dropped_capability"] = {
                "count": len(result["dropped"]),
                "reason": "目标无域正则能力 (narrowed, 能力收窄, 已申报)"}
        audit_targets[name] = {
            "files": sorted(result["files"]),
            "rules": [{k: v for k, v in r.items()} for r in result["rules"]],
            "dropped": result.get("dropped", []),
            "summary": summary,
        }
        summary_all[name] = summary

    audit = {
        "source": str(src),
        "targets": audit_targets,
        "decisions": [
            {**__import__("dataclasses").asdict(d)} for d in ir.decisions],
        "upstream_input_lines": ir.input_lines,
    }
    (outdir / "audit-targets.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(summary_all, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
