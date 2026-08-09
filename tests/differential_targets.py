#!/usr/bin/env python3
"""
多目标全量对拍测试: gfwlist 原版语义 (双引擎 oracle) vs
dist 中 Surge/Clash/Xray/Quantumult X 产物语义 (归一化模拟器)。

与 sing-box/Shadowrocket 对拍共用:
  - 样本生成 / 双引擎 oracle / 未申报偏差门禁;
  - 产物与 audit-targets.json 逐行一致性校验 (防生成器/写出 drift)。

目标特有机制:
  - 模拟器按归一化规则类型求值: suffix / keyword / ip (no-resolve 语义:
    仅匹配 IP 字面量目标) / host_regex (RE2 host search) / url_regex (URL search);
  - 例外集先于阻断集 (先命中先生效 = AutoProxy @@ 否决语义);
  - qx 等无域正则能力的目标: 用 sim_full (含被丢弃正则的完整语义) 复核 ——
    sim_full 与 oracle 一致而目标 sim 不一致的样本, 计为"能力收窄 (已申报)"。

用法: python3 differential_targets.py <gfwlist.txt> <dist目录> <surge|clash|xray|qx>
      [--max-bg N] [--oracle adblock|adblockparser|both]
退出码: 0 通过, 1 存在未申报偏差或产物与审计不一致。
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from differential_test import (  # noqa: E402
    generate_samples, load_gfwlist, make_oracle, oracle_candidates,
)

DECLARED = {"widened", "narrowed", "approximated"}

# ================================================== 归一化语义模拟器

class TRule:
    def __init__(self, r: dict):
        self.ntype, self.value = r["ntype"], r["value"]
        self.policy = r.get("policy") or (
            "direct" if r["set"] == "exception" else "proxy")
        self.src_line, self.precision = r["src_line"], r["precision"]
        if self.ntype in ("host_regex", "url_regex"):
            self.regex = re.compile(self.value)
        if self.ntype == "ip":
            self.net = ipaddress.ip_network(self.value)

    def match(self, host: str, url: str, ip: str | None) -> bool:
        t, v = self.ntype, self.value
        if t == "suffix":
            return host == v or host.endswith("." + v)
        if t == "keyword":
            return v in host
        if t == "ip":
            return ip is not None and ipaddress.ip_address(ip) in self.net
        if t == "host_regex":
            return self.regex.search(host) is not None
        if t == "url_regex":
            return self.regex.search(url) is not None
        raise ValueError(t)


class TSimulator:
    """规则按序求值, 先命中先生效; 无命中 = direct。
    suffix 规则走标签索引快速候选 (语义等价: suffix 命中仅取决于 host 本身
    或其父域), 其余类型 (regex/keyword/ip) 逐条求值后按原序仲裁。"""

    def __init__(self, rules: list[TRule]):
        self.rules = rules
        self.suffix_index: dict[str, list[int]] = {}
        self.other_idx: list[int] = []
        for i, r in enumerate(rules):
            if r.ntype == "suffix":
                self.suffix_index.setdefault(r.value, []).append(i)
            else:
                self.other_idx.append(i)

    def decide(self, host: str, url: str, ip: str | None = None):
        cand = set(self.other_idx)
        labels = host.split(".")
        for i in range(len(labels)):
            for idx in self.suffix_index.get(".".join(labels[i:]), ()):
                cand.add(idx)
        for i in sorted(cand):
            r = self.rules[i]
            if r.match(host, url, ip):
                return r.policy == "proxy", r
        return False, None


# ================================================== 产物 ↔ 审计一致性校验

def _significant_lines(path: Path, comment_prefix="#") -> list[str]:
    return [l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.strip().startswith(comment_prefix)]


def check_consistency(target: str, dist_dir: Path, t_audit: dict) -> None:
    rules = t_audit["rules"]
    files = t_audit["files"]

    def rendered(sel):
        return [r["rendered"] for r in sel]

    exc = [r for r in rules if r["set"] == "exception"]
    blk = [r for r in rules if r["set"] == "block"]

    if target == "surge":
        actual = {f: _significant_lines(dist_dir / f) for f in files}
        expect = {"gfwlist-exception.list": rendered(exc),
                  "gfwlist-block.list": rendered(blk)}
    elif target == "clash":
        actual = {}
        for f in files:
            lines = _significant_lines(dist_dir / f)
            payload = [re.fullmatch(r"- '(.*)'", l).group(1)
                       for l in lines if l.startswith("- '")]
            actual[f] = payload
        expect = {"gfwlist-clash-exception.yaml": rendered(exc),
                  "gfwlist-clash-block.yaml": rendered(blk)}
    elif target == "xray":
        doc = json.loads((dist_dir / files[0]).read_text())
        objs = doc[0]["rules"]
        actual = {
            "exception_domain": objs[0].get("domain", []),
            "exception_ip": objs[0].get("ip", []),
            "block_domain": objs[1].get("domain", []),
            "block_ip": objs[1].get("ip", []),
        }
        expect = {
            "exception_domain": rendered([r for r in exc if r["ntype"] != "ip"]),
            "exception_ip": rendered([r for r in exc if r["ntype"] == "ip"]),
            "block_domain": rendered([r for r in blk if r["ntype"] != "ip"]),
            "block_ip": rendered([r for r in blk if r["ntype"] == "ip"]),
        }
    elif target == "qx":
        actual = {"f": _significant_lines(dist_dir / files[0])}
        expect = {"f": rendered(rules)}
    else:
        raise ValueError(target)

    if actual != expect:
        for k in expect:
            a, e = actual.get(k), expect[k]
            if a != e:
                print(f"[fatal] {target} 产物与审计不一致 ({k}):")
                for i, (x, y) in enumerate(zip((a or []) + [None] * len(e),
                                               e + [None] * len(a or []))):
                    if x != y:
                        print(f"  首处差异 index {i}:\n  产物: {str(x)[:120]}\n  审计: {str(y)[:120]}")
                        break
                break
        raise SystemExit(1)
    print(f"[check] {target} 产物与审计逐行一致 ({len(rules)} 条规则)")


# ================================================== 主流程

def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    max_bg = 1500
    oracle_name = "both"
    if "--max-bg" in sys.argv:
        max_bg = int(sys.argv[sys.argv.index("--max-bg") + 1])
    if "--oracle" in sys.argv:
        oracle_name = sys.argv[sys.argv.index("--oracle") + 1]
    gfw_path, dist_dir, target = args[0], Path(args[1]), args[2]

    text = load_gfwlist(gfw_path)
    lines = text.splitlines()
    audit = json.loads((dist_dir / "audit-targets.json").read_text())
    t_audit = audit["targets"][target]

    check_consistency(target, dist_dir, t_audit)

    # 责任规则溯源: 原始行号 -> 目标侧精度
    line_precision: dict[int, set] = {}
    for r in t_audit["rules"]:
        if r["src_line"] > 0:
            line_precision.setdefault(r["src_line"], set()).add(r["precision"])
    # 被目标丢弃的规则 = 收窄决策, 也登记 (qx)
    for r in t_audit.get("dropped", []):
        if r["src_line"] > 0:
            line_precision.setdefault(r["src_line"], set()).add("narrowed")
    for d in audit["decisions"]:
        if d["precision"] != "exact":
            line_precision.setdefault(d["line_no"], set()).add(d["precision"])

    sim = TSimulator([TRule(r) for r in t_audit["rules"]])
    print(f"[sim] {target} 规则 {len(sim.rules)} 条")

    # 能力收窄复核器 (仅 qx 等有 dropped 的目标): 完整语义 = 规则 + 被丢正则
    sim_full = None
    if t_audit.get("dropped"):
        full_rules = list(t_audit["rules"])
        for r in t_audit["dropped"]:
            if r.get("value"):
                full_rules.append({**r, "ntype": "host_regex"})
        full_rules.sort(key=lambda r: (0 if r["set"] == "exception" else 1))
        sim_full = TSimulator([TRule(r) for r in full_rules])
        print(f"[sim] 含被丢能力的完整语义规则 {len(sim_full.rules)} 条 (能力收窄复核用)")

    rule_lines = [l.strip() for l in lines
                  if l.strip() and not l.strip().startswith(("!", "["))]
    names = ["adblock", "adblockparser"] if oracle_name == "both" else [oracle_name]
    oracles = {n: make_oracle(n, rule_lines) for n in names}
    for n in names:
        print(f"[oracle] 加载 {len(rule_lines)} 条原始规则 ({oracles[n].name})")

    samples = generate_samples(lines, max_bg)
    print(f"[samples] 共 {len(samples)} 个测试 URL")

    # gap 正则溯源: 命中时回溯到具体 suffix 行 (取边界出现的最长 suffix)
    suffix_by_line: dict[str, tuple[int, str]] = {}
    for r in t_audit["rules"]:
        if r["ntype"] == "suffix":
            suffix_by_line.setdefault(r["value"],
                                      (r["src_line"], r["precision"]))

    def trace_gap(url: str) -> tuple[int, str] | None:
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        best = None
        labels = host.split(".")
        for i in range(len(labels)):
            for j in range(i + 2, len(labels) + 1):
                s = ".".join(labels[i:j])
                if s in suffix_by_line and (best is None or len(s) > len(best)):
                    best = s
        # path 边界误命中的情况: 在整条 URL 中找
        if best is None:
            ul = url.lower()
            for s in sorted(suffix_by_line, key=len, reverse=True):
                if re.search(r"(?:^|://|\.)" + re.escape(s) + r"\.", ul):
                    best = s
                    break
        return suffix_by_line.get(best) if best else None

    mismatches = []
    n_block_o = {n: 0 for n in names}
    n_block_s = 0
    for idx, url in enumerate(samples):
        if idx % 10000 == 0 and idx:
            print(f"  ... {idx}/{len(samples)}")
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        ip = host if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) else None
        s_blocked, s_rule = sim.decide(host, url, ip)
        n_block_s += s_blocked
        for name, orc in oracles.items():
            o_blocked = orc.blocked(url)
            n_block_o[name] += o_blocked
            if o_blocked != s_blocked:
                mismatches.append((url, name, o_blocked, s_blocked, s_rule))

    for n in names:
        print(f"[result] {n} 拦截 {n_block_o[n]}", end="")
    print(f", sim 拦截 {n_block_s}, 不一致事件 {len(mismatches)}")

    undeclared, declared_count = [], 0
    engine_divergence = 0
    capability_narrowed = 0
    direction_stats = {}

    exact_suffixes = sorted({
        r["value"] for r in t_audit["rules"]
        if r["ntype"] == "suffix" and r["precision"] == "exact"})

    def is_continuation(host: str) -> bool:
        for s in exact_suffixes:
            start = 0
            while True:
                i = host.find(s, start)
                if i < 0:
                    break
                if (i == 0 or host[i - 1] == "."):
                    end = i + len(s)
                    if end < len(host) and host[end] == ".":
                        return True
                start = i + 1
        return False

    def host_ip_of(url: str):
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        ip = host if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) else None
        return host, ip

    def trace_responsibility(url: str, eng: str, s_rule) -> tuple[set, set]:
        """责任溯源 + 精度收集 (仅在需要分类时计算, 开销大)。"""
        resp_lines, precs = set(), set()
        if s_rule is not None:
            src, prec = s_rule.src_line, s_rule.precision
            if src < 0:  # 集合级 gap -> 溯源到 suffix 行
                traced = trace_gap(url)
                if traced:
                    src, prec = traced
            resp_lines.add(src)
            precs.add(prec)
        orc = oracles[eng]
        for cand in oracle_candidates(rule_lines, url):
            try:
                if orc.single_blocks(cand, url):
                    resp_lines.add(cand)
                elif cand.startswith("@@") and orc.single_excepts(cand, url):
                    resp_lines.add(cand)
            except Exception:
                pass
        for rl in resp_lines:
            if isinstance(rl, int):
                precs.update(line_precision.get(rl, {"?"}))
            else:
                for d in audit["decisions"]:
                    if d["raw"].strip() == rl:
                        precs.add(d["precision"])
                        break
        return resp_lines, precs

    classified = []  # (url, eng, ob, sb, resp, precs, category)
    for url, eng, ob, sb, s_rule in mismatches:
        # 能力收窄: 完整语义与 oracle 一致 -> 差异由目标能力缺失导致 (已申报)
        if sim_full is not None:
            host, ip = host_ip_of(url)
            fb, _ = sim_full.decide(host, url, ip)
            if fb == ob:
                capability_narrowed += 1
                classified.append((url, eng, ob, sb, set(), set(), "capability"))
                continue
        resp, precs = trace_responsibility(url, eng, s_rule)
        dkey = f"{eng}:" + ("oracle>sim" if ob else "sim>oracle") + \
            ":" + ",".join(sorted(precs))
        direction_stats[dkey] = direction_stats.get(dkey, 0) + 1
        if precs and precs <= DECLARED | {"exact"} and (precs & DECLARED):
            declared_count += 1
            classified.append((url, eng, ob, sb, resp, precs, "declared"))
            continue
        host, _ = host_ip_of(url)
        if eng == "adblock" and "adblockparser" in oracles \
                and oracles["adblockparser"].blocked(url) == sb:
            engine_divergence += 1
            classified.append((url, eng, ob, sb, resp, precs, "engine"))
            continue
        if is_continuation(host):
            engine_divergence += 1
            classified.append((url, eng, ob, sb, resp, precs, "engine"))
            continue
        undeclared.append((url, eng, ob, sb, resp, precs))
        classified.append((url, eng, ob, sb, resp, precs, "undeclared"))

    (dist_dir / f"mismatches-{target}.json").write_text(json.dumps([
        {"url": u, "engine": e, "oracle": ob, "sim": sb,
         "responsible": sorted(str(r) for r in resp), "precision": sorted(precs)}
        for u, e, ob, sb, resp, precs, _cat in sorted(classified)],
        indent=1, ensure_ascii=False))
    print("[result] 偏差方向分布:", json.dumps(direction_stats, ensure_ascii=False))
    extra = f", 能力收窄(已申报) {capability_narrowed}" if sim_full is not None else ""
    print(f"[result] 已申报偏差 {declared_count}, 引擎分歧(白名单) {engine_divergence}"
          f"{extra}, 未申报偏差 {len(undeclared)}")
    if undeclared:
        print("\n=== 未申报偏差 (语义不等价!) ===")
        for url, eng, ob, sb, resp, precs in undeclared[:50]:
            print(f"  [{eng}] {url}\n    oracle={'block' if ob else 'direct'} "
                  f"sim={'block' if sb else 'direct'} 责任={list(resp)[:3]} 精度={precs}")
        return 1
    print("[result] OK — 所有差异均在审计申报范围内")
    return 0


if __name__ == "__main__":
    sys.exit(main())
