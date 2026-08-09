#!/usr/bin/env python3
"""
Shadowrocket 目标全量对拍测试: gfwlist 原版语义 (双引擎 oracle) vs
dist/gfwlist-shadowrocket.conf 的 Shadowrocket 规则语义 (内置模拟器)。

与 sing-box 对拍 (differential_test.py) 共用:
  - 样本生成 (每条规则派生正例/负例/变异, 每条线覆盖);
  - 双引擎 oracle (adblockparser 规范引擎 + adblock-rust 交叉验证);
  - 门禁: 不一致样本的责任规则精度 ∈ {widened, narrowed, approximated}
    (审计已申报) 或属已声明引擎分歧才允许通过。

模拟器精确实现 Shadowrocket 语义:
  - 规则按 conf 文件顺序逐条求值, 先命中先生效 (例外 DIRECT 自然优先);
  - DOMAIN / DOMAIN-SUFFIX (标签边界) / DOMAIN-KEYWORD / IP-CIDR(no-resolve:
    仅匹配 IP 字面量目标) / URL-REGEX (对整条 URL 做正则 search)。

用法: python3 differential_shadowrocket.py <gfwlist.txt> <dist目录> [--max-bg N] [--oracle adblock|adblockparser|both]
退出码: 0 通过, 1 存在未申报偏差或 conf 与审计不一致。
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from differential_test import (  # noqa: E402
    extract_host_tokens, generate_samples, load_gfwlist,
    make_oracle, oracle_candidates,
)

DECLARED = {"widened", "narrowed", "approximated"}

# ================================================== Shadowrocket 语义模拟器

class SRRule:
    def __init__(self, rtype: str, value: str, policy: str,
                 src_line: int, precision: str):
        self.type, self.value, self.policy = rtype, value, policy
        self.src_line, self.precision = src_line, precision
        if rtype == "URL-REGEX":
            self.regex = re.compile(value)
        if rtype == "IP-CIDR":
            self.net = ipaddress.ip_network(value)

    def match(self, host: str, url: str, ip: str | None) -> bool:
        t, v = self.type, self.value
        if t == "DOMAIN":
            return host == v
        if t == "DOMAIN-SUFFIX":
            return host == v or host.endswith("." + v)
        if t == "DOMAIN-KEYWORD":
            return v in host
        if t == "URL-REGEX":
            return self.regex.search(url) is not None
        if t == "IP-CIDR":
            # no-resolve: 仅当目标是 IP 字面量时匹配
            return ip is not None and ipaddress.ip_address(ip) in self.net
        raise ValueError(t)


class SRSimulator:
    """按 conf 顺序求值, 先命中先生效; 无命中 = DIRECT (FINAL,DIRECT)。"""

    def __init__(self, rules: list[SRRule]):
        self.rules = rules

    def decide(self, host: str, url: str, ip: str | None = None):
        """返回 (是否走代理, 命中规则|None)"""
        for r in self.rules:
            if r.match(host, url, ip):
                return r.policy == "PROXY", r
        return False, None


def load_conf_rule_lines(conf_path: Path) -> list[str]:
    """提取 conf [Rule] 段的非注释规则行 (不含 FINAL)。"""
    lines = conf_path.read_text().splitlines()
    in_rule = False
    out = []
    for raw in lines:
        s = raw.strip()
        if s == "[Rule]":
            in_rule = True
            continue
        if in_rule and s.startswith("["):
            break
        if in_rule and s and not s.startswith("#"):
            out.append(s)
    return out


def build_simulator(dist_dir: Path, audit: dict) -> SRSimulator:
    """以审计中的 sr_rules 为准构建模拟器, 并校验其与 conf 文件逐行一致。"""
    sr_rules = audit["sr_rules"]
    expected = [f"{r['type']},{r['value']},{r['policy']}{r['suffix']}"
                for r in sr_rules]
    conf_lines = load_conf_rule_lines(dist_dir / audit["conf_file"])
    conf_rules = [l for l in conf_lines if not l.startswith("FINAL,")]
    if conf_rules != expected:
        for i, (a, b) in enumerate(zip(conf_rules + [None] * len(expected),
                                       expected + [None] * len(conf_rules))):
            if a != b:
                print(f"[fatal] conf 与审计不一致, 首处差异 index {i}:")
                print(f"  conf : {str(a)[:120]}")
                print(f"  audit: {str(b)[:120]}")
                break
        raise SystemExit(1)
    print(f"[check] conf [Rule] 与审计 sr_rules 逐行一致 ({len(expected)} 条)")
    rules = [SRRule(r["type"], r["value"], r["policy"],
                    r["src_line"], r["precision"]) for r in sr_rules]
    return SRSimulator(rules)


# ================================================== 主流程

def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    max_bg = 1500
    oracle_name = "both"
    if "--max-bg" in sys.argv:
        max_bg = int(sys.argv[sys.argv.index("--max-bg") + 1])
    if "--oracle" in sys.argv:
        oracle_name = sys.argv[sys.argv.index("--oracle") + 1]
    gfw_path, dist_dir = args[0], Path(args[1])

    text = load_gfwlist(gfw_path)
    lines = text.splitlines()
    audit = json.loads((dist_dir / "audit-shadowrocket.json").read_text())

    # 责任规则溯源: 原始行号 -> 目标侧精度
    # (URL-REGEX 由域正则翻译而来时精度可能被目标侧调整, 以 sr_rules 为准;
    #  DOMAIN-SUFFIX/KEYWORD/IP-CIDR 与源决策一致)
    line_precision: dict[int, set] = {}
    for r in audit["sr_rules"]:
        if r["src_line"] > 0:
            line_precision.setdefault(r["src_line"], set()).add(r["precision"])
    # 源决策中本身非精确但目标侧无规则输出的行 (如 narrowed 丢弃)
    for d in audit["decisions"]:
        if d["precision"] != "exact":
            line_precision.setdefault(d["line_no"], set()).add(d["precision"])

    rule_lines = [l.strip() for l in lines
                  if l.strip() and not l.strip().startswith(("!", "["))]
    names = ["adblock", "adblockparser"] if oracle_name == "both" else [oracle_name]
    oracles = {n: make_oracle(n, rule_lines) for n in names}
    for n in names:
        print(f"[oracle] 加载 {len(rule_lines)} 条原始规则 ({oracles[n].name})")

    sim = build_simulator(dist_dir, audit)
    print(f"[sim] Shadowrocket 规则 {len(sim.rules)} 条")

    samples = generate_samples(lines, max_bg)
    print(f"[samples] 共 {len(samples)} 个测试 URL")

    # gap 正则溯源: 命中时回溯到具体 suffix 行
    suffix_by_line = {}
    for r in audit["sr_rules"]:
        if r["type"] == "DOMAIN-SUFFIX":
            suffix_by_line.setdefault(r["value"],
                                      (r["src_line"], r["precision"]))

    def trace_gap(rule: SRRule, url: str) -> tuple[int, str] | None:
        """URL-REGEX gap 命中 -> 找在边界出现的 suffix (取最长) 溯源。"""
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
            if o_blocked == s_blocked:
                continue
            resp_lines, precs = set(), set()
            if s_rule is not None:
                src, prec = s_rule.src_line, s_rule.precision
                if src < 0 and s_rule.type == "URL-REGEX":
                    traced = trace_gap(s_rule, url)
                    if traced:
                        src, prec = traced
                resp_lines.add(src)
                precs.add(prec)
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
            mismatches.append((url, name, o_blocked, s_blocked, resp_lines, precs))

    for n in names:
        print(f"[result] {n} 拦截 {n_block_o[n]}", end="")
    print(f", sim 拦截 {n_block_s}, 不一致事件 {len(mismatches)}")

    undeclared, declared_count = [], 0
    engine_divergence = 0
    direction_stats = {}

    # 引擎分歧白名单 (与 sing-box 对拍一致): exact 精度 suffix 的延续形态
    exact_suffixes = sorted({
        r["value"] for r in audit["sr_rules"]
        if r["type"] == "DOMAIN-SUFFIX" and r["precision"] == "exact"})

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

    for url, eng, ob, sb, resp, precs in mismatches:
        dkey = f"{eng}:" + ("oracle>sim" if ob else "sim>oracle") + \
            ":" + ",".join(sorted(precs))
        direction_stats[dkey] = direction_stats.get(dkey, 0) + 1
        if precs and precs <= DECLARED | {"exact"} and (precs & DECLARED):
            declared_count += 1
            continue
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        # adblock-rust token 化 quirk: 规范引擎与 sim 一致时计为引擎分歧
        if eng == "adblock" and "adblockparser" in oracles \
                and oracles["adblockparser"].blocked(url) == sb:
            engine_divergence += 1
            continue
        if is_continuation(host):
            engine_divergence += 1
            continue
        undeclared.append((url, eng, ob, sb, resp, precs))

    (dist_dir / "mismatches-shadowrocket.json").write_text(json.dumps([
        {"url": u, "engine": e, "oracle": ob, "sim": sb,
         "responsible": sorted(str(r) for r in resp), "precision": sorted(precs)}
        for u, e, ob, sb, resp, precs in sorted(mismatches)],
        indent=1, ensure_ascii=False))
    print("[result] 偏差方向分布:", json.dumps(direction_stats, ensure_ascii=False))
    print(f"[result] 已申报偏差 {declared_count}, 引擎分歧(白名单) {engine_divergence}, "
          f"未申报偏差 {len(undeclared)}")
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
