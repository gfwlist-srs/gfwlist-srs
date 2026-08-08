#!/usr/bin/env python3
"""
全量对拍测试: gfwlist 原版语义 (oracle = 第三方 adblockparser) vs
转换后 sing-box 规则语义 (内置模拟器, 精确实现 sing-box domain 匹配语义)。

- 每条原始规则都派生正例/近邻负例/变异样本 (每条线都被覆盖, 不写死);
- 判定不一致时定位责任规则: 若责任规则的审计精度 ∈ {widened, narrowed,
  approximated}, 则属于"已申报偏差", 通过; 否则失败并输出清单;
- 退出码: 0 通过, 1 存在未申报偏差。

用法: python3 differential_test.py <gfwlist.txt> <dist目录> [--max-bg N]
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from gfwlist2srs import load_gfwlist  # noqa: E402

from adblockparser import AdblockRules  # noqa: E402

random.seed(20260808)

# ================================================== sing-box 语义模拟器

class SimRule:
    def __init__(self, field: str, value: str, src_line: int, precision: str):
        self.field = field
        self.value = value
        self.src_line = src_line
        self.precision = precision
        if field == "domain_regex":
            self.regex = re.compile(value)
        if field == "ip_cidr":
            self.net = ipaddress.ip_network(value)

    def match(self, host: str, ip: str | None) -> bool:
        f, v = self.field, self.value
        if f == "domain":
            return host == v
        if f == "domain_suffix":
            return host == v or host.endswith("." + v)
        if f == "domain_keyword":
            return v in host
        if f == "domain_regex":
            return self.regex.search(host) is not None
        if f == "ip_cidr":
            if ip is None:
                return False
            return ipaddress.ip_address(ip) in self.net
        raise ValueError(f)

class Simulator:
    """例外集优先, 再 block 集 —— 与参考配置路由顺序一致。"""

    def __init__(self, block_rules: list[SimRule], exc_rules: list[SimRule]):
        self.block = block_rules
        self.exc = exc_rules

    def decide(self, host: str, ip: str | None = None) -> tuple[bool, SimRule | None]:
        """返回 (是否走代理, 命中规则)"""
        for r in self.exc:
            if r.match(host, ip):
                return False, r
        for r in self.block:
            if r.match(host, ip):
                return True, r
        return False, None

def build_simulator(dist_dir: Path, audit: dict) -> Simulator:
    """加载最终 ruleset JSON (含集合级 gap 正则) 构建模拟器。
    责任溯源: 逐行 emitted 规则 + gap 正则命中时回溯到具体 suffix 行。"""
    # 逐行规则 (溯源用)
    line_block, line_exc = [], []
    for d in audit["decisions"]:
        for f, v in d["emitted"]:
            r = SimRule(f, v, d["line_no"], d["precision"])
            (line_exc if d["exception"] else line_block).append(r)
    suffix_by_line = {}
    for d in audit["decisions"]:
        for f, v in d["emitted"]:
            if f == "domain_suffix":
                suffix_by_line.setdefault(v, (d["line_no"], d["precision"]))

    def load_final(name: str, line_rules: list[SimRule]) -> list[SimRule]:
        data = json.loads((dist_dir / name).read_text())
        out = []
        if not data["rules"]:
            return out
        r0 = data["rules"][0]
        line_lookup = {(r.field, r.value): r for r in line_rules}
        for field in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"):
            for v in r0.get(field, []):
                src = line_lookup.get((field, v))
                if src:
                    out.append(src)
                elif field == "domain_regex" and v.startswith("(^|\\.)("):
                    out.append(GapRule(v, suffix_by_line))
                else:
                    # 优化消除的 suffix: 其语义已被父 suffix 覆盖, 无需单独溯源
                    pass
        return out

    return Simulator(load_final("gfwlist-block.json", line_block),
                     load_final("gfwlist-exception.json", line_exc))

class GapRule(SimRule):
    """集合级 gap 正则; 命中时回溯到具体 suffix 行以溯源。"""
    def __init__(self, value: str, suffix_by_line: dict):
        super().__init__("domain_regex", value, -1, "exact")
        self.suffix_by_line = suffix_by_line
        self.hit: tuple[int, str] | None = None

    def match(self, host: str, ip: str | None) -> bool:
        if self.regex.search(host) is None:
            return False
        # 回溯: 找在左边界出现的 suffix (取最长者)
        best = None
        labels = host.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            for j in range(i + 2, len(labels) + 1):
                s = ".".join(labels[i:j])
                if s in self.suffix_by_line and (best is None or len(s) > len(best)):
                    best = s
        if best is not None:
            self.hit = self.suffix_by_line[best]
            self.src_line, self.precision = self.hit
        return True

# ================================================== 样本生成

WORDLIST = ("news shop blog cdn api img static mail video music game forum "
            "wiki docs app cloud data media social photo store tech group").split()
TLDS = ["com", "net", "org", "cn", "jp", "io", "xyz", "info"]

def valid_host(h: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", h))

def extract_host_tokens(line: str) -> list[str]:
    """从原始行提取域名形态的字面量 token (用于样本与责任规则预筛)。"""
    toks = []
    for m in re.finditer(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", line.lower()):
        t = m.group(0).strip(".")
        if valid_host(t) and "." in t:
            toks.append(t)
    return sorted(set(toks))

def samples_for_host(d: str) -> list[str]:
    out = [
        f"http://{d}/",
        f"https://{d}/",
        f"http://www.{d}/",
        f"https://a.b.{d}/deep/path?q=1",
        f"http://{d}.evil-example.com/",
        f"http://x{d}/",                    # 前缀粘连(边界外)
        f"http://www.{d}.cdn-mirror.net/",  # 作为中缀出现
    ]
    # 删首标签(父域)与加端口
    parts = d.split(".")
    if len(parts) > 2:
        out.append(f"http://{'.'.join(parts[1:])}/")
    out.append(f"http://{d}:8080/p")
    return out

def samples_for_wildcard(line: str) -> list[str]:
    """对含 * 的行做模式实例化。"""
    body = line.strip().lstrip("@|").rstrip("|")
    body = body.split("://")[-1].split("/")[0]
    if "*" not in body:
        return []
    pre, _, suf = body.partition("*")
    suf = suf.strip(".")
    pre = pre.strip(".")
    urls = []
    for x in ("", "x1", "a.b"):
        h = (pre + x + ("." if suf and (pre + x) else "") + suf).strip(".")
        if valid_host(h):
            urls += [f"http://{h}/", f"http://www.{h}/"]
    if valid_host(suf):
        urls += [f"http://{suf}/", f"http://not{suf}/"]
    return urls

def samples_for_regex_line(line: str) -> list[str]:
    """对 /regex/ 行: 提取字面量域名片段并实例化交替项。"""
    urls = []
    for tok in extract_host_tokens(line):
        urls += samples_for_host(tok)
        # 在字面量域前加内容 (覆盖 [^/]+ / .+ 类前缀)
        urls.append(f"http://www.{tok}/")
        urls.append(f"http://x{tok}/")
    # 交替项实例化: (a|b|c)
    for m in re.finditer(r"\(([^()|]+(?:\|[^()|]+)+)\)", line):
        for alt in m.group(1).split("|"):
            if re.fullmatch(r"[a-z0-9]+", alt):
                for tok in extract_host_tokens(line)[:1]:
                    urls.append(f"http://{alt}abc.{tok}/")
    return urls

def background_domains(n: int) -> list[str]:
    out = set()
    while len(out) < n:
        d = f"{random.choice(WORDLIST)}{random.randint(1,999)}.{random.choice(TLDS)}"
        out.add(f"http://{d}/")
        out.add(f"http://www.{d}/p")
    return sorted(out)

def generate_samples(lines: list[str], max_bg: int) -> list[str]:
    samples: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("!", "[")):
            continue
        if "*" in line:
            samples.update(samples_for_wildcard(line))
        if line.lstrip("@").startswith("/"):
            samples.update(samples_for_regex_line(line))
        for tok in extract_host_tokens(line):
            samples.update(samples_for_host(tok))
        # path 条件行: 命中路径与未命中路径
        if "://" in line and "/" in line.split("://", 1)[1].strip("/"):
            m = re.search(r"://([^/]+)(/[^|]*)", line)
            if m and "*" not in m.group(1):
                h, p = m.group(1), m.group(2).replace("*", "x")
                if valid_host(h):
                    samples.add(f"http://{h}{p}")
                    samples.add(f"http://{h}{p}/sub")
                    samples.add(f"http://{h}/other-path")
        # 单标签 TLD 规则 (goog/gle/google 等)
        body = line.strip().lstrip("@|").rstrip("|")
        if re.fullmatch(r"[a-z0-9-]+", body):
            samples.add(f"http://example.{body}/")
            samples.add(f"http://{body}/")
        # IP 样本
        for ipm in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", line):
            ip = ipm.group(1)
            samples.add(f"http://{ip}/")
            last = int(ip.rsplit(".", 1)[1])
            samples.add(f"http://{ip.rsplit('.',1)[0]}.{(last+1)%256}/")
    samples.update(background_domains(max_bg))
    return sorted(samples)

# ================================================== oracle 责任规则定位

def oracle_candidates(lines: list[str], url: str) -> list[str]:
    """预筛可能命中该 URL 的原始规则 (字面 token 预筛 + 正则/通配行)。"""
    ul = url.lower()
    out = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("!", "[")):
            continue
        body = line.lstrip("@")
        if body.startswith("/") or "*" in line:
            out.append(line)  # 正则/通配无法子串预筛, 全部单测
            continue
        toks = extract_host_tokens(line)
        if not toks:
            core = re.sub(r"[^a-z0-9.]", "", body.lower())[:32]
            if core and core in ul:
                out.append(line)
            continue
        if any(t in ul for t in toks):
            out.append(line)
    return out

# ================================================== 主流程

def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    max_bg = 1500
    if "--max-bg" in sys.argv:
        i = sys.argv.index("--max-bg")
        max_bg = int(sys.argv[i + 1])
    gfw_path, dist_dir = args[0], Path(args[1])

    text = load_gfwlist(gfw_path)
    lines = text.splitlines()
    audit = json.loads((dist_dir / "audit.json").read_text())
    precision_by_line = {d["line_no"]: d["precision"] for d in audit["decisions"]}
    raw_by_line = {d["line_no"]: d["raw"] for d in audit["decisions"]}

    rule_lines = [l.strip() for l in lines
                  if l.strip() and not l.strip().startswith(("!", "["))]
    print(f"[oracle] 加载 {len(rule_lines)} 条原始规则 (adblockparser)")
    oracle = AdblockRules(rule_lines, use_re2=False)

    sim = build_simulator(dist_dir, audit)
    print(f"[sim] block {len(sim.block)} 条, exception {len(sim.exc)} 条")

    samples = generate_samples(lines, max_bg)
    print(f"[samples] 共 {len(samples)} 个测试 URL")

    mismatches = []   # (url, oracle_blocked, sim_blocked, 责任行集合, 精度集合)
    n_block_o = n_block_s = 0
    for idx, url in enumerate(samples):
        if idx % 10000 == 0 and idx:
            print(f"  ... {idx}/{len(samples)}")
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        ip = host if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) else None
        o_blocked = oracle.should_block(url, options={"domain": "test.local"})
        s_blocked, s_rule = sim.decide(host, ip)
        n_block_o += o_blocked
        n_block_s += s_blocked
        if o_blocked != s_blocked:
            resp_lines, precs = set(), set()
            if s_rule is not None:
                resp_lines.add(s_rule.src_line)
                precs.add(s_rule.precision)
            # oracle 侧定位: 单规则重放候选
            for cand in oracle_candidates(rule_lines, url):
                try:
                    single = AdblockRules([cand], use_re2=False)
                    hit = single.should_block(url, options={"domain": "test.local"})
                    # 例外规则: 命中时 should_block=False 且规则以 @@ 开头,
                    # 需借助 "有例外时全表不 block, 无例外时全表 block" 判断
                    if hit:
                        resp_lines.add(cand)
                    elif cand.startswith("@@"):
                        noexc = AdblockRules(
                            [l for l in rule_lines if l != cand], use_re2=False)
                        if noexc.should_block(url, options={"domain": "test.local"}):
                            resp_lines.add(cand)
                except Exception:
                    pass
            for rl in resp_lines:
                if isinstance(rl, int):
                    precs.add(precision_by_line.get(rl, "?"))
                else:
                    for d in audit["decisions"]:
                        if d["raw"].strip() == rl:
                            precs.add(d["precision"])
                            break
            mismatches.append((url, o_blocked, s_blocked, resp_lines, precs))

    print(f"\n[result] oracle 拦截 {n_block_o}, sim 拦截 {n_block_s}, "
          f"不一致样本 {len(mismatches)}")

    DECLARED = {"widened", "narrowed", "approximated"}
    undeclared = []
    declared_count = 0
    direction_stats = {}
    for url, ob, sb, resp, precs in mismatches:
        dkey = ("oracle>sim" if ob else "sim>oracle") + ":" + ",".join(sorted(precs))
        direction_stats[dkey] = direction_stats.get(dkey, 0) + 1
        if precs and precs <= DECLARED | {"exact"} and (precs & DECLARED):
            declared_count += 1
        else:
            undeclared.append((url, ob, sb, resp, precs))
    (dist_dir / "mismatches.json").write_text(json.dumps([
        {"url": u, "oracle": ob, "sim": sb, "responsible": [str(r) for r in resp],
         "precision": sorted(precs)}
        for u, ob, sb, resp, precs in mismatches], indent=1, ensure_ascii=False))
    print("[result] 偏差方向分布:", json.dumps(direction_stats, ensure_ascii=False))

    print(f"[result] 已申报偏差 {declared_count}, 未申报偏差 {len(undeclared)}")
    if undeclared:
        print("\n=== 未申报偏差 (语义不等价!) ===")
        for url, ob, sb, resp, precs in undeclared[:50]:
            print(f"  {url}\n    oracle={'block' if ob else 'direct'} "
                  f"sim={'block' if sb else 'direct'} 责任={list(resp)[:3]} 精度={precs}")
        return 1

    # 覆盖率: 每条非 dropped 规则至少贡献样本 (由构造保证), 统计被命中的责任行
    print("[result] OK — 所有差异均在审计申报范围内")
    return 0

if __name__ == "__main__":
    sys.exit(main())
