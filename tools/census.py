#!/usr/bin/env python3
"""gfwlist 语法全量普查：把每一行分类到语法形态，并给出样本。"""
import base64, re, sys
from collections import defaultdict, Counter
from urllib.parse import unquote

path = sys.argv[1] if len(sys.argv) > 1 else "gfwlist.txt"
raw = open(path, "rb").read()
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    text = base64.b64decode(raw).decode("utf-8")

lines = text.splitlines()

def classify(line: str) -> str:
    s = line.strip()
    if not s:
        return "blank"
    if s.startswith("!"):
        return "comment"
    if s.startswith("[") and s.endswith("]"):
        return "header"
    exc = s.startswith("@@")
    if exc:
        s = s[2:]
    body = s
    prefix = "exception+" if exc else ""

    if body.startswith("/") and body.rfind("/") > 0 and body.endswith("/"):
        return prefix + "regex /.../ "
    if body.startswith("||"):
        return prefix + "host-anchor ||"
    if body.startswith("|"):
        return prefix + "url-prefix |..."
    if body.endswith("|"):
        return prefix + "url-suffix ...|"
    if "*" in body:
        return prefix + "wildcard *"
    if body.startswith("."):  # 形如 .example.com
        return prefix + "leading-dot"
    return prefix + "plain-substring"

cats = defaultdict(list)
for ln, line in enumerate(lines, 1):
    cats[classify(line)].append((ln, line))

print(f"total lines: {len(lines)}\n")
for cat, items in sorted(cats.items(), key=lambda kv: -len(kv[1])):
    print(f"{cat:28s} {len(items):5d}")
    for ln, line in items[:5]:
        print(f"    L{ln}: {line[:100]}")
    if len(items) > 5:
        print(f"    ... ({len(items)-5} more)")
    print()

# 细节统计：规则体内的特殊字符
rule_lines = [(ln, l.strip()) for ln, l in enumerate(lines, 1)
              if l.strip() and not l.strip().startswith(("!", "["))]
print("=== 规则体字符特征 ===")
feats = {
    "含 % (URL编码)": lambda b: "%" in b,
    "含 ^ (分隔符)": lambda b: "^" in b,
    "含 http://": lambda b: "http://" in b,
    "含 https://": lambda b: "https://" in b,
    "含路径 /(非regex)": lambda b: "/" in b.strip("/"),
    "含端口 :": lambda b: re.search(r":\d+", b) is not None,
    "纯 IP 地址": lambda b: re.fullmatch(r"\|*@*\|*(\d{1,3}\.){3}\d{1,3}\|*/*.*", b) is not None,
    "非 ASCII": lambda b: any(ord(c) > 127 for c in b),
}
for name, f in feats.items():
    hits = [(ln, l) for ln, l in rule_lines if f(l)]
    print(f"{name:22s} {len(hits):5d}   e.g. {hits[:3]}")

# exception 规则单独看
exc = [(ln, l) for ln, l in rule_lines if l.startswith("@@")]
print(f"\n=== exception 共 {len(exc)} 条，抽样 10 ===")
for ln, l in exc[:10]:
    print(f"  L{ln}: {l[:110]}")
