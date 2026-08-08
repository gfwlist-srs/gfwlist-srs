#!/usr/bin/env python3
"""gfwlist 输入验证 (CI 门禁用):
  1. base64 可解码且含 [AutoProxy] 头
  2. 行数在合理区间 (>1000), Last Modified 日期可解析
  3. (尽力) Checksum: gfwlist 的校验算法与 ABP/AutoProxy 公开变体均不匹配,
     尝试全部已知变体, 仅作信息输出, 不作为门禁。
用法: validate_input.py <gfwlist.b64原始下载文件>
退出码 0=结构有效, 1=无效。
"""
import base64
import binascii
import email.utils
import hashlib
import re
import sys

def try_checksums(text: str, expected: str) -> str | None:
    def md5b64(b: bytes) -> str:
        return base64.b64encode(hashlib.md5(b).digest()).decode().rstrip("=")
    no_line = re.sub(r"^!\s*Checksum:[^\n\r]*\r?", "", text, count=1, flags=re.M)
    variants = {
        "utf8-no-line": no_line.encode(),
        "utf8-join-no-nl": "".join(no_line.splitlines()).encode(),
        "utf8-no-ws": re.sub(r"\s", "", no_line).encode(),
        "utf16le-no-line": no_line.encode("utf-16-le"),
        "utf16le-no-ws": re.sub(r"\s", "", no_line).encode("utf-16-le"),
    }
    for name, b in variants.items():
        if md5b64(b) == expected:
            return name
    return None

def main() -> int:
    raw = open(sys.argv[1], "rb").read()
    try:
        text = base64.b64decode(re.sub(rb"\s", b"", raw), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f"FAIL: base64/utf-8 解码失败: {e}")
        return 1
    lines = text.splitlines()
    if not lines or not lines[0].startswith("[AutoProxy"):
        print("FAIL: 缺少 [AutoProxy] 头")
        return 1
    m = re.search(r"^! Last Modified:\s*(.+)$", text, flags=re.M)
    if not m or not email.utils.parsedate_to_datetime(m.group(1).strip()):
        print("FAIL: Last Modified 缺失或不可解析")
        return 1
    if len(lines) < 1000:
        print(f"FAIL: 行数异常 ({len(lines)})")
        return 1
    cm = re.search(r"^! Checksum:\s*(\S+)", text, flags=re.M)
    if cm:
        hit = try_checksums(text, cm.group(1))
        print(f"INFO: Checksum {'匹配 (' + hit + ')' if hit else '与已知公开算法均不匹配 (gfwlist 私有变体), 仅记录'}")
    print(f"OK: {len(lines)} 行, Last Modified: {m.group(1).strip()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
