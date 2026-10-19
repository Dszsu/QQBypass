#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位 smali 中某个字符串所在的方法，打印方法签名与其上下文。"""
import sys, os, re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

METHOD_START = re.compile(r"^\.method\s+(.+)$")
END = ".end method"


def find(path, needle, ctx=25):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    out = []
    for i, line in enumerate(lines):
        if needle in line:
            # 向上找 .method
            j = i
            while j >= 0 and not lines[j].startswith(".method"):
                j -= 1
            # 向下找 .end method
            k = i
            while k < len(lines) and lines[k].strip() != END:
                k += 1
            sig = lines[j].strip() if j >= 0 else "?"
            out.append((j + 1, sig, lines[j + 1:k]))
    return out


def main():
    if len(sys.argv) < 3:
        print("用法: python findstr.py <要搜的字符串> <file1.smali> [file2.smali ...]")
        print("示例: python findstr.py '/system/bin/su' work/smali_root/xxx.smali")
        return
    needle = sys.argv[1]
    paths = sys.argv[2:]
    for p in paths:
        if not os.path.isfile(p):
            continue
        hits = find(p, needle)
        for lineno, sig, body in hits:
            print("=" * 76)
            print("%s:%d" % (p, lineno))
            print(sig)
            print("-" * 76)
            shown = 0
            for ln in body:
                s = ln.rstrip()
                if not s.strip() or s.strip().startswith("#"):
                    continue
                if s.strip().startswith(".line"):
                    continue
                print("  " + s)
                shown += 1
                if shown > 90:
                    print("  ... (truncated)")
                    break
            print()


if __name__ == "__main__":
    main()
