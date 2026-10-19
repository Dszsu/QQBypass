#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 smali 目录提取类的方法签名清单，便于写 hook。"""
import os, re, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

METHOD_RE = re.compile(r"^\.method\s+(.+)$")
FIELD_RE = re.compile(r"^\.field\s+(.+)$")
STRING_RE = re.compile(r'const-string(?:/jumbo)?\s+\S+,\s*"((?:[^"\\]|\\.)*)"')


def parse_smali(path):
    methods, fields, strings = [], [], []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = METHOD_RE.match(line)
            if m:
                methods.append(m.group(1))
                continue
            m = FIELD_RE.match(line)
            if m:
                fields.append(m.group(1))
                continue
            m = STRING_RE.search(line)
            if m:
                strings.append(m.group(1))
    return methods, fields, strings


def main():
    roots = sys.argv[1:]
    for root in roots:
        if not os.path.isdir(root):
            continue
        print("=" * 78)
        print("### " + root)
        for dirpath, _, files in os.walk(root):
            for fn in sorted(files):
                if not fn.endswith(".smali"):
                    continue
                p = os.path.join(dirpath, fn)
                methods, fields, strings = parse_smali(p)
                if not methods:
                    continue
                cls = os.path.relpath(p, root).replace("\\", "/")[:-len(".smali")]
                print("\n--- %s" % cls)
                for m in methods:
                    print("    .method " + m)
                if fields:
                    for fd in fields[:20]:
                        print("    .field  " + fd)
                if strings:
                    uniq = []
                    for s in strings:
                        if s not in uniq:
                            uniq.append(s)
                    print("    strings: " + " | ".join(uniq[:25]))


if __name__ == "__main__":
    main()
