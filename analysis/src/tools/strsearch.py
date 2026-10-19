#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 APK 全部 dex 的字符串池里搜索关键词，报告命中所在的 dex 和下一条相邻字符串。
用于定位「哪个 dex 引用了这个方法名 / 这个常量」。"""
import sys, zipfile, struct, re, os, json

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import find_apk

APK = find_apk()


def read_uleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        if x < 0x80:
            return r, i
        s += 7


def strings_of(data):
    sid_size, sid_off = struct.unpack_from("<II", data, 0x38)
    offs = struct.unpack_from("<%dI" % sid_size, data, sid_off)
    out = []
    for off in offs:
        _, p = read_uleb(data, off)
        try:
            end = data.index(b"\x00", p)
        except ValueError:
            out.append("")
            continue
        out.append(data[p:end].decode("utf-8", "replace"))
    return out


def main():
    kws = sys.argv[1:]
    if not kws:
        print("usage: strsearch.py KW1 KW2 ...")
        return
    with zipfile.ZipFile(APK) as z:
        dexes = sorted([n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)],
                       key=lambda n: int(re.sub(r"\D", "", n) or 0))
        results = {k: [] for k in kws}
        for n in dexes:
            data = z.read(n)
            try:
                strs = strings_of(data)
            except Exception as e:
                print("FAIL", n, e); continue
            for i, s in enumerate(strs):
                for k in kws:
                    if k in s:
                        ctx = strs[max(0, i - 1):i + 3]
                        results[k].append((n, s, ctx))
            del data, strs
        for k in kws:
            lst = results[k]
            print("\n" + "=" * 78)
            print("### %r  -> %d hits" % (k, len(lst)))
            # 按 dex 聚合
            bydex = {}
            for n, s, ctx in lst:
                bydex.setdefault(n, []).append((s, ctx))
            for n in sorted(bydex, key=lambda x: int(re.sub(r"\D", "", x) or 0)):
                items = bydex[n]
                print("  -- %s (%d)" % (n, len(items)))
                seen = set()
                for s, ctx in items:
                    if s in seen:
                        continue
                    seen.add(s)
                    print("     %r" % s)
                    if len(seen) >= 40:
                        print("     ...")
                        break


if __name__ == "__main__":
    main()
