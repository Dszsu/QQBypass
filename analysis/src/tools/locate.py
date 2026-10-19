#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按类名定位所在 dex，并可选导出该类在 dex 中的 method 签名清单。"""
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


def dex_tables(data):
    sid_size, sid_off = struct.unpack_from("<II", data, 0x38)
    tid_size, tid_off = struct.unpack_from("<II", data, 0x40)
    cdef_size, cdef_off = struct.unpack_from("<II", data, 0x60)
    return (sid_size, sid_off), (tid_size, tid_off), (cdef_size, cdef_off)


STR_CACHE = {}


def get_string(data, offs, idx):
    off = offs[idx]
    _, p = read_uleb(data, off)
    end = data.index(b"\x00", p)
    return data[p:end].decode("utf-8", "replace")


def class_names(data):
    (ss, so), (ts, to), (cs, co) = dex_tables(data)
    str_offs = struct.unpack_from("<%dI" % ss, data, so)
    type_str = struct.unpack_from("<%dI" % ts, data, to)
    # class_def_item: 8 x u32, class_idx at offset 0
    cdefs = struct.unpack_from("<%dI" % (cs * 8), data, co)
    out = {}
    for k in range(cs):
        class_idx = cdefs[k * 8]
        if class_idx >= ts:
            continue
        s = get_string(data, str_offs, type_str[class_idx])
        if s.startswith("L") and s.endswith(";"):
            out[s[1:-1].replace("/", ".")] = k
    return out


def main():
    wanted = sys.argv[1:]
    hits = {}
    with zipfile.ZipFile(APK) as z:
        dexes = sorted([n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)],
                       key=lambda n: int(re.sub(r"\D", "", n) or 0))
        for n in dexes:
            data = z.read(n)
            names = class_names(data)
            if wanted:
                for w in wanted:
                    for c in names:
                        if c == w or c.startswith(w):
                            hits.setdefault(w, []).append((n, c))
            else:
                print(n, len(names))
            del data
    for w in wanted:
        lst = hits.get(w, [])
        print("\n== %s  (%d)" % (w, len(lst)))
        for d, c in lst:
            print("   %-16s %s" % (d, c))


if __name__ == "__main__":
    main()
