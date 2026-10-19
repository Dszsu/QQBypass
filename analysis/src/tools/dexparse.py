#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""直接从 APK(zip) 里流式解析每个 classes*.dex，导出类名清单。
不依赖 jadx / baksmali，内存占用按单个 dex 计。"""
import sys, zipfile, struct, os, json, re

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import find_apk

APK = find_apk()
OUT = os.path.join(os.environ.get("QQRK_OUT", os.getcwd()), "dexnames")


def uleb128(b, i):
    r = 0
    s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if x < 0x80:
            return r, i
        s += 7


def parse_dex(data):
    """返回 (class_names, info)"""
    if data[:4] != b"dex\n":
        raise ValueError("not a dex")
    (string_ids_size, string_ids_off) = struct.unpack_from("<II", data, 0x38)
    (type_ids_size, type_ids_off) = struct.unpack_from("<II", data, 0x40)
    class_defs_size = struct.unpack_from("<I", data, 0x60)[0]

    # string data offsets
    str_offs = struct.unpack_from("<%dI" % string_ids_size, data, string_ids_off)
    # type -> string idx
    type_str_idx = struct.unpack_from("<%dI" % type_ids_size, data, type_ids_off)

    # 只解出 type 用到的字符串（比全解快）
    needed = set(type_str_idx)
    strings = {}
    for sidx in needed:
        off = str_offs[sidx]
        _, p = uleb128(data, off)          # utf16 length
        end = data.index(b"\x00", p)
        try:
            strings[sidx] = data[p:end].decode("utf-8", "surrogatepass")
        except UnicodeDecodeError:
            strings[sidx] = data[p:end].decode("utf-8", "replace")

    names = []
    for tidx in type_str_idx:
        s = strings.get(tidx, "")
        if s.startswith("L") and s.endswith(";"):
            names.append(s[1:-1].replace("/", "."))
    info = dict(strings=string_ids_size, types=type_ids_size, classes=class_defs_size)
    return names, info


KEYWORDS = [
    "login", "Login", "auth", "Auth", "ticket", "Ticket", "sign", "Sign",
    "crypt", "Crypt", "encrypt", "Encrypt", "aes", "AES", "rsa", "RSA",
    "sec", "Sec", "safe", "Safe", "guard", "Guard", "risk", "Risk",
    "root", "Root", "hook", "Hook", "xposed", "Xposed", "frida", "Frida",
    "debug", "Debug", "emu", "Emu", "anti", "Anti", "detect", "Detect",
    "protocol", "Protocol", "packet", "Packet", "msf", "MSF",
    "qimei", "Qimei", "device", "Device", "fingerprint", "Fingerprint",
    "token", "Token", "cookie", "Cookie", "key", "Key", "qsec", "QSec",
]

def main():
    os.makedirs(OUT, exist_ok=True)
    all_names = []
    per_dex = {}
    with zipfile.ZipFile(APK) as z:
        dexes = sorted(
            [n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)],
            key=lambda n: int(re.sub(r"\D", "", n) or 0),
        )
        print("dex files:", len(dexes))
        for n in dexes:
            data = z.read(n)
            try:
                names, info = parse_dex(data)
            except Exception as e:
                print("%-16s FAILED %s" % (n, e))
                continue
            per_dex[n] = dict(info, names=len(names))
            all_names.extend(names)
            with open(os.path.join(OUT, n + ".txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(set(names))))
            print("%-16s %7d classes  %10d types" % (n, len(set(names)), info["types"]))
            del data

    uniq = sorted(set(all_names))
    with open(os.path.join(OUT, "ALL_CLASSES.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(uniq))
    with open(os.path.join(OUT, "per_dex.json"), "w", encoding="utf-8") as f:
        json.dump(per_dex, f, indent=1)

    # 顶层包统计
    tops = {}
    for c in uniq:
        p = ".".join(c.split(".")[:4])
        tops[p] = tops.get(p, 0) + 1
    with open(os.path.join(OUT, "top_packages.txt"), "w", encoding="utf-8") as f:
        for k, v in sorted(tops.items(), key=lambda x: -x[1]):
            f.write("%8d  %s\n" % (v, k))

    # 关键词命中
    with open(os.path.join(OUT, "interesting.txt"), "w", encoding="utf-8") as f:
        for kw in KEYWORDS:
            hits = [c for c in uniq if kw in c]
            if hits:
                f.write("### %s (%d)\n" % (kw, len(hits)))
                for h in hits[:400]:
                    f.write("  " + h + "\n")
                if len(hits) > 400:
                    f.write("  ... %d more\n" % (len(hits) - 400))
                f.write("\n")

    print("TOTAL unique classes:", len(uniq))


if __name__ == "__main__":
    main()
