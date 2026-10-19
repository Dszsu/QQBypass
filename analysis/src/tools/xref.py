#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DEX 交叉引用 (xref) 工具。

对 APK 内所有 dex 解析 code_item 的 invoke 指令，找出「谁调用了指定的类/方法」。
不依赖 baksmali / jadx / androguard。

用法:
  python xref.py 'com/tencent/mobileqq/qsec/qsecurity/QSec'      # 该类所有方法
  python xref.py 'Lcom/tencent/mobileqq/qsec/qsecurity/QSec;->detectMethod'
"""
import sys, zipfile, struct, re, os
from collections import defaultdict

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import find_apk

APK = find_apk()

# invoke opcodes -> method_idx 在指令流中的位置偏移
INVOKE_35C = {0x6E, 0x6F, 0x70, 0x71, 0x72}   # virtual/super/direct/static/interface
INVOKE_3RC = {0x74, 0x75, 0x76, 0x77, 0x78}
INVOKE_35MS = {0xFA, 0xFB}                     # invoke-polymorphic
INVOKE_RANGE_MS = {0xFC, 0xFD}
INVOKE_CUSTOM = {0xFC, 0xFD}                   # 0xfc invoke-custom, 0xfd invoke-custom/range


def uleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        if x < 0x80:
            return r, i
        s += 7


def sleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            if x & 0x40:
                r -= (1 << s)
            return r, i


class Dex:
    def __init__(self, data, name):
        self.d = data
        self.name = name
        (self.ss, self.so) = struct.unpack_from("<II", data, 0x38)
        (self.ts, self.to) = struct.unpack_from("<II", data, 0x40)
        (self.ps, self.po) = struct.unpack_from("<II", data, 0x48)
        (self.fs, self.fo) = struct.unpack_from("<II", data, 0x50)
        (self.ms, self.mo) = struct.unpack_from("<II", data, 0x58)
        (self.cs, self.co) = struct.unpack_from("<II", data, 0x60)
        self._str_cache = {}

    def string(self, idx):
        if idx in self._str_cache:
            return self._str_cache[idx]
        off = struct.unpack_from("<I", self.d, self.so + idx * 4)[0]
        _, p = uleb(self.d, off)
        try:
            end = self.d.index(b"\x00", p)
        except ValueError:
            end = len(self.d)
        s = self.d[p:end].decode("utf-8", "replace")
        self._str_cache[idx] = s
        return s

    def type_name(self, idx):
        sidx = struct.unpack_from("<I", self.d, self.to + idx * 4)[0]
        return self.string(sidx)

    def method_info(self, idx):
        """(class_name, method_name)"""
        cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.d, self.mo + idx * 8)
        return self.type_name(cls_idx), self.string(name_idx)

    def class_defs(self):
        for k in range(self.cs):
            base = self.co + k * 32
            class_idx, access, super_idx, ifaces, src_idx, annots, class_data_off, static_vals = \
                struct.unpack_from("<IIIIIIII", self.d, base)
            if class_data_off == 0:
                continue
            yield self.type_name(class_idx), class_data_off

    def codes_of_class(self, class_data_off):
        """遍历 class_data_item，产出 (method_idx 列表含其 code_off)"""
        d = self.d
        i = class_data_off
        sf, i = uleb(d, i)
        inf, i = uleb(d, i)
        dm, i = uleb(d, i)
        vm, i = uleb(d, i)
        out = []
        for _ in range(sf):
            _, i = uleb(d, i); _, i = uleb(d, i)
        for _ in range(inf):
            _, i = uleb(d, i); _, i = uleb(d, i)
        for _ in range(dm + vm):
            diff, i = uleb(d, i)
            acc, i = uleb(d, i)
            code_off, i = uleb(d, i)
            out.append((diff, code_off))
        return out

    def iter_code_items(self):
        """遍历全部 code_item: (code_off, insns_off, insns_size)"""
        for cname, cdoff in self.class_defs():
            try:
                meths = self.codes_of_class(cdoff)
            except Exception:
                continue
            for _, code_off in meths:
                if not code_off:
                    continue
                try:
                    regs, ins, outs, tries, dbg, insns_size = struct.unpack_from("<HHHHII", self.d, code_off)
                except Exception:
                    continue
                yield cname, code_off, code_off + 16, insns_size

    def caller_method(self, code_off):
        """反查 code_off 属于哪个 method_idx（走 method table 线性查找太慢，
        改为在 iter 时记录）。这里保留占位。"""
        return None


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else ""
    # want 形如 'com/tencent/.../QSec' 或 'Lcom/.../QSec;->method'
    want_cls = want.split("->")[0].lstrip("L").rstrip(";")
    want_meth = want.split("->")[1] if "->" in want else None

    targets = defaultdict(set)   # (cls, meth) -> {dex}
    hits = defaultdict(list)     # (caller_cls, caller_code_off) -> [(dex, target)]

    with zipfile.ZipFile(APK) as z:
        dexes = sorted([n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)],
                       key=lambda n: int(re.sub(r"\D", "", n) or 0))
        for n in dexes:
            data = z.read(n)
            dx = Dex(data, n)

            # 1) 该 dex 是否引用目标类（type_ids）
            refs = set()
            for t in range(dx.ts):
                tn = dx.type_name(t)
                if want_cls in tn:
                    refs.add(t)
            if not refs:
                del data
                continue
            print("[%s] 引用 %s 的 type: %d 个" % (n, want_cls, len(refs)))

            # 2) 收集目标 method_idx
            tgt = set()
            for m in range(dx.ms):
                cls, meth = dx.method_info(m)
                if want_cls in cls and (want_meth is None or meth == want_meth):
                    tgt.add(m)
                    targets[(cls, meth)].add(n)
            if not tgt:
                print("    该 dex 无目标方法定义")
                del data
                continue

            # 3) 建立 method_idx -> (cls, meth) 全表，供报告调用者
            mid = {}
            for m in range(dx.ms):
                mid[m] = dx.method_info(m)

            # 4) 扫 code_item 指令
            import time
            t0 = time.time()
            n_scan = 0
            for cname, code_off, insns_off, insns_size in dx.iter_code_items():
                n_scan += 1
                # 找该 code_off 对应的 method
                # 先扫指令
                found = []
                for k in range(0, insns_size, 2):
                    try:
                        unit = struct.unpack_from("<H", dx.d, insns_off + k * 2)[0]
                    except struct.error:
                        break
                    op = unit & 0xFF
                    if op in INVOKE_35C or op in INVOKE_3RC:
                        try:
                            mi = struct.unpack_from("<H", dx.d, insns_off + (k + 1) * 2)[0]
                        except struct.error:
                            continue
                        if mi in tgt:
                            found.append(mid.get(mi))
                if found:
                    hits[(cname, code_off)].extend([(n, f) for f in found])
            print("    扫描 code_item: %d 条, %.1fs" % (n_scan, time.time() - t0))
            del data, dx

    print("\n" + "=" * 78)
    print("### 目标方法定义")
    for (c, m), ds in sorted(targets.items()):
        print("  %s->%s   in %s" % (c.replace("/", "."), m, ",".join(sorted(ds))))
    print("\n### 调用点 (caller -> target)")
    if not hits:
        print("  无")
    for (cname, code_off), lst in sorted(hits.items()):
        for dn, tgt2 in lst:
            print("  [%s] %s  ==invoke==>  %s->%s" % (dn, cname.replace("/", "."), tgt2[0].replace("/", "."), tgt2[1]))


if __name__ == "__main__":
    main()
