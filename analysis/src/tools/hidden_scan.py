#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度挖掘隐藏检测：不看导入符号，看「行为特征」。

四个维度：
  A. 直接系统调用（svc #0）—— 绕过 libc hook
  B. 自定义 syscall 表 / libc 函数指针 —— 绕过 PLT hook
  C. 反汇编里的特征指令序列（mrs tpidr / adrp 扫描 / 循环比较）
  D. 加密混淆的检测字符串（高熵区段 + 短串）
"""
import sys, os, re, struct, collections, math

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(find_dec() or "", "lib", "arm64-v8a")

TARGETS = ["libfekit.so", "libMSFKernel.so", "librmonitor_base.so",
           "libbasic_share.so", "libBugly_Native.so",
           "librmonitor_memory.so", "libbugly_dumper.so",
           "libQSec.so", "libturingxq.so", "libturingmfa.so"]

# AArch64 svc #0 = D4000001 (little endian: 01 00 00 D4)
SVC0 = struct.pack("<I", 0xD4000001)
SVC_ANY = re.compile(rb"[\x00-\xff][\x00-\xff][\x00-\xff][\xd4]")


def entropy(b):
    if not b:
        return 0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def scan_svc(data):
    """统计 svc #0 指令数量及位置"""
    res = []
    i = 0
    while True:
        i = data.find(SVC0, i)
        if i < 0:
            break
        res.append(i)
        i += 4
        if len(res) > 500:
            break
    return res


def find_high_entropy_regions(data, window=4096, thresh=7.4):
    """找高熵区段 = 加密数据"""
    regions = []
    start = None
    for off in range(0, len(data) - window, window):
        e = entropy(data[off:off + window])
        if e > thresh:
            if start is None:
                start = off
        else:
            if start is not None:
                regions.append((start, off))
                start = None
    if start is not None:
        regions.append((start, len(data)))
    return regions


def main():
    print("=" * 78)
    print("隐藏检测深度挖掘")
    print("=" * 78)

    for name in TARGETS:
        p = os.path.join(LIB, name)
        if not os.path.isfile(p):
            continue
        e = ELF(p)
        d = e.d
        funcs = [s for s in e.dynsym if s["type"] == 2 and s["name"]]
        imported = set(s["name"] for s in e.dynsym
                       if s["type"] == 2 and s["name"] and s["value"] == 0)

        print("\n" + "=" * 78)
        print("%s   %.2f MB   %d FUNC" % (name, len(d) / 1048576, len(funcs)))
        print("=" * 78)

        # ---------- A. svc #0 ----------
        svcs = scan_svc(d)
        if svcs:
            print("  [A] 直接系统调用 svc #0 : %d 处" % len(svcs))
            print("      位置: " + ", ".join("0x%x" % x for x in svcs[:12])
                  + (" ..." if len(svcs) > 12 else ""))
        else:
            print("  [A] 直接系统调用 svc #0 : 无")

        # ---------- B. libc 函数指针 / 自定义 syscall ----------
        dyn = []
        for sym in ("syscall", "real_syscall", "__syscall", "svc"):
            if sym in imported:
                dyn.append(sym)
        # 找导出里带 syscall 的
        for s in funcs:
            if "syscall" in s["name"].lower():
                dyn.append(s["name"])
        if dyn:
            print("  [B] syscall 相关符号: " + ", ".join(sorted(set(dyn))))
        else:
            print("  [B] syscall 相关符号: 无")

        # ---------- C. 反调试特征指令 ----------
        # mrs xN, tpidr_el0 (D53BD04x) 用于取 TLS
        # 更关键：找 "prctl" 的 PR_SET_DUMPABLE 常量 4/22
        feats = []
        if b"prctl" in e.dynsym and True:
            pass
        # 检查是否引用 /proc/self/status 的 TracerPid 字段名
        for k in (b"TracerPid", b"tracerpid", b"TracerPid:"):
            if k in d:
                feats.append("TracerPid")
                break
        # 检查 capability/namespace 探测
        for k in (b"/proc/self/attr", b"/proc/self/cgroup", b"/proc/self/uid_map",
                  b"/proc/self/mountinfo", b"/proc/self/namespace"):
            if k in d:
                feats.append(k.decode())
        if feats:
            print("  [C] 深度探测特征: " + ", ".join(feats))
        else:
            print("  [C] 深度探测特征: 无")

        # ---------- D. 高熵区段（加密数据） ----------
        regs = find_high_entropy_regions(d)
        if regs:
            total = sum(b - a for a, b in regs)
            print("  [D] 高熵区段: %d 段 / %d B (%.1f%% 文件)"
                  % (len(regs), total, total * 100.0 / len(d)))
            for a, b in regs[:6]:
                print("        0x%06x - 0x%06x  (%.1f KB, H=%.2f)"
                      % (a, b, (b - a) / 1024, entropy(d[a:b])))
        else:
            print("  [D] 高熵区段: 无（无大面积加密数据）")

        # ---------- E. dlopen 目标（动态加载） ----------
        libs = set()
        for m in re.finditer(rb"lib[a-zA-Z0-9_\-]+\.so", d):
            libs.add(m.group().decode())
        if libs:
            own = [x for x in libs if not x.startswith("libc") and
                   not x.startswith("libm.") and not x.startswith("libdl")]
            if own:
                print("  [E] 引用的其他 .so (%d): %s"
                      % (len(own), ", ".join(sorted(own)[:10])))


if __name__ == "__main__":
    main()
