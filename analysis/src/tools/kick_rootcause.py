#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
周期性被踢（30min/90min）根因定位。

假设 1：模块与 QQ 共用同一个 bytehook 实例 → QQ 能枚举出你的 hook
假设 2：dl_iterate_phdr 枚举已加载 .so，发现模块的 so 名字
假设 3：定时任务（alarm/nanosleep/timer）周期性触发 RuntimeEnvCensorTask
"""
import sys, os, re, struct

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(find_dec() or "", "lib", "arm64-v8a")


def check_needed(name):
    """读 DT_NEEDED，看依赖了哪些 so"""
    p = os.path.join(LIB, name)
    if not os.path.isfile(p):
        return None
    e = ELF(p)
    d = e.d
    # .dynamic
    dyn = [s for s in e.sh if s["sname"] == ".dynamic"]
    dynstr = [s for s in e.sh if s["sname"] == ".dynstr"]
    if not dyn or not dynstr:
        return None
    ds = dynstr[0]
    strtab = d[ds["off"]:ds["off"] + ds["size"]]
    seg = d[dyn[0]["off"]:dyn[0]["off"] + dyn[0]["size"]]
    needed = []
    for i in range(0, len(seg), 16):
        if i + 16 > len(seg):
            break
        tag, val = struct.unpack_from("<QQ", seg, i)
        if tag == 0:
            break
        if tag == 1:  # DT_NEEDED
            end = strtab.find(b"\x00", val)
            needed.append(strtab[val:end].decode("ascii", "replace"))
    return needed


def main():
    print("=" * 78)
    print("一、bytehook 实例共用分析（假设 1）")
    print("=" * 78)
    print("""
关键机制：Android linker 按 soname 去重。
如果 QQ 和你的模块都依赖 libbytehook.so，
加载到内存里的是【同一个实例】，共享【同一张 records 表】。
""")

    for n in ("librmonitor_base.so", "librmonitor_memory.so",
              "libBugly_Native.so", "libfekit.so"):
        need = check_needed(n)
        if need:
            bh = [x for x in need if "bytehook" in x or "shadowhook" in x]
            print("  %-24s DT_NEEDED 含 hook 引擎: %s"
                  % (n, ", ".join(bh) if bh else "无"))

    print("\n  → 若模块也链接 libbytehook.so，QQ 调 bytehook_get_records() 就能列出你的 hook")

    # ---------- 二、定时机制 ----------
    print("\n" + "=" * 78)
    print("二、周期性触发机制（假设 3）")
    print("=" * 78)

    # 时间常量（毫秒）：30min=1800000, 90min=5400000
    CONSTS = {
        "1800000 (30min ms)": struct.pack("<I", 1800000),
        "1800000000 (30min us)": struct.pack("<I", 1800000000),
        "5400000 (90min ms)": struct.pack("<I", 5400000),
        "1800 (30min s)": struct.pack("<I", 1800),
        "5400 (90min s)": struct.pack("<I", 5400),
        "300000 (5min ms)": struct.pack("<I", 300000),
        "60000 (1min ms)": struct.pack("<I", 60000),
        "600000 (10min ms)": struct.pack("<I", 600000),
    }

    for n in ("libfekit.so", "librmonitor_base.so", "libbasic_share.so",
              "libMSFKernel.so"):
        p = os.path.join(LIB, n)
        if not os.path.isfile(p):
            continue
        d = open(p, "rb").read()
        print("\n  %s" % n)
        found = False
        for label, pat in CONSTS.items():
            c = d.count(pat)
            if c:
                print("    %-26s ×%d" % (label, c))
                found = True
        if not found:
            print("    未找到常见时间常量（可能用浮点或运行时计算）")

    # ---------- 三、枚举机制 ----------
    print("\n" + "=" * 78)
    print("三、模块枚举机制（假设 2）")
    print("=" * 78)
    print("""
  7 个库全部导入 dl_iterate_phdr —— 这是最直接的枚举手段：
    它回调每个已加载的 ELF，给出 name（完整路径）
    模块的 so 路径形如 /data/app/~~xxx==/com.xxx.module-xxx==/lib/arm64/libxxx.so
    → 路径里直接带包名，改名无用

  对比手段：
    strstr / strcasecmp 比对名字（hook_libfekit.cpp 拦的就是这个）
    fopen("/proc/self/maps") 逐行读（libfekit 有 0x442217 处）
""")

    # 检查各库对 maps 的处理方式
    print("  各库对 /proc/self/maps 的引用：")
    for n in ("libfekit.so", "librmonitor_base.so", "librmonitor_memory.so",
              "libBugly_Native.so", "libbasic_share.so"):
        p = os.path.join(LIB, n)
        if not os.path.isfile(p):
            continue
        d = open(p, "rb").read()
        c1 = d.count(b"/proc/self/maps")
        c2 = d.count(b"/proc/self/smaps")
        c3 = d.count(b"/proc/self/task")
        c4 = d.count(b"/proc/self/cmdline")
        if c1 or c2 or c3 or c4:
            print("    %-24s maps×%d smaps×%d task×%d cmdline×%d"
                  % (n, c1, c2, c3, c4))


if __name__ == "__main__":
    main()
