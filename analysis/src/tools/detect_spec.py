#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ 检测面全量清单（静态）
目标：产出「要 hook 哪些 libc 函数 / 要隐藏哪些字符串」的精确规格。
"""
import sys, os, re, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(find_dec() or "", "lib", "arm64-v8a")

# 前 7 名
TOP = ["libfekit.so", "libMSFKernel.so", "librmonitor_base.so",
       "libbasic_share.so", "libBugly_Native.so", "librmonitor_memory.so",
       "libbugly_dumper.so"]

# 需要重点看字符串的库
STR_FOCUS = {
    "librmonitor_base.so": "hook 框架检测（26 处）",
    "librmonitor_memory.so": "内存 hook 检测",
    "libBugly_Native.so": "ptrace + proc 路径",
    "libfekit.so": "QSec 主体",
}


def extract(blob, minlen=4, maxlen=200):
    res = []
    i = 0
    n = len(blob)
    while i < n:
        if 32 <= blob[i] < 127:
            j = i
            while j < n and 32 <= blob[j] < 127:
                j += 1
            if minlen <= j - i <= maxlen:
                res.append((i, blob[i:j]))
            i = j
        else:
            i += 1
    return res


def main():
    # ---------- 1. 汇总所有导入的检测函数 ----------
    print("=" * 78)
    print("一、libc 边界：7 个库导入的检测函数（去重）")
    print("=" * 78)

    DETECT_SYMS = {
        "ptrace", "process_vm_readv", "sigaction", "sigprocmask", "signal",
        "timer_create", "timer_settime", "setitimer", "alarm",
        "nanosleep", "clock_nanosleep",
        "dladdr", "dl_iterate_phdr", "dlopen", "dlsym",
        "access", "faccessat", "stat", "lstat", "fstatat", "open", "openat",
        "fopen", "opendir", "readlink", "readlinkat", "realpath",
        "system", "popen", "execl", "execve", "fork",
        "getpid", "getppid", "getuid", "geteuid", "kill", "tgkill",
        "prctl", "getpgid", "pthread_getattr_np", "pthread_getname_np",
        "pthread_kill", "pthread_create",
        "__system_property_get", "__system_property_find",
        "__system_property_read_callback",
        "socket", "connect", "getsockname", "getsockopt", "getifaddrs",
        "mprotect", "mmap", "munmap", "syscall",
    }

    per_lib = {}
    all_imports = collections.Counter()
    for name in TOP:
        p = os.path.join(LIB, name)
        if not os.path.isfile(p):
            continue
        e = ELF(p)
        imp = set()
        for s in e.dynsym:
            if s["type"] == 2 and s["name"] and s["value"] == 0:
                imp.add(s["name"])
        hit = sorted(imp & DETECT_SYMS)
        per_lib[name] = hit
        for h in hit:
            all_imports[h] += 1

    for name in TOP:
        if name in per_lib:
            print("\n  %s  (%d 个)" % (name, len(per_lib[name])))
            print("    " + ", ".join(per_lib[name]))

    print("\n  --- 全局去重清单（按使用库数排序）---")
    print("  %-28s %s" % ("函数", "使用者"))
    for sym, cnt in all_imports.most_common():
        users = [n for n in TOP if n in per_lib and sym in per_lib[n]]
        print("  %-28s %d/%d  %s" % (sym, cnt, len(TOP),
                                     ", ".join(x.replace("lib", "").replace(".so", "")
                                               for x in users)))

    print("\n  合计需要 hook 的 libc 函数: %d" % len(all_imports))

    # ---------- 2. 各库的敏感字符串 ----------
    print("\n" + "=" * 78)
    print("二、敏感字符串（要隐藏的目标）")
    print("=" * 78)

    PATS = {
        "root": [b"su", b"magisk", b"busybox", b"Superuser", b"/data/adb",
                 b"kernelsu", b"apatch", b"ksu"],
        "模拟器": [b"goldfish", b"ranchu", b"qemu", b"genymotion",
                    b"vbox86", b"generic_x86", b"sdk_gphone"],
        "hook框架": [b"frida", b"xposed", b"lsposed", b"substrate",
                      b"sandhook", b"yahfa", b"epic", b"pine", b"taichi",
                      b"bytehook", b"dexkit", b"lspatch", b"riru", b"zygisk",
                      b"qauxv", b"qnotified", b"npatch", b"lspd"],
        "proc": [b"/proc/self/", b"/proc/net/", b"/proc/%d/"],
        "QSec": [b"RuntimeEnvCensor", b"parse_libart", b"detection_",
                  b"DlVmTask", b"MSFIntChkStrike", b"memchk", b"antitrace"],
    }

    for name, desc in STR_FOCUS.items():
        p = os.path.join(LIB, name)
        if not os.path.isfile(p):
            continue
        e = ELF(p)
        strs = extract(e.d, 4, 120)
        print("\n" + "-" * 74)
        print("%s   %s" % (name, desc))
        print("-" * 74)
        for cat, pats in PATS.items():
            found = []
            for off, s in strs:
                low = s.lower()
                for pat in pats:
                    if pat.lower() in low:
                        found.append((off, s))
                        break
            if found:
                print("  [%s] %d 处" % (cat, len(found)))
                seen = set()
                for off, s in found[:25]:
                    t = s.decode("ascii", "replace")
                    if t in seen:
                        continue
                    seen.add(t)
                    print("      0x%06x  %s" % (off, t[:95]))


if __name__ == "__main__":
    main()
