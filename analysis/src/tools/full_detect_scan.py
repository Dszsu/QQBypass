#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全量 .so 检测面扫描 —— 输出每个库的检测能力矩阵。"""
import sys, os, re, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(find_dec() or "", "lib", "arm64-v8a")

# 检测能力分类（用**导入符号**判定，比字符串可靠）
IMPORT_RULES = {
    "反调试 ptrace": ["ptrace", "process_vm_readv"],
    "调试状态": ["/proc/self/status"],  # 字符串
    "信号处理": ["sigaction", "sigprocmask", "signal"],
    "定时自检": ["timer_create", "timer_settime", "setitimer", "alarm",
                  "nanosleep", "clock_nanosleep"],
    "自身基址": ["dladdr", "dl_iterate_phdr", "dlopen", "dlsym"],
    "文件探测": ["access", "faccessat", "stat", "lstat", "fstatat",
                  "open", "openat", "fopen", "opendir", "readlink",
                  "readlinkat", "realpath"],
    "命令执行": ["system", "popen", "execve", "execl", "fork"],
    "进程信息": ["getpid", "getppid", "getuid", "geteuid", "getgid",
                  "kill", "tgkill", "prctl", "getpgid"],
    "属性读取": ["__system_property_get", "__system_property_find",
                  "__system_property_read_callback"],
    "网络自检": ["socket", "connect", "getsockname", "getsockopt",
                  "getifaddrs"],
    "内存自检": ["mprotect", "mmap", "munmap", "msync"],
    "线程枚举": ["pthread_getattr_np", "pthread_getname_np",
                  "pthread_kill", "pthread_create"],
    "系统调用": ["syscall"],
}

# 关键字符串特征
STR_RULES = {
    "root路径": [b"/system/bin/su", b"/system/xbin/su", b"/sbin/su",
                  b"/su/bin", b"Superuser", b"magisk", b"busybox",
                  b"/data/adb"],
    "模拟器": [b"goldfish", b"ranchu", b"qemu", b"genymotion",
                b"vbox86", b"generic_x86", b"sdk_gphone", b"ttVM"],
    "hook框架": [b"frida", b"xposed", b"lsposed", b"substrate",
                  b"sandhook", b"yahfa", b"epic", b"pine", b"taichi",
                  b"bytehook", b"dexkit", b"lspatch"],
    "proc路径": [b"/proc/self/", b"/proc/%d/", b"/proc/net/"],
    "QSec任务": [b"RuntimeEnvCensor", b"parse_libart", b"detection_",
                  b"DlVmTask", b"QSec", b"FEKit"],
    "上报通道": [b"trpc.o3", b"SsoReport", b"SsoEventReport",
                  b"beacon.qq.com", b"tdid.m.qq.com"],
}


def main():
    files = sorted(f for f in os.listdir(LIB) if f.endswith(".so"))
    print("共 %d 个 .so\n" % len(files))

    rows = []
    for name in files:
        p = os.path.join(LIB, name)
        try:
            e = ELF(p)
        except Exception:
            continue

        # 导入符号（value==0 的 FUNC）
        imported = set()
        for s in e.dynsym:
            if s["type"] == 2 and s["name"] and s["value"] == 0:
                imported.add(s["name"])
        blob = e.d
        funcs = [s for s in e.dynsym if s["type"] == 2 and s["name"]]

        # 能力打分
        caps = {}
        for cat, syms in IMPORT_RULES.items():
            hit = [x for x in syms if x in imported]
            if hit:
                caps[cat] = hit

        # 字符串特征
        strhits = {}
        for cat, pats in STR_RULES.items():
            c = 0
            for pat in pats:
                c += blob.count(pat)
            if c:
                strhits[cat] = c

        if not caps and not strhits:
            continue

        score = len(caps) * 2 + len(strhits)
        rows.append((score, name, len(e.d), len(funcs), caps, strhits))

    rows.sort(reverse=True)

    for score, name, size, nfunc, caps, strhits in rows:
        print("=" * 78)
        print("%s   %.2f MB   %d FUNC   检测强度=%d" %
              (name, size / 1048576, nfunc, score))
        print("=" * 78)
        for cat, hit in caps.items():
            print("  [%-10s] 导入: %s" % (cat, ", ".join(hit[:8])))
        for cat, c in strhits.items():
            print("  [%-10s] 字符串 ×%d" % (cat, c))
        print()


if __name__ == "__main__":
    main()
