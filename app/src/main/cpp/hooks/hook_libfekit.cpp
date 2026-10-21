#include "hook_libfekit.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include "../utils/safe_bytehook.h"
#include <bytehook.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <link.h>
#include <atomic>
#include <cstdlib>
#include <algorithm>

namespace hook_libfekit {

static char* (*real_fekit_strstr_ptr)(const char*, const char*) = nullptr;

/**
 * libfekit.so 的检测函数符号被剥离，无法直接 hook。
 * 策略：拦截它依赖的 libc 系统调用（命令执行、字符串匹配、符号解析、文件探测）。
 */

static bool is_fekit_blocked_path(const char* pathname) {
    if (!pathname) return false;
    if (hook_libc::is_sensitive_path(pathname) || hook_libc::is_sensitive_name(pathname)) {
        return true;
    }
    const char* root_probes[] = {
        "su", "busybox", "sudo", "bdsu", "sutemp", "shuamesu", "ku.sud",
        "magisk", "kernelsu", "apatch", "root", "patch", "xposed", "lsposed",
        "cydia", "substrate", "sandhook", "topjohnwu", "kingroot", "oneclickroot",
        "daemonsu", "permmgrd", "360sguard",
        nullptr
    };
    for (int i = 0; root_probes[i]; i++) {
        if (strcasestr(pathname, root_probes[i])) {
            return true;
        }
    }
    return false;
}

// system 代理：阻止 root 检测命令
static int fake_system(const char* command) {
    SAFE_BYTEHOOK_SCOPE();

    if (command && (strstr(command, "logcat") || strstr(command, "bin.mt") ||
                    strstr(command, "mt.plus") || strstr(command, "io.github.qauxv") ||
                    strstr(command, "lspatch") || strstr(command, "moe.ono") ||
                    strstr(command, "ono") || strstr(command, "lzlnb") || strstr(command, "cnm") ||
                    strstr(command, "magisk") || strstr(command, "su") ||
                    strstr(command, "mount") || strstr(command, "/proc/mounts") ||
                    strstr(command, "which") || strstr(command, "getprop") ||
                    strstr(command, "ksu") || strstr(command, "apatch") ||
                    strstr(command, "daemonsu") || strstr(command, "permmgrd") ||
                    strstr(command, "360sguard") || strstr(command, "ps") ||
                    strstr(command, "ls /") || strstr(command, "ls -") ||
                    strstr(command, "cat /proc"))) {
        LOGI("Blocked system command: %s", command);
        return 0;
    }
    return BYTEHOOK_CALL_PREV(fake_system, command);
}

// popen 代理：阻止管道命令检测
static FILE* fake_popen(const char* command, const char* type) {
    SAFE_BYTEHOOK_SCOPE();

    if (command) {
        if (strstr(command, "mountinfo") || strstr(command, "/proc/self/mountinfo")) {
            LOGI("Redirected popen mountinfo: %s", command);
            return hook_libc::build_filtered_mountinfo();
        }
        if (strstr(command, "mount") || strstr(command, "/proc/mounts")) {
            LOGI("Redirected popen mount: %s", command);
            return hook_libc::build_filtered_mounts();
        }
        if (strstr(command, "logcat") || strstr(command, "bin.mt") ||
            strstr(command, "mt.plus") || strstr(command, "io.github.qauxv") ||
            strstr(command, "lspatch") || strstr(command, "moe.ono") ||
            strstr(command, "ono") || strstr(command, "lzlnb") || strstr(command, "cnm") ||
            strstr(command, "magisk") || strstr(command, "su") ||
            strstr(command, "which") || strstr(command, "getprop") ||
            strstr(command, "ksu") || strstr(command, "apatch") ||
            strstr(command, "/data/adb") || strstr(command, "daemonsu") ||
            strstr(command, "permmgrd") || strstr(command, "360sguard") ||
            strstr(command, "grep") || strstr(command, "ps") ||
            strstr(command, "ls /") || strstr(command, "ls -") ||
            strstr(command, "cat /proc")) {
            LOGI("Blocked popen command: %s", command);
            return tmpfile();
        }
    }
    return BYTEHOOK_CALL_PREV(fake_popen, command, type);
}

// strstr 代理：仅拦截 libfekit.so 对敏感关键字的匹配
static char* fake_strstr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();

    char* result = real_fekit_strstr_ptr ? real_fekit_strstr_ptr(haystack, needle) : BYTEHOOK_CALL_PREV(fake_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "KSU", "ksu", "apatch", "shamiko",
            "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa", "epic", "pine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "bin.mt", "mt.plus", "top.nkbe.npatch", "npatch", "singleneuron", "bytebuddy",
            "nep.timeline", "me.ketal", "me.hd", "xyz.nextalone", "top.linl",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono", "lzlnb", "cnm", "libcnm", "liball-jni",
            "sesearchcache",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            "RuntimeEnvCensor", "parse_libart", "detection_libfekit_file",
            "VMStack_getThreadStackTrace", "trpc.o3.report.Report.SsoReport",
            nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

// access / faccessat 代理：彻底封死 FEKit RuntimeEnvCensorTask 22 个前缀扫描 root/busybox/su 探测
static int fake_fekit_access(const char* pathname, int mode) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked access: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_access, pathname, mode);
}

static int fake_fekit_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked faccessat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_faccessat, dirfd, pathname, mode, flags);
}

// stat / lstat 代理：阻断 FEKit 的 inode/size 扫描
static int fake_fekit_stat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked stat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_stat, pathname, statbuf);
}

static int fake_fekit_lstat(const char* pathname, struct stat* statbuf) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked lstat: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_lstat, pathname, statbuf);
}

// open / fopen 代理：阻断 FEKit 直接打开敏感文件
static int fake_fekit_open(const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked open: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_open, pathname, flags, mode);
}

static FILE* fake_fekit_fopen(const char* pathname, const char* mode) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return nullptr;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked fopen: %s", pathname);
        errno = ENOENT;
        return nullptr;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_fopen, pathname, mode);
}

// opendir 代理：阻断 FEKit 遍历敏感目录
static DIR* fake_fekit_opendir(const char* name) {
    SAFE_BYTEHOOK_SCOPE();
    if (!name) return nullptr;
    if (is_fekit_blocked_path(name)) {
        LOGD("FEKit blocked opendir: %s", name);
        errno = ENOENT;
        return nullptr;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_opendir, name);
}

// readlink 代理：阻断 FEKit 解析软链接
static ssize_t fake_fekit_readlink(const char* pathname, char* buf, size_t bufsiz) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked readlink: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_readlink, pathname, buf, bufsiz);
}

#if defined(__aarch64__)
// Universal ARM64 Proximity Trampoline (34 instructions + 8 bytes literal pool = 144 bytes)
static const uint32_t TRAMPOLINE_TEMPLATE[] = {
    0xd10383ff, // sub sp, sp, #0xe0
    0xa90d7bfd, // stp x29, x30, [sp, #0xd0]
    0xa9010be1, // stp x1, x2, [sp, #0x10]
    0xa90213e3, // stp x3, x4, [sp, #0x20]
    0xa9031be5, // stp x5, x6, [sp, #0x30]
    0xa90423e7, // stp x7, x8, [sp, #0x40]
    0xa9052be9, // stp x9, x10, [sp, #0x50]
    0xa90633eb, // stp x11, x12, [sp, #0x60]
    0xa9073bed, // stp x13, x14, [sp, #0x70]
    0xa90843ef, // stp x15, x16, [sp, #0x80]
    0xa9094bf1, // stp x17, x18, [sp, #0x90]
    0x6d0a07e0, // stp d0, d1, [sp, #0xa0]
    0x6d0b0fe2, // stp d2, d3, [sp, #0xb0]
    0x6d0c17e4, // stp d4, d5, [sp, #0xc0]
    0xaa0803e6, // mov x6, x8
    0xaa1e03e7, // mov x7, x30
    0x58000250, // ldr x16, [pc, #72] (loads literal pool at offset 0x88)
    0xd63f0200, // blr x16
    0x6d4c17e4, // ldp d4, d5, [sp, #0xc0]
    0x6d4b0fe2, // ldp d2, d3, [sp, #0xb0]
    0x6d4a07e0, // ldp d0, d1, [sp, #0xa0]
    0xa9494bf1, // ldp x17, x18, [sp, #0x90]
    0xa94843ef, // ldp x15, x16, [sp, #0x80]
    0xa9473bed, // ldp x13, x14, [sp, #0x70]
    0xa94633eb, // ldp x11, x12, [sp, #0x60]
    0xa9452be9, // ldp x9, x10, [sp, #0x50]
    0xa94423e7, // ldp x7, x8, [sp, #0x40]
    0xa9431be5, // ldp x5, x6, [sp, #0x30]
    0xa94213e3, // ldp x3, x4, [sp, #0x20]
    0xa9410be1, // ldp x1, x2, [sp, #0x10]
    0xa94d7bfd, // ldp x29, x30, [sp, #0xd0]
    0x910383ff, // add sp, sp, #0xe0
    0xd65f03c0, // ret
    0xd503201f  // nop (padding for 8-byte alignment)
    // Followed by uint64_t target_func_ptr at offset 0x88 (136 bytes)
};

extern "C" long c_fekit_syscall_handler(long a0, long a1, long a2, long a3, long a4, long a5, long syscall_num, void* caller_pc) {
    // Syscall 56: openat(int dirfd, const char *pathname, int flags, mode_t mode)
    if (syscall_num == 56 || syscall_num == 437) {
        const char* path = (const char*)a1;
        if (path) {
            if (is_fekit_blocked_path(path)) {
                audit_native_probe("FEKit", "openat_blocked", path);
                LOGD("FEKit inline syscall openat blocked: %s (caller=%p)", path, caller_pc);
                return -ENOENT;
            }
            if (strstr(path, "smaps")) {
                FILE* fake = hook_libc::build_filtered_smaps();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_smaps", "redirected to clean smaps");
                    LOGI("FEKit inline syscall openat smaps redirected: %s -> fd %d", path, fd);
                    return fd;
                }
            } else if (strcmp(path, "/proc/self/maps") == 0 || (strstr(path, "/proc/") && strstr(path, "/maps"))) {
                FILE* fake = hook_libc::build_filtered_maps();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_maps", "redirected to clean maps");
                    LOGI("FEKit inline syscall openat maps redirected: %s -> fd %d", path, fd);
                    return fd;
                }
            } else if (strstr(path, "mountinfo")) {
                FILE* fake = hook_libc::build_filtered_mountinfo();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_mountinfo", "redirected to clean mountinfo");
                    return fd;
                }
            } else if (strstr(path, "mounts")) {
                FILE* fake = hook_libc::build_filtered_mounts();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_mounts", "redirected to clean mounts");
                    return fd;
                }
            } else if (strstr(path, "/status")) {
                FILE* fake = hook_libc::build_filtered_status();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_status", "redirected to clean status");
                    return fd;
                }
            } else if (strstr(path, "/wchan")) {
                FILE* fake = hook_libc::build_filtered_wchan();
                if (fake) {
                    int fd = dup(fileno(fake));
                    fclose(fake);
                    audit_native_probe("FEKit", "openat_wchan", "redirected to clean wchan");
                    return fd;
                }
            }
        }
    }
    // Syscall 79: newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
    else if (syscall_num == 79) {
        const char* path = (const char*)a1;
        if (path && is_fekit_blocked_path(path)) {
            audit_native_probe("FEKit", "newfstatat_blocked", path);
            LOGD("FEKit inline syscall newfstatat blocked: %s (caller=%p)", path, caller_pc);
            return -ENOENT;
        }
    }
    // Syscall 78: readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
    else if (syscall_num == 78) {
        const char* path = (const char*)a1;
        if (path && is_fekit_blocked_path(path)) {
            audit_native_probe("FEKit", "readlinkat_blocked", path);
            LOGD("FEKit inline syscall readlinkat blocked: %s (caller=%p)", path, caller_pc);
            return -ENOENT;
        }
    }
    // Syscall 48/439: faccessat
    else if (syscall_num == 48 || syscall_num == 439) {
        const char* path = (const char*)a1;
        if (path && is_fekit_blocked_path(path)) {
            audit_native_probe("FEKit", "faccessat_blocked", path);
            LOGD("FEKit inline syscall faccessat blocked: %s (caller=%p)", path, caller_pc);
            return -ENOENT;
        }
    }
    // Syscall 43: statfs
    else if (syscall_num == 43) {
        const char* path = (const char*)a0;
        if (path && is_fekit_blocked_path(path)) {
            audit_native_probe("FEKit", "statfs_blocked", path);
            LOGD("FEKit inline syscall statfs blocked: %s (caller=%p)", path, caller_pc);
            return -ENOENT;
        }
    }

    errno = 0;
    long ret = hook_libc::fake_syscall_ex(syscall_num, (void*)a0, (void*)a1, (void*)a2, (void*)a3, (void*)a4, (void*)a5, caller_pc);
    if (ret < 0) {
        int err = errno != 0 ? errno : ENOENT;
        return (long)(-err);
    }
    return ret;
}

struct ElfSearchInfo {
    const char* target_name;
    uintptr_t base;
    uintptr_t text_vaddr;
    size_t text_size;
};

static int find_fekit_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    ElfSearchInfo* search = (ElfSearchInfo*)data;
    if (!info || !info->dlpi_name) return 0;
    if (strstr(info->dlpi_name, search->target_name)) {
        search->base = info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr)& ph = info->dlpi_phdr[i];
            if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
                search->text_vaddr = ph.p_vaddr;
                search->text_size = ph.p_memsz;
                break;
            }
        }
        return 1;
    }
    return 0;
}
#endif

static std::atomic<bool> s_fekit_patched{false};

void patch_libfekit_in_memory() {
#if defined(__aarch64__)
    if (s_fekit_patched.load(std::memory_order_relaxed)) return;

    ElfSearchInfo search{"libfekit.so", 0, 0, 0};
    dl_iterate_phdr(find_fekit_callback, &search);

    // Fallback: search /proc/self/maps if dl_iterate_phdr didn't find base
    if (!search.base) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libfekit.so") && strstr(line, "r-xp")) {
                    uintptr_t start = 0, end = 0;
                    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                        search.base = start;
                        search.text_vaddr = 0;
                        search.text_size = end - start;
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    if (!search.base || !search.text_size) {
        return;
    }

    uintptr_t text_start = search.base + search.text_vaddr;
    uintptr_t text_end = text_start + search.text_size;

    // Allocate 4KB proximity trampoline page in guard gap right after libfekit.so text
    uintptr_t hint = search.base + ((search.text_size + 4095) & ~4095);
    void* tramp_page = mmap((void*)hint, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (tramp_page == MAP_FAILED) {
        LOGE("libfekit.so: Failed to allocate proximity trampoline page at %p (errno=%d)", (void*)hint, errno);
        return;
    }

    hook_libc::register_trampoline_range((uintptr_t)tramp_page, (uintptr_t)tramp_page + 4096);

    uint8_t* tp = (uint8_t*)tramp_page;
    memcpy(tp, TRAMPOLINE_TEMPLATE, sizeof(TRAMPOLINE_TEMPLATE));
    uint64_t target_fn = (uint64_t)&c_fekit_syscall_handler;
    memcpy(tp + 136, &target_fn, sizeof(target_fn));

    mprotect(tramp_page, 4096, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)tramp_page, (char*)tramp_page + 4096);

    // Scan text segment for inline svc #0 instructions
    size_t patched_count = 0;
    uint32_t* p = (uint32_t*)text_start;
    uint32_t* pend = (uint32_t*)(text_end - 4);

    for (; p <= pend; p++) {
        if (*p == 0xd4000001) { // svc #0
            uint32_t prev = *(p - 1);
            bool is_valid = false;
            uint32_t sys_num = 0;
            if ((prev & 0xffe0001f) == 0xd2800008) { // mov x8, #imm
                sys_num = (prev >> 5) & 0xffff;
                is_valid = true;
            } else if ((prev & 0xffe0001f) == 0x52800008) { // mov w8, #imm
                sys_num = (prev >> 5) & 0xffff;
                is_valid = true;
            }
            if (is_valid) {
                intptr_t delta = (intptr_t)tramp_page - (intptr_t)p;
                if (delta >= -0x8000000 && delta <= 0x7fffffc) {
                    uint32_t imm26 = (uint32_t)((delta >> 2) & 0x03ffffff);
                    uint32_t bl_inst = 0x94000000 | imm26;
                    uintptr_t page_addr = ((uintptr_t)p) & ~4095;
                    mprotect((void*)page_addr, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
                    *p = bl_inst;
                    __builtin___clear_cache((char*)p, (char*)(p + 1));
                    mprotect((void*)page_addr, 4096 * 2, PROT_READ | PROT_EXEC);
                    patched_count++;
                    (void)sys_num;
                    LOGI("libfekit.so: Patched inline svc #0 (sys=%u) at %p (offset 0x%lx) -> bl trampoline",
                         sys_num, p, (unsigned long)((uintptr_t)p - search.base));
                }
            }
        }
    }

    s_fekit_patched.store(true, std::memory_order_relaxed);
    (void)patched_count;
    LOGI("libfekit.so inline syscall patching complete: %zu stubs redirected to proximity trampoline at %p",
         patched_count, tramp_page);
#endif
}

void install_hooks() {
    patch_libfekit_in_memory();

    // 命令执行类：全局拦截（调用频率低，安全）
    TRACK_NATIVE_HOOK_ALL(nullptr, "system", (void*)fake_system, nullptr, nullptr);
    TRACK_NATIVE_HOOK_ALL(nullptr, "popen", (void*)fake_popen, nullptr, nullptr);

    // 字符串匹配：仅对 libfekit.so 作为调用方拦截，避免全局性能损耗
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "strstr", (void*)fake_strstr, nullptr, nullptr);

    // 文件访问与探测类：针对 libfekit.so 拦截所有探测 API
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "access", (void*)fake_fekit_access, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "faccessat", (void*)fake_fekit_faccessat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "stat", (void*)fake_fekit_stat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "lstat", (void*)fake_fekit_lstat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "open", (void*)fake_fekit_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "fopen", (void*)fake_fekit_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "opendir", (void*)fake_fekit_opendir, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "readlink", (void*)fake_fekit_readlink, nullptr, nullptr);
}

} // namespace hook_libfekit
