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
    return hook_libc::is_sensitive_path(pathname) ||
           hook_libc::is_sensitive_name(pathname) ||
           hook_libc::is_root_proc_path(pathname) ||
           hook_libc::is_sensitive_proc_fd(pathname);
}

static bool is_fekit_blocked_path(int dirfd, const char* pathname) {
    if (!pathname) return false;
    return is_fekit_blocked_path(pathname) ||
           hook_libc::is_sensitive_proc_fd(dirfd, pathname);
}

// system 代理：阻止 root 检测命令
static int fake_system(const char* command) {
    SAFE_BYTEHOOK_SCOPE();

    if (command && (strstr(command, "logcat") || strstr(command, "bin.mt") ||
                    strstr(command, "mt.plus") || strstr(command, "io.github.qauxv") ||
                    strstr(command, "lspatch") || strstr(command, "moe.ono") ||
                    strstr(command, "ono_") || strstr(command, "lzlnb") || strstr(command, "libcnm") || strstr(command, "cnm0") ||
                    strstr(command, "magisk") || (strstr(command, "/su") || strstr(command, "su ") || strcmp(command, "su") == 0) ||
                    strstr(command, "mount") || strstr(command, "/proc/mounts") ||
                    strstr(command, "which") || strstr(command, "getprop") ||
                    (strstr(command, "kernelsu") || strstr(command, "ksud") || strstr(command, "/ksu") || strstr(command, "ksu ")) ||
                    (strstr(command, "libapatch") || strstr(command, "/apatch") || strstr(command, "apatch ") || strstr(command, "me.bmax.apatch")) ||
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
            strstr(command, "ono_") || strstr(command, "lzlnb") || strstr(command, "libcnm") || strstr(command, "cnm0") ||
            strstr(command, "magisk") || (strstr(command, "/su") || strstr(command, "su ") || strcmp(command, "su") == 0) ||
            strstr(command, "which") || strstr(command, "getprop") ||
            (strstr(command, "kernelsu") || strstr(command, "ksud") || strstr(command, "/ksu") || strstr(command, "ksu ")) ||
            (strstr(command, "libapatch") || strstr(command, "/apatch") || strstr(command, "apatch ") || strstr(command, "me.bmax.apatch")) ||
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
            "lsposed", "xposed", "riru", "zygisk", "magisk", ".magisk", "frida", "kernelsu", "ksud", "/ksu/", "libapatch", "me.bmax.apatch", "/apatch/", "shamiko",
            "dexkit", "libdexkit", "sandhook", "yahfa", "libepic", "libpine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "bin.mt", "mt.plus", "top.nkbe.npatch", "npatch", "singleneuron", "bytebuddy",
            "nep.timeline", "me.ketal", "me.hd", "xyz.nextalone", "top.linl",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono_", "lzlnb", "libcnm", "cnm0", "liball-jni",
            "sesearchcache",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            "RuntimeEnvCensor", "parse_libart", "detection_libfekit_file",
            "busybox", "substrate", "cydia", "sutemp", "daemonsu", "permmgrd", "360sguard",
            "/data/adb",
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

// strcasestr 代理：拦截 libfekit.so 对敏感关键字的忽略大小写匹配
static char* fake_strcasestr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = BYTEHOOK_CALL_PREV(fake_strcasestr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", ".magisk", "frida", "kernelsu", "ksud", "/ksu/", "libapatch", "me.bmax.apatch", "/apatch/", "shamiko",
            "dexkit", "libdexkit", "sandhook", "yahfa", "libepic", "libpine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "bin.mt", "mt.plus", "top.nkbe.npatch", "npatch", "singleneuron", "bytebuddy",
            "nep.timeline", "me.ketal", "me.hd", "xyz.nextalone", "top.linl",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono_", "lzlnb", "libcnm", "cnm0", "liball-jni",
            "sesearchcache",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            "RuntimeEnvCensor", "parse_libart", "detection_libfekit_file",
            "busybox", "substrate", "cydia", "sutemp", "daemonsu", "permmgrd", "360sguard",
            "/data/adb",
            nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("Blocked strcasestr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

// FEKit 专有虚拟/过滤文件流重定向助手
static FILE* get_fekit_redirected_stream(const char* pathname) {
    if (!pathname) return nullptr;
    if (hook_libc::is_root_proc_path(pathname)) {
        return nullptr;
    }
    if (hook_libc::is_proc_cmdline_path(pathname)) {
        audit_native_probe("FEKit", "file_cmdline", "redirected to clean cmdline");
        LOGI("FEKit redirected cmdline: %s", pathname);
        return hook_libc::build_virtual_cmdline(pathname);
    }
    if (strstr(pathname, "smaps")) {
        audit_native_probe("FEKit", "file_smaps", "redirected to clean smaps");
        LOGI("FEKit redirected smaps: %s", pathname);
        return hook_libc::build_filtered_smaps();
    }
    if (strcmp(pathname, "/proc/self/maps") == 0 || (strstr(pathname, "/proc/") && strstr(pathname, "/maps"))) {
        audit_native_probe("FEKit", "file_maps", "redirected to clean maps");
        LOGI("FEKit redirected maps: %s", pathname);
        return hook_libc::build_filtered_maps();
    }
    if (strstr(pathname, "mountinfo")) {
        audit_native_probe("FEKit", "file_mountinfo", "redirected to clean mountinfo");
        LOGI("FEKit redirected mountinfo: %s", pathname);
        return hook_libc::build_filtered_mountinfo();
    }
    if (strstr(pathname, "mounts")) {
        audit_native_probe("FEKit", "file_mounts", "redirected to clean mounts");
        LOGI("FEKit redirected mounts: %s", pathname);
        return hook_libc::build_filtered_mounts();
    }
    if (strstr(pathname, "net/unix")) {
        audit_native_probe("FEKit", "file_net_unix", "redirected to clean net_unix");
        LOGI("FEKit redirected net/unix: %s", pathname);
        return hook_libc::build_filtered_net_unix();
    }
    if (strstr(pathname, "net/tcp")) {
        audit_native_probe("FEKit", "file_net_tcp", "redirected to clean net_tcp");
        LOGI("FEKit redirected net/tcp: %s", pathname);
        return hook_libc::build_filtered_net_tcp(strstr(pathname, "tcp6") != nullptr);
    }
    if (strstr(pathname, "attr/current")) {
        audit_native_probe("FEKit", "file_attr_current", "redirected to clean selinux_attr");
        LOGI("FEKit redirected attr/current: %s", pathname);
        return hook_libc::build_filtered_selinux_attr();
    }
    if (strstr(pathname, "cgroup")) {
        audit_native_probe("FEKit", "file_cgroup", "redirected to clean cgroup");
        LOGI("FEKit redirected cgroup: %s", pathname);
        return hook_libc::build_filtered_cgroup();
    }
    if (strstr(pathname, "/status") && strstr(pathname, "/proc/")) {
        audit_native_probe("FEKit", "file_status", "redirected to clean status");
        LOGI("FEKit redirected status: %s", pathname);
        return hook_libc::build_filtered_status();
    }
    if (strstr(pathname, "/wchan") && strstr(pathname, "/proc/")) {
        audit_native_probe("FEKit", "file_wchan", "redirected to clean wchan");
        LOGI("FEKit redirected wchan: %s", pathname);
        return hook_libc::build_filtered_wchan();
    }
    return nullptr;
}

static int get_fekit_redirected_fd(const char* pathname) {
    FILE* fp = get_fekit_redirected_stream(pathname);
    if (!fp) return -1;
    int fd = dup(fileno(fp));
    fclose(fp);
    return fd;
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
    if (hook_libc::is_proc_cmdline_path(pathname)) {
        return 0;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_access, pathname, mode);
}

static int fake_fekit_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(dirfd, pathname)) {
        LOGD("FEKit blocked faccessat: %s (dirfd=%d)", pathname, dirfd);
        errno = ENOENT;
        return -1;
    }
    if (hook_libc::is_proc_cmdline_path(pathname)) {
        return 0;
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
    if (hook_libc::handle_virtual_stat(pathname, statbuf)) {
        return 0;
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
    if (hook_libc::handle_virtual_stat(pathname, statbuf)) {
        return 0;
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_lstat, pathname, statbuf);
}

// open / fopen / openat 代理：彻底重定向/阻断 FEKit 访问 maps/mountinfo/sensitive 文件
static int fake_fekit_open(const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked open: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    int fake_fd = get_fekit_redirected_fd(pathname);
    if (fake_fd >= 0) return fake_fd;

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_open, pathname, flags, mode);
}

static int fake_fekit_openat(int dirfd, const char* pathname, int flags, ...) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(dirfd, pathname)) {
        LOGD("FEKit blocked openat: %s (dirfd=%d)", pathname, dirfd);
        errno = ENOENT;
        return -1;
    }
    int fake_fd = get_fekit_redirected_fd(pathname);
    if (fake_fd >= 0) return fake_fd;

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    return BYTEHOOK_CALL_PREV(fake_fekit_openat, dirfd, pathname, flags, mode);
}

static FILE* fake_fekit_fopen(const char* pathname, const char* mode) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return nullptr;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked fopen: %s", pathname);
        errno = ENOENT;
        return nullptr;
    }
    FILE* fake_fp = get_fekit_redirected_stream(pathname);
    if (fake_fp) return fake_fp;

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

// readlink / readlinkat 代理：阻断 FEKit 解析软链接
static ssize_t fake_fekit_readlink(const char* pathname, char* buf, size_t bufsiz) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(pathname)) {
        LOGD("FEKit blocked readlink: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = BYTEHOOK_CALL_PREV(fake_fekit_readlink, pathname, buf, bufsiz);
    if (ret > 0 && buf) {
        buf[ret < (ssize_t)bufsiz ? ret : bufsiz - 1] = '\0';
        if (hook_libc::is_sensitive_link_target(buf)) {
            LOGI("FEKit readlink sensitive target blocked: %s -> %s", pathname, buf);
            buf[0] = '\0';
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}

static ssize_t fake_fekit_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
    SAFE_BYTEHOOK_SCOPE();
    if (!pathname) return -1;
    if (is_fekit_blocked_path(dirfd, pathname)) {
        LOGD("FEKit blocked readlinkat: %s (dirfd=%d)", pathname, dirfd);
        errno = ENOENT;
        return -1;
    }
    ssize_t ret = BYTEHOOK_CALL_PREV(fake_fekit_readlinkat, dirfd, pathname, buf, bufsiz);
    if (ret > 0 && buf) {
        buf[ret < (ssize_t)bufsiz ? ret : bufsiz - 1] = '\0';
        if (hook_libc::is_sensitive_link_target(buf)) {
            LOGI("FEKit readlinkat sensitive target blocked: %s -> %s", pathname, buf);
            buf[0] = '\0';
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}

#if defined(__aarch64__)
// Universal ARM64 Proximity Trampoline (34 instructions + 8 bytes literal pool = 144 bytes)
[[maybe_unused]] static const uint32_t TRAMPOLINE_TEMPLATE[] = {
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
        int dirfd = (int)a0;
        const char* path = (const char*)a1;
        if (path) {
            if (is_fekit_blocked_path(dirfd, path)) {
                audit_native_probe("FEKit", "openat_blocked", path);
                LOGD("FEKit inline syscall openat blocked: %s (dirfd=%d, caller=%p)", path, dirfd, caller_pc);
                return -ENOENT;
            }
            int fake_fd = get_fekit_redirected_fd(path);
            if (fake_fd >= 0) {
                LOGI("FEKit inline syscall openat redirected: %s -> fd %d", path, fake_fd);
                return fake_fd;
            }
        }
    }
    // Syscall 79: newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
    else if (syscall_num == 79) {
        int dirfd = (int)a0;
        const char* path = (const char*)a1;
        if (path) {
            if (is_fekit_blocked_path(dirfd, path)) {
                audit_native_probe("FEKit", "newfstatat_blocked", path);
                LOGD("FEKit inline syscall newfstatat blocked: %s (dirfd=%d, caller=%p)", path, dirfd, caller_pc);
                return -ENOENT;
            }
            if (hook_libc::handle_virtual_stat(path, (struct stat*)a2)) {
                return 0;
            }
        }
    }
    // Syscall 78: readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
    else if (syscall_num == 78) {
        int dirfd = (int)a0;
        const char* path = (const char*)a1;
        if (path && is_fekit_blocked_path(dirfd, path)) {
            audit_native_probe("FEKit", "readlinkat_blocked", path);
            LOGD("FEKit inline syscall readlinkat blocked: %s (dirfd=%d, caller=%p)", path, dirfd, caller_pc);
            return -ENOENT;
        }
    }
    // Syscall 48/439: faccessat
    else if (syscall_num == 48 || syscall_num == 439) {
        int dirfd = (int)a0;
        const char* path = (const char*)a1;
        if (path) {
            if (is_fekit_blocked_path(dirfd, path)) {
                audit_native_probe("FEKit", "faccessat_blocked", path);
                LOGD("FEKit inline syscall faccessat blocked: %s (dirfd=%d, caller=%p)", path, dirfd, caller_pc);
                return -ENOENT;
            }
            if (hook_libc::is_proc_cmdline_path(path)) {
                return 0;
            }
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

[[maybe_unused]] static int find_fekit_callback(struct dl_phdr_info* info, size_t size, void* data) {
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
    // No-op: Do NOT patch .text segment or inject proximity trampolines into libfekit.so.
    // In-memory code patching triggers libfekit's internal code hash integrity checks,
    // overwrites .rodata via MAP_FIXED, and fragments /proc/self/maps into 27 separate VMAs,
    // which results in security sign verification failures and server-side kick w21.
    if (s_fekit_patched.exchange(true)) return;
    LOGI("libfekit.so: Preserving authentic text segment & code integrity (in-memory patching disabled)");
}

void install_hooks() {
    patch_libfekit_in_memory();

    // 命令执行类：全局拦截（调用频率低，安全）
    TRACK_NATIVE_HOOK_ALL(nullptr, "system", (void*)fake_system, nullptr, nullptr);
    TRACK_NATIVE_HOOK_ALL(nullptr, "popen", (void*)fake_popen, nullptr, nullptr);

    // 字符串匹配：仅对 libfekit.so 作为调用方拦截，避免全局性能损耗
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "strstr", (void*)fake_strstr, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "strcasestr", (void*)fake_strcasestr, nullptr, nullptr);

    // 文件访问与探测类：针对 libfekit.so 拦截所有探测 API
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "access", (void*)fake_fekit_access, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "faccessat", (void*)fake_fekit_faccessat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "stat", (void*)fake_fekit_stat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "lstat", (void*)fake_fekit_lstat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "open", (void*)fake_fekit_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "open64", (void*)fake_fekit_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "openat", (void*)fake_fekit_openat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "openat64", (void*)fake_fekit_openat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "fopen", (void*)fake_fekit_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "fopen64", (void*)fake_fekit_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "opendir", (void*)fake_fekit_opendir, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "readlink", (void*)fake_fekit_readlink, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libfekit.so", nullptr, "readlinkat", (void*)fake_fekit_readlinkat, nullptr, nullptr);
}

} // namespace hook_libfekit
