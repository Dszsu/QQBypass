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

void install_hooks() {
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
