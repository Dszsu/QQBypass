#include "hook_libturingxq.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include "../utils/safe_bytehook.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <stdarg.h>
#include <atomic>

namespace hook_libturingxq {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_syscall = nullptr;
static real_syscall_t original_real_syscall = nullptr;
static char* (*real_xq_strstr_ptr)(const char*, const char*) = nullptr;
static std::atomic<bool> s_turingxq_patched{false};

static long hooked_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

static long hooked_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

static char* fake_xq_strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return nullptr;
    const char* result = real_xq_strstr_ptr ? real_xq_strstr_ptr(haystack, needle) : strstr(haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "kernelsu", "ksud", "/ksu/", "libapatch", "me.bmax.apatch", "/apatch/", "shamiko",
            "dexkit", "libdexkit", "sandhook", "yahfa", "libepic", "libpine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono_", "lzlnb", "libcnm", "cnm0", "liball-jni",
            "sesearchcache",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            "debugfs", "fclnicsd", "jshenoea", "mountify", "tricky_store", "metamodule",
            nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("libturingxq: Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return (char*)result;
}

static FILE* xq_fake_fopen(const char* pathname, const char* mode) {
    if (pathname) {
        if (strstr(pathname, "mounts") != nullptr) {
            LOGI("libturingxq: fopen mounts redirected to filtered mounts");
            return hook_libc::build_filtered_mounts();
        }
        if (strstr(pathname, "mountinfo") != nullptr) {
            LOGI("libturingxq: fopen mountinfo redirected to filtered mountinfo");
            return hook_libc::build_filtered_mountinfo();
        }
        if (strstr(pathname, "smaps") != nullptr) {
            LOGI("libturingxq: fopen smaps redirected to filtered smaps");
            return hook_libc::build_filtered_smaps();
        }
        if (strstr(pathname, "maps") != nullptr) {
            LOGI("libturingxq: fopen maps redirected to filtered maps");
            return hook_libc::build_filtered_maps();
        }
        if (strstr(pathname, "attr/current") != nullptr) {
            return hook_libc::build_filtered_selinux_attr();
        }
        if (strstr(pathname, "cgroup") != nullptr) {
            return hook_libc::build_filtered_cgroup();
        }
        if (strstr(pathname, "status") != nullptr) {
            return hook_libc::build_filtered_status();
        }
        if (strstr(pathname, "cmdline") != nullptr || hook_libc::is_proc_cmdline_path(pathname)) {
            LOGI("libturingxq: fopen cmdline redirected to virtual cmdline");
            return hook_libc::build_virtual_cmdline(pathname);
        }
        if (hook_libc::is_sensitive_path(pathname)) {
            LOGD("libturingxq: fopen blocked sensitive path %s", pathname);
            errno = ENOENT;
            return nullptr;
        }
    }
    return fopen(pathname, mode);
}

static int xq_fake_open(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (pathname) {
        if (strstr(pathname, "mounts") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_mounts());
        }
        if (strstr(pathname, "mountinfo") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_mountinfo());
        }
        if (strstr(pathname, "smaps") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_smaps());
        }
        if (strstr(pathname, "maps") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_maps());
        }
        if (strstr(pathname, "attr/current") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_selinux_attr());
        }
        if (strstr(pathname, "cgroup") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_cgroup());
        }
        if (strstr(pathname, "status") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_status());
        }
        if (strstr(pathname, "cmdline") != nullptr || hook_libc::is_proc_cmdline_path(pathname)) {
            LOGI("libturingxq: open cmdline redirected to virtual cmdline");
            return hook_libc::open_virtual_file(hook_libc::build_virtual_cmdline(pathname));
        }
        if (hook_libc::is_sensitive_path(pathname)) {
            LOGD("libturingxq: open blocked sensitive path %s", pathname);
            errno = ENOENT;
            return -1;
        }
    }
    return open(pathname, flags, mode);
}

static int xq_fake_open_2(const char* pathname, int flags) {
    return xq_fake_open(pathname, flags, 0);
}

static int xq_fake_openat(int dirfd, const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (pathname) {
        if (strstr(pathname, "mounts") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_mounts());
        }
        if (strstr(pathname, "mountinfo") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_mountinfo());
        }
        if (strstr(pathname, "smaps") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_smaps());
        }
        if (strstr(pathname, "maps") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_maps());
        }
        if (strstr(pathname, "attr/current") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_selinux_attr());
        }
        if (strstr(pathname, "cgroup") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_cgroup());
        }
        if (strstr(pathname, "status") != nullptr) {
            return hook_libc::open_virtual_file(hook_libc::build_filtered_status());
        }
        if (strstr(pathname, "cmdline") != nullptr || hook_libc::is_proc_cmdline_path(pathname)) {
            LOGI("libturingxq: open cmdline redirected to virtual cmdline");
            return hook_libc::open_virtual_file(hook_libc::build_virtual_cmdline(pathname));
        }
        if (hook_libc::is_sensitive_path(pathname)) {
            LOGD("libturingxq: openat blocked sensitive path %s", pathname);
            errno = ENOENT;
            return -1;
        }
    }
    return openat(dirfd, pathname, flags, mode);
}

static int xq_fake_openat_2(int dirfd, const char* pathname, int flags) {
    return xq_fake_openat(dirfd, pathname, flags, 0);
}

static int xq_fake_stat(const char* pathname, struct stat* statbuf) {
    if (pathname && hook_libc::is_sensitive_path(pathname)) {
        LOGD("libturingxq: stat blocked sensitive path: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return stat(pathname, statbuf);
}

static int xq_fake_lstat(const char* pathname, struct stat* statbuf) {
    if (pathname && hook_libc::is_sensitive_path(pathname)) {
        LOGD("libturingxq: lstat blocked sensitive path: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return lstat(pathname, statbuf);
}

static int xq_fake_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    if (pathname && hook_libc::is_sensitive_path(pathname)) {
        LOGD("libturingxq: fstatat blocked sensitive path: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return fstatat(dirfd, pathname, statbuf, flags);
}

static int xq_fake_access(const char* pathname, int mode) {
    if (pathname && hook_libc::is_sensitive_path(pathname)) {
        LOGD("libturingxq: access blocked sensitive path: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return access(pathname, mode);
}

static int xq_fake_faccessat(int dirfd, const char* pathname, int mode, int flags) {
    if (pathname && hook_libc::is_sensitive_path(pathname)) {
        LOGD("libturingxq: faccessat blocked sensitive path: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return faccessat(dirfd, pathname, mode, flags);
}

static int xq_fake_statfs(const char* path, struct statfs* buf) {
    return statfs(path, buf);
}

static FILE* xq_fake_popen(const char* command, const char* type) {
    if (command && (strstr(command, "mount") || strstr(command, "su") || strstr(command, "which") || strstr(command, "getprop") || strstr(command, "ls "))) {
        LOGD("libturingxq: popen blocked: %s", command);
        errno = ENOENT;
        return nullptr;
    }
    return popen(command, type);
}

static char* xq_fake_fgets(char* s, int size, FILE* stream) {
    return fgets(s, size, stream);
}

static ssize_t xq_fake_readlink(const char* pathname, char* buf, size_t bufsiz) {
    return hook_libc::fake_readlink(pathname, buf, bufsiz);
}

static ssize_t xq_fake_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
    return hook_libc::fake_readlinkat(dirfd, pathname, buf, bufsiz);
}

void patch_libturingxq_in_memory() {
    // No-op: Do NOT patch .text segment or GOT tables of libturingxq.so.
    // In-memory code patching triggers TuringFD internal code hash/integrity checks
    // and causes VMA fragmentation in /proc/self/maps, resulting in security verification failures.
    if (s_turingxq_patched.exchange(true)) return;
    LOGI("libturingxq.so: Preserving authentic text segment & code integrity (in-memory patching disabled)");
}

void install_hooks() {
    patch_libturingxq_in_memory();

    TRACK_NATIVE_HOOK_SINGLE(
        "libturingxq.so",
        nullptr,
        "syscall",
        (void*)hooked_syscall,
        nullptr,
        (void**)&original_syscall
    );

    TRACK_NATIVE_HOOK_SINGLE(
        "libturingxq.so",
        nullptr,
        "real_syscall",
        (void*)hooked_real_syscall,
        nullptr,
        (void**)&original_real_syscall
    );

    TRACK_NATIVE_HOOK_SINGLE(
        "libturingxq.so",
        nullptr,
        "strstr",
        (void*)fake_xq_strstr,
        nullptr,
        nullptr
    );

    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "fopen", (void*)xq_fake_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "fopen64", (void*)xq_fake_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "open", (void*)xq_fake_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "open64", (void*)xq_fake_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "__open_2", (void*)xq_fake_open_2, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "openat", (void*)xq_fake_openat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "openat64", (void*)xq_fake_openat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "__openat_2", (void*)xq_fake_openat_2, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "stat", (void*)xq_fake_stat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "lstat", (void*)xq_fake_lstat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "fstatat", (void*)xq_fake_fstatat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "access", (void*)xq_fake_access, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "faccessat", (void*)xq_fake_faccessat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "statfs", (void*)xq_fake_statfs, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "popen", (void*)xq_fake_popen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "fgets", (void*)xq_fake_fgets, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "readlink", (void*)xq_fake_readlink, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingxq.so", nullptr, "readlinkat", (void*)xq_fake_readlinkat, nullptr, nullptr);
}

} // namespace hook_libturingxq
