#include "hook_libturingmfa.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include <bytehook.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>

#include "../utils/safe_bytehook.h"

namespace {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_syscall_mfa = nullptr;
static real_syscall_t original_real_syscall_mfa = nullptr;
static char* (*real_mfa_strstr_ptr)(const char*, const char*) = nullptr;

/**
 * libturingmfa.so (Turing Multi-Factor Authentication & Face ID engine)
 * 内部既有 real_syscall 汇编实现，也有对 libc.so 的 syscall@plt 调用。
 * 在人脸核身与多因子验证期间：
 * - 0x1658c: syscall 56 (__NR_openat) 扫描 /proc/self/maps，随后 fdopen 逐行匹配 Hook 特征
 * - 0x13d90: syscall 79 (__NR_newfstatat) 探测 su / magisk / ksu 等文件元数据
 * - 0x13f78: syscall 56 (__NR_openat) 扫描敏感路径
 * - 0xe8c4: syscall 56 (__NR_openat) 嗅探敏感路径及 /proc/mounts
 * - syscall 198 (socket), 206 (sendto), 207 (recvfrom): 认证数据传输
 *
 * 策略：统一通过 hook_libc::fake_syscall 进行敏感路径阻断与 maps/mounts 虚拟清洗，
 * 保证人脸认证与网络通信正常放行。
 */
static long hooked_mfa_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

static long hooked_mfa_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

/**
 * 拦截 libturingmfa.so 的 strstr 敏感关键字匹配，消除内存与模块特征检测
 */
static char* fake_mfa_strstr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = real_mfa_strstr_ptr ? real_mfa_strstr_ptr(haystack, needle) : BYTEHOOK_CALL_PREV(fake_mfa_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "kernelsu", "ksud", "/ksu/", "libapatch", "me.bmax.apatch", "/apatch/", "shamiko",
            "dexkit", "libdexkit", "sandhook", "yahfa", "libepic", "libpine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono_", "lzlnb", "libcnm", "cnm0", "liball-jni",
            "sesearchcache", "mountify", "tricky_store", "zygisksu", "metamodule",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("libturingmfa: Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

} // namespace

void install_turingmfa_hooks() {
    // 1. Hook syscall in libturingmfa.so
    TRACK_NATIVE_HOOK_SINGLE(
        "libturingmfa.so",
        nullptr,
        "syscall",
        (void*)hooked_mfa_syscall,
        nullptr,
        (void**)&original_syscall_mfa
    );

    // 2. Hook real_syscall in libturingmfa.so
    TRACK_NATIVE_HOOK_SINGLE(
        "libturingmfa.so",
        "libturingmfa.so",
        "real_syscall",
        (void*)hooked_mfa_real_syscall,
        nullptr,
        (void**)&original_real_syscall_mfa
    );

    TRACK_NATIVE_HOOK_SINGLE(
        "libturingmfa.so",
        nullptr,
        "real_syscall",
        (void*)hooked_mfa_real_syscall,
        nullptr,
        (void**)&original_real_syscall_mfa
    );

    // 3. Hook strstr in libturingmfa.so
    TRACK_NATIVE_HOOK_SINGLE(
        "libturingmfa.so",
        nullptr,
        "strstr",
        (void*)fake_mfa_strstr,
        nullptr,
        nullptr
    );

    // 4. Hook network routing and interface queries in libturingmfa.so
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "recvfrom", (void*)hook_libc::fake_recvfrom, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "if_indextoname", (void*)hook_libc::fake_if_indextoname, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "ioctl", (void*)hook_libc::fake_ioctl, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "getifaddrs", (void*)hook_libc::fake_getifaddrs, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "freeifaddrs", (void*)hook_libc::fake_freeifaddrs, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "__system_property_get", (void*)hook_libc::fake_system_property_get, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libturingmfa.so", nullptr, "__system_property_find", (void*)hook_libc::fake_system_property_find, nullptr, nullptr);
}
