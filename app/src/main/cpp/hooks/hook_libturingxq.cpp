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

namespace hook_libturingxq {

typedef long (*real_syscall_t)(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
static real_syscall_t original_syscall = nullptr;
static real_syscall_t original_real_syscall = nullptr;
static char* (*real_xq_strstr_ptr)(const char*, const char*) = nullptr;

static long hooked_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

static long hooked_real_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6) {
    return hook_libc::fake_syscall(number, a1, a2, a3, a4, a5, a6);
}

static char* fake_xq_strstr(const char* haystack, const char* needle) {
    SAFE_BYTEHOOK_SCOPE();
    char* result = real_xq_strstr_ptr ? real_xq_strstr_ptr(haystack, needle) : BYTEHOOK_CALL_PREV(fake_xq_strstr, haystack, needle);
    if (result && needle) {
        const char* sensitive[] = {
            "lsposed", "xposed", "riru", "zygisk", "magisk", "frida", "KSU", "ksu", "apatch", "shamiko",
            "dexkit", "libdexkit", "flatbuffers", "sandhook", "yahfa", "epic", "pine", "taichi", "liblspd",
            "qqbypass", "xalsace", "libnative-bypass", "libbytehook", "bytehook", "trampoline",
            "qauxv", "io.github.qauxv", "libqauxv", "cc.ioctl", "qnotified",
            "lspatch", "org.lsposed.lspatch", "moe.ono", "ono_", "lzlnb", "libcnm", "cnm0", "liball-jni",
            "sesearchcache",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
            "com.shuame.rootgenius", "com.applisto.appcloner",
            nullptr
        };
        for (int i = 0; sensitive[i]; i++) {
            if (strcasecmp(needle, sensitive[i]) == 0 || strstr(needle, sensitive[i])) {
                LOGD("libturingxq: Blocked strstr match: %s", needle);
                return nullptr;
            }
        }
    }
    return result;
}

void install_hooks() {
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
}

} // namespace hook_libturingxq
