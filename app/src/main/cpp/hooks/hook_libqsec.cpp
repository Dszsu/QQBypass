#include <jni.h>
#include <dlfcn.h>
#include <string.h>
#include "../utils/log.h"
#include "../utils/safe_bytehook.h"
#include "bytehook.h"
#include "hook_libc.h"

/**
 * Hook dlopen - 防止 QSec 检测 ByteHook 等 hook 框架
 */
static void* hooked_dlopen(const char* filename, int flag) {
    SAFE_BYTEHOOK_SCOPE();
    if (filename) {
        // 拦截对 hook 框架的检测
        if (strcasestr(filename, "bytehook") ||
            strcasestr(filename, "xposed") ||
            strcasestr(filename, "lsposed") ||
            strcasestr(filename, "liblspd") ||
            strcasestr(filename, "substrate") ||
            strcasestr(filename, "dexkit") ||
            strcasestr(filename, "libdexkit") ||
            strcasestr(filename, "sandhook") ||
            strcasestr(filename, "yahfa") ||
            strcasestr(filename, "epic") ||
            strcasestr(filename, "pine") ||
            strcasestr(filename, "taichi") ||
            strcasestr(filename, "qqbypass") ||
            strcasestr(filename, "xalsace") ||
            strcasestr(filename, "bin.mt") ||
            strcasestr(filename, "npatch") ||
            strcasestr(filename, "qauxv") ||
            strcasestr(filename, "bytebuddy") ||
            strcasestr(filename, "lspatch") ||
            strcasestr(filename, "liblspatch") ||
            strcasestr(filename, "moe.ono") ||
            strcasestr(filename, "ono") ||
            strcasestr(filename, "lzlnb") ||
            strcasestr(filename, "cnm") ||
            strcasestr(filename, "libcnm") ||
            strcasestr(filename, "liball-jni")) {
            LOGI("QSec dlopen blocked: %s", filename);
            return nullptr;
        }
    }
    void* prev = bytehook_get_prev_func((void*)hooked_dlopen);
    if (prev) {
        return ((void* (*)(const char*, int))prev)(filename, flag);
    }
    return dlopen(filename, flag);
}

static jboolean fake_is_debuggable() {
    return JNI_FALSE;
}

/**
 * Hook dlsym - 防止符号表扫描检测
 */
static void* hooked_dlsym(void* handle, const char* symbol) {
    SAFE_BYTEHOOK_SCOPE();
    if (symbol) {
        if (strstr(symbol, "isJavaDebuggable") ||
            strstr(symbol, "isNativeDebuggable") ||
            strstr(symbol, "isDebuggable")) {
            LOGI("QSec dlsym spoofed %s -> JNI_FALSE", symbol);
            return (void*)fake_is_debuggable;
        }
        if (strcmp(symbol, "bytehook_get_records") == 0) return (void*)fake_bytehook_get_records;
        if (strcmp(symbol, "bytehook_dump_records") == 0) return (void*)fake_bytehook_dump_records;
        if (strcmp(symbol, "shadowhook_get_records") == 0) return (void*)fake_shadowhook_get_records;
        if (strcmp(symbol, "shadowhook_dump_records") == 0) return (void*)fake_shadowhook_dump_records;
        // 拦截对 hook 相关符号的查询（指定精确框架名，避免误杀正常函数）
        if (strcasestr(symbol, "bytehook") ||
            strcasestr(symbol, "xposed") ||
            strcasestr(symbol, "lsposed") ||
            strcasestr(symbol, "sandhook") ||
            strcasestr(symbol, "yahfa") ||
            strcasestr(symbol, "pine") ||
            strcasestr(symbol, "dexkit") ||
            strcasestr(symbol, "epic") ||
            strcasestr(symbol, "dobby") ||
            strcasestr(symbol, "riru") ||
            strcasestr(symbol, "zygisk") ||
            strcasestr(symbol, "qauxv") ||
            strcasestr(symbol, "bin.mt") ||
            strcasestr(symbol, "npatch") ||
            strcasestr(symbol, "libqauxv") ||
            strcasestr(symbol, "bytebuddy") ||
            strcasestr(symbol, "lspatch") ||
            strcasestr(symbol, "moe.ono") ||
            strcasestr(symbol, "ono") ||
            strcasestr(symbol, "lzlnb") ||
            strcasestr(symbol, "cnm") ||
            strcasestr(symbol, "libcnm") ||
            strcasestr(symbol, "liball-jni")) {
            LOGI("QSec dlsym blocked: %s", symbol);
            return nullptr;
        }
    }
    void* prev = bytehook_get_prev_func((void*)hooked_dlsym);
    if (prev) {
        return ((void* (*)(void*, const char*))prev)(handle, symbol);
    }
    return dlsym(handle, symbol);
}

/**
 * Hook dladdr - 防止地址反查检测 hook 框架
 */
static int hooked_dladdr(const void* addr, Dl_info* info) {
    SAFE_BYTEHOOK_SCOPE();
    int ret = 0;
    void* prev = bytehook_get_prev_func((void*)hooked_dladdr);
    if (prev) {
        ret = ((int (*)(const void*, Dl_info*))prev)(addr, info);
    } else {
        ret = dladdr(addr, info);
    }

    if (ret != 0 && info && info->dli_fname) {
        const char* fname = info->dli_fname;
        // 如果查到的是 hook 框架，伪装成系统库
        if (strcasestr(fname, "bytehook") ||
            strcasestr(fname, "native-bypass") ||
            strcasestr(fname, "xposed") ||
            strcasestr(fname, "lsposed") ||
            strcasestr(fname, "liblspd") ||
            strcasestr(fname, "dexkit") ||
            strcasestr(fname, "libdexkit") ||
            strcasestr(fname, "sandhook") ||
            strcasestr(fname, "yahfa") ||
            strcasestr(fname, "epic") ||
            strcasestr(fname, "pine") ||
            strcasestr(fname, "taichi") ||
            strcasestr(fname, "qqbypass") ||
            strcasestr(fname, "xalsace") ||
            strcasestr(fname, "qauxv") ||
            strcasestr(fname, "io.github.qauxv") ||
            strcasestr(fname, "libqauxv") ||
            strcasestr(fname, "libqauxv-core") ||
            strcasestr(fname, "bin.mt") ||
            strcasestr(fname, "npatch") ||
            strcasestr(fname, "bytebuddy") ||
            strcasestr(fname, "cc.ioctl") ||
            strcasestr(fname, "qnotified") ||
            strcasestr(fname, "moe.ono") ||
            strcasestr(fname, "ono") ||
            strcasestr(fname, "lzlnb") ||
            strcasestr(fname, "cnm") ||
            strcasestr(fname, "libcnm") ||
            strcasestr(fname, "liball-jni") ||
            strcasestr(fname, "riru") ||
            strcasestr(fname, "libriru") ||
            strcasestr(fname, "zygisk") ||
            strcasestr(fname, "libzygisk") ||
            strcasestr(fname, "apatch") ||
            strcasestr(fname, "libapatch") ||
            strcasestr(fname, "kernelsu") ||
            strcasestr(fname, "ksu") ||
            strcasestr(fname, "magisk") ||
            strcasestr(fname, "shamiko") ||
            strcasestr(fname, "lspatch") ||
            strcasestr(fname, "liblspatch")) {
            LOGI("QSec dladdr spoofed: %s -> libc.so", info->dli_fname);
#if defined(__aarch64__) || defined(__x86_64__)
            info->dli_fname = "/system/lib64/libc.so";
#else
            info->dli_fname = "/system/lib/libc.so";
#endif
            info->dli_fbase = nullptr;
            info->dli_sname = nullptr;
            info->dli_saddr = nullptr;
        }
    }

    return ret;
}

/**
 * 安装 libQSec 及 libfekit 的 anti-hook 防护
 */
void install_qsec_hooks() {
    LOGI("Installing libQSec & libfekit anti-hook hooks (ByteHook)...");

    const char* targets[] = {
        "libQSec.so", "libfekit.so", "libBeaconDT.so", "libqimei.so",
        "libnativefilescan.so", "libunusedcodecheck.so", "libKcsdk-2.0.9.so",
        "libthreadsuspend.so", "libqqPerfNativeTool.so",
        "libcuckoo.so", "libwarbler.so", "libtsmqqsc.so",
        "libqq_la.so", "libqqdid.so", "libturingxq.so", "libturingmfa.so",
        "libtencentloc.so", "libMMANDKSignature.so", "liblogcathook.so",
        "libmqpintchk.so", "libckguard.so", "libckeygeneratorV2.so",
        "libckeygenerator.so", "libmsfbootV2.so", "libMSFKernel.so",
        "libsec.so", "libtears.so", "libYTCommonLiveness.so",
        "libYTLiveness.so", "libhardcoder_new.so", "libgcloud.so",
        "librmonitor_base.so", "librmonitor_memory.so", "libBugly_Native.so",
        "libbugly_dumper.so", "libbugly_shadowhook.so", "libmatrix-memoryhook.so",
        "libtfd.so", nullptr
    };
    for (int i = 0; targets[i]; i++) {
        const char* target = targets[i];

        // Hook dlopen
        bytehook_stub_t stub = bytehook_hook_single(
            target,
            nullptr,
            "dlopen",
            (void*)hooked_dlopen,
            nullptr,
            nullptr
        );
        if (stub == nullptr) {
            LOGD("Failed to hook %s dlopen", target);
        }

        // Hook dlsym
        stub = bytehook_hook_single(
            target,
            nullptr,
            "dlsym",
            (void*)hooked_dlsym,
            nullptr,
            nullptr
        );
        if (stub == nullptr) {
            LOGD("Failed to hook %s dlsym", target);
        }

        // Hook dladdr
        stub = bytehook_hook_single(
            target,
            nullptr,
            "dladdr",
            (void*)hooked_dladdr,
            nullptr,
            nullptr
        );
        if (stub == nullptr) {
            LOGD("Failed to hook %s dladdr", target);
        }
    }

    LOGI("libQSec & libfekit anti-hook hooks installed");
}

