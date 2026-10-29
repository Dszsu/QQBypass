#include <jni.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <link.h>
#include <atomic>
#include <cstdlib>
#include <algorithm>
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include "../utils/safe_bytehook.h"
#include "bytehook.h"
#include "hook_libc.h"
#include "hook_libqsec.h"

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
            strcasestr(filename, "libepic") ||
            strcasestr(filename, "libpine") ||
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
            strcasestr(filename, "ono_") ||
            strcasestr(filename, "lzlnb") ||
            strcasestr(filename, "cnm0") ||
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
            strcasestr(symbol, "libpine") ||
            strcasestr(symbol, "pine_") ||
            strcasestr(symbol, "dexkit") ||
            strcasestr(symbol, "libepic") ||
            strcasestr(symbol, "epic_") ||
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
            strcasestr(symbol, "ono_") ||
            strcasestr(symbol, "lzlnb") ||
            strcasestr(symbol, "cnm0") ||
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
 * Hook dladdr - 防止地址反查检测 hook 框架，全量依托 hook_libc::fake_dladdr 合规规范化
 */
static int hooked_dladdr(const void* addr, Dl_info* info) {
    SAFE_BYTEHOOK_SCOPE();
    return hook_libc::fake_dladdr(addr, info);
}

extern "C" long c_fekit_syscall_handler(long a0, long a1, long a2, long a3, long a4, long a5, long syscall_num, void* caller_pc);

#if defined(__aarch64__)
[[maybe_unused]] static const uint32_t QSEC_TRAMPOLINE_TEMPLATE[] = {
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
    0x58000250, // ldr x16, [pc, #72]
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
    0xd503201f  // nop
};

struct QSecSearchInfo {
    const char* target_name;
    uintptr_t base;
    uintptr_t text_vaddr;
    size_t text_size;
};

[[maybe_unused]] static int find_qsec_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    QSecSearchInfo* search = (QSecSearchInfo*)data;
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

namespace hook_libqsec {

static std::atomic<bool> s_qsec_patched{false};

void patch_libqsec_in_memory() {
    // No-op: Do NOT patch .text segment or inject proximity trampolines into libQSec.so.
    if (s_qsec_patched.exchange(true)) return;
    LOGI("libQSec.so: Preserving authentic text segment & code integrity (in-memory patching disabled)");
}

/**
 * 安装 libQSec 及 libfekit 的 anti-hook 防护
 */
void install_qsec_hooks() {
    patch_libqsec_in_memory();
    const char* targets[] = {
        "libQSec.so", "libfekit.so", "libBeaconDT.so", "libqimei.so",
        "libnativefilescan.so", "libunusedcodecheck.so", "libKcsdk-2.0.9.so",
        "libthreadsuspend.so", "libqqPerfNativeTool.so",
        "libcuckoo.so", "libwarbler.so", "libtsmqqsc.so",
        "libqq_la.so", "libqqdid.so", "libturingxq.so", "libturingmfa.so",
        "libtencentloc.so", "libMMANDKSignature.so", "liblogcathook.so",
        "libmqpintchk.so", "libckguard.so", "libckeygeneratorV2.so",
        "libckeygenerator.so",
        "libsec.so", "libtears.so", "libYTCommonLiveness.so",
        "libYTLiveness.so", "libhardcoder_new.so", "libgcloud.so",
        "librmonitor_base.so", "librmonitor_memory.so", "libBugly_Native.so",
        "libbugly_dumper.so", "libbugly_shadowhook.so", "libmatrix-memoryhook.so",
        "libtfd.so", nullptr
    };
    for (int i = 0; targets[i]; i++) {
        const char* target = targets[i];

        TRACK_NATIVE_HOOK_SINGLE(
            target,
            nullptr,
            "dlopen",
            (void*)hooked_dlopen,
            nullptr,
            nullptr
        );

        TRACK_NATIVE_HOOK_SINGLE(
            target,
            nullptr,
            "dlsym",
            (void*)hooked_dlsym,
            nullptr,
            nullptr
        );

        TRACK_NATIVE_HOOK_SINGLE(
            target,
            nullptr,
            "dladdr",
            (void*)hooked_dladdr,
            nullptr,
            nullptr
        );
    }
}

} // namespace hook_libqsec

