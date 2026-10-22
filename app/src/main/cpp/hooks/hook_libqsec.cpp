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
            strcasestr(fname, "libepic") ||
            strcasestr(fname, "libpine") ||
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
            strcasestr(fname, "ono_") ||
            strcasestr(fname, "lzlnb") ||
            strcasestr(fname, "cnm0") ||
            strcasestr(fname, "libcnm") ||
            strcasestr(fname, "liball-jni") ||
            strcasestr(fname, "riru") ||
            strcasestr(fname, "libriru") ||
            strcasestr(fname, "zygisk") ||
            strcasestr(fname, "libzygisk") ||
            strcasestr(fname, "libapatch") ||
            strcasestr(fname, "me.bmax.apatch") ||
            strstr(fname, "/apatch/") ||
            strstr(fname, "apatchd") ||
            strcasestr(fname, "kernelsu") ||
            strcasestr(fname, "ksud") ||
            strstr(fname, "/ksu/") ||
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

extern "C" long c_fekit_syscall_handler(long a0, long a1, long a2, long a3, long a4, long a5, long syscall_num, void* caller_pc);

#if defined(__aarch64__)
static const uint32_t QSEC_TRAMPOLINE_TEMPLATE[] = {
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

static int find_qsec_callback(struct dl_phdr_info* info, size_t size, void* data) {
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
#if defined(__aarch64__)
    if (s_qsec_patched.load(std::memory_order_relaxed)) return;

    QSecSearchInfo search{"libQSec.so", 0, 0, 0};
    dl_iterate_phdr(find_qsec_callback, &search);

    if (!search.base) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libQSec.so") && strstr(line, "r-xp")) {
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

    // Allocate 4KB proximity trampoline page in guard gap right after libQSec.so text
    uintptr_t hint = search.base + ((search.text_size + 4095) & ~4095);
    void* tramp_page = mmap((void*)hint, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (tramp_page == MAP_FAILED) {
        LOGE("libQSec.so: Failed to allocate proximity trampoline page at %p (errno=%d)", (void*)hint, errno);
        return;
    }

    hook_libc::register_trampoline_range((uintptr_t)tramp_page, (uintptr_t)tramp_page + 4096);

    uint8_t* tp = (uint8_t*)tramp_page;
    memcpy(tp, QSEC_TRAMPOLINE_TEMPLATE, sizeof(QSEC_TRAMPOLINE_TEMPLATE));
    uint64_t target_fn = (uint64_t)&c_fekit_syscall_handler;
    memcpy(tp + 136, &target_fn, sizeof(target_fn));

    mprotect(tramp_page, 4096, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char*)tramp_page, (char*)tramp_page + 4096);

    size_t patched_count = 0;
    uint32_t* p = (uint32_t*)text_start;
    uint32_t* pend = (uint32_t*)(text_end - 4);

    for (; p <= pend; p++) {
        if (*p == 0xd4000001) { // svc #0
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
                LOGI("libQSec.so: Patched inline svc #0 at %p (offset 0x%lx) -> bl trampoline",
                     p, (unsigned long)((uintptr_t)p - search.base));
            }
        }
    }

    s_qsec_patched.store(true, std::memory_order_relaxed);
    (void)patched_count;
    LOGI("libQSec.so inline syscall patching complete: %zu stubs redirected to proximity trampoline at %p",
         patched_count, tramp_page);
#endif
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
        "libckeygenerator.so", "libmsfbootV2.so", "libMSFKernel.so",
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

