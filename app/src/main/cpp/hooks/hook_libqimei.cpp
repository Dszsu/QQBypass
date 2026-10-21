#include "hook_libqimei.h"
#include "hook_libc.h"
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bytehook.h>

namespace hook_libqimei {

static bool s_qimei_patched = false;

// Trampoline targets for inline svc #0 in libqimei.so
extern "C" int qimei_trampoline_openat(int dirfd, const char* pathname, int flags, mode_t mode) {
    if (!pathname) return -1;
    if (hook_libc::is_sensitive_path(pathname) || hook_libc::is_sensitive_name(pathname)) {
        LOGD("libqimei: Neutralized direct svc openat probe: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return hook_libc::fake_openat(dirfd, pathname, flags, mode);
}

extern "C" int qimei_trampoline_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    if (!pathname) return -1;
    if (hook_libc::is_sensitive_path(pathname) || hook_libc::is_sensitive_name(pathname)) {
        LOGD("libqimei: Neutralized direct svc fstatat probe: %s", pathname);
        errno = ENOENT;
        return -1;
    }
    return hook_libc::fake_fstatat(dirfd, pathname, statbuf, flags);
}

static int dl_iterate_find_qimei(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    if (!info || !info->dlpi_name) return 0;
    if (strstr(info->dlpi_name, "libqimei.so")) {
        uintptr_t* out_base = (uintptr_t*)data;
        *out_base = info->dlpi_addr;
        return 1; // found
    }
    return 0;
}

void patch_libqimei_in_memory() {
    if (s_qimei_patched) return;

    uintptr_t base = 0;
    dl_iterate_phdr(dl_iterate_find_qimei, &base);
    if (!base) return;

    LOGI("libqimei.so located at base 0x%lx, checking inline syscall instructions...", (unsigned long)base);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    // Check 0x18548: mov x8, #0x38 (0xd2800708), svc #0 (0xd4000001)
    uint32_t* p_openat = (uint32_t*)(base + 0x18548);
    if (p_openat[0] == 0xd2800708 && p_openat[1] == 0xd4000001) {
        uintptr_t page_start = ((uintptr_t)p_openat) & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            uintptr_t target = (uintptr_t)qimei_trampoline_openat;
            p_openat[0] = 0x58000050; // ldr x16, #8
            p_openat[1] = 0xd61f0200; // br x16
            p_openat[2] = (uint32_t)(target & 0xFFFFFFFF);
            p_openat[3] = (uint32_t)(((uint64_t)target >> 32) & 0xFFFFFFFF);
            __builtin___clear_cache((char*)p_openat, (char*)p_openat + 16);
            mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_EXEC);
            LOGI("libqimei.so: Patched inline svc openat at 0x%lx -> qimei_trampoline_openat", (unsigned long)p_openat);
        } else {
            LOGE("libqimei.so: mprotect failed for openat: %d", errno);
        }
    }

    // Check 0x187f4: mov x8, #0x4f (0xd28009e8), svc #0 (0xd4000001)
    uint32_t* p_fstatat = (uint32_t*)(base + 0x187f4);
    if (p_fstatat[0] == 0xd28009e8 && p_fstatat[1] == 0xd4000001) {
        uintptr_t page_start = ((uintptr_t)p_fstatat) & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            uintptr_t target = (uintptr_t)qimei_trampoline_fstatat;
            p_fstatat[0] = 0x58000050; // ldr x16, #8
            p_fstatat[1] = 0xd61f0200; // br x16
            p_fstatat[2] = (uint32_t)(target & 0xFFFFFFFF);
            p_fstatat[3] = (uint32_t)(((uint64_t)target >> 32) & 0xFFFFFFFF);
            __builtin___clear_cache((char*)p_fstatat, (char*)p_fstatat + 16);
            mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_EXEC);
            LOGI("libqimei.so: Patched inline svc fstatat at 0x%lx -> qimei_trampoline_fstatat", (unsigned long)p_fstatat);
        } else {
            LOGE("libqimei.so: mprotect failed for fstatat: %d", errno);
        }
    }

    s_qimei_patched = true;
}

void install_hooks() {
    // Try patching inline syscalls immediately if already loaded
    patch_libqimei_in_memory();

    // Hook PLT imports of libqimei.so via ByteHook
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "fopen", (void*)hook_libc::fake_fopen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "open", (void*)hook_libc::fake_open, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "stat", (void*)hook_libc::fake_stat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "lstat", (void*)hook_libc::fake_lstat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "fstatat64", (void*)hook_libc::fake_fstatat, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "access", (void*)hook_libc::fake_access, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "opendir", (void*)hook_libc::fake_opendir, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "readdir", (void*)hook_libc::fake_readdir, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "popen", (void*)hook_libc::fake_popen, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "__system_property_get", (void*)hook_libc::fake_system_property_get, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "__system_property_find", (void*)hook_libc::fake_system_property_find, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "__system_property_read", (void*)hook_libc::fake_system_property_read, nullptr, nullptr);
    TRACK_NATIVE_HOOK_SINGLE("libqimei.so", nullptr, "statfs", (void*)hook_libc::fake_statfs, nullptr, nullptr);
}

} // namespace hook_libqimei
