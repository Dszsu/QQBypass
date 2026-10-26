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

void patch_libqimei_in_memory() {
    // No-op: Do NOT patch .text segment or inject proximity trampolines into libqimei.so.
    // In-memory code patching triggers code integrity self-check failures and /proc/self/maps VMA fragmentation.
    if (s_qimei_patched) return;
    s_qimei_patched = true;
    LOGI("libqimei.so: Preserving authentic text segment & code integrity (in-memory patching disabled)");
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
