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
        if (strstr(pathname, "maps") != nullptr) {
            LOGI("libturingxq: fopen maps redirected to filtered maps");
            return hook_libc::build_filtered_maps();
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
            FILE* fp = hook_libc::build_filtered_mounts();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "mountinfo") != nullptr) {
            FILE* fp = hook_libc::build_filtered_mountinfo();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "maps") != nullptr) {
            FILE* fp = hook_libc::build_filtered_maps();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "status") != nullptr) {
            FILE* fp = hook_libc::build_filtered_status();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "cmdline") != nullptr || hook_libc::is_proc_cmdline_path(pathname)) {
            LOGI("libturingxq: open cmdline redirected to virtual cmdline");
            FILE* fp = hook_libc::build_virtual_cmdline(pathname);
            return fp ? fileno(fp) : -1;
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
            FILE* fp = hook_libc::build_filtered_mounts();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "mountinfo") != nullptr) {
            FILE* fp = hook_libc::build_filtered_mountinfo();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "maps") != nullptr) {
            FILE* fp = hook_libc::build_filtered_maps();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "status") != nullptr) {
            FILE* fp = hook_libc::build_filtered_status();
            return fp ? fileno(fp) : -1;
        }
        if (strstr(pathname, "cmdline") != nullptr || hook_libc::is_proc_cmdline_path(pathname)) {
            LOGI("libturingxq: open cmdline redirected to virtual cmdline");
            FILE* fp = hook_libc::build_virtual_cmdline(pathname);
            return fp ? fileno(fp) : -1;
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

#if defined(__aarch64__)
struct TuringSearchInfo {
    const char* target_name;
    uintptr_t base;
    uintptr_t dynamic_vaddr;
    size_t dynamic_size;
};

static int find_turing_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    TuringSearchInfo* search = (TuringSearchInfo*)data;
    if (!info || !info->dlpi_name) return 0;
    if (strstr(info->dlpi_name, search->target_name)) {
        search->base = info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr)& ph = info->dlpi_phdr[i];
            if (ph.p_type == PT_DYNAMIC) {
                search->dynamic_vaddr = ph.p_vaddr;
                search->dynamic_size = ph.p_memsz;
            }
        }
        return 1;
    }
    return 0;
}

static bool patch_got_entry(uintptr_t got_addr, void* new_func, long page_size) {
    if (!got_addr || !new_func) return false;
    uintptr_t page_start = got_addr & ~(page_size - 1);
    if (mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_WRITE) == 0) {
        *(void**)got_addr = new_func;
        mprotect((void*)page_start, page_size * 2, PROT_READ);
        return true;
    }
    return false;
}
#endif

void patch_libturingxq_in_memory() {
#if defined(__aarch64__)
    if (s_turingxq_patched.load(std::memory_order_relaxed)) return;

    TuringSearchInfo search{"libturingxq.so", 0, 0, 0};
    dl_iterate_phdr(find_turing_callback, &search);

    // Fallback: search /proc/self/maps if dl_iterate_phdr didn't find base
    if (!search.base) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libturingxq.so") && strstr(line, "r-xp")) {
                    uintptr_t start = 0, end = 0;
                    if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                        search.base = start;
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    if (!search.base) {
        return;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    LOGI("libturingxq.so found at base 0x%lx, applying in-memory GOT & syscall hardening...", (unsigned long)search.base);

    // 1. Inline trampoline patch on exported `real_syscall` at 0x46ad0
    // Opcode pattern: 0xaa0003e8 (mov x8, x0), 0xaa0103e0 (mov x0, x1)
    uint32_t* p_real_syscall = (uint32_t*)(search.base + 0x46ad0);
    if (p_real_syscall[0] == 0xaa0003e8) {
        uintptr_t page_start = ((uintptr_t)p_real_syscall) & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            uintptr_t target = (uintptr_t)hooked_real_syscall;
            p_real_syscall[0] = 0x58000050; // ldr x16, #8
            p_real_syscall[1] = 0xd61f0200; // br x16
            p_real_syscall[2] = (uint32_t)(target & 0xFFFFFFFF);
            p_real_syscall[3] = (uint32_t)(((uint64_t)target >> 32) & 0xFFFFFFFF);
            __builtin___clear_cache((char*)p_real_syscall, (char*)p_real_syscall + 16);
            mprotect((void*)page_start, page_size * 2, PROT_READ | PROT_EXEC);
            LOGI("libturingxq.so: Patched inline real_syscall at 0x%lx -> hooked_real_syscall", (unsigned long)p_real_syscall);
        } else {
            LOGE("libturingxq.so: mprotect failed for real_syscall trampoline: %d", errno);
        }
    }

    // 2. Dynamic ELF GOT patching via PT_DYNAMIC
    bool parsed_dyn = false;
    if (search.dynamic_vaddr != 0) {
        ElfW(Dyn)* dyn = (ElfW(Dyn)*)(search.base + search.dynamic_vaddr);
        ElfW(Rela)* jmprel = nullptr;
        size_t pltrelsz = 0;
        ElfW(Sym)* symtab = nullptr;
        const char* strtab = nullptr;

        for (size_t i = 0; dyn[i].d_tag != DT_NULL; i++) {
            switch (dyn[i].d_tag) {
                case DT_JMPREL:
                    jmprel = (ElfW(Rela)*)(search.base + dyn[i].d_un.d_ptr);
                    break;
                case DT_PLTRELSZ:
                    pltrelsz = dyn[i].d_un.d_val;
                    break;
                case DT_SYMTAB:
                    symtab = (ElfW(Sym)*)(search.base + dyn[i].d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    strtab = (const char*)(search.base + dyn[i].d_un.d_ptr);
                    break;
            }
        }

        if (jmprel && symtab && strtab && pltrelsz > 0) {
            size_t count = pltrelsz / sizeof(ElfW(Rela));
            for (size_t i = 0; i < count; i++) {
                ElfW(Word) sym_idx = ELF64_R_SYM(jmprel[i].r_info);
                const char* sym_name = strtab + symtab[sym_idx].st_name;
                uintptr_t got_addr = search.base + jmprel[i].r_offset;

                void* target_func = nullptr;
                if (strcmp(sym_name, "fopen") == 0 || strcmp(sym_name, "fopen64") == 0) {
                    target_func = (void*)xq_fake_fopen;
                } else if (strcmp(sym_name, "open") == 0 || strcmp(sym_name, "open64") == 0) {
                    target_func = (void*)xq_fake_open;
                } else if (strcmp(sym_name, "__open_2") == 0) {
                    target_func = (void*)xq_fake_open_2;
                } else if (strcmp(sym_name, "openat") == 0 || strcmp(sym_name, "openat64") == 0) {
                    target_func = (void*)xq_fake_openat;
                } else if (strcmp(sym_name, "__openat_2") == 0) {
                    target_func = (void*)xq_fake_openat_2;
                } else if (strcmp(sym_name, "syscall") == 0) {
                    target_func = (void*)hooked_syscall;
                } else if (strcmp(sym_name, "real_syscall") == 0) {
                    target_func = (void*)hooked_real_syscall;
                } else if (strcmp(sym_name, "strstr") == 0) {
                    target_func = (void*)fake_xq_strstr;
                } else if (strcmp(sym_name, "stat") == 0 || strcmp(sym_name, "stat64") == 0) {
                    target_func = (void*)xq_fake_stat;
                } else if (strcmp(sym_name, "lstat") == 0 || strcmp(sym_name, "lstat64") == 0) {
                    target_func = (void*)xq_fake_lstat;
                } else if (strcmp(sym_name, "fstatat") == 0 || strcmp(sym_name, "fstatat64") == 0) {
                    target_func = (void*)xq_fake_fstatat;
                } else if (strcmp(sym_name, "access") == 0) {
                    target_func = (void*)xq_fake_access;
                } else if (strcmp(sym_name, "faccessat") == 0) {
                    target_func = (void*)xq_fake_faccessat;
                } else if (strcmp(sym_name, "statfs") == 0 || strcmp(sym_name, "statfs64") == 0) {
                    target_func = (void*)xq_fake_statfs;
                } else if (strcmp(sym_name, "popen") == 0) {
                    target_func = (void*)xq_fake_popen;
                } else if (strcmp(sym_name, "fgets") == 0) {
                    target_func = (void*)xq_fake_fgets;
                } else if (strcmp(sym_name, "readlink") == 0) {
                    target_func = (void*)xq_fake_readlink;
                } else if (strcmp(sym_name, "readlinkat") == 0) {
                    target_func = (void*)xq_fake_readlinkat;
                }

                if (target_func) {
                    if (patch_got_entry(got_addr, target_func, page_size)) {
                        LOGI("libturingxq.so: Dynamic GOT hooked %s at 0x%lx", sym_name, (unsigned long)got_addr);
                    }
                }
            }
            parsed_dyn = true;
        }
    }

    // 3. Fallback verified static offsets (in case dynamic parsing was skipped or partial)
    if (!parsed_dyn) {
        LOGI("libturingxq.so: Dynamic parsing not available, applying static GOT table");
    }
    patch_got_entry(search.base + 0x4cdd8, (void*)xq_fake_fopen, page_size);
    patch_got_entry(search.base + 0x4cd28, (void*)xq_fake_open, page_size);
    patch_got_entry(search.base + 0x4cd08, (void*)xq_fake_open_2, page_size);
    patch_got_entry(search.base + 0x4cd58, (void*)hooked_syscall, page_size);
    patch_got_entry(search.base + 0x4cc70, (void*)hooked_real_syscall, page_size);
    patch_got_entry(search.base + 0x4cbd8, (void*)fake_xq_strstr, page_size);

    s_turingxq_patched = true;
    LOGI("libturingxq.so: In-memory patching successfully completed (dyn=%d)", parsed_dyn);
#endif
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
