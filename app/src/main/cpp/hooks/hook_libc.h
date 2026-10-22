#ifndef NATIVE_BYPASS_HOOK_LIBC_H
#define NATIVE_BYPASS_HOOK_LIBC_H

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <sys/system_properties.h>

namespace hook_libc {

void install_hooks();

bool is_sensitive_path(const char* path);
bool is_sensitive_name(const char* name);
bool is_sensitive_link_target(const char* target);
bool is_sensitive_proc_fd(const char* path);
bool is_sensitive_proc_fd(int dirfd, const char* path);
FILE* build_filtered_maps();
FILE* build_filtered_smaps();
FILE* build_filtered_mounts();
FILE* build_filtered_mountinfo();
FILE* build_filtered_net_unix();
FILE* build_filtered_net_tcp(bool is_v6 = false);
FILE* build_filtered_selinux_attr();
FILE* build_filtered_status();
FILE* build_filtered_wchan();
FILE* build_filtered_cgroup();
FILE* build_virtual_cmdline(const char* pathname);
bool is_proc_cmdline_path(const char* path);
bool is_root_proc_path(const char* path);
bool handle_virtual_stat(const char* pathname, struct stat* statbuf);

FILE* fake_fopen(const char* pathname, const char* mode);
int fake_open(const char* pathname, int flags, ...);
int fake_open_2(const char* pathname, int flags);
int fake_openat(int dirfd, const char* pathname, int flags, ...);
int fake_openat_2(int dirfd, const char* pathname, int flags);
int fake_stat(const char* pathname, struct stat* statbuf);
int fake_lstat(const char* pathname, struct stat* statbuf);
int fake_fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags);
int fake_access(const char* pathname, int mode);
int fake_faccessat(int dirfd, const char* pathname, int mode, int flags);
char* fake_fgets(char* s, int size, FILE* stream);
ssize_t fake_readlink(const char* pathname, char* buf, size_t bufsiz);
ssize_t fake_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz);
DIR* fake_opendir(const char* name);
struct dirent* fake_readdir(DIR* dirp);
FILE* fake_popen(const char* command, const char* type);
int fake_pclose(FILE* stream);
int fake_statfs(const char* path, struct statfs* buf);
int fake_system_property_get(const char* name, char* value);
const prop_info* fake_system_property_find(const char* name);
int fake_system_property_read(const prop_info* pi, char* name, char* value);

long fake_syscall(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
long fake_syscall_ex(long number, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* caller_addr);
void register_trampoline_range(uintptr_t start, uintptr_t end);

} // namespace hook_libc

extern "C" {
int fake_bytehook_get_records(void* stub, void** records, size_t* len);
void fake_bytehook_dump_records(int fd);
char* fake_shadowhook_get_records(uint32_t item_flags);
void fake_shadowhook_dump_records(int fd, uint32_t item_flags);
}

#endif // NATIVE_BYPASS_HOOK_LIBC_H
