#ifndef NATIVE_BYPASS_SAFE_BYTEHOOK_H
#define NATIVE_BYPASS_SAFE_BYTEHOOK_H

#include <bytehook.h>
#include <pthread.h>
#include <stdint.h>
#include <dlfcn.h>

extern bool g_bytehook_hooks_installed;

#ifdef __cplusplus
#if defined(__aarch64__)
static inline bool is_bytehook_stack_active() {
    static uintptr_t s_bh_base = 0;
    static bool s_inited = false;
    if (!s_inited) {
        Dl_info info;
        if (dladdr((void*)bytehook_pop_stack, &info) && info.dli_fbase) {
            s_bh_base = (uintptr_t)info.dli_fbase;
        }
        s_inited = true;
    }
    if (s_bh_base != 0) {
        pthread_key_t key = *(pthread_key_t*)(s_bh_base + 0x15a68);
        void* stack = pthread_getspecific(key);
        return stack != nullptr;
    }
    return false;
}
#else
static inline bool is_bytehook_stack_active() { return true; }
#endif

struct SafeBytehookScope {
    void* ret_addr;
    SafeBytehookScope(void* ret) : ret_addr(ret) {}
    ~SafeBytehookScope() {
        if (g_bytehook_hooks_installed && bytehook_get_mode() == BYTEHOOK_MODE_AUTOMATIC) {
            if (is_bytehook_stack_active()) {
                bytehook_pop_stack(ret_addr);
            }
        }
    }
};
#define SAFE_BYTEHOOK_SCOPE() SafeBytehookScope __safe_bh_scope(__builtin_return_address(0))
#else
#define SAFE_BYTEHOOK_SCOPE() do {} while(0)
#endif

#endif // NATIVE_BYPASS_SAFE_BYTEHOOK_H
