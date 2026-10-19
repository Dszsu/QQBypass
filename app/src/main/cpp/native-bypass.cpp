#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <bytehook.h>
#include "utils/log.h"
#include "hooks/hook_libc.h"
#include "hooks/hook_libfekit.h"
#include "hooks/hook_libturingxq.h"
#include "hooks/hook_libmsf.h"
#include "hooks/hook_libqsec.h"
#include "hooks/hook_libmsfkernel.h"
#include "hooks/hook_libturingmfa.h"
#include "hooks/hook_libqimei.h"

/**
 * Native Bypass Module for QQ Enhanced Bypass (ByteHook Engine)
 *
 * This module provides comprehensive native protection against QQ & Tencent risk detection:
 * - Engine: ByteHook (Automatic PLT/GOT hooking across library linkage boundaries)
 *
 * Key targets:
 * - libc: File I/O interception (/proc/self/maps via memfd_create, /proc/self/status, mounts, syscalls)
 * - libfekit.so: Root/Xposed detection
 * - libturingxq.so: ART integrity checks and risk reporting
 * - libMSFKernel.so: qimei36 fingerprint injection (QQ 9.3.50+)
 * - libQSec.so: Anti-hook detection (dlopen/dlsym/dladdr)
 * - libturingmfa.so: Multi-factor authentication & face ID engine (syscall & real_syscall interception)
 * - libMSF hooks: Signature verification (experimental)
 */

#include "utils/safe_bytehook.h"
#include <stdlib.h>

// Standalone C++ memory operators to avoid any external libc++ dependency
void* operator new(size_t size) { return malloc(size); }
void* operator new[](size_t size) { return malloc(size); }
void operator delete(void* p) noexcept { free(p); }
void operator delete[](void* p) noexcept { free(p); }
void operator delete(void* p, size_t) noexcept { free(p); }
void operator delete[](void* p, size_t) noexcept { free(p); }

bool g_bytehook_hooks_installed = false;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Install all hooks via ByteHook in a background thread
 */
static void* install_hooks_thread(void* arg) {
    (void)arg;
    LOGI("=== Native Bypass Module (ByteHook Engine) Starting ===");
    LOGI("Process: %d", getpid());

    pthread_mutex_lock(&g_init_mutex);

    if (g_bytehook_hooks_installed) {
        pthread_mutex_unlock(&g_init_mutex);
        return nullptr;
    }

    // 初始化 ByteHook（AUTOMATIC 模式：自动 hook 后续加载的库）
    int bh_ret = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    if (bh_ret != 0) {
        LOGE("bytehook_init failed: %d", bh_ret);
        pthread_mutex_unlock(&g_init_mutex);
        return nullptr;
    }
    LOGI("ByteHook initialized (AUTOMATIC mode)");

    // Install hooks in order of importance
    LOGI("Installing ByteHook hooks...");

    // 1. libc hooks (highest priority - intercept file I/O & syscalls)
    hook_libc::install_hooks();

    // 2. libfekit.so hooks (root/xposed detection)
    hook_libfekit::install_hooks();

    // 3. libturingxq.so hooks (ART integrity and risk reporting)
    hook_libturingxq::install_hooks();

    // 4. QQ 9.3.50+ extended hooks
    install_qsec_hooks();        // Anti-hook detection
    install_msfkernel_hooks();   // qimei36 fingerprint injection
    install_turingmfa_hooks();   // Multi-factor authentication & face verification
    hook_libqimei::install_hooks(); // libqimei inline syscalls & imports

    // 5. libMSF hooks (signature verification bypass)
    hook_libmsf::install_hooks();

    // 6. Hook bytehook & shadowhook query APIs (prevent Tencent monitor from enumerating hooks)
    bytehook_hook_all(nullptr, "bytehook_get_records", (void*)fake_bytehook_get_records, nullptr, nullptr);
    bytehook_hook_all(nullptr, "bytehook_dump_records", (void*)fake_bytehook_dump_records, nullptr, nullptr);
    bytehook_hook_all(nullptr, "shadowhook_get_records", (void*)fake_shadowhook_get_records, nullptr, nullptr);
    bytehook_hook_all(nullptr, "shadowhook_dump_records", (void*)fake_shadowhook_dump_records, nullptr, nullptr);

    g_bytehook_hooks_installed = true;
    LOGI("=== All ByteHook Native Hooks Installed Successfully ===");

    pthread_mutex_unlock(&g_init_mutex);

    return nullptr;
}

/**
 * Initialize native hooks (called from Java layer)
 */
extern "C" JNIEXPORT void JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_initNativeHooksNative(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    LOGI("initNativeHooks called from Java layer");

    if (g_bytehook_hooks_installed) {
        LOGW("ByteHook native hooks already installed");
        return;
    }

    // Install hooks in background thread to avoid blocking main thread
    pthread_t thread;
    if (pthread_create(&thread, nullptr, install_hooks_thread, nullptr) == 0) {
        pthread_detach(thread);
        LOGI("ByteHook installation thread started");
    } else {
        LOGE("Failed to create hook installation thread");
    }
}

/**
 * Check if hooks are installed
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_isHooksInstalledNative(JNIEnv* env, jclass clazz) {
    (void)env;
    (void)clazz;
    return g_bytehook_hooks_installed;
}

/**
 * Get hook status message
 */
extern "C" JNIEXPORT jstring JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_getHookStatusNative(JNIEnv* env, jclass clazz) {
    (void)clazz;
    char status_buf[256];
    snprintf(status_buf, sizeof(status_buf),
             "Native hooks installed: ByteHook PLT=%s",
             g_bytehook_hooks_installed ? "active" : "standby");
    return env->NewStringUTF(status_buf);
}

/**
 * Notify Native layer about Java detection event (Java → Native communication)
 */
extern "C" JNIEXPORT void JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_notifyDetectionNative(
    JNIEnv* env, jclass clazz, jstring event, jstring data) {
    (void)clazz;

    const char* event_str = env->GetStringUTFChars(event, nullptr);
    const char* data_str = env->GetStringUTFChars(data, nullptr);

    LOGI("[Java→Native] Detection event: %s, data: %s", event_str, data_str);

    // Handle different events
    if (strcmp(event_str, "file_blocked") == 0) {
        LOGD("Java layer blocked file access: %s", data_str);
    } else if (strcmp(event_str, "package_blocked") == 0) {
        LOGD("Java layer blocked package query: %s", data_str);
    } else if (strcmp(event_str, "class_blocked") == 0) {
        LOGD("Java layer blocked class load: %s", data_str);
    }

    env->ReleaseStringUTFChars(event, event_str);
    env->ReleaseStringUTFChars(data, data_str);
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_getHookStatisticsNative(JNIEnv* env, jclass clazz) {
    (void)clazz;
    return env->NewStringUTF("ByteHook PLT hooks active");
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_xalsace_qqbypass_NativeBypass_isHookActiveNative(JNIEnv* env, jclass clazz, jstring hook_name) {
    (void)env;
    (void)clazz;
    (void)hook_name;
    return g_bytehook_hooks_installed;
}
