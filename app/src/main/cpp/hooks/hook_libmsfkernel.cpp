#include <jni.h>
#include <string.h>
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include "bytehook.h"

// MSFKernel 关键函数的原始指针
/**
 * Hook MSFKernelBridge.native_setQimei36
 *
 * 这个函数将 qimei36 设备指纹注入到 MSF 协议层，是风控的核心数据源。
 * 拦截它可以防止异常设备指纹被上报。
 */
[[maybe_unused]] static void hooked_setQimei36(JNIEnv* env, jobject thiz, jstring qimei36) {
    const char* qimei_str = env->GetStringUTFChars(qimei36, nullptr);

    LOGI("MSFKernel setQimei36 intercepted: %s", qimei_str ? qimei_str : "(null)");

    // 策略选择：
    // 1. 完全阻断（不调用原函数）— 可能导致协议异常
    // 2. 伪装指纹（替换成正常设备的 qimei）— 需要有效样本
    // 3. 放行但记录（当前策略）

    // 当前：放行但记录，便于后续分析
    void* prev = bytehook_get_prev_func((void*)hooked_setQimei36);
    if (prev) {
        typedef void (*setQimei36_t)(JNIEnv*, jobject, jstring);
        ((setQimei36_t)prev)(env, thiz, qimei36);
    }

    if (qimei_str) {
        env->ReleaseStringUTFChars(qimei36, qimei_str);
    }
}

/**
 * 安装 libMSFKernel 的 hook
 */
void install_msfkernel_hooks() {
    // 100% exempt libMSFKernel.so from Native ByteHook to respect zero-intervention invariants.
    // Official QQ generates valid authentic qimei36; MSF protocol bridge runs naturally without modification.
    LOGI("hook_libmsfkernel: libMSFKernel.so 100% exempted from native hooks");
}
