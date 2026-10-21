#include "hook_libmsf.h"
#include "../utils/log.h"
#include "../utils/native_hook_tracker.h"
#include <bytehook.h>
#include <jni.h>

namespace hook_libmsf {

/**
 * 逆向分析成果：
 * 1. libmsfbootV2.so 导出 _ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject
 *    内部调用 getPackagesForUid -> getPackageInfo(..., 64) -> toCharsString() -> QSCrypt::Md5Hash
 *    校验哈希是否匹配腾讯官方签名哈希。
 *    hook 点：拦截该函数，强制返回 JNI_TRUE (1)。
 *
 * 2. libcodecwrapperV2.so 在 CCodecWarpper::encodeRequest 中通过 PLT 调用：
 *    _Z12GetSignatureP7_JNIEnvP8_jobjectRNSt6__ndk16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE
 *    （PLT 偏移 0x5c9c0，GOT 偏移 0x61e80，R_AARCH64_JUMP_SLOT）。
 *    hook 点：通过 ByteHook 单库 PLT hook 挂接。
 */

typedef jboolean (*IsSignatureValid_t)(JNIEnv*, jobject);

static jboolean hooked_IsSignatureValid(JNIEnv* env, jobject context) {
    (void)env;
    (void)context;
    LOGI("CMSFJavaUtil::IsSignatureValid intercepted! Bypassing signature verification (returning JNI_TRUE)");
    return JNI_TRUE;
}

typedef void (*GetSignature_t)(JNIEnv*, jobject, void*);

static void hooked_GetSignature(JNIEnv* env, jobject context, void* vec) {
    LOGI("libcodecwrapperV2 GetSignature intercepted, executing with spoofed Java PackageManager signatures");
    void* prev = bytehook_get_prev_func((void*)hooked_GetSignature);
    if (prev) {
        ((GetSignature_t)prev)(env, context, vec);
    }
}

void install_hooks() {
    // 1. Hook CMSFJavaUtil::IsSignatureValid
    TRACK_NATIVE_HOOK_SINGLE(
        "libmsfbootV2.so",
        nullptr,
        "_ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject",
        (void*)hooked_IsSignatureValid,
        nullptr,
        nullptr
    );

    TRACK_NATIVE_HOOK_SINGLE(
        "libMSFKernel.so",
        nullptr,
        "_ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject",
        (void*)hooked_IsSignatureValid,
        nullptr,
        nullptr
    );

    TRACK_NATIVE_HOOK_ALL(
        nullptr,
        "_ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject",
        (void*)hooked_IsSignatureValid,
        nullptr,
        nullptr
    );

    // 2. Hook GetSignature in libcodecwrapperV2.so (PLT hook)
    TRACK_NATIVE_HOOK_SINGLE(
        "libcodecwrapperV2.so",
        nullptr,
        "_Z12GetSignatureP7_JNIEnvP8_jobjectRNSt6__ndk16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE",
        (void*)hooked_GetSignature,
        nullptr,
        nullptr
    );
}

} // namespace hook_libmsf
