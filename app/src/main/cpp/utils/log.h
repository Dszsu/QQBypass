#ifndef NATIVE_BYPASS_LOG_H
#define NATIVE_BYPASS_LOG_H

#include <android/log.h>

#define TAG "QQNativeBypass"

// 确保模块调试日志不写入系统 logcat，防止被 QQ/Bugly/APM 抓取上传
#define LOGD(...) ((void)0)
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 记录 Native 层敏感环境探测与系统调用拦截记录 (Native Security Probe Audit)
 * 采用原子 POSIX 追加写机制，直接写入安全审计日志文件，完全不经过 logcat，
 * 彻底防止被系统及应用内 APM/Bugly 日志扫描器嗅探。
 */
void audit_native_probe(const char* tag, const char* probe_type, const char* detail);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_BYPASS_LOG_H
