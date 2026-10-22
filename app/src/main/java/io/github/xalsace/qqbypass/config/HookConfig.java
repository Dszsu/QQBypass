package io.github.xalsace.qqbypass.config;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 模块全局配置与运行期参数 (Central Configuration)
 */
public class HookConfig {

    public static XC_LoadPackage.LoadPackageParam loadPackageParam;
    public static ClassLoader classLoader;

    // 模块版本信息与缓存版本
    public static final int MODULE_VERSION_CODE = 89;
    public static final String MODULE_VERSION_NAME = "1.0.89";
    public static final int CACHE_SCHEMA_VERSION = 3;

    // =========================================================================
    // 5 个受管理的编译期条件编译开关 (委托至 CompileHookConfig)
    // =========================================================================
    /** 1. 拦截下线开关 (默认关闭且严禁开启) */
    public static final boolean ENABLE_KICK_INTERCEPT = CompileHookConfig.ENABLE_KICK_INTERCEPT;

    /** 2. 设备修改开关 */
    public static final boolean ENABLE_DEVICE_SPOOF = CompileHookConfig.ENABLE_DEVICE_SPOOF;

    /** 3. 模拟器伪装开关 */
    public static final boolean ENABLE_EMULATOR_SPOOF = CompileHookConfig.ENABLE_EMULATOR_SPOOF;

    /** 4. 记录 QQ 上报开关 (默认开启) */
    public static final boolean ENABLE_RECORD_QQ_REPORT = CompileHookConfig.ENABLE_RECORD_QQ_REPORT;

    /** 5. QAuxiliary 文件处理报错兼容开关 */
    public static final boolean ENABLE_QAUXILIARY_FILE_COMPAT = CompileHookConfig.ENABLE_QAUXILIARY_FILE_COMPAT;

    /** 判断当前是否开启拦截下线 */
    public static boolean isKickInterceptEnabled() {
        return ENABLE_KICK_INTERCEPT;
    }

    /** 判断当前是否开启记录 QQ 上报 */
    public static boolean isRecordQqReportEnabled() {
        return ENABLE_RECORD_QQ_REPORT;
    }

    /** 判断当前是否开启 QAuxiliary 文件处理报错兼容 */
    public static boolean isQAuxiliaryFileCompatEnabled() {
        return ENABLE_QAUXILIARY_FILE_COMPAT;
    }

    // 核心固定开关（模块默认防御基础，始终激活）
    public static final boolean ENABLE_DEXKIT = true;
    public static final boolean ENABLE_NATIVE_HOOKS = true;
    public static final boolean ENABLE_ROOT_BYPASS = true;
    public static final boolean ENABLE_XPOSED_BYPASS = true;
    public static final boolean ENABLE_DEBUG_BYPASS = true;
    public static final boolean ENABLE_RUNTIME_BYPASS = true;
    public static final boolean ENABLE_QQ950_PATCH = true;
    public static final boolean ENABLE_QQ950_RISK_BLOCK = true;
    public static final boolean ENABLE_NETWORK_INTERCEPT = false;

    // 详细调试日志开关
    public static boolean VERBOSE_LOGGING = false;

    // 伪造设备信息 (由 CompileHookConfig 静态注入)
    public static final String FAKE_IMEI = CompileHookConfig.FAKE_IMEI;
    public static final String FAKE_ANDROID_ID = CompileHookConfig.FAKE_ANDROID_ID;
    public static final String FAKE_SERIAL = CompileHookConfig.FAKE_SERIAL;

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        loadPackageParam = lpparam;
        classLoader = lpparam.classLoader;
    }

    public static ClassLoader getClassLoader() {
        return classLoader;
    }
}
