package io.github.xalsace.qqbypass.config;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Central configuration for hook modules
 */
public class HookConfig {

    public static XC_LoadPackage.LoadPackageParam loadPackageParam;
    public static ClassLoader classLoader;

    // Module version info & cache schema
    public static final int MODULE_VERSION_CODE = 65;
    public static final String MODULE_VERSION_NAME = "1.0.65";
    public static final int CACHE_SCHEMA_VERSION = 3;

    // Feature toggles
    public static boolean ENABLE_DEXKIT = (android.os.Build.VERSION.SDK_INT < 35); // Disabled on Android 15/16+ (jemalloc tagged pointer abort)
    public static boolean ENABLE_NATIVE_HOOKS = true;        // Native layer hooks (70% coverage)
    public static boolean ENABLE_ROOT_BYPASS = true;
    public static boolean ENABLE_XPOSED_BYPASS = true;
    public static boolean ENABLE_DEBUG_BYPASS = true;
    public static boolean ENABLE_DEVICE_SPOOF = true;
    public static boolean ENABLE_NETWORK_INTERCEPT = false;  // Disabled: allow normal requests to proceed
    public static boolean ENABLE_RUNTIME_BYPASS = true;
    public static boolean ENABLE_QQ950_PATCH = true;        // QQ 9.3.50 detection-point completion
    public static boolean ENABLE_QQ950_RISK_BLOCK = true;   // Tier 2: object-return risk blocks (NPE-caveat; disable if NPE appears)

    // Kick Interception feature toggle (打包时确定，无需动态开销)
    public static final boolean ENABLE_KICK_INTERCEPT = true;

    /**
     * 判断当前是否开启拦截下线功能。
     * 打包时确定，零动态 I/O 开销与反射开销。
     */
    public static boolean isKickInterceptEnabled() {
        return ENABLE_KICK_INTERCEPT;
    }

    // Verbose logging (output to LSPosed log via XposedBridge.log)
    public static boolean VERBOSE_LOGGING = true;

    // Fake device info (used when spoofing is enabled)
    public static String FAKE_IMEI = null; // null = use real device info
    public static String FAKE_ANDROID_ID = null;
    public static String FAKE_SERIAL = null;

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        loadPackageParam = lpparam;
        classLoader = lpparam.classLoader;
    }

    public static ClassLoader getClassLoader() {
        return classLoader;
    }
}
