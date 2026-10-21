package io.github.xalsace.qqbypass.hooks;

import android.os.Build;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * 设备修改受管 Hook (Device Modification & Spoofing Hook)
 *
 * 条件编译受管类：仅在 CompileHookConfig.ENABLE_DEVICE_SPOOF 为 true 时编译打包并生效。
 * 带对应设备参数 (FAKE_BRAND, FAKE_MODEL, FAKE_IMEI, FAKE_ANDROID_ID, FAKE_SERIAL, FAKE_MAC 等)。
 * 若设置为 false，该类在打包时将被 R8 完全剥离剔除，绝不计入 Hook 统计总数。
 */
public class DeviceInfoHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_DEVICE_SPOOF) return;

        try {
            spoofBuildFields();
            hookTelephonyManager();
            hookBuildSerial();
            hookSystemProperties();
            hookAndroidId();
            hookWifiMac();
            hookPandoraMonitor();
        } catch (Throwable t) {
            XposedEntry.logError("Failed to initialize DeviceInfoHook: " + t.getMessage(), t);
        }
    }

    private static void spoofBuildFields() {
        setStaticField(Build.class, "BRAND", CompileHookConfig.FAKE_BRAND);
        setStaticField(Build.class, "MANUFACTURER", CompileHookConfig.FAKE_MANUFACTURER);
        setStaticField(Build.class, "MODEL", CompileHookConfig.FAKE_MODEL);
        setStaticField(Build.class, "PRODUCT", CompileHookConfig.FAKE_PRODUCT);
        setStaticField(Build.class, "DEVICE", CompileHookConfig.FAKE_DEVICE);
        setStaticField(Build.class, "BOARD", CompileHookConfig.FAKE_BOARD);
        setStaticField(Build.class, "HARDWARE", CompileHookConfig.FAKE_HARDWARE);
        setStaticField(Build.class, "FINGERPRINT", CompileHookConfig.FAKE_FINGERPRINT);
        setStaticField(Build.class, "SERIAL", CompileHookConfig.FAKE_SERIAL);
    }

    private static void setStaticField(Class<?> clazz, String fieldName, String value) {
        if (value == null) return;
        try {
            Field f = clazz.getDeclaredField(fieldName);
            f.setAccessible(true);
            Field mod = Field.class.getDeclaredField("modifiers");
            mod.setAccessible(true);
            mod.setInt(f, f.getModifiers() & ~Modifier.FINAL);
            f.set(null, value);
        } catch (Throwable ignored) {}
    }

    private static void hookTelephonyManager() {
        String[] methods = {"getImei", "getDeviceId", "getMeid"};
        for (String method : methods) {
            HookUtils.hookAllMethods("android.telephony.TelephonyManager", method,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (CompileHookConfig.FAKE_IMEI != null) {
                            param.setResult(CompileHookConfig.FAKE_IMEI);
                        }
                    }
                });
        }

        HookUtils.hookAllMethods("android.telephony.TelephonyManager", "getSimSerialNumber",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (CompileHookConfig.FAKE_SERIAL != null) {
                        param.setResult(CompileHookConfig.FAKE_SERIAL);
                    }
                }
            });
    }

    private static void hookBuildSerial() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            HookUtils.hookMethod(Build.class, "getSerial",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (CompileHookConfig.FAKE_SERIAL != null) {
                            param.setResult(CompileHookConfig.FAKE_SERIAL);
                        }
                    }
                });
        }
    }

    private static void hookSystemProperties() {
        HookUtils.hookAllMethods("android.os.SystemProperties", "get",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.boot.serialno".equals(key) || "gsm.serial".equals(key)) {
                            if (CompileHookConfig.FAKE_SERIAL != null) param.setResult(CompileHookConfig.FAKE_SERIAL);
                        } else if ("ro.product.model".equals(key)) {
                            if (CompileHookConfig.FAKE_MODEL != null) param.setResult(CompileHookConfig.FAKE_MODEL);
                        } else if ("ro.product.brand".equals(key)) {
                            if (CompileHookConfig.FAKE_BRAND != null) param.setResult(CompileHookConfig.FAKE_BRAND);
                        } else if ("ro.product.manufacturer".equals(key)) {
                            if (CompileHookConfig.FAKE_MANUFACTURER != null) param.setResult(CompileHookConfig.FAKE_MANUFACTURER);
                        } else if ("ro.build.fingerprint".equals(key)) {
                            if (CompileHookConfig.FAKE_FINGERPRINT != null) param.setResult(CompileHookConfig.FAKE_FINGERPRINT);
                        }
                    }
                }
            });
    }

    private static void hookAndroidId() {
        HookUtils.hookAllMethods("android.provider.Settings.Secure", "getString",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        String key = String.valueOf(param.args[1]);
                        if ("android_id".equals(key) && CompileHookConfig.FAKE_ANDROID_ID != null) {
                            param.setResult(CompileHookConfig.FAKE_ANDROID_ID);
                        }
                    }
                }
            });
    }

    private static void hookWifiMac() {
        HookUtils.hookAllMethods("android.net.wifi.WifiInfo", "getMacAddress",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (CompileHookConfig.FAKE_MAC != null) {
                        param.setResult(CompileHookConfig.FAKE_MAC);
                    }
                }
            });
    }

    private static void hookPandoraMonitor() {
        HookUtils.hookAllMethods("com.tencent.qmethod.pandoraex.monitor.DeviceInfoMonitor", "getImei",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (CompileHookConfig.FAKE_IMEI != null) {
                        param.setResult(CompileHookConfig.FAKE_IMEI);
                    }
                }
            });
    }
}
