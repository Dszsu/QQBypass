package io.github.xalsace.qqbypass.hooks;

import android.os.Debug;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Debug/Emulator Detection Bypass
 * Dynamically locates and neutralizes debugging and emulator checks
 */
public class DynamicDebugDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_DEBUG_BYPASS) return;

        // Universal hooks: Android debug APIs
        hookDebugAPIs();

        // Dynamic hooks: DexKit-discovered debug/emulator checkers
        new Thread(() -> {
            try {
                // Wait for the single shared bridge; false in a subprocess (gated off).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicDebug: DexKit not available, skipping");
                    return;
                }
                hookDebugCheckers(lpparam);
                if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_EMULATOR_SPOOF) {
                    hookEmulatorCheckers(lpparam);
                }

            } catch (Throwable e) {
                XposedEntry.log("Dynamic debug detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookDebugAPIs() {
        // Debug.isDebuggerConnected()
        HookUtils.hookMethod(Debug.class, "isDebuggerConnected",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });

        // Debug.waitingForDebugger()
        HookUtils.hookMethod(Debug.class, "waitingForDebugger",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });

        // Settings.Global & Settings.Secure adb_enabled / development_settings_enabled
        try {
            HookUtils.hookAllMethods("android.provider.Settings$Global", "getInt", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            param.setResult(0);
                        }
                    }
                }
            });

            HookUtils.hookAllMethods("android.provider.Settings$Global", "getString", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            param.setResult("0");
                        }
                    }
                }
            });

            HookUtils.hookAllMethods("android.provider.Settings$Secure", "getInt", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            param.setResult(0);
                        }
                    }
                }
            });

            HookUtils.hookAllMethods("android.provider.Settings$Secure", "getString", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            param.setResult("0");
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook Settings debug properties: " + t.getMessage());
        }
    }

    private static void hookDebugCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedEntry.log("DynamicDebug: Querying debug checkers from DexKitDetector...");
            List<DexMethodData> debugCheckers = DexKitDetector.findDebugCheckers();
            List<DexMethodData> tracerPidReaders = DexKitDetector.findTracerPidReaders();

            XposedEntry.log("DynamicDebug: Found " + debugCheckers.size() + " debug checkers");
            XposedEntry.log("DynamicDebug: Found " + tracerPidReaders.size() + " TracerPid readers");

            hookCheckerList(lpparam, debugCheckers, "Debug");
            hookCheckerList(lpparam, tracerPidReaders, "TracerPid");

        } catch (Throwable e) {
            XposedEntry.log("Failed to hook debug checkers: "
                + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    private static void hookEmulatorCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedEntry.log("DynamicDebug: Querying emulator checkers from DexKitDetector...");
            List<DexMethodData> emulatorCheckers = DexKitDetector.findEmulatorCheckers();

            XposedEntry.log("DynamicDebug: Found " + emulatorCheckers.size() + " emulator checkers");

            hookCheckerList(lpparam, emulatorCheckers, "Emulator");

        } catch (Exception e) {
            XposedEntry.log("Failed to hook emulator checkers: " + e.getMessage());
        }
    }

    private static void hookCheckerList(XC_LoadPackage.LoadPackageParam lpparam,
                                        List<DexMethodData> checkers, String type) {
        for (DexMethodData methodData : checkers) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

                // Exclude static initializers, constructors, and object life-cycle methods
                if ("<clinit>".equals(methodName) || "<init>".equals(methodName)) {
                    continue;
                }

                // Exclude non-security framework, UI, and threading classes
                if (className.contains("DisplayUtil") || className.contains("ScreenUtil")
                        || className.contains("SystemBar") || className.contains("DimensionsUtil")
                        || className.contains("richframework") || className.contains("RFWThread")
                        || className.contains("GameActivity") || className.contains("MsgRespHandler")
                        || className.contains("PushSvc") || className.contains("SLAReporter")
                        || className.contains("LagObserver") || className.contains("DeviceInfo")) {
                    continue;
                }

                Member method;
                try {
                    method = methodData.getMethodInstance(lpparam.classLoader);
                } catch (Throwable t) {
                    continue;
                }

                HookUtils.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();

                        // Neutralize positive detection results
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log(type + " checker neutralized: " + className);
                        }

                        // Neutralize non-zero detection codes
                        if (result instanceof Integer && (Integer) result != 0) {
                            param.setResult(0);
                            XposedEntry.log(type + " detection code zeroed: " + className);
                        }

                        // Normalize detection result strings to genuine device string (never empty string)
                        if (result instanceof String) {
                            String str = (String) result;
                            if (isSuspiciousString(str)) {
                                param.setResult("unknown");
                                XposedEntry.log(type + " result string normalized: " + className);
                            }
                        }
                    }
                });

                XposedEntry.log("Hooked " + type + " checker: " + className + "." + methodName);

            } catch (Exception e) {
                XposedEntry.log("Failed to hook " + type + " checker: " + e.getMessage());
            }
        }
    }

    private static boolean isSuspiciousString(String str) {
        if (str == null || str.isEmpty()) return false;
        String lower = str.toLowerCase();

        return lower.contains("debug") || lower.contains("tracer")
            || lower.contains("goldfish") || lower.contains("qemu")
            || lower.contains("emulator") || lower.contains("genymotion");
    }
}
