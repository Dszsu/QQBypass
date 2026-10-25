package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.io.File;
import java.lang.reflect.Field;

/**
 * Root Detection Bypass Hook
 *
 * Bypasses Java-layer root detection implementations according to 04_检测点清单.md:
 * 1. oicq.wlogin_sdk.request.w.h() & oicq.wlogin_sdk.tools.util.isFileExist() - Wlogin SDK (w.Y=0)
 * 2. org.light.device.LightDeviceUtils.isRooted() (cache field reset)
 * 3. com.tenpay.charge.v2.util.ChargeV2Utils.isDeviceRooted()
 * 4. com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl.isRooted()
 * 5. com.tencent.camerasdk.avreport.DeviceInfo.getDebugInfo()
 */
public class RootDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        // Hook 1: Wlogin SDK root check & isFileExist
        hookWloginRoot();

        // Hook 2: Light Device Utils
        hookLightDeviceRoot();

        // Hook 3: Tenpay charge utils
        hookTenpayRoot();

        // Hook 4: GathererGA UserInfoImpl root check
        hookUserInfoRoot();

        // Hook 5: CameraSDK DeviceInfo debug info sanitization
        hookDeviceInfoDebugInfo();

        // Hook 6: Crash report isXposedInstalled sanitization
        hookCrashReportXposed();

        // Generic file existence checks for su binaries
        hookFileExists();

        // Hook Runtime.exec to prevent su detection
        hookRuntimeExec();
    }

    private static void hookWloginRoot() {
        // 1. Hook w.h() -> force reset static int w.Y = 0
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Class<?> clazz = param.method != null ? param.method.getDeclaringClass() :
                            (param.thisObject != null ? param.thisObject.getClass() : null);
                        if (clazz != null) {
                            Field fieldY = clazz.getDeclaredField("Y");
                            fieldY.setAccessible(true);
                            fieldY.setInt(null, 0);
                            XposedEntry.log("[WloginRoot] Reset w.Y = 0");
                        }
                    } catch (Throwable ignored) {}
                }
            });

        // 2. Hook util.isFileExist(String) -> false for su/root binaries & Bugly backdoors
        HookUtils.hookMethod("oicq.wlogin_sdk.tools.util", "isFileExist", String.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] != null) {
                        String p = (String) param.args[0];
                        if (p.equals("/system/bin/su") || p.equals("/system/xbin/su") || p.equals("/sbin/su")
                                || p.equals("/su/bin/su") || p.equals("/data/local/su") || p.equals("/data/local/bin/su")
                                || DynamicRootDetectionHook.isSuspiciousPath(p)) {
                            param.setResult(false);
                        }
                    }
                }
            });
    }

    private static void hookLightDeviceRoot() {
        HookUtils.hookMethod("org.light.device.LightDeviceUtils", "isRooted",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == Boolean.TRUE) {
                        param.setResult(false);
                    }
                    try {
                        Class<?> clazz = param.thisObject != null ? param.thisObject.getClass() :
                            HookUtils.findClass("org.light.device.LightDeviceUtils", null);
                        if (clazz != null) {
                            Field field = clazz.getDeclaredField("isRooted");
                            field.setAccessible(true);
                            field.set(null, Boolean.FALSE);
                        }
                    } catch (Throwable ignored) {}
                }
            });
    }

    private static void hookTenpayRoot() {
        HookUtils.hookMethod("com.tenpay.charge.v2.util.ChargeV2Utils", "isDeviceRooted",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == Boolean.TRUE) {
                        param.setResult(false);
                    }
                }
            });
    }

    private static void hookUserInfoRoot() {
        HookUtils.hookAllMethods("com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", "isRooted",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res != null) {
                        try {
                            for (Field f : res.getClass().getDeclaredFields()) {
                                f.setAccessible(true);
                                if (f.getType() == Object.class || f.getType() == Boolean.class) {
                                    f.set(res, Boolean.FALSE);
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            });
    }

    private static void hookDeviceInfoDebugInfo() {
        HookUtils.hookAllMethods("com.tencent.camerasdk.avreport.DeviceInfo", "getDebugInfo",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        s = s.replaceAll("ro\\.secure\\|[^;]*;", "ro.secure|1;")
                             .replaceAll("ro\\.debuggable\\|[^;]*;", "ro.debuggable|0;")
                             .replaceAll("tracer_pid\\|[^;]*;", "tracer_pid|0;");
                        param.setResult(s);
                    }
                }
            });
    }

    private static void hookCrashReportXposed() {
        HookUtils.hookAllMethods("com.tencent.qqperf.monitor.crash.c", "c",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (s.contains("isXposedInstalled: true")) {
                            param.setResult(s.replace("isXposedInstalled: true", "isXposedInstalled: false"));
                            XposedEntry.log("[CrashReport] Sanitized isXposedInstalled: true -> false");
                        }
                    }
                }
            });

        HookUtils.hookAllMethods("com.tencent.mobileqq.utils.PackageUtil", "isAppInstalled",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0) {
                        for (Object arg : param.args) {
                            if (arg instanceof String) {
                                String pkg = (String) arg;
                                if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                                    param.setResult(false);
                                    return;
                                }
                            }
                        }
                    }
                }
            });
    }

    private static void hookFileExists() {
        // Hook File status methods to hide su binaries and root artifacts
        XC_MethodHook fileCheckHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();
                if (isSuspiciousPath(path)) {
                    String methodName = param.method.getName();
                    if ("length".equals(methodName)) {
                        param.setResult(0L);
                    } else {
                        param.setResult(false);
                    }
                }
            }
        };

        HookUtils.hookMethod(File.class, "exists", fileCheckHook);
        HookUtils.hookMethod(File.class, "canRead", fileCheckHook);
        HookUtils.hookMethod(File.class, "canExecute", fileCheckHook);
        HookUtils.hookMethod(File.class, "length", fileCheckHook);
    }

    private static void hookRuntimeExec() {
        // Hook Runtime.exec to prevent command-based detection
        HookUtils.hookAllMethods("java.lang.Runtime", "exec",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String command = param.args[0].toString();

                        // Block root-detection commands
                        if (command.equals("su") || command.startsWith("su ") || command.contains("/su") || command.contains(" su") ||
                            command.contains("magisk") ||
                            command.contains("which su") || command.contains("which ksu") || command.contains("which magisk") || command.contains("which apatch") ||
                            (command.contains("mount") && command.contains("grep"))) {

                            XposedEntry.log("Blocked Runtime.exec: " + command);
                            // Return a dummy process that exits immediately
                            param.setResult(new ProcessBuilder("echo").start());
                        }
                    }
                }
            });
    }

    private static boolean isSuspiciousPath(String path) {
        if (path == null) return false;
        // Comprehensive list of root-related paths
        String[] suspiciousPaths = {
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/bin/.ext/.su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            // Magisk & KernelSU & APatch
            "/data/adb",
            "/sbin/.magisk",
            "/cache/magisk.log",
            "mountify",
            "tricky_store",
            "zygisksu",
            "metamodule",
            "busybox",
            // Bugly 18 backdoor & su probing paths (04_检测点清单.md)
            "cufsdosck",
            "cufsmgr",
            "cufaevdd",
            "conbb",
            "daemonsu",
            "permmgrd",
            "360sguard"
        };

        for (String suspicious : suspiciousPaths) {
            if (path.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }
}
