package io.github.xalsace.qqbypass;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.hooks.*;

/**
 * QQBypass - Comprehensive Detection Bypass Module
 *
 * This module provides multi-layered protection against QQ's environment detection:
 * - Java Layer: Root/Xposed/Debug detection bypass (30%)
 * - Native Layer: libc/libfekit/libturingxq hooks (70%)
 * - Network reporting interception
 * - Device info spoofing with cross-validation protection
 */
import de.robv.android.xposed.IXposedHookZygoteInit;

public class XposedEntry implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    private static final String TAG = "QQBypass";
    private static final String TARGET_PACKAGE = "com.tencent.mobileqq";
    public static String MODULE_PATH = null;

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        MODULE_PATH = startupParam.modulePath;
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        // Initialize configuration and detect host version profile
        HookConfig.init(lpparam);
        io.github.xalsace.qqbypass.version.HostVersionManager.init(lpparam);
        io.github.xalsace.qqbypass.utils.ReportAuditManager.setProcessName(lpparam.processName);

        // Process gate: DexKit parses the whole ~112MB APK, so DexKit is strictly gated to isMainProcess.
        // Universal framework hooks and security libraries run across ALL processes (:MSF, :video, :tool, etc.)
        // to prevent security library leaks (e.g., :video running unhooked libqsec/libfekit leading to flag-2 kicks).
        boolean isMainProcess = lpparam.packageName.equals(lpparam.processName);
        DexKitDetector.setEnabled(isMainProcess && HookConfig.ENABLE_DEXKIT);

        // === DexKit Disk Cache Check (< 5ms) ===
        // If valid cache exists on disk, load cached method signatures directly
        boolean cacheHit = DexKitDetector.tryInitWithCache(lpparam);
        if (!cacheHit && isMainProcess && HookConfig.ENABLE_DEXKIT) {
            // === DexKit Dynamic Detection (Background Thread) on Cache Miss ===
            new Thread(() -> {
                try {
                    String apkPath = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;
                    if (apkPath == null) {
                        try {
                            android.content.Context context = (android.content.Context)
                                de.robv.android.xposed.XposedHelpers.callStaticMethod(
                                    de.robv.android.xposed.XposedHelpers.findClass(
                                        "android.app.ActivityThread", null),
                                    "currentApplication");
                            if (context != null && context.getApplicationInfo() != null) {
                                apkPath = context.getApplicationInfo().sourceDir;
                            }
                        } catch (Throwable ignored) { }
                    }

                    if (apkPath != null) {
                        DexKitDetector.scanAndCache(apkPath, lpparam);
                    }
                } catch (Throwable e) {
                    logError("DexKit scan failed: " + e.getMessage(), e);
                }
            }).start();
        }

        try {
            // === Initialize Unified Hook Coordinator ===
            // This coordinates Java and Native layers seamlessly
            UnifiedHookCoordinator.initialize(lpparam);

            // === Java Layer Hooks (30% detection coverage) ===

            // Layer 1: Network reporting interception (highest priority)
            NetworkReportHook.hook(lpparam);

            // Layer 2: Root detection bypass (DexKit-based dynamic version)
            DynamicRootDetectionHook.hook(lpparam);

            // Layer 3: Xposed/Hook framework detection mitigation (DexKit-based dynamic version)
            DynamicXposedDetectionHook.hook(lpparam);

            // Layer 4: Debug detection bypass (DexKit-based dynamic version)
            DynamicDebugDetectionHook.hook(lpparam);

            // Layer 5: Runtime monitoring bypass (DexKit-based dynamic version)
            DynamicRuntimeMonitorHook.hook(lpparam);

            // Layer 6: QQ 9.3.50 detection-point completion (real risk/kick targets)
            QQ950PatchHook.hook(lpparam);

            // Layer 7: QAuxv (QNotified) compatibility
            if (isMainProcess && CompileHookConfig.ENABLE_QAUXILIARY_FILE_COMPAT) {
                io.github.xalsace.qqbypass.hooks.QAuxvCompatHook.hook(lpparam);
            }

            // Layer 8: Security Libraries & FEKit Censor Enhancement (ShadowHook, QQPerfTool, Desensitization, Dtc, fe.utils.a)
            SecurityLibrariesEnhanceHook.hook(lpparam);

            // Layer 9: Dynamic secondary dex & Tinker hot patch lifecycle monitor
            hookClassLoaderAndLifecycle(lpparam);

            // Layer 10: Dynamic side-channel defense & physics simulation (Sensors, Battery, Timing benchmark, Traffic)
            io.github.xalsace.qqbypass.defense.SideChannelDefense.hook(lpparam);

            // Layer 11: Managed conditional compile hooks (Kick Intercept, Device Spoof, Emulator Camouflage)
            ManagedHooks.installManagedHooks(lpparam);

            // === Report Status ===
            // 异步等待 Native 层安装完成后，最终统一输出一条汇总报告
            UnifiedHookCoordinator.reportSummaryLogAsync(lpparam);

        } catch (Throwable t) {
            logError("Error during hook initialization: " + t.getMessage(), t);
        }
    }

    /**
     * Initialize native layer hooks (deprecated - now handled by UnifiedHookCoordinator)
     */
    @Deprecated
    private void initNativeHooks() {
        // This method is kept for compatibility but functionality moved to UnifiedHookCoordinator
    }

    private static final java.util.Set<ClassLoader> sObservedLoaders =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static final java.util.concurrent.ExecutorService sLateHookExecutor =
        java.util.concurrent.Executors.newSingleThreadExecutor();

    public static void dispatchLateStageHooks(ClassLoader cl) {
        if (cl == null || sObservedLoaders.contains(cl)) return;
        sObservedLoaders.add(cl);
        try {
            NetworkReportHook.hookLateStage(cl);
            QQ950PatchHook.hookLateStage(cl);
            DynamicRootDetectionHook.hookLateStage(cl);
            SecurityLibrariesEnhanceHook.hookLateStage(cl);
            if (CompileHookConfig.ENABLE_QAUXILIARY_FILE_COMPAT) {
                QAuxvCompatHook.hookLateStage(cl);
            }
            ManagedHooks.hookLateStage(cl);
            io.github.xalsace.qqbypass.version.HostVersionManager.getCurrentProfile().applyVersionSpecificHooks(HookConfig.loadPackageParam, cl);
        } catch (Throwable t) {
            logError("Error dispatching late-stage hooks: " + t.getMessage(), t);
        }
    }

    private static void hookClassLoaderAndLifecycle(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // 1. Hook ContextWrapper.attachBaseContext(Context) for Application
            de.robv.android.xposed.XposedBridge.hookAllMethods(
                android.content.ContextWrapper.class,
                "attachBaseContext",
                new de.robv.android.xposed.XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.thisObject instanceof android.app.Application) {
                            android.content.Context ctx = (android.content.Context) param.args[0];
                            if (ctx != null) {
                                dispatchLateStageHooks(ctx.getClassLoader());
                            }
                        }
                    }
                }
            );
        } catch (Throwable t) {
            log("Failed to hook Application.attachBaseContext: " + t.getMessage());
        }

        try {
            // 2. Hook dalvik.system.BaseDexClassLoader constructors asynchronously to never block main thread
            de.robv.android.xposed.XposedBridge.hookAllConstructors(
                dalvik.system.BaseDexClassLoader.class,
                new de.robv.android.xposed.XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        ClassLoader cl = (ClassLoader) param.thisObject;
                        if (cl != null) {
                            String clStr = cl.toString().toLowerCase();
                            if (clStr.contains("moe.ono") || clStr.contains("lzlnb") || clStr.contains("cnm") ||
                                clStr.contains("qauxv") || clStr.contains("org.lsposed") || clStr.contains("dexkit") ||
                                clStr.contains("cn.jesse") || clStr.contains("lspatch")) {
                                return;
                            }
                            sLateHookExecutor.execute(() -> dispatchLateStageHooks(cl));
                        }
                    }
                }
            );
        } catch (Throwable t) {
            log("Failed to hook BaseDexClassLoader constructors: " + t.getMessage());
        }
    }

    public static void log(String message) {
        if (!HookConfig.VERBOSE_LOGGING) return;
        try {
            android.util.Log.i(TAG, message);
            de.robv.android.xposed.XposedBridge.log("[" + TAG + "] " + message);
        } catch (Throwable ignored) {
        }
    }

    public static void logError(String message, Throwable t) {
        if (!HookConfig.VERBOSE_LOGGING) return;
        try {
            android.util.Log.e(TAG, message, t);
            de.robv.android.xposed.XposedBridge.log("[" + TAG + "] " + message);
            if (t != null) {
                de.robv.android.xposed.XposedBridge.log(t);
            }
        } catch (Throwable ignored) {
        }
    }
}
