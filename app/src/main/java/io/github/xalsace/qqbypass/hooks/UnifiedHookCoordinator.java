package io.github.xalsace.qqbypass.hooks;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.NativeBypass;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Unified Hook Coordinator
 *
 * This module coordinates between Java and Native hooks to provide
 * seamless protection across both layers.
 *
 * Java Hook → If failed → Try Native Hook
 * Native Hook → Notify Java layer
 */
public class UnifiedHookCoordinator {

    private static boolean nativeLayerAvailable = false;

    public static void initialize(XC_LoadPackage.LoadPackageParam lpparam) {
        // Check Native layer availability
        nativeLayerAvailable = NativeBypass.isLibraryLoaded();

        if (nativeLayerAvailable) {
            initNativeIntegration();
        }

        // Install coordinated hooks
        installCoordinatedHooks(lpparam);
    }

    /**
     * Initialize Native integration
     */
    private static void initNativeIntegration() {
        // Initialize Native hooks
        NativeBypass.initNativeHooks();

        // Register callback from Native layer
        registerNativeCallbacks();
    }

    /**
     * Register callbacks for Native → Java communication
     */
    private static void registerNativeCallbacks() {
        // Native layer can notify Java layer through JNI
        // e.g., when a detection is blocked at Native level
    }

    /**
     * Install hooks with Java/Native coordination
     */
    private static void installCoordinatedHooks(XC_LoadPackage.LoadPackageParam lpparam) {
        // Setup bidirectional communication
        setupCommunicationChannel(lpparam);
    }

    public static void notifyNativeIfAvailable(String event, String data) {
        if (!nativeLayerAvailable) return;
        notifyNativeLayer(event, data);
    }

    /**
     * Setup bidirectional communication
     */
    private static void setupCommunicationChannel(XC_LoadPackage.LoadPackageParam lpparam) {
        // Java can query Native status
        // Native can notify Java about detections

        if (nativeLayerAvailable) {
            // Check Native hook status periodically
            new Thread(() -> {
                try {
                    Thread.sleep(3000);
                    NativeBypass.getHookStatus();
                } catch (Exception ignored) {
                }
            }).start();
        }
    }

    /**
     * Notify Native layer about Java detections
     */
    private static void notifyNativeLayer(String event, String data) {
        if (!nativeLayerAvailable) return;

        try {
            // JNI call to Native layer
            NativeBypass.notifyDetection(event, data);
        } catch (Throwable t) {
            // Silent fail
        }
    }

    /**
     * Check if path is sensitive
     */
    private static boolean isSensitivePath(String path) {
        if (path == null) return false;

        String[] sensitivePaths = {
            "/system/bin/su",
            "/system/xbin/su",
            "/data/adb/magisk",
            "/data/adb/lsposed"
        };

        for (String sensitive : sensitivePaths) {
            if (path.contains(sensitive)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get protection level
     */
    public static String getProtectionLevel() {
        if (nativeLayerAvailable && NativeBypass.isHooksInstalled()) {
            return "Full (80%)";
        } else if (nativeLayerAvailable) {
            return "Native loading (60%)";
        } else {
            return "Java only (30%)";
        }
    }

    /**
     * 异步等待 Native 层安装完成后，输出全量统一汇总日志。
     */
    public static void reportFinalProtectionLevelAsync() {
        reportSummaryLogAsync(null);
    }

    public static void reportSummaryLogAsync(final XC_LoadPackage.LoadPackageParam lpparam) {
        new Thread(() -> {
            if (nativeLayerAvailable) {
                final int maxWaitMs = 5000;   // 最多等 5 秒
                final int intervalMs = 150;
                int waited = 0;

                while (waited < maxWaitMs) {
                    if (NativeBypass.isHooksInstalled()) {
                        break;
                    }
                    try {
                        Thread.sleep(intervalMs);
                        waited += intervalMs;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            // 输出最终唯一的 Hook 汇总统计日志
            String procName = (lpparam != null && lpparam.processName != null) ? lpparam.processName : "";
            io.github.xalsace.qqbypass.utils.HookTracker.printSummaryReport(procName);
        }, "QQBypass-SummaryReporter").start();
    }
}
