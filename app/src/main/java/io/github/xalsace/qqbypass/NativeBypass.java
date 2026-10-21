package io.github.xalsace.qqbypass;

/**
 * JNI bridge for native hooks
 *
 * This class loads the native library and provides interface
 * to initialize and check native hook status.
 */
public class NativeBypass {

    private static final String TAG = "NativeBypass";
    private static boolean libraryLoaded = false;

    static {
        loadLibraries();
    }

    private static synchronized void loadLibraries() {
        if (libraryLoaded) return;

        // Clean up any stale .so files previously dropped in code_cache to prevent detection
        try {
            java.io.File cacheDir = new java.io.File("/data/data/com.tencent.mobileqq/code_cache");
            if (cacheDir.exists() && cacheDir.isDirectory()) {
                java.io.File[] staleFiles = cacheDir.listFiles();
                if (staleFiles != null) {
                    for (java.io.File f : staleFiles) {
                        String name = f.getName();
                        if (name.contains("bytehook") || name.contains("native-bypass") || name.contains("libc++_shared")) {
                            f.delete();
                            XposedEntry.log("Deleted stale library from code_cache: " + name);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        // 1. First, check if module APK directory contains pre-extracted native libraries in lib/arm64
        try {
            String moduleApkPath = XposedEntry.MODULE_PATH;
            if (moduleApkPath == null) {
                // Find module APK path from /proc/self/maps
                java.io.File maps = new java.io.File("/proc/self/maps");
                if (maps.exists()) {
                    try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(maps))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            if (line.contains("io.github.xalsace.qqbypass") && line.contains(".apk")) {
                                int idx = line.indexOf('/');
                                if (idx != -1) {
                                    moduleApkPath = line.substring(idx).trim();
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (moduleApkPath != null) {
                java.io.File apkFile = new java.io.File(moduleApkPath);
                java.io.File parent = apkFile.getParentFile();
                if (parent != null) {
                    java.io.File[] candidateDirs = new java.io.File[] {
                        new java.io.File(parent, "lib/arm64"),
                        new java.io.File(parent, "lib/arm64-v8a"),
                        new java.io.File(parent, "lib/arm")
                    };
                    for (java.io.File libDir : candidateDirs) {
                        java.io.File nativeBypassSo = new java.io.File(libDir, "libnative-bypass.so");
                        if (nativeBypassSo.exists()) {
                            // 1. First load libshadowhook.so (critical dependency for libbytehook.so)
                            java.io.File shadowhookSo = new java.io.File(libDir, "libshadowhook.so");
                            if (shadowhookSo.exists()) {
                                try {
                                    System.load(shadowhookSo.getAbsolutePath());
                                    XposedEntry.log("[NativeBypass] Successfully loaded " + shadowhookSo.getAbsolutePath());
                                } catch (Throwable t) {
                                    XposedEntry.logError("[NativeBypass] Failed to load libshadowhook.so: " + t.getMessage(), t);
                                }
                            }

                            // 2. Next load libbytehook.so (critical dependency for libnative-bypass.so)
                            java.io.File bytehookSo = new java.io.File(libDir, "libbytehook.so");
                            if (bytehookSo.exists()) {
                                try {
                                    System.load(bytehookSo.getAbsolutePath());
                                    XposedEntry.log("[NativeBypass] Successfully loaded " + bytehookSo.getAbsolutePath());
                                } catch (Throwable t) {
                                    XposedEntry.logError("[NativeBypass] Failed to load libbytehook.so: " + t.getMessage(), t);
                                }
                            }

                            // 3. Load libc++_shared.so if present (for backward compatibility)
                            java.io.File cppShared = new java.io.File(libDir, "libc++_shared.so");
                            if (cppShared.exists()) {
                                try {
                                    System.load(cppShared.getAbsolutePath());
                                    XposedEntry.log("[NativeBypass] Successfully loaded " + cppShared.getAbsolutePath());
                                } catch (Throwable t) {
                                    XposedEntry.logError("[NativeBypass] Failed to load libc++_shared.so: " + t.getMessage(), t);
                                }
                            }

                            // 4. Finally load libnative-bypass.so
                            System.load(nativeBypassSo.getAbsolutePath());
                            XposedEntry.log("[NativeBypass] Successfully loaded " + nativeBypassSo.getAbsolutePath());
                            libraryLoaded = true;
                            return;
                        }
                    }
                }
            }
        } catch (Throwable e) {
            XposedEntry.logError("[NativeBypass] Failed to load directly from module libDir: " + e.getMessage(), e);
        }

        // 2. Fallback to System.loadLibrary
        try {
            try {
                System.loadLibrary("shadowhook");
            } catch (Throwable ignored) {}
            try {
                System.loadLibrary("bytehook");
            } catch (Throwable t) {
                try {
                    com.bytedance.android.bytehook.ByteHook.init();
                } catch (Throwable ignored) {}
            }
            System.loadLibrary("native-bypass");
            libraryLoaded = true;
            XposedEntry.log("[NativeBypass] Successfully loaded via fallback System.loadLibrary");
            return;
        } catch (Throwable e) {
            XposedEntry.logError("All native library loading strategies failed: " + e.getMessage(), e);
        }
    }

    /**
     * Check if native library is loaded
     */
    public static boolean isLibraryLoaded() {
        if (!libraryLoaded) {
            loadLibraries();
        }
        return libraryLoaded;
    }

    /**
     * Initialize native hooks
     * This should be called early in QQ's lifecycle
     */
    public static void initNativeHooks() {
        if (!libraryLoaded) {
            XposedEntry.log("Native library not loaded, cannot init hooks");
            return;
        }

        try {
            initNativeHooksNative();
        } catch (Throwable t) {
            XposedEntry.logError("Failed to init native hooks", t);
        }
    }

    /**
     * Check if native hooks are installed
     */
    public static boolean isHooksInstalled() {
        if (!libraryLoaded) {
            return false;
        }

        try {
            return isHooksInstalledNative();
        } catch (Throwable t) {
            XposedEntry.logError("Failed to check hook status", t);
            return false;
        }
    }

    /**
     * Get hook status message
     */
    public static String getHookStatus() {
        if (!libraryLoaded) {
            return "Native library not loaded";
        }

        try {
            return getHookStatusNative();
        } catch (Throwable t) {
            return "Error getting hook status: " + t.getMessage();
        }
    }

    /**
     * Notify Native layer about Java detection event
     * This enables Java → Native communication
     */
    public static void notifyDetection(String event, String data) {
        if (!libraryLoaded) {
            return;
        }

        try {
            notifyDetectionNative(event, data);
        } catch (Throwable t) {
            XposedEntry.log("Failed to notify native layer: " + t.getMessage());
        }
    }

    /**
     * Check if specific Native hook is active
     */
    public static boolean isHookActive(String hookName) {
        if (!libraryLoaded) {
            return false;
        }

        try {
            return isHookActiveNative(hookName);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Get detailed hook statistics
     */
    public static String getHookStatistics() {
        if (!libraryLoaded) {
            return "Native layer unavailable";
        }

        try {
            return getHookStatisticsNative();
        } catch (Throwable t) {
            return "Error: " + t.getMessage();
        }
    }

    // Native methods
    private static native void initNativeHooksNative();
    private static native boolean isHooksInstalledNative();
    private static native String getHookStatusNative();
    private static native void notifyDetectionNative(String event, String data);
    private static native boolean isHookActiveNative(String hookName);
    private static native String getHookStatisticsNative();
    public static native int getNativeHookTotal();
    public static native int getNativeHookSuccess();
    public static native int getNativeHookFailed();
    public static native String getNativeFailedHooks();
}
