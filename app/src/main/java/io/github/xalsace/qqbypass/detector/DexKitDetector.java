package io.github.xalsace.qqbypass.detector;

import android.content.Context;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.config.HookConfig;

/**
 * DexKit-based detector for dynamically locating obfuscated detection points in QQ.
 * Supports persistent disk caching so DexKit and multi-DEX parsing are skipped on subsequent runs
 * as long as the application and module versions remain unchanged.
 */
public class DexKitDetector {
    private static final String TAG = "DexKitDetector";
    private static volatile DexKitBridge dexKitBridge;
    private static volatile boolean enabled = false; // set true only in the gated (main) process
    private static volatile boolean ready = false;   // cache loaded or bridge created and usable
    private static final Object initLock = new Object();
    private static final CountDownLatch readyLatch = new CountDownLatch(1);

    // Cache of discovered method metadata across all categories
    private static final Map<String, List<DexMethodData>> detectionCache = new ConcurrentHashMap<>();

    /** Enable DexKit for this process. Call only in the main process. */
    public static void setEnabled(boolean value) { enabled = value; }
    public static boolean isEnabled() { return enabled; }
    public static boolean isReady() { return ready; }
    public static DexKitBridge getBridge() { return dexKitBridge; }

    /**
     * Attempts to initialize from persistent disk cache.
     * Returns true if valid cache was hit and loaded in <5ms.
     */
    public static boolean tryInitWithCache(XC_LoadPackage.LoadPackageParam lpparam) {
        if (ready) return true;
        synchronized (initLock) {
            if (ready) return true;
            Map<String, List<DexMethodData>> cached = DexKitCacheManager.loadCache(lpparam);
            if (cached != null && !cached.isEmpty()) {
                detectionCache.putAll(cached);
                ready = true;
                readyLatch.countDown();
                XposedBridge.log("[" + TAG + "] Initialized via disk cache! Total cached categories: " + cached.size());
                return true;
            }
        }
        return false;
    }

    /**
     * Block until the shared bridge or cache is ready, up to timeoutMs.
     * Returns false immediately in a non-enabled (sub)process if cache is not present.
     */
    public static boolean awaitReady(long timeoutMs) {
        if (ready) return true;
        if (!enabled) return false;
        try {
            readyLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        return ready;
    }

    /**
     * Initialize DexKit native bridge if cache was missed.
     */
    public static void init(String apkPath) {
        if (ready && dexKitBridge != null) return;
        if (!enabled || !HookConfig.ENABLE_DEXKIT || android.os.Build.VERSION.SDK_INT >= 35) {
            ready = true;
            readyLatch.countDown();
            return;
        }
        synchronized (initLock) {
            if (dexKitBridge != null) return;
            try {
                XposedBridge.log("[" + TAG + "] Initializing DexKit with APK: " + apkPath);
                loadDexKitNativeLib();
                dexKitBridge = DexKitBridge.create(apkPath);
                try {
                    dexKitBridge.setThreadNum(1);
                } catch (Throwable ignored) {}
                ready = true;
                XposedBridge.log("[" + TAG + "] DexKit initialized successfully");
            } catch (Throwable e) {
                XposedBridge.log("[" + TAG + "] Failed to initialize DexKit: "
                    + e.getClass().getName() + ": " + e.getMessage());
            } finally {
                readyLatch.countDown();
            }
        }
    }

    /**
     * Full scan and cache generation workflow on cache miss.
     */
    public static void scanAndCache(String apkPath, XC_LoadPackage.LoadPackageParam lpparam) {
        if (!enabled || !HookConfig.ENABLE_DEXKIT || android.os.Build.VERSION.SDK_INT >= 35) {
            XposedBridge.log("[" + TAG + "] DexKit dynamic scan skipped: disabled or Android 15/16+ jemalloc protection");
            ready = true;
            readyLatch.countDown();
            return;
        }
        init(apkPath);
        if (dexKitBridge == null) {
            XposedBridge.log("[" + TAG + "] DexKit bridge unavailable, scan aborted");
            return;
        }

        try {
            XposedBridge.log("[" + TAG + "] === Starting dynamic DexKit scan for all categories ===");
            findRuntimeExecCallers();
            findProcessBuilderCallers();
            findSuPathCheckers();
            findSuspiciousPackageQueries();
            findArtHookDetectors();
            findMapsReaders();
            findWtloginErrorHandlers();
            findQSecHookDetectors();
            findDebugCheckers();
            findTracerPidReaders();
            findEmulatorCheckers();
            findImeiReaders();
            findAndroidIdReaders();
            findSerialReaders();
            findTuringFdProcReaders();
            findSafeCenterPushHandlers();
            findRepackCheckers();
            findTuringBridges();

            XposedBridge.log("[" + TAG + "] === Dynamic scan complete, writing to disk cache ===");
            DexKitCacheManager.saveCache(lpparam, detectionCache);

        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] Error during scanAndCache: " + t.getMessage());
        }
    }

    public static void init(Context context) {
        if (context != null && context.getApplicationInfo() != null) {
            init(context.getApplicationInfo().sourceDir);
        } else {
            readyLatch.countDown();
        }
    }

    private static void loadDexKitNativeLib() {
        try {
            System.loadLibrary("dexkit");
            XposedBridge.log("[" + TAG + "] loadLibrary(dexkit) OK");
        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] loadLibrary(dexkit) failed: " + t.getMessage());
            throw t;
        }
    }

    private static List<DexMethodData> toDexMethodList(List<MethodData> list) {
        List<DexMethodData> result = new ArrayList<>();
        if (list != null) {
            for (MethodData md : list) {
                result.add(DexMethodData.from(md));
            }
        }
        return result;
    }

    // =========================================================================
    // Category Finders
    // =========================================================================

    public static List<DexMethodData> findArtHookDetectors() {
        if (detectionCache.containsKey("art_hook")) {
            return detectionCache.get("art_hook");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for ArtMethod hook detectors...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "ArtMethod", "art_quick", "entry_point", "jni_code",
                "instrumentationExit", "quick_to_interpreter");

            detectionCache.put("art_hook", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " ArtMethod hook detectors");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding ArtMethod detectors: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findMapsReaders() {
        if (detectionCache.containsKey("maps_reader")) {
            return detectionCache.get("maps_reader");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for /proc/self/maps readers...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "/proc/self/maps", "/proc/self/task", "/proc/%d/maps");

            detectionCache.put("maps_reader", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " maps readers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding maps readers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findWtloginErrorHandlers() {
        if (detectionCache.containsKey("wtlogin_error")) {
            return detectionCache.get("wtlogin_error");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for wtlogin error handlers...");
            List<MethodData> raw = new ArrayList<>();

            raw.addAll(dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .declaredClass("com.tencent.mobileqq.msf.core.wtlogin.*")
                        .usingStrings("error", "code", "msg")
                    )
            ));

            raw.addAll(dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .paramTypes("oicq.wlogin_sdk.tools.ErrMsg")
                    )
            ));

            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("wtlogin_error", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " wtlogin error handlers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding wtlogin handlers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findQSecHookDetectors() {
        if (detectionCache.containsKey("qsec_hook")) {
            return detectionCache.get("qsec_hook");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for QSec hook detectors...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "registerHookSo", "nativeFileHook", "isHookedSoLoad", "QSecConfig",
                "all_so_hook", "ArtTiHookTask");

            detectionCache.put("qsec_hook", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " QSec hook detectors");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding QSec detectors: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findRuntimeExecCallers() {
        if (detectionCache.containsKey("runtime_exec")) {
            return detectionCache.get("runtime_exec");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for Runtime.exec callers...");
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("java.lang.Runtime")
                            .name("exec"))
                        .usingStrings("su")
                    )
            );

            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("runtime_exec", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Runtime.exec callers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding Runtime.exec callers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findProcessBuilderCallers() {
        if (detectionCache.containsKey("process_builder")) {
            return detectionCache.get("process_builder");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for ProcessBuilder callers...");
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("java.lang.ProcessBuilder")
                            .name("start"))
                    )
            );

            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("process_builder", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " ProcessBuilder callers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding ProcessBuilder callers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findSuPathCheckers() {
        if (detectionCache.containsKey("su_path")) {
            return detectionCache.get("su_path");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for su path checkers...");
            String[] suPaths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/su/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
                "/data/local/su", "/data/local/xbin/su", "/data/local/bin/su",
                "/data/adb/magisk", "/system/app/Superuser.apk",
                "/data/adb/modules", "/data/adb/lsposed", "/data/adb/ksu", "/data/adb/ap"
            };
            Map<String, DexMethodData> unique = new HashMap<>();
            for (String p : suPaths) {
                try {
                    List<MethodData> found = dexKitBridge.findMethod(
                        FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .addInvoke(MethodMatcher.create()
                                    .declaredClass("java.io.File")
                                    .name("exists"))
                                .usingStrings(p))
                    );
                    for (MethodData m : found) {
                        DexMethodData dmd = DexMethodData.from(m);
                        unique.put(dmd.getDescriptor(), dmd);
                    }
                } catch (Exception e) {
                    XposedBridge.log("[" + TAG + "] su-path query failed for '" + p + "': " + e.getMessage());
                }
            }
            List<DexMethodData> results = new ArrayList<>(unique.values());
            detectionCache.put("su_path", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " su path checkers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding su path checkers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findSuspiciousPackageQueries() {
        if (detectionCache.containsKey("package_query")) {
            return detectionCache.get("package_query");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for suspicious package queries...");
            String[] suspiciousPatterns = {
                "magisk", "xposed", "de.robv.android.xposed", "lsposed", "edxposed",
                "kernelsu", "apatch", "shamiko", "frida", "sandhook"
            };
            Map<String, DexMethodData> unique = new HashMap<>();
            for (String pattern : suspiciousPatterns) {
                try {
                    List<MethodData> found = dexKitBridge.findMethod(
                        FindMethod.create()
                            .matcher(MethodMatcher.create()
                                .addInvoke(MethodMatcher.create()
                                    .declaredClass("android.content.pm.PackageManager")
                                    .name("getPackageInfo"))
                                .usingStrings(pattern))
                    );
                    for (MethodData m : found) {
                        DexMethodData dmd = DexMethodData.from(m);
                        unique.put(dmd.getDescriptor(), dmd);
                    }
                } catch (Exception e) {
                    XposedBridge.log("[" + TAG + "] package-query failed for '" + pattern + "': " + e.getMessage());
                }
            }
            List<DexMethodData> results = new ArrayList<>(unique.values());
            detectionCache.put("package_query", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " package query methods");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding package queries: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findDebugCheckers() {
        if (detectionCache.containsKey("debug_checker")) {
            return detectionCache.get("debug_checker");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for Debug.isDebuggerConnected callers...");
            List<MethodData> rawMethodData = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.os.Debug")
                            .name("isDebuggerConnected"))
                    )
            );
            List<DexMethodData> raw = toDexMethodList(rawMethodData);
            List<DexMethodData> results = new ArrayList<>();
            for (DexMethodData m : raw) {
                String name = m.getMethodName();
                String cls = m.getClassName();
                if ("<clinit>".equals(name) || "<init>".equals(name)) continue;
                if (cls.contains("richframework") || cls.contains("RFWThread")
                    || cls.contains("GameActivity") || cls.contains("MsgRespHandler")
                    || cls.contains("SLAReporter") || cls.contains("LagObserver")) continue;
                results.add(m);
            }
            detectionCache.put("debug_checker", results);
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding debug checkers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findTracerPidReaders() {
        if (detectionCache.containsKey("tracerpid_reader")) {
            return detectionCache.get("tracerpid_reader");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for TracerPid readers...");
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("TracerPid"))
            );
            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("tracerpid_reader", results);
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding TracerPid readers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findEmulatorCheckers() {
        if (detectionCache.containsKey("emulator_checker")) {
            return detectionCache.get("emulator_checker");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for emulator checkers...");
            List<DexMethodData> raw = findMethodsUsingAnyString(
                "goldfish", "ranchu", "qemu", "vbox", "genymotion");
            List<DexMethodData> results = new ArrayList<>();
            for (DexMethodData m : raw) {
                String name = m.getMethodName();
                String cls = m.getClassName();
                if ("<clinit>".equals(name) || "<init>".equals(name)) continue;
                if (cls.contains("DisplayUtil") || cls.contains("ScreenUtil")
                    || cls.contains("SystemBar") || cls.contains("DimensionsUtil")
                    || cls.contains("PushSvc") || cls.contains("DeviceInfo")) continue;
                results.add(m);
            }
            detectionCache.put("emulator_checker", results);
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding emulator checkers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findImeiReaders() {
        if (detectionCache.containsKey("imei_reader")) {
            return detectionCache.get("imei_reader");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.telephony.TelephonyManager")
                            .name("getDeviceId"))
                    )
            );
            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("imei_reader", results);
            return results;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findAndroidIdReaders() {
        if (detectionCache.containsKey("android_id_reader")) {
            return detectionCache.get("android_id_reader");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.provider.Settings$Secure")
                            .name("getString"))
                        .usingStrings("android_id")
                    )
            );
            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("android_id_reader", results);
            return results;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findSerialReaders() {
        if (detectionCache.containsKey("serial_reader")) {
            return detectionCache.get("serial_reader");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .addInvoke(MethodMatcher.create()
                            .declaredClass("android.os.Build")
                            .name("getSerial"))
                    )
            );
            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("serial_reader", results);
            return results;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findTuringFdProcReaders() {
        if (detectionCache.containsKey("turingfd_proc")) {
            return detectionCache.get("turingfd_proc");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            List<MethodData> raw = dexKitBridge.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create()
                        .usingStrings("/proc/%d/cmdline"))
            );
            List<DexMethodData> results = toDexMethodList(raw);
            detectionCache.put("turingfd_proc", results);
            return results;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findSafeCenterPushHandlers() {
        if (detectionCache.containsKey("safecenter_push")) {
            return detectionCache.get("safecenter_push");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for SafeCenter push handlers...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "SafeCenterPushHandler", "onReceive: onReceive push package"
            );
            detectionCache.put("safecenter_push", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " SafeCenter push handlers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding SafeCenter push handlers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findRepackCheckers() {
        if (detectionCache.containsKey("repack_checker")) {
            return detectionCache.get("repack_checker");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for Repack signature checkers...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "sig_check", "SignatureReport", "SignatureResult"
            );
            detectionCache.put("repack_checker", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Repack signature checkers");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding Repack signature checkers: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> findTuringBridges() {
        if (detectionCache.containsKey("turing_bridge")) {
            return detectionCache.get("turing_bridge");
        }
        if (dexKitBridge == null) return new ArrayList<>();

        try {
            XposedBridge.log("[" + TAG + "] Searching for Turing bridge components...");
            List<DexMethodData> results = findMethodsUsingAnyString(
                "TuringSdkInitHelper", "turing risk detect success, deviceToken: ", "turing init failed, error: "
            );
            detectionCache.put("turing_bridge", results);
            XposedBridge.log("[" + TAG + "] Found " + results.size() + " Turing bridge components");
            return results;
        } catch (Exception e) {
            XposedBridge.log("[" + TAG + "] Error finding Turing bridge: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public static List<DexMethodData> getSafeCenterPushHandlers() {
        List<DexMethodData> list = detectionCache.get("safecenter_push");
        return list != null ? list : java.util.Collections.emptyList();
    }

    public static List<DexMethodData> getRepackCheckers() {
        List<DexMethodData> list = detectionCache.get("repack_checker");
        return list != null ? list : java.util.Collections.emptyList();
    }

    public static List<DexMethodData> getTuringBridges() {
        List<DexMethodData> list = detectionCache.get("turing_bridge");
        return list != null ? list : java.util.Collections.emptyList();
    }

    private static List<DexMethodData> findMethodsUsingAnyString(String... markers) {
        Map<String, DexMethodData> unique = new HashMap<>();
        for (String marker : markers) {
            try {
                List<MethodData> found = dexKitBridge.findMethod(
                    FindMethod.create()
                        .matcher(MethodMatcher.create().usingStrings(marker))
                );
                for (MethodData m : found) {
                    DexMethodData dmd = DexMethodData.from(m);
                    unique.put(dmd.getDescriptor(), dmd);
                }
            } catch (Exception e) {
                XposedBridge.log("[" + TAG + "] query failed for '" + marker + "': " + e.getMessage());
            }
        }
        return new ArrayList<>(unique.values());
    }

    public static int getCachedCount() {
        int count = 0;
        for (List<DexMethodData> list : detectionCache.values()) {
            count += list.size();
        }
        return count;
    }

    public static Map<String, List<DexMethodData>> getAllDetectionResults() {
        return new HashMap<>(detectionCache);
    }

    public static void release() {
        synchronized (initLock) {
            if (dexKitBridge != null) {
                try {
                    dexKitBridge.close();
                    XposedBridge.log("[" + TAG + "] DexKit released");
                } catch (Exception e) {
                    XposedBridge.log("[" + TAG + "] Error releasing DexKit: " + e.getMessage());
                } finally {
                    dexKitBridge = null;
                }
            }
        }
    }
}
