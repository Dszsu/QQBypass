package io.github.xalsace.qqbypass.hooks;

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
 * DexKit-based Xposed/LSPosed Detection Bypass
 * Dynamically locates and hooks obfuscated framework detection methods
 */
public class DynamicXposedDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        // Universal hook: Stack trace sanitization (removes xposed/lsposed/qb frames)
        hookStackTrace();

        // ClassLoader and reflection probing bypass (ClassNotFoundException for hook framework queries)
        hookClassLoaderAndReflection(lpparam);

        // Crash reporter (Bugly / QQPerf) xposed status spoofing
        hookBuglyCrashReporter(lpparam);

        // AssetManager and ZipFile asset inspection bypass (conceals xposed_init / module assets)
        hookAssetManager();
        hookZipFile();

        // Dynamic hooks: DexKit-discovered detection points
        new Thread(() -> {
            try {
                // Wait for the shared scan instead of a fixed sleep (the old
                // sleep(5000) raced the scan and read an empty cache).
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicXposed: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookArtMethodDetectors(lpparam);
                hookMapsReaders(lpparam);
                hookQSecDetectors(lpparam);

            } catch (Throwable e) {
                XposedEntry.log("Dynamic Xposed detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookArtMethodDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> artDetectors = DexKitDetector.findArtHookDetectors();
        if (artDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No ArtMethod detectors found by DexKit");
            return;
        }

        for (DexMethodData methodData : artDetectors) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

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

                        // If returns boolean (isHooked check), force false
                        if (result instanceof Boolean && (Boolean) result) {
                            param.setResult(false);
                            XposedEntry.log("ArtMethod detector neutralized: " + className);
                        }

                        // If returns int (hook count), force 0
                        if (result instanceof Integer && (Integer) result > 0) {
                            param.setResult(0);
                            XposedEntry.log("ArtMethod hook count zeroed: " + className);
                        }

                        // If returns List/Array (hooked methods list), force empty
                        if (result instanceof java.util.List && !((java.util.List<?>) result).isEmpty()) {
                            param.setResult(new java.util.ArrayList<>());
                            XposedEntry.log("ArtMethod hook list cleared: " + className);
                        }
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook ArtMethod detector: " + e.getMessage());
            }
        }
    }

    private static void hookMapsReaders(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> mapsReaders = DexKitDetector.findMapsReaders();
        if (mapsReaders.isEmpty()) {
            XposedEntry.log("DynamicXposed: No maps readers found by DexKit");
            return;
        }

        for (DexMethodData methodData : mapsReaders) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

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

                        // If returns String (maps content), filter suspicious lines
                        if (result instanceof String) {
                            String filtered = filterMapsContent((String) result);
                            if (!filtered.equals(result)) {
                                param.setResult(filtered);
                                XposedEntry.log("Maps reader output filtered: " + className);
                            }
                        }

                        // If returns List<String> (maps lines), filter
                        if (result instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) result;
                            if (!list.isEmpty() && list.get(0) instanceof String) {
                                @SuppressWarnings("unchecked")
                                java.util.List<String> lines = (java.util.List<String>) list;
                                java.util.List<String> filtered = filterMapsList(lines);
                                if (filtered.size() != lines.size()) {
                                    param.setResult(filtered);
                                    XposedEntry.log("Maps reader list filtered: " + className);
                                }
                            }
                        }
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook maps reader: " + e.getMessage());
            }
        }
    }

    private static void hookQSecDetectors(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> qsecDetectors = DexKitDetector.findQSecHookDetectors();
        if (qsecDetectors.isEmpty()) {
            XposedEntry.log("DynamicXposed: No QSec detectors found by DexKit");
            return;
        }

        for (DexMethodData methodData : qsecDetectors) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

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
                            XposedEntry.log("QSec detector neutralized: " + className + "." + methodName);
                        }

                        if (result instanceof Integer && (Integer) result != 0) {
                            String mLower = methodName.toLowerCase();
                            if (mLower.contains("check") || mLower.contains("detect")
                                    || mLower.contains("hook") || mLower.contains("is")
                                    || mLower.contains("verify") || mLower.contains("status")
                                    || mLower.contains("scan") || mLower.contains("count")) {
                                param.setResult(0);
                                XposedEntry.log("QSec detection code zeroed: " + className + "." + methodName);
                            }
                        }
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook QSec detector: " + e.getMessage());
            }
        }
    }

    private static String filterMapsContent(String content) {
        if (content == null) return content;

        StringBuilder filtered = new StringBuilder();
        for (String line : content.split("\n")) {
            if (!isSuspiciousMapLine(line)) {
                filtered.append(line).append("\n");
            }
        }
        return filtered.toString();
    }

    private static java.util.List<String> filterMapsList(java.util.List<String> lines) {
        java.util.List<String> filtered = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!isSuspiciousMapLine(line)) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    private static boolean isSuspiciousMapLine(String line) {
        if (line == null) return false;
        String lower = line.toLowerCase();

        return lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("edxposed") || lower.contains("magisk")
            || lower.contains("zygisk") || lower.contains("riru")
            || lower.contains("frida") || lower.contains("substrate")
            || lower.contains("/data/adb") || lower.contains("shamiko")
            || lower.contains("dexkit") || lower.contains("libdexkit")
            || lower.contains("flatbuffers") || lower.contains("sandhook")
            || lower.contains("yahfa") || lower.contains("epic")
            || lower.contains("pine") || lower.contains("taichi")
            || lower.contains("top.canyie") || lower.contains("liblspd")
            || lower.contains("lspatch") || lower.contains("liblspatch")
            // Filter our own module and native dependencies
            || lower.contains("xalsace") || lower.contains("qqbypass")
            || lower.contains("bypass") || lower.contains("libnative-bypass")
            || lower.contains("bytehook") || lower.contains("libbytehook")
            // Filter QAuxv and related
            || lower.contains("qauxv") || lower.contains("io.github.qauxv")
            || lower.contains("libqauxv") || lower.contains("libqauxv-core0")
            || lower.contains("cc.ioctl") || lower.contains("qnotified")
            // Filter moe.ono and lzlnb (模了个块)
            || lower.contains("libcnm") || lower.contains("liball-jni")
            || lower.contains("lzlnb") || lower.contains("moe.ono")
            || lower.contains("ono_mmkv") || lower.contains("ono_hcb_")
            || lower.contains("sesearchcache") || lower.contains("kc.dat");
    }

    private static StackTraceElement[] filterStackTrace(StackTraceElement[] traces) {
        if (traces == null) return null;
        if (Boolean.TRUE.equals(bypassStackFilter.get())) {
            return traces;
        }

        // Fast-path: check if caller of getStackTrace is QAuxiliary, MMKV, LSPatch, or bypass module
        for (StackTraceElement element : traces) {
            String cls = element.getClassName();
            if (cls == null) continue;
            if (cls.equals("java.lang.Thread") || cls.equals("java.lang.Throwable")
                    || cls.startsWith("de.robv.android.xposed.")
                    || cls.startsWith("io.github.xalsace.")) {
                continue;
            }
            if (cls.startsWith("io.github.qauxv.") || cls.startsWith("cc.ioctl.")
                    || cls.startsWith("me.singleneuron.") || cls.startsWith("nep.timeline.")
                    || cls.startsWith("me.ketal.") || cls.startsWith("xyz.nextalone.")
                    || cls.startsWith("org.lsposed.") || cls.startsWith("top.canyie.")
                    || cls.startsWith("moe.ono.") || cls.startsWith("lzlnb.cnm.")
                    || cls.startsWith("cnm0.") || cls.startsWith("lzlnb.")
                    || cls.startsWith("com.tencent.mmkv.")) {
                return traces;
            }
            break;
        }

        java.util.List<StackTraceElement> clean = new java.util.ArrayList<>();
        for (StackTraceElement element : traces) {
            String cls = element.getClassName();
            String method = element.getMethodName();
            if (cls == null) continue;
            String lower = cls.toLowerCase();
            if (lower.contains("de.robv.android.xposed") ||
                lower.contains("org.lsposed") ||
                lower.contains("lspatch") ||
                lower.contains("io.github.xalsace") ||
                lower.contains("edxposed") ||
                lower.contains("sandhook") ||
                lower.contains("epic") ||
                lower.contains("pine") ||
                lower.contains("yahfa") ||
                lower.contains("taichi") ||
                lower.contains("top.canyie") ||
                lower.contains("me.weishu") ||
                lower.contains("me.bmax") ||
                lower.contains("org.luckypray.dexkit") ||
                lower.contains("com.google.flatbuffers") ||
                lower.contains("com.elderdrivers.riru") ||
                lower.contains("bytehook") ||
                lower.contains("bin.mt") ||
                lower.contains("top.nkbe.npatch") ||
                lower.contains("npatch") ||
                lower.contains("io.github.qauxv") ||
                lower.contains("qauxv") ||
                lower.contains("cc.ioctl") ||
                lower.contains("me.singleneuron") ||
                lower.contains("nep.timeline") ||
                lower.contains("me.ketal") ||
                lower.contains("me.hd") ||
                lower.contains("xyz.nextalone") ||
                lower.contains("top.linl") ||
                lower.contains("net.bytebuddy") ||
                lower.contains("io.github.libxposed") ||
                lower.contains("moe.ono") ||
                lower.contains("lzlnb") ||
                lower.contains("cnm0") ||
                lower.contains("neibuff") ||
                lower.contains("qnotified")) {
                continue;
            }
            if (method != null) {
                if (method.equals("handleHookedMethod") ||
                    method.equals("beforeHookedMethod") ||
                    method.equals("afterHookedMethod") ||
                    method.equals("invokedTargetMethod")) {
                    continue;
                }
            }
            clean.add(element);
        }
        return clean.toArray(new StackTraceElement[0]);
    }

    private static void hookStackTrace() {
        try {
            HookUtils.hookMethod(Throwable.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (Boolean.TRUE.equals(bypassStackFilter.get())) return;
                    Object res = param.getResult();
                    if (res instanceof StackTraceElement[]) {
                        StackTraceElement[] traces = (StackTraceElement[]) res;
                        StackTraceElement[] clean = filterStackTrace(traces);
                        if (clean.length != traces.length) {
                            param.setResult(clean);
                        }
                    }
                }
            });

            HookUtils.hookMethod(Thread.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (Boolean.TRUE.equals(bypassStackFilter.get())) return;
                    Object res = param.getResult();
                    if (res instanceof StackTraceElement[]) {
                        StackTraceElement[] traces = (StackTraceElement[]) res;
                        StackTraceElement[] clean = filterStackTrace(traces);
                        if (clean.length != traces.length) {
                            param.setResult(clean);
                        }
                    }
                }
            });

            HookUtils.hookMethod(Thread.class, "getAllStackTraces", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (Boolean.TRUE.equals(bypassStackFilter.get())) return;
                    Object res = param.getResult();
                    if (res instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<Thread, StackTraceElement[]> map = (java.util.Map<Thread, StackTraceElement[]>) res;
                        java.util.Map<Thread, StackTraceElement[]> cleanMap = new java.util.HashMap<>();
                        for (java.util.Map.Entry<Thread, StackTraceElement[]> entry : map.entrySet()) {
                            Thread thread = entry.getKey();
                            if (thread != null) {
                                String name = thread.getName();
                                if (name != null) {
                                     String nameLower = name.toLowerCase();
                                    if (nameLower.contains("dexkit") || nameLower.contains("qqbypass") || nameLower.contains("xalsace")
                                            || nameLower.contains("qauxv") || nameLower.contains("qnotified") || nameLower.contains("cc.ioctl")
                                            || nameLower.contains("se-dexkit") || nameLower.contains("ono") || nameLower.contains("lzlnb")
                                            || nameLower.contains("cnm") || nameLower.contains("lspatch")) {
                                        continue;
                                    }
                                }
                            }
                            StackTraceElement[] cleanStack = filterStackTrace(entry.getValue());
                            cleanMap.put(thread, cleanStack);
                        }
                        param.setResult(cleanMap);
                    }
                }
            });

            // Native VMStack stack trace hook (prevents direct VMStack.getThreadStackTrace bypass)
            try {
                Class<?> vmStackClass = Class.forName("dalvik.system.VMStack");
                HookUtils.hookMethod(vmStackClass, "getThreadStackTrace", Thread.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (Boolean.TRUE.equals(bypassStackFilter.get())) return;
                        Object res = param.getResult();
                        if (res instanceof StackTraceElement[]) {
                            StackTraceElement[] traces = (StackTraceElement[]) res;
                            StackTraceElement[] clean = filterStackTrace(traces);
                            if (clean.length != traces.length) {
                                param.setResult(clean);
                            }
                        }
                    }
                });
                XposedEntry.log("VMStack.getThreadStackTrace sanitization installed");
            } catch (Throwable t) {
                XposedEntry.log("VMStack hook not available: " + t.getMessage());
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook StackTrace: " + t.getMessage());
        }
    }

    public static final ThreadLocal<Boolean> bypassStackFilter = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

    private static final ThreadLocal<Boolean> inReflectionHook = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return false;
        }
    };

    public static boolean isSuspiciousClass(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.startsWith("de.robv.android.xposed.")
            || lower.startsWith("org.lsposed.")
            || lower.contains("lspatch")
            || lower.startsWith("edxposed.")
            || lower.startsWith("com.swift.sandhook.")
            || lower.startsWith("top.canyie.pine.")
            || lower.startsWith("top.canyie.")
            || lower.startsWith("lab.galaxy.yahfa.")
            || lower.startsWith("me.ele.epic.")
            || lower.startsWith("me.weishu.exposed.")
            || lower.startsWith("bin.mt.")
            || lower.startsWith("top.nkbe.npatch.")
            || lower.startsWith("io.github.qauxv.")
            || lower.startsWith("cc.ioctl.")
            || lower.startsWith("me.singleneuron.")
            || lower.startsWith("nep.timeline.")
            || lower.startsWith("net.bytebuddy.")
            || lower.startsWith("io.github.libxposed.")
            || lower.startsWith("moe.ono.")
            || lower.startsWith("lzlnb.cnm.")
            || lower.startsWith("cnm0.")
            || lower.contains("neibuff")
            || lower.startsWith("com.applisto.appcloner.")
            || lower.contains("appcloner")
            || lower.startsWith("lzlnb.")
            || lower.startsWith("com.elderdrivers.riru.")
            || lower.startsWith("com.topjohnwu.magisk.")
            || lower.contains("zygisk")
            || lower.contains("apatch")
            || lower.contains("kernelsu")
            || lower.contains("saurik.substrate")
            || lower.contains("frida")
            || lower.contains("cydia")
            || lower.contains("substrate")
            || lower.contains("sukisu")
            || lower.contains("ksunext")
            || lower.startsWith("io.github.xalsace.")
            || lower.startsWith("org.luckypray.dexkit.");
    }

    public static boolean isSuspiciousResource(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.contains("xposed_init")
            || lower.contains("liblspd")
            || lower.contains("lspatch")
            || lower.contains("libcnm")
            || lower.contains("liball-jni")
            || lower.contains("moe.ono")
            || lower.contains("lzlnb")
            || lower.contains("native-bypass")
            || lower.contains("qqbypass");
    }

    private static boolean isModuleClassLoader(Object obj) {
        if (obj == null) return false;
        String clStr = obj.toString().toLowerCase();
        return clStr.contains("moe.ono") || clStr.contains("lzlnb") || clStr.contains("cnm")
            || clStr.contains("qauxv") || clStr.contains("lsposed") || clStr.contains("lspatch")
            || clStr.contains("dexkit") || clStr.contains("luckypray") || clStr.contains("cn.jesse");
    }

    private static boolean isCallerWhitelisted() {
        try {
            bypassStackFilter.set(true);
            String tName = Thread.currentThread().getName();
            if (tName != null) {
                String lt = tName.toLowerCase();
                if (lt.contains("qauxv") || lt.contains("ioctl") || lt.contains("singleneuron")
                        || lt.contains("lspatch") || lt.contains("lsposed") || lt.contains("xposed")
                        || lt.contains("ono") || lt.contains("lzlnb") || lt.contains("cnm")
                        || lt.contains("se-dexkit") || lt.contains("luckypray")) {
                    return true;
                }
            }
            ClassLoader contextCl = Thread.currentThread().getContextClassLoader();
            if (contextCl != null) {
                String clStr = contextCl.toString().toLowerCase();
                if (clStr.contains("qauxv") || clStr.contains("lspatch") || clStr.contains("lsposed")
                        || clStr.contains("ono") || clStr.contains("lzlnb") || clStr.contains("cnm")
                        || clStr.contains("dexkit") || clStr.contains("luckypray")) {
                    return true;
                }
            }
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls == null) continue;
                if (cls.startsWith("io.github.xalsace.")
                    || cls.startsWith("io.github.qauxv.")
                    || cls.startsWith("cc.ioctl.")
                    || cls.startsWith("me.singleneuron.")
                    || cls.startsWith("nep.timeline.")
                    || cls.startsWith("me.ketal.")
                    || cls.startsWith("xyz.nextalone.")
                    || cls.startsWith("top.linl.")
                    || cls.startsWith("net.bytebuddy.")
                    || cls.startsWith("io.github.libxposed.")
                    || cls.startsWith("bin.mt.")
                    || cls.startsWith("de.robv.android.xposed.")
                    || cls.startsWith("org.lsposed.")
                    || cls.startsWith("top.canyie.")
                    || cls.contains("lspatch")
                    || cls.startsWith("moe.ono.")
                    || cls.startsWith("lzlnb.cnm.")
                    || cls.startsWith("cnm0.")
                    || cls.startsWith("lzlnb.")
                    || cls.startsWith("cn.jesse.")
                    || cls.startsWith("org.luckypray.dexkit.")
                    || cls.startsWith("com.tencent.mmkv.")) {
                    return true;
                }
            }
            return false;
        } finally {
            bypassStackFilter.set(false);
        }
    }

    private static void hookClassLoaderAndReflection(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final ClassLoader moduleLoader = DynamicXposedDetectionHook.class.getClassLoader();

            XC_MethodHook forNameHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (param.args != null && param.args.length > 2 && (param.args[2] == moduleLoader || isModuleClassLoader(param.args[2]))) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String className = (String) param.args[0];
                            if (isSuspiciousClass(className) && !isCallerWhitelisted()) {
                                param.setThrowable(new ClassNotFoundException("Didn't find class \"" + className + "\""));
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            };

            // NEVER hook 1-arg Class.forName(String)!
            // In Android ART, 1-arg Class.forName(String) is @CallerSensitive and relies on
            // VMStack.getCallingClassLoader() to identify the caller's ClassLoader. Hooking it with
            // Xposed inserts XposedBridge/reflection frames on the stack, forcing VMStack to fall back
            // to BootClassLoader (null), which causes all internal QQ Class.forName() lookups (such as
            // QRoute resolving QQCoreBridgeImpl in classes3.dex) to fail with ClassNotFoundException.
            // Calls to Class.forName(String) naturally delegate to ClassLoader.loadClass, which is
            // already protected by loadClassHook below.

            // 3-arg Class.forName(String, boolean, ClassLoader) - explicitly passes ClassLoader so safe to hook
            HookUtils.hookMethod(Class.class, "forName", String.class, boolean.class, ClassLoader.class, forNameHook);

            // Hook ClassLoader.loadClass(String) and loadClass(String, boolean)
            XC_MethodHook loadClassHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (isModuleClassLoader(param.thisObject)) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String className = (String) param.args[0];
                            if (isSuspiciousClass(className) && !isCallerWhitelisted()) {
                                param.setThrowable(new ClassNotFoundException("Didn't find class \"" + className + "\""));
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            };
            HookUtils.hookMethod(ClassLoader.class, "loadClass", String.class, loadClassHook);
            HookUtils.hookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, loadClassHook);

            // Hook ClassLoader.findLoadedClass(String)
            HookUtils.hookMethod(ClassLoader.class, "findLoadedClass", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (isModuleClassLoader(param.thisObject)) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String className = (String) param.args[0];
                            if (isSuspiciousClass(className) && !isCallerWhitelisted()) {
                                param.setResult(null);
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            });

            // Hook ClassLoader.getResource / getResources / getResourceAsStream
            XC_MethodHook resourceHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (isModuleClassLoader(param.thisObject)) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String resName = (String) param.args[0];
                            if (isSuspiciousResource(resName) && !isCallerWhitelisted()) {
                                if (param.method instanceof java.lang.reflect.Method) {
                                    Class<?> ret = ((java.lang.reflect.Method) param.method).getReturnType();
                                    if (ret == java.util.Enumeration.class) {
                                        param.setResult(java.util.Collections.emptyEnumeration());
                                    } else {
                                        param.setResult(null);
                                    }
                                } else {
                                    param.setResult(null);
                                }
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            };
            HookUtils.hookMethod(ClassLoader.class, "getResource", String.class, resourceHook);
            HookUtils.hookMethod(ClassLoader.class, "getResources", String.class, resourceHook);
            HookUtils.hookMethod(ClassLoader.class, "getResourceAsStream", String.class, resourceHook);

            // Hook ClassLoader.findLibrary
            HookUtils.hookMethod(ClassLoader.class, "findLibrary", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (inReflectionHook.get()) return;
                    if (isModuleClassLoader(param.thisObject)) return;
                    try {
                        inReflectionHook.set(true);
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String libName = (String) param.args[0];
                            if (isSuspiciousResource(libName) && !isCallerWhitelisted()) {
                                param.setResult(null);
                            }
                        }
                    } finally {
                        inReflectionHook.set(false);
                    }
                }
            });

            HookUtils.hookMethod(dalvik.system.BaseDexClassLoader.class, "toString", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (s.contains("xposed") || s.contains("lsposed") || s.contains("edxposed") || s.contains("lspatch")
                                || s.contains("moe.ono") || s.contains("lzlnb") || s.contains("canyie")) {
                            param.setResult(s.replaceAll("(?i)xposed", "dalvik")
                                            .replaceAll("(?i)lsposed", "dalvik")
                                            .replaceAll("(?i)edxposed", "dalvik")
                                            .replaceAll("(?i)lspatch", "dalvik")
                                            .replaceAll("(?i)moe\\.ono", "dalvik")
                                            .replaceAll("(?i)lzlnb", "dalvik")
                                            .replaceAll("(?i)canyie", "dalvik"));
                        }
                    }
                }
            });
            XposedEntry.log("ClassLoader and reflection hook protection installed");
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook ClassLoader and reflection: " + t.getMessage());
        }
    }

    private static void hookAssetManager() {
        try {
            Class<?> amClass = android.content.res.AssetManager.class;
            XC_MethodHook openHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String filename = (String) param.args[0];
                        if (isSuspiciousResource(filename) && !isCallerWhitelisted()) {
                            param.setThrowable(new java.io.FileNotFoundException("Asset not found: " + filename));
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(amClass, "open", openHook);
            HookUtils.hookAllMethods(amClass, "openNonAssetFd", openHook);

            HookUtils.hookAllMethods(amClass, "list", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerWhitelisted()) return;
                    Object res = param.getResult();
                    if (res instanceof String[]) {
                        String[] list = (String[]) res;
                        List<String> filtered = new java.util.ArrayList<>();
                        for (String item : list) {
                            if (!isSuspiciousResource(item)) {
                                filtered.add(item);
                            }
                        }
                        if (filtered.size() != list.length) {
                            param.setResult(filtered.toArray(new String[0]));
                        }
                    }
                }
            });
            XposedEntry.log("AssetManager xposed_init concealment installed");
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook AssetManager: " + t.getMessage());
        }
    }

    private static void hookZipFile() {
        try {
            XC_MethodHook getEntryHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String entryName = (String) param.args[0];
                        if (isSuspiciousResource(entryName) && !isCallerWhitelisted()) {
                            param.setResult(null);
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(java.util.zip.ZipFile.class, "getEntry", getEntryHook);
            HookUtils.hookAllMethods(java.util.jar.JarFile.class, "getJarEntry", getEntryHook);

            HookUtils.hookMethod(java.util.zip.ZipFile.class, "entries", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerWhitelisted()) return;
                    Object res = param.getResult();
                    if (res instanceof java.util.Enumeration) {
                        @SuppressWarnings("unchecked")
                        final java.util.Enumeration<? extends java.util.zip.ZipEntry> orig =
                                (java.util.Enumeration<? extends java.util.zip.ZipEntry>) res;
                        final List<java.util.zip.ZipEntry> cleanList = new java.util.ArrayList<>();
                        while (orig.hasMoreElements()) {
                            java.util.zip.ZipEntry ze = orig.nextElement();
                            if (ze != null && !isSuspiciousResource(ze.getName())) {
                                cleanList.add(ze);
                            }
                        }
                        param.setResult(java.util.Collections.enumeration(cleanList));
                    }
                }
            });

            HookUtils.hookAllMethods(java.util.zip.ZipFile.class, "getInputStream", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof java.util.zip.ZipEntry) {
                        java.util.zip.ZipEntry ze = (java.util.zip.ZipEntry) param.args[0];
                        if (ze != null && isSuspiciousResource(ze.getName()) && !isCallerWhitelisted()) {
                            param.setThrowable(new java.io.FileNotFoundException("Entry concealed: " + ze.getName()));
                        }
                    }
                }
            });
            XposedEntry.log("ZipFile / JarFile xposed entry concealment installed");
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook ZipFile: " + t.getMessage());
        }
    }

    private static boolean containsSensitiveLog(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase();
        return lower.contains("xposed") || lower.contains("lsposed") || lower.contains("lspatch") || lower.contains("qauxv")
            || lower.contains("qqbypass") || lower.contains("nativebypass") || lower.contains("native-bypass")
            || lower.contains("dexkit") || lower.contains("bin.mt") || lower.contains("npatch")
            || lower.contains("bytebuddy") || lower.contains("singleneuron") || lower.contains("magisk")
            || lower.contains("shamiko") || lower.contains("kernel_su") || lower.contains("apatch");
    }

    private static void hookBuglyCrashReporter(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> crashHandlerClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qqperf.monitor.crash.c", lpparam.classLoader);
            if (crashHandlerClass != null) {
                HookUtils.hookAllMethods(crashHandlerClass, "c", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof String) {
                            String str = (String) res;
                            if (str.contains("isXposedInstalled: true")) {
                                str = str.replace("isXposedInstalled: true", "isXposedInstalled: false");
                                param.setResult(str);
                            }
                        }
                    }
                });
                XposedEntry.log("Bugly crash reporter xposed spoofing hooked");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook Bugly crash reporter: " + t.getMessage());
        }

        // Sanitize BuglyLog to drop sensitive framework logs
        try {
            Class<?> buglyLogClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.bugly.crashreport.BuglyLog", lpparam.classLoader);
            if (buglyLogClass != null) {
                XC_MethodHook buglyFilter = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                    param.setResult(null);
                                    return;
                                }
                            }
                        }
                    }
                };
                for (String m : new String[]{"v", "d", "i", "w", "e"}) {
                    HookUtils.hookAllMethods(buglyLogClass, m, buglyFilter);
                }
                XposedEntry.log("BuglyLog sanitization installed");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook BuglyLog: " + t.getMessage());
        }

        // Sanitize QLog to drop sensitive module/framework logs
        try {
            Class<?> qLogClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qphone.base.util.QLog", lpparam.classLoader);
            if (qLogClass != null) {
                XC_MethodHook qlogFilter = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                    param.setResult(null);
                                    return;
                                }
                            }
                        }
                    }
                };
                for (String m : new String[]{"d", "i", "w", "e"}) {
                    HookUtils.hookAllMethods(qLogClass, m, qlogFilter);
                }
                XposedEntry.log("QLog sanitization installed");
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook QLog: " + t.getMessage());
        }

        // Sanitize CrashReport.putUserData and catch exception reports
        String[] crashClasses = {
            "com.tencent.bugly.crashreport.CrashReport",
            "com.tencent.feedback.eup.CrashReport"
        };
        for (String crashClassName : crashClasses) {
            try {
                Class<?> crashReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                    crashClassName, lpparam.classLoader);
                if (crashReportCls != null) {
                    HookUtils.hookAllMethods(crashReportCls, "putUserData", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (param.args != null) {
                                for (Object arg : param.args) {
                                    if (arg instanceof String && containsSensitiveLog((String) arg)) {
                                        param.setResult(null);
                                        return;
                                    }
                                }
                            }
                        }
                    });

                    XC_MethodHook exceptionHook = new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (param.args == null || param.args.length == 0) return;
                            Throwable ex = null;
                            String msg = "";
                            for (Object arg : param.args) {
                                if (arg instanceof Throwable) {
                                    ex = (Throwable) arg;
                                } else if (arg instanceof String && msg.isEmpty()) {
                                    msg = (String) arg;
                                }
                            }
                            if (ex != null || !msg.isEmpty()) {
                                boolean suppressed = io.github.xalsace.qqbypass.utils.ReportAuditManager.recordAndSanitizeException(
                                    crashClassName, ex, msg);
                                if (suppressed) {
                                    Class<?> ret = param.method instanceof java.lang.reflect.Method ?
                                        ((java.lang.reflect.Method) param.method).getReturnType() : void.class;
                                    if (ret == boolean.class) {
                                        param.setResult(true);
                                    } else {
                                        param.setResult(null);
                                    }
                                }
                            }
                        }
                    };

                    HookUtils.hookCandidateMethods(crashReportCls, new String[]{"handleCatchException", "postCatchedException", "postException"}, exceptionHook);
                    XposedEntry.log("[CrashReport] Installed exception sanitization on " + crashClassName);
                }
            } catch (Throwable ignored) {}
        }
    }
}
