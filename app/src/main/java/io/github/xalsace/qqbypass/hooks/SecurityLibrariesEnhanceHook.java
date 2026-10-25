package io.github.xalsace.qqbypass.hooks;

import android.content.Context;
import android.text.TextUtils;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Enhanced Protection for Security & Diagnostic Libraries:
 * - libbugly_shadowhook.so / libshadowhook.so: com.bytedance.shadowhook.ShadowHook
 * - libqqPerfNativeTool.so: com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI
 * - libandroid_desensitization.so: com.luggage.desensitization.DesensitizationJni
 * - RuntimeEnvCensorTask & FEKit Companion:
 *     com.tencent.mobileqq.fe.utils.a (ClassLoader & dexElements scanner)
 *     com.tencent.mobileqq.dt.app.Dtc (isAbnormalConfig, checkAppInstalled, dtcSendMessage)
 */
public class SecurityLibrariesEnhanceHook {

    private static final Set<String> sHookedClasses =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final Map<String, List<ClassHookCallback>> sPendingClassHooks =
        new ConcurrentHashMap<>();

    private static final String[] SENSITIVE_STACK_KEYWORDS = {
        "xposed", "lsposed", "lspatch", "qauxv", "qqbypass",
        "native-bypass", "bytehook", "sandhook", "pine", "yahfa",
        "riru", "zygisk", "magisk", "top.nkbe", "npatch",
        "moe.ono", "ono", "lzlnb", "cnm", "xalsace", "canyie"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookAll(cl);
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null || sPendingClassHooks.isEmpty()) return;
        resolvePendingHooks(cl);
    }

    private static void hookAll(ClassLoader cl) {
        if (cl == null) return;
        hookFEKitAndDtc(cl);
        hookShadowHook(cl);
        hookQQPerfNativeTool(cl);
        hookDesensitization(cl);
        hookRMonitorAndBuglyDumpers(cl);
        hookUnusedCodeCheck(cl);
        hookNativeFileScan(cl);
        hookQSec(cl);
    }

    private static String getSafePropValue(String key) {
        if (key == null) return "-1";
        if ("ro.debuggable".equals(key)) return "0";
        if ("ro.secure".equals(key)) return "1";
        if ("ro.build.tags".equals(key)) return "release-keys";
        if ("ro.boot.flash.locked".equals(key)) return "1";
        if ("ro.boot.vbmeta.device_state".equals(key)) return "locked";
        if ("ro.boot.verifiedbootstate".equals(key)) return "green";
        if ("persist.sys.adb.engineermode".equals(key)) return "0";
        if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key) || "persist.sys.usb.config".equals(key)) return "none";
        if ("init.svc.adbd".equals(key)) return "stopped";
        if (key.contains("magisk") || key.contains("kernelsu") || key.contains("ksud") || key.contains("apatchd") || key.contains("ro.apatch") || key.contains("xposed") || "service.adb.root".equals(key)) {
            return "-1";
        }
        return null;
    }

    /**
     * 1. Neutralize FEKit RuntimeEnvCensor companion classes:
     * - com.tencent.mobileqq.fe.utils.a:
     *     g(Context) -> checks ClassLoader hierarchy and dexElements; returns true if abnormal.
     *     Hook all methods to return false/clean values!
     * - com.tencent.mobileqq.dt.app.Dtc:
     *     isAbnormalConfig() -> delegates to fe.utils.a.g; hook to return false!
     *     checkAppInstalled(String) -> unconditionally returns false to prevent all package profiling!
     *     getAccessibilityServiceList & getAccessibilityEnabledServiceList -> return empty!
     *     getAccessibilityEnabledStatus -> return 0!
     *     getPluginInfo -> clean string!
     *     getGoogleCertsVerify -> empty!
     *     getNetworkInterfaceNames -> clean interface string!
     *     getPropSafe / systemGetSafe -> sanitize sensitive properties!
     *     dtcSendMessage(String cmd, byte[] data, long callbackId) -> intercept SSO reports and synthesize 1000 ACK!
     */
    private static void hookFEKitAndDtc(ClassLoader cl) {
        // Delegate fe.utils.a to transparent normalization in QQ950PatchHook
        QQ950PatchHook.hookFeUtilsAWithClassLoader(cl);

        final String dtcCls = "com.tencent.mobileqq.dt.app.Dtc";
        hookSafe(cl, dtcCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // 1. isAbnormalConfig -> normalize to false in afterHookedMethod
                HookUtils.hookAllMethods(clazz, "isAbnormalConfig", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                        }
                    }
                });

                // 2. checkAppInstalled -> sanitize in afterHookedMethod if suspicious package queried
                HookUtils.hookAllMethods(clazz, "checkAppInstalled", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String pkg = (String) param.args[0];
                            if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                                param.setResult(false);
                            }
                        }
                    }
                });

                // 3. getAccessibilityServiceList & getAccessibilityEnabledServiceList
                XC_MethodHook assistListHook = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof String) {
                            String s = (String) res;
                            if (DynamicRootDetectionHook.isSuspiciousPackage(s) || s.contains("xposed")) {
                                param.setResult("-1");
                            }
                        }
                    }
                };
                HookUtils.hookAllMethods(clazz, "getAccessibilityServiceList", assistListHook);
                HookUtils.hookAllMethods(clazz, "getAccessibilityEnabledServiceList", assistListHook);

                // 4. getAccessibilityEnabledStatus
                HookUtils.hookAllMethods(clazz, "getAccessibilityEnabledStatus", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() instanceof Number && ((Number) param.getResult()).intValue() > 0) {
                            param.setResult(0);
                        }
                    }
                });

                // 5. getPluginInfo & getNetworkInterfaceNames & getLibraryList:
                // DO NOT hook getPluginInfo with fake "-1|-1|-1|-1|0|-1"!
                // On real devices, Dtc.getPluginInfo() naturally computes:
                // getMtpMode() + "|" + hasSimCard() + "|" + formatEmpty(getAccessibilityServiceList(true)) + "|" + formatEmpty(getAccessibilityEnabledServiceList(true)) + "|" + getAccessibilityEnabledStatus() + "|-1"
                // which yields "none|1|[]|[]|0|-1", perfectly consistent with SIM presence and system properties.
                // DO NOT hook getNetworkInterfaceNames with static "wlan0,rmnet_data0" (NetworkInterface.getNetworkInterfaces is already cleanly filtered).
                // DO NOT hook getLibraryList with fake "12345678" (authentic Dtc.getLibraryList computes genuine system shared libraries hash).

                // 6. getGoogleCertsVerify -> empty
                HookUtils.hookAllMethods(clazz, "getGoogleCertsVerify", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("");
                    }
                });

                // 7. getPropSafe & systemGetSafe -> sanitize sensitive keys
                HookUtils.hookAllMethods(clazz, "getPropSafe", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String key = (String) param.args[0];
                            String mocked = getSafePropValue(key);
                            if (mocked != null) {
                                param.setResult(mocked);
                            }
                        }
                    }
                });
                HookUtils.hookAllMethods(clazz, "systemGetSafe", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String key = (String) param.args[0];
                            String mocked = getSafePropValue(key);
                            if (mocked != null) {
                                param.setResult(mocked);
                            }
                        }
                    }
                });

                // 8. getMtpMode -> none
                HookUtils.hookAllMethods(clazz, "getMtpMode", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("none");
                    }
                });

                // 9. checkRiskPermission -> 0
                HookUtils.hookAllMethods(clazz, "checkRiskPermission", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });

                // 11. dtcSendMessage: Allow normal sending of SSO reports with sanitized environment data & audit
                HookUtils.hookAllMethods(clazz, "dtcSendMessage", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0) {
                            String cmd = String.valueOf(param.args[0]);
                            byte[] data = param.args.length > 1 && param.args[1] instanceof byte[] ? (byte[]) param.args[1] : null;
                            long cbId = param.args.length > 2 && param.args[2] instanceof Number ? ((Number) param.args[2]).longValue() : 0L;
                            if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordChannelManager("Dtc." + cmd, cbId, data != null ? data.length : 0, data);
                            }
                        }
                    }
                });
            }
        });

        final String dtHCls = "com.tencent.mobileqq.dt.app.h";
        hookSafe(cl, dtHCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                XC_MethodHook emptyListHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(new java.util.ArrayList<>());
                    }
                };
                for (Method m : clazz.getDeclaredMethods()) {
                    if (List.class.isAssignableFrom(m.getReturnType())) {
                        HookUtils.hookMethod(m, emptyListHook);
                    }
                }
            }
        });
    }

    /**
     * 2. Neutralize ByteDance ShadowHook (libbugly_shadowhook.so / libshadowhook.so):
     * com.bytedance.shadowhook.ShadowHook
     * Prevents Bugly / RMonitor from dumping hooked functions or detecting inline trampolines.
     */
    private static void hookShadowHook(ClassLoader cl) {
        final String shadowHookCls = "com.bytedance.shadowhook.ShadowHook";
        hookSafe(cl, shadowHookCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // nativeGetRecords / getRecords -> empty string
                XC_MethodHook emptyStringHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult("");
                    }
                };
                HookUtils.hookCandidateMethods(clazz, new String[]{"nativeGetRecords", "getRecords"}, emptyStringHook);

                // nativeGetRecordable / getRecordable / nativeGetDebuggable -> false
                XC_MethodHook falseHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                };
                HookUtils.hookCandidateMethods(clazz, new String[]{"nativeGetRecordable", "getRecordable", "nativeGetDebuggable", "getDebuggable"}, falseHook);
            }
        });
    }

    /**
     * 3. Neutralize QQPerfNativeTool signal reporting:
     * com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI
     * Scrubs stack traces passed to onSignalCaught so Xposed / hook framework frames are never reported.
     */
    private static void hookQQPerfNativeTool(ClassLoader cl) {
        final String signalCatcherCls = "com.tencent.mobileqq.qqperfnativetool.signalTool.SignalCatcherJNI";
        hookSafe(cl, signalCatcherCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // Hook onSignalCaught(int sig, int code, int errno, int arg4, String stackTrace)
                HookUtils.hookAllMethods(clazz, "onSignalCaught", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length == 0) return;

                        int sig = 0;
                        if (param.args[0] instanceof Number) {
                            sig = ((Number) param.args[0]).intValue();
                        }

                        // Locate stack trace argument
                        int strIdx = -1;
                        for (int i = param.args.length - 1; i >= 0; i--) {
                            if (param.args[i] instanceof String) {
                                strIdx = i;
                                break;
                            }
                        }

                        if (strIdx >= 0) {
                            String rawTrace = (String) param.args[strIdx];
                            if (rawTrace != null && !rawTrace.isEmpty()) {
                                String cleanTrace = sanitizeStackTrace(rawTrace);
                                param.args[strIdx] = cleanTrace;
                            }
                        }

                        // If signal is self-directed anti-tamper crash (SIGSEGV=11, SIGBUS=7, SIGILL=4, SIGTRAP=5, SIGABRT=6)
                        if (sig == 11 || sig == 7 || sig == 4 || sig == 5 || sig == 6) {
                            XposedEntry.log("[SignalCatcher] Sanitized signal telemetry for sig=" + sig);
                        }
                    }
                });

                // Inhibit unwanted native signal catchers from taking over signal chain
                HookUtils.hookAllMethods(clazz, "initANRSignalCatcher", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });
                HookUtils.hookAllMethods(clazz, "initNativeCrashSignalCatcher", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });
            }
        });
    }

    /**
     * 4. Neutralize Tencent Luggage Desensitization JNI:
     * com.luggage.desensitization.DesensitizationJni
     */
    private static void hookDesensitization(ClassLoader cl) {
        final String desensCls = "com.luggage.desensitization.DesensitizationJni";
        hookSafe(cl, desensCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                XC_MethodHook desensHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String input = (String) param.args[0];
                            if (input != null) {
                                boolean modified = false;
                                for (String kw : SENSITIVE_STACK_KEYWORDS) {
                                    if (input.toLowerCase().contains(kw)) {
                                        input = input.replaceAll("(?i)" + java.util.regex.Pattern.quote(kw), "normal");
                                        modified = true;
                                    }
                                }
                                if (modified) {
                                    param.args[0] = input;
                                }
                            }
                        }
                    }
                };

                HookUtils.hookCandidateMethods(clazz, new String[]{
                    "a",
                    "nativeStrDesensitizeDetectedContentWithMask",
                    "nativeStrDesensitizeWithMask"
                }, desensHook);
            }
        });
    }

    private static String sanitizeStackTrace(String rawTrace) {
        if (rawTrace == null || rawTrace.isEmpty()) return rawTrace;
        String[] lines = rawTrace.split("\n");
        StringBuilder sb = new StringBuilder();
        int removedCount = 0;
        for (String line : lines) {
            boolean sensitive = false;
            String lower = line.toLowerCase();
            for (String kw : SENSITIVE_STACK_KEYWORDS) {
                if (lower.contains(kw)) {
                    sensitive = true;
                    break;
                }
            }
            if (!sensitive) {
                sb.append(line).append("\n");
            } else {
                removedCount++;
            }
        }
        if (removedCount > 0) {
            XposedEntry.log("[SignalCatcher] Scrubbed " + removedCount + " sensitive frames from stack trace");
        }
        if (sb.length() == 0) {
            return "java.lang.Throwable: Normal\n\tat android.os.MessageQueue.nativePollOnce(Native Method)\n";
        }
        return sb.toString();
    }

    /**
     * 5. Neutralize RMonitor and Bugly In-Memory Thread & Heap Dumpers (librmonitor_base.so / bytehook)
     */
    private static void hookRMonitorAndBuglyDumpers(ClassLoader cl) {
        // com.tencent.rmonitor.base.thread.suspend.ThreadSuspend: hooks ART stack trace & suspends threads
        hookSafe(cl, "com.tencent.rmonitor.base.thread.suspend.ThreadSuspend", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if ("nativeHookStackTrace".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                                XposedEntry.log("[RMonitorPatch] Neutralized ThreadSuspend.nativeHookStackTrace");
                            }
                        });
                    } else if ("nativeInit".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(0);
                                XposedEntry.log("[RMonitorPatch] Neutralized ThreadSuspend.nativeInit");
                            }
                        });
                    } else if ("nativeSuspendThread".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                            }
                        });
                    } else if ("nativeResumeThread".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(true);
                            }
                        });
                    }
                }
            }
        });

        // com.tencent.bugly.common.heapdump.StripHeapDumper: hooks open/write via ByteHook
        hookSafe(cl, "com.tencent.bugly.common.heapdump.StripHeapDumper", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if (name.startsWith("nSet") || name.startsWith("nEnable") || name.startsWith("nStrip")) {
                        Class<?> ret = m.getReturnType();
                        if (ret == boolean.class) {
                            HookUtils.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    p.setResult(false);
                                }
                            });
                        } else if (ret == void.class) {
                            HookUtils.hookMethod(m, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                    p.setResult(null);
                                }
                            });
                        }
                    }
                }
            }
        });

        // com.tencent.bugly.common.heapdump.ForkJvmHeapDumper: forks process to dump memory
        hookSafe(cl, "com.tencent.bugly.common.heapdump.ForkJvmHeapDumper", new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                for (Method m : clazz.getDeclaredMethods()) {
                    String name = m.getName();
                    if ("nInitForkDump".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(false);
                                XposedEntry.log("[BuglyPatch] Neutralized ForkJvmHeapDumper.nInitForkDump");
                            }
                        });
                    } else if ("dump".equals(name)) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                                p.setResult(101); // DUMP_DISABLED / FAIL
                                XposedEntry.log("[BuglyPatch] Intercepted ForkJvmHeapDumper.dump");
                            }
                        });
                    }
                }
            }
        });
    }

    /**
     * 6. Neutralize UnusedCodeCheck (libunusedcodecheck.so & CheckCore):
     * com.tencent.mobileqq.unusedcodecheck.CheckCore
     * Verifies loaded classes against expected baseline to detect modified/injected classes.
     */
    private static void hookUnusedCodeCheck(ClassLoader cl) {
        final String checkCoreCls = "com.tencent.mobileqq.unusedcodecheck.CheckCore";
        hookSafe(cl, checkCoreCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // checkClassLoadedResult -> returns 0 (SUCCESS)
                HookUtils.hookAllMethods(clazz, "checkClassLoadedResult", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });

                // isCheckSuc$unusedcode_check_debug -> returns true
                HookUtils.hookAllMethods(clazz, "isCheckSuc$unusedcode_check_debug", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(true);
                    }
                });
            }
        });

        final String initClassInfoCls = "com.tencent.mobileqq.unusedcodecheck.InitClassInfo";
        hookSafe(cl, initClassInfoCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                // c() -> returns true (initialization valid)
                HookUtils.hookAllMethods(clazz, "c", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(true);
                    }
                });

                // e() -> returns 0 (error code clean)
                HookUtils.hookAllMethods(clazz, "e", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(0);
                    }
                });

                // f(Context) -> suppress full dex scan and MMKV integrity writes
                HookUtils.hookAllMethods(clazz, "f", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            XposedHelpers.setIntField(param.thisObject, "g", 0);
                        } catch (Throwable ignored) {}
                        param.setResult(null);
                    }
                });
            }
        });
    }

    /**
     * 7. Neutralize NativeFileScan (libnativefilescan.so & FileScanCore):
     * com.tencent.mobileqq.nativefilescan.FileScanCore
     * Prevents scanning and profiling sensitive QA private files and injected modules.
     */
    private static void hookNativeFileScan(ClassLoader cl) {
        final String fileScanCoreCls = "com.tencent.mobileqq.nativefilescan.FileScanCore";
        hookSafe(cl, fileScanCoreCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                XC_MethodHook scanSuppressHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String path = (String) param.args[0];
                            if (DynamicRootDetectionHook.isSuspiciousPath(path)) {
                                XposedEntry.log("[FileScanCore] Suppressed directory scan on sensitive path: " + path);
                                if (param.method instanceof Method) {
                                    Class<?> ret = ((Method) param.method).getReturnType();
                                    if (ret == void.class) {
                                        param.setResult(null);
                                    } else if (ret == boolean.class) {
                                        param.setResult(false);
                                    } else if (ret == int.class) {
                                        param.setResult(0);
                                    } else {
                                        param.setResult(null);
                                    }
                                } else {
                                    param.setResult(null);
                                }
                            }
                        }
                    }
                };

                HookUtils.hookAllMethods(clazz, "getDirSize", scanSuppressHook);
                HookUtils.hookAllMethods(clazz, "getTargetFormatFileList", scanSuppressHook);
                HookUtils.hookAllMethods(clazz, "d", scanSuppressHook);
                HookUtils.hookAllMethods(clazz, "e", scanSuppressHook);
            }
        });
    }

    /**
     * 8. Neutralize QSec method probe:
     * com.tencent.mobileqq.qsec.qsecurity.QSec.detectMethod(String className, String methodName)
     */
    private static void hookQSec(ClassLoader cl) {
        final String qsecCls = "com.tencent.mobileqq.qsec.qsecurity.QSec";
        hookSafe(cl, qsecCls, new ClassHookCallback() {
            @Override
            public void onClassFound(Class<?> clazz) {
                HookUtils.hookAllMethods(clazz, "detectMethod", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String targetClass = (String) param.args[0];
                            if (DynamicXposedDetectionHook.isSuspiciousClass(targetClass)) {
                                param.setResult(false);
                            }
                        }
                    }
                });
            }
        });
    }

    private interface ClassHookCallback {
        void onClassFound(Class<?> clazz);
    }

    private static void resolvePendingHooks(ClassLoader cl) {
        if (cl == null || sPendingClassHooks.isEmpty()) return;
        List<String> resolved = new java.util.ArrayList<>();
        for (Map.Entry<String, List<ClassHookCallback>> entry : sPendingClassHooks.entrySet()) {
            String className = entry.getKey();
            Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
            if (clazz != null) {
                String key = className + "@" + clazz.hashCode();
                if (sHookedClasses.add(key)) {
                    for (ClassHookCallback cb : entry.getValue()) {
                        try {
                            cb.onClassFound(clazz);
                        } catch (Throwable t) {
                            XposedEntry.log("Failed to initialize late hooks on " + className + ": " + t.getMessage());
                        }
                    }
                }
                resolved.add(className);
            }
        }
        for (String c : resolved) {
            sPendingClassHooks.remove(c);
        }
        if (!resolved.isEmpty()) {
            XposedEntry.log("[SecurityEnhance] Resolved " + resolved.size() + " pending classes in late stage");
        }
    }

    private static void hookSafe(ClassLoader cl, final String className, final ClassHookCallback callback) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
        if (clazz != null) {
            String key = className + "@" + clazz.hashCode();
            if (sHookedClasses.add(key)) {
                try {
                    callback.onClassFound(clazz);
                } catch (Throwable t) {
                    XposedEntry.log("Failed to initialize hooks on " + className + ": " + t.getMessage());
                }
            }
        } else {
            // NEVER hook ClassLoader.loadClass! It adds massive CPU delay to all class resolution in ART.
            // Queue for resolution when secondary dexes are attached via MultiDex (attachBaseContext).
            List<ClassHookCallback> list = sPendingClassHooks.computeIfAbsent(className, k -> new java.util.concurrent.CopyOnWriteArrayList<>());
            if (!list.contains(callback)) {
                list.add(callback);
            }
        }
    }
}
