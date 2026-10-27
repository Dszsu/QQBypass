package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.io.FileNotFoundException;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Root Detection Bypass
 * Dynamically locates and hooks obfuscated su path checkers
 */
public class DynamicRootDetectionHook {

    private static final String[] SU_PATHS = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/adb",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/ap",
        "/data/adb/modules",
        "/data/adb/shamiko",
        "/system/bin/cufsdosck",
        "/system/xbin/cufsdosck",
        "/system/bin/cufsmgr",
        "/system/xbin/cufsmgr",
        "/system/bin/cufaevdd",
        "/system/xbin/cufaevdd",
        "/system/bin/conbb",
        "/system/xbin/conbb",
        "/system/xbin/daemonsu",
        "/system/bin/permmgrd",
        "/system/bin/360sguard"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        // Targeted checklist hooks (04_检测点清单.md): Wlogin, LightDevice, ChargeV2, UserInfo, DeviceInfo, CrashReport
        RootDetectionHook.hook(lpparam);

        // Universal hook: File methods - catches all path checks
        hookFileChecks();
        hookFileStreams();
        hookSharedPreferences(lpparam);

        // Environment properties & package inventory checks
        hookInstalledPackages(lpparam);
        hookActivityManager(lpparam);
        hookInstalledAppListMonitor(lpparam);
        hookUsageStatsManager(lpparam);
        hookSystemProperties();
        hookSettingsSecureAndGlobal();
        hookProcessExecution();
        hookNetworkInterfaces();

        // Gatherer SDK root detection hook
        hookGathererRootCheck(lpparam);

        // Tencent Beacon root detection & device info hooks
        hookBeaconRootCheck(lpparam);

        // Dynamic hooks: DexKit-discovered su path checkers
        new Thread(() -> {
            try {
                // Wait for the shared scan to finish instead of a fixed sleep.
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicRoot: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookSuPathCheckers(lpparam);
                hookPackageQueries(lpparam);

            } catch (Throwable e) {
                XposedEntry.log("Dynamic root detection hook failed: " + e.getMessage());
            }
        }).start();
    }

    public static boolean isVirtualOrVpnIface(String name) {
        if (name == null || name.isEmpty()) return false;
        String lower = name.toLowerCase();
        return lower.startsWith("tun") || lower.startsWith("ppp") ||
               lower.startsWith("p2p") || lower.startsWith("tap") ||
               lower.startsWith("dummy") || lower.startsWith("ifb") ||
               lower.startsWith("vgate") || lower.startsWith("ovnet") ||
               lower.startsWith("ap") || lower.startsWith("wondertap") ||
               lower.startsWith("veth") || lower.startsWith("docker") ||
               lower.startsWith("virbr") || lower.startsWith("br-") ||
               lower.startsWith("sit") || lower.startsWith("gre") ||
               lower.startsWith("ip_vti") || lower.startsWith("ip6");
    }

    private static void hookNetworkInterfaces() {
        try {
            HookUtils.hookMethod(NetworkInterface.class, "getNetworkInterfaces", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == null) return;
                    @SuppressWarnings("unchecked")
                    Enumeration<NetworkInterface> en = (Enumeration<NetworkInterface>) param.getResult();
                    ArrayList<NetworkInterface> filtered = new ArrayList<>();
                    while (en.hasMoreElements()) {
                        NetworkInterface ni = en.nextElement();
                        String name = ni.getName();
                        if (isVirtualOrVpnIface(name)) {
                            continue;
                        }
                        filtered.add(ni);
                    }
                    param.setResult(Collections.enumeration(filtered));
                }
            });

            HookUtils.hookMethod(NetworkInterface.class, "getByName", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String name = (String) param.args[0];
                        if (isVirtualOrVpnIface(name)) {
                            param.setResult(null);
                        }
                    }
                }
            });

            HookUtils.hookMethod(NetworkInterface.class, "getByInetAddress", java.net.InetAddress.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof java.net.InetAddress) {
                        java.net.InetAddress addr = (java.net.InetAddress) param.args[0];
                        String ip = addr.getHostAddress();
                        if (ip != null && (ip.startsWith("198.18.") || ip.startsWith("172.30."))) {
                            param.setResult(null);
                        }
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() instanceof NetworkInterface) {
                        NetworkInterface ni = (NetworkInterface) param.getResult();
                        if (isVirtualOrVpnIface(ni.getName())) {
                            param.setResult(null);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("NetworkInterface hook failed: " + t.getMessage());
        }
    }

    private static void hookFileChecks() {
        XC_MethodHook booleanFileHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();

                if (isSuspiciousPath(path)) {
                    if (isCallerQAuxv()) {
                        return;
                    }
                    param.setResult(false);
                    XposedEntry.log("File check blocked: " + path);
                    UnifiedHookCoordinator.notifyNativeIfAvailable("file_blocked", path);
                    if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProbe("FileCheck", path, "blocked");
                    }
                }
            }
        };

        HookUtils.hookMethod(File.class, "exists", booleanFileHook);
        HookUtils.hookMethod(File.class, "canRead", booleanFileHook);
        HookUtils.hookMethod(File.class, "canExecute", booleanFileHook);
        HookUtils.hookMethod(File.class, "isFile", booleanFileHook);
        HookUtils.hookMethod(File.class, "isDirectory", booleanFileHook);
        HookUtils.hookMethod(File.class, "canWrite", booleanFileHook);

        HookUtils.hookMethod(File.class, "length", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File file = (File) param.thisObject;
                String path = file.getAbsolutePath();

                if (isSuspiciousPath(path)) {
                    if (isCallerQAuxv()) {
                        return;
                    }
                    param.setResult(0L);
                    UnifiedHookCoordinator.notifyNativeIfAvailable("file_blocked", path);
                }
            }
        });

        XC_MethodHook listHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (isCallerQAuxv()) return;
                Object res = param.getResult();
                if (res instanceof String[]) {
                    String[] list = (String[]) res;
                    if (list.length == 0) return;
                    File dir = param.thisObject instanceof File ? (File) param.thisObject : null;
                    List<String> filtered = new ArrayList<>(list.length);
                    for (String name : list) {
                        if (name.equalsIgnoreCase("lspatch")) continue;
                        if (isSuspiciousPath(name)) continue;
                        if (dir != null && isSuspiciousPath(new File(dir, name).getAbsolutePath())) continue;
                        filtered.add(name);
                    }
                    if (filtered.size() != list.length) {
                        param.setResult(filtered.toArray(new String[0]));
                    }
                }
            }
        };
        HookUtils.hookAllMethods(File.class, "list", listHook);

        XC_MethodHook listFilesHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (isCallerQAuxv()) return;
                Object res = param.getResult();
                if (res instanceof File[]) {
                    File[] list = (File[]) res;
                    if (list.length == 0) return;
                    List<File> filtered = new ArrayList<>(list.length);
                    for (File f : list) {
                        if (f != null && ("lspatch".equalsIgnoreCase(f.getName()) || isSuspiciousPath(f.getAbsolutePath()))) continue;
                        filtered.add(f);
                    }
                    if (filtered.size() != list.length) {
                        param.setResult(filtered.toArray(new File[0]));
                    }
                }
            }
        };
        HookUtils.hookAllMethods(File.class, "listFiles", listFilesHook);
    }

    private static void hookFileStreams() {
        XC_MethodHook streamHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args == null || param.args.length == 0 || param.args[0] == null) return;
                String path = null;
                Object first = param.args[0];
                if (first instanceof File) {
                    path = ((File) first).getAbsolutePath();
                } else if (first instanceof String) {
                    path = (String) first;
                }
                if (path != null) {
                    if (isSuspiciousPath(path)) {
                        if (isCallerQAuxv()) {
                            return;
                        }
                        XposedEntry.log("File stream blocked: " + path);
                        UnifiedHookCoordinator.notifyNativeIfAvailable("file_blocked", path);
                        throw new FileNotFoundException("No such file or directory: " + path);
                    }
                }
            }
        };

        try {
            HookUtils.hookAllConstructors(FileInputStream.class, streamHook);
            HookUtils.hookAllConstructors(FileOutputStream.class, streamHook);
            HookUtils.hookAllConstructors(RandomAccessFile.class, streamHook);
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook file streams: " + t.getMessage());
        }
    }

    private static void hookSharedPreferences(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> contextImplClass = XposedHelpers.findClassIfExists("android.app.ContextImpl", lpparam.classLoader);
            if (contextImplClass == null) {
                contextImplClass = XposedHelpers.findClassIfExists("android.app.ContextImpl", ClassLoader.getSystemClassLoader());
            }
            if (contextImplClass != null) {
                HookUtils.hookMethod(contextImplClass, "getSharedPreferences", String.class, int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                        String name = (String) param.args[0];
                        if (isSuspiciousPrefName(name)) {
                            if (isCallerQAuxv()) {
                                return;
                            }
                            XposedEntry.log("SharedPreferences probe blocked: " + name);
                            param.args[0] = "__qb_empty_dummy_pref__";
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook getSharedPreferences: " + t.getMessage());
        }
    }

    private static void hookGathererRootCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> userInfoImplClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", lpparam.classLoader);
            if (userInfoImplClass != null) {
                HookUtils.hookAllMethods(userInfoImplClass, "isRooted", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result != null) {
                            try {
                                de.robv.android.xposed.XposedHelpers.setObjectField(result, "b", Boolean.FALSE);
                                XposedEntry.log("[GathererPatch] UserInfoImpl.isRooted result forced to Boolean.FALSE");
                            } catch (Throwable ignored) {}
                        }
                    }
                });
                XposedEntry.log("[GathererPatch] Hooked UserInfoImpl.isRooted successfully");
            }
        } catch (Throwable t) {
            XposedEntry.log("[GathererPatch] Failed to hook UserInfoImpl.isRooted: " + t.getMessage());
        }
    }

    /**
     * Intercept Tencent Beacon Root Detection:
     * com.tencent.beacon.base.util.d:
     * - d(): overall root status (returns false)
     * - a(): su command execution probe (returns false)
     * - b(): /system/app/Superuser.apk probe (returns false)
     * - c(): Build.TAGS test-keys probe (returns false)
     * - e(): executes "/system/bin/sh -c type su" via RuntimeMonitor.exec (neutralized to return empty list)
     * - static boolean a: latched root flag (force to false)
     *
     * com.tencent.beacon.a.c.e:
     * - m(): device hardware provider root check (returns false)
     */
    private static final java.util.Set<Class<?>> sHookedBeaconClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static void hookBeaconClassD(Class<?> beaconUtilD) {
        if (beaconUtilD == null || sHookedBeaconClasses.contains(beaconUtilD)) return;
        sHookedBeaconClasses.add(beaconUtilD);
        try {
            XC_MethodHook falseHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == Boolean.TRUE) {
                        param.setResult(false);
                    }
                }
            };

            HookUtils.hookAllMethods(beaconUtilD, "d", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "a", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "b", falseHook);
            HookUtils.hookAllMethods(beaconUtilD, "c", falseHook);

            // Neutralize e() so it never forks shell commands
            HookUtils.hookAllMethods(beaconUtilD, "e", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(new java.util.ArrayList<String>());
                }
            });

            // Reset static latched flag 'a'
            try {
                de.robv.android.xposed.XposedHelpers.setStaticBooleanField(beaconUtilD, "a", false);
            } catch (Throwable ignored) {}

            XposedEntry.log("[BeaconRoot] Fully neutralized com.tencent.beacon.base.util.d root probes");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] Failed to hook com.tencent.beacon.base.util.d: " + t.getMessage());
        }
    }

    private static void hookBeaconClassE(Class<?> beaconDevInfo) {
        if (beaconDevInfo == null || sHookedBeaconClasses.contains(beaconDevInfo)) return;
        sHookedBeaconClasses.add(beaconDevInfo);
        try {
            HookUtils.hookAllMethods(beaconDevInfo, "m", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == Boolean.TRUE) {
                        param.setResult(false);
                    }
                }
            });
            XposedEntry.log("[BeaconRoot] Neutralized com.tencent.beacon.a.c.e.m root check");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconRoot] Failed to hook com.tencent.beacon.a.c.e: " + t.getMessage());
        }
    }

    private static boolean isBusinessOrUiEvent(String eventCode) {
        if (eventCode == null) return false;
        String c = eventCode.toLowerCase(Locale.ROOT);
        return c.startsWith("qq_") || c.startsWith("dt_") || c.startsWith("ev_") ||
               c.startsWith("act") || c.startsWith("em_") || c.startsWith("push_") ||
               c.startsWith("msg_") || c.startsWith("new_msg_") || c.startsWith("rqd_") ||
               c.startsWith("dim_") || c.startsWith("cost_tracer") || c.startsWith("apm_") ||
               c.startsWith("wt_") || c.startsWith("login_") || c.startsWith("markdown_") ||
               c.startsWith("vip") || c.startsWith("chat") || c.startsWith("fav") ||
               c.startsWith("relation_") || c.startsWith("report_process_") ||
               c.startsWith("gm_") || c.startsWith("notification_");
    }

    private static boolean isBusinessOrUiKey(String key) {
        if (key == null || key.isEmpty()) return true;
        String k = key.toLowerCase(Locale.ROOT);
        return k.equals("udf_kv") || k.equals("message_box") ||
               k.startsWith("dt_") || k.startsWith("qq_") || k.startsWith("aio_") ||
               k.startsWith("pg_") || k.startsWith("cur_") || k.startsWith("ref_") ||
               k.startsWith("cre_") || k.startsWith("session_") || k.startsWith("msg") ||
               k.startsWith("chat_") || k.startsWith("channel_") || k.startsWith("red_") ||
               k.startsWith("uin") || k.startsWith("uid") || k.startsWith("app_") ||
               k.startsWith("param_") || k.startsWith("client_") ||
               k.equals("client_page_name") || k.equals("tianshu_id") || k.equals("page_id") ||
               k.equals("eid") || k.equals("target_url") || k.equals("url") ||
               k.equals("jump_url") || k.equals("web_url") || k.equals("schema") ||
               k.equals("content") || k.equals("title") || k.equals("text") ||
               k.equals("summary") || k.equals("process") || k.equals("os_vrsn") ||
               k.equals("ui_vrsn") || k.equals("app_vr") || k.equals("user_id") ||
               k.equals("happen_time") || k.equals("account_uin");
    }

    private static boolean isSecurityStatusKey(String key) {
        if (key == null || key.isEmpty()) return false;
        String k = key.toLowerCase(Locale.ROOT);
        return k.equals("is_root") || k.equals("isroot") || k.equals("has_root") ||
               k.equals("root_status") || k.equals("is_rooted") || k.equals("root_detected") ||
               k.equals("device_rooted") || k.equals("is_jailbreak") || k.equals("jailbreak") ||
               k.equals("fake_gps") || k.equals("mock_location") || k.equals("is_mock") ||
               k.equals("xposed_status") || k.equals("xposed_installed") || k.equals("has_xposed") ||
               k.equals("magisk_status") || k.equals("magisk_installed") || k.equals("has_magisk") ||
               k.equals("risk_level") || k.equals("device_risk") || k.equals("sec_risk") ||
               k.equals("risk_status") || k.equals("tamper_status");
    }

    private static boolean isSecurityDetailKey(String key) {
        if (key == null || key.isEmpty()) return false;
        String k = key.toLowerCase(Locale.ROOT);
        return k.equals("su_path") || k.equals("root_path") || k.equals("xposed_path") ||
               k.equals("magisk_path") || k.equals("hook_path") || k.equals("risk_detail") ||
               k.equals("detect_detail") || k.equals("tamper_detail");
    }

    private static void hookBeaconReport(Class<?> beaconReportCls) {
        if (beaconReportCls == null || sHookedBeaconClasses.contains(beaconReportCls)) return;
        sHookedBeaconClasses.add(beaconReportCls);
        try {
            HookUtils.hookAllMethods(beaconReportCls, "report", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] != null) {
                        Object event = param.args[0];
                        try {
                            String eventCode = null;
                            try {
                                eventCode = (String) de.robv.android.xposed.XposedHelpers.callMethod(event, "getCode");
                            } catch (Throwable ignored) {}
                            boolean isSuccess = true;
                            try {
                                isSuccess = (boolean) de.robv.android.xposed.XposedHelpers.callMethod(event, "isSuccess");
                            } catch (Throwable ignored) {}
                            String appKey = null;
                            try {
                                appKey = (String) de.robv.android.xposed.XposedHelpers.callMethod(event, "getAppKey");
                            } catch (Throwable ignored) {}

                            @SuppressWarnings("unchecked")
                            java.util.Map<String, String> params = (java.util.Map<String, String>)
                                de.robv.android.xposed.XposedHelpers.callMethod(event, "getParams");
                            java.util.List<String> sanitizedDetails = null;

                            // Transparent data normalization: ONLY sanitize when event is not pure business/UI
                            // and the key is an explicit security/risk check key. NEVER touch business/UI analytics!
                            if (params != null && !isBusinessOrUiEvent(eventCode)) {
                                for (java.util.Map.Entry<String, String> entry : params.entrySet()) {
                                    String rawKey = entry.getKey();
                                    if (rawKey == null || isBusinessOrUiKey(rawKey)) continue;

                                    String v = entry.getValue();
                                    if (v == null) continue;

                                    if (isSecurityStatusKey(rawKey)) {
                                        if (!"0".equals(v) && !"false".equalsIgnoreCase(v)) {
                                            if (sanitizedDetails == null) sanitizedDetails = new java.util.ArrayList<>();
                                            sanitizedDetails.add(rawKey + ": " + v + " -> 0");
                                            entry.setValue("0");
                                        }
                                    } else if (isSecurityDetailKey(rawKey)) {
                                        if (!"none".equalsIgnoreCase(v) && !v.isEmpty()) {
                                            if (sanitizedDetails == null) sanitizedDetails = new java.util.ArrayList<>();
                                            sanitizedDetails.add(rawKey + ": " + v + " -> none");
                                            entry.setValue("none");
                                        }
                                    }
                                }
                            }

                            if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordBeacon(eventCode, isSuccess, params, appKey, sanitizedDetails);
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[BeaconReport] Installed transparent data normalization & audit on BeaconReport.report");
        } catch (Throwable t) {
            XposedEntry.log("[BeaconReport] Failed to hook BeaconReport: " + t.getMessage());
        }
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        try {
            Class<?> beaconUtilD = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.base.util.d", cl);
            if (beaconUtilD != null) {
                hookBeaconClassD(beaconUtilD);
            }
            Class<?> beaconDevInfo = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.a.c.e", cl);
            if (beaconDevInfo != null) {
                hookBeaconClassE(beaconDevInfo);
            }
            Class<?> beaconReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.event.open.BeaconReport", cl);
            if (beaconReportCls != null) {
                hookBeaconReport(beaconReportCls);
            }
            Class<?> userInfoImpl = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", cl);
            if (userInfoImpl != null && !sHookedBeaconClasses.contains(userInfoImpl)) {
                sHookedBeaconClasses.add(userInfoImpl);
                HookUtils.hookAllMethods(userInfoImpl, "isRooted", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result != null) {
                            try {
                                de.robv.android.xposed.XposedHelpers.setObjectField(result, "b", Boolean.FALSE);
                            } catch (Throwable ignored) {}
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XposedEntry.logError("[BeaconRoot] hookLateStage error: " + t.getMessage(), t);
        }
    }

    private static void hookBeaconRootCheck(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl != null) {
            Class<?> beaconUtilD = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.base.util.d", cl);
            if (beaconUtilD != null) {
                hookBeaconClassD(beaconUtilD);
            }
            Class<?> beaconDevInfo = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.a.c.e", cl);
            if (beaconDevInfo != null) {
                hookBeaconClassE(beaconDevInfo);
            }
            Class<?> beaconReportCls = de.robv.android.xposed.XposedHelpers.findClassIfExists("com.tencent.beacon.event.open.BeaconReport", cl);
            if (beaconReportCls != null) {
                hookBeaconReport(beaconReportCls);
            }
        }
    }

    private static void hookSuPathCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> suCheckers = DexKitDetector.findSuPathCheckers();
        if (suCheckers.isEmpty()) {
            XposedEntry.log("DynamicRoot: No su path checkers found by DexKit");
            return;
        }

        XposedEntry.log("DynamicRoot: Hooking " + suCheckers.size() + " su path checkers");

        for (DexMethodData methodData : suCheckers) {
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
                        // If method returns boolean (isRooted check), force false
                        if (param.getResult() instanceof Boolean && (Boolean) param.getResult()) {
                            param.setResult(false);
                            XposedEntry.log("Su path checker neutralized: " + className);
                        } else if (param.getResult() != null) {
                            try {
                                Object res = param.getResult();
                                if (Boolean.TRUE.equals(de.robv.android.xposed.XposedHelpers.getObjectField(res, "b"))) {
                                    de.robv.android.xposed.XposedHelpers.setObjectField(res, "b", Boolean.FALSE);
                                    XposedEntry.log("Su path checker object field b neutralized: " + className);
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook su checker: " + e.getMessage());
            }
        }
    }

    private static void hookPackageQueries(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> packageQueries = DexKitDetector.findSuspiciousPackageQueries();
        if (packageQueries.isEmpty()) {
            XposedEntry.log("DynamicRoot: No package queries found by DexKit");
            return;
        }

        for (DexMethodData methodData : packageQueries) {
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
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Check if querying for suspicious packages
                        for (Object arg : param.args) {
                            if (arg instanceof String) {
                                String pkg = (String) arg;
                                if (isSuspiciousPackage(pkg)) {
                                    if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProbe("PackageQuery", pkg, "blocked");
                                    }
                                    if (param.method instanceof java.lang.reflect.Method) {
                                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                                        Class<?> retType = m.getReturnType();
                                        if (retType == boolean.class) {
                                            param.setResult(false);
                                            return;
                                        }
                                        boolean canThrow = false;
                                        for (Class<?> ex : m.getExceptionTypes()) {
                                            if (ex.isAssignableFrom(android.content.pm.PackageManager.NameNotFoundException.class)) {
                                                canThrow = true;
                                                break;
                                            }
                                        }
                                        if (canThrow) {
                                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(
                                                "Package not found: " + pkg));
                                            return;
                                        } else {
                                            param.setResult(null);
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook package query: " + e.getMessage());
            }
        }
    }

    @SuppressWarnings("deprecation")
    private static void hookInstalledPackages(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> pmsClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "android.app.ApplicationPackageManager", lpparam.classLoader);
            if (pmsClass == null) {
                pmsClass = android.content.pm.PackageManager.class;
            }

            // Hook getInstalledPackages
            HookUtils.hookAllMethods(pmsClass, "getInstalledPackages", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledApplications
            HookUtils.hookAllMethods(pmsClass, "getInstalledApplications", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getPackageInfo & getPackageInfoAsUser: 拦截敏感包查询，注入官方签名
            XC_MethodHook packageInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String pkg = (String) param.args[0];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) {
                                return;
                            }
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException("Package not found: " + pkg));
                            return;
                        }
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.PackageInfo) {
                        android.content.pm.PackageInfo pi = (android.content.pm.PackageInfo) res;
                        String hostPkg = lpparam.packageName != null ? lpparam.packageName : "com.tencent.mobileqq";
                        if (hostPkg.equals(pi.packageName) || "com.tencent.mobileqq".equals(pi.packageName)) {
                            byte[] certBytes = android.util.Base64.decode(OFFICIAL_QQ_SIGNATURE_B64, android.util.Base64.DEFAULT);
                            android.content.pm.Signature officialSig = new android.content.pm.Signature(certBytes);

                            if (pi.signatures != null || isSignatureFlagRequested(param.args)) {
                                pi.signatures = new android.content.pm.Signature[]{ officialSig };
                            }

                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                                try {
                                    if (pi.signingInfo != null) {
                                        java.lang.reflect.Field detailsField = pi.signingInfo.getClass().getDeclaredField("mSigningDetails");
                                        detailsField.setAccessible(true);
                                        Object signingDetails = detailsField.get(pi.signingInfo);
                                        if (signingDetails != null) {
                                            java.lang.reflect.Field sigsField = signingDetails.getClass().getDeclaredField("signatures");
                                            sigsField.setAccessible(true);
                                            sigsField.set(signingDetails, new android.content.pm.Signature[]{ officialSig });
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "getPackageInfo", packageInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageInfoAsUser", packageInfoHook);

            // Hook getApplicationInfo & getPackageUid: 隐藏敏感包
            XC_MethodHook appInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String pkg = (String) param.args[0];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) {
                                return;
                            }
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException("Package not found: " + pkg));
                            return;
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "getApplicationInfo", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getApplicationInfoAsUser", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageUid", appInfoHook);
            HookUtils.hookAllMethods(pmsClass, "getPackageUidAsUser", appInfoHook);

            // Hook hasSigningCertificate(String, byte[], int) & hasSigningCertificate(int, byte[], int)
            XC_MethodHook hasSigningCertHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 3) return;
                    Object target = param.args[0];
                    byte[] certInput = param.args[1] instanceof byte[] ? (byte[]) param.args[1] : null;
                    int type = param.args[2] instanceof Integer ? (Integer) param.args[2] : 0;

                    if (certInput == null) {
                        param.setResult(false);
                        return;
                    }

                    String hostPkg = lpparam.packageName != null ? lpparam.packageName : "com.tencent.mobileqq";
                    boolean isHost = false;
                    if (target instanceof String) {
                        String pkg = (String) target;
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException("Package not found: " + pkg));
                            return;
                        }
                        if (hostPkg.equals(pkg) || "com.tencent.mobileqq".equals(pkg)) {
                            isHost = true;
                        }
                    } else if (target instanceof Integer) {
                        int uid = (Integer) target;
                        if (uid == android.os.Process.myUid()) {
                            isHost = true;
                        }
                    }

                    if (isHost) {
                        byte[] officialCertBytes = android.util.Base64.decode(OFFICIAL_QQ_SIGNATURE_B64, android.util.Base64.DEFAULT);
                        if (type == 0) { // CERT_INPUT_RAW_X509
                            param.setResult(java.util.Arrays.equals(certInput, officialCertBytes));
                        } else if (type == 1) { // CERT_INPUT_SHA256
                            try {
                                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                                byte[] officialSha256 = md.digest(officialCertBytes);
                                param.setResult(java.util.Arrays.equals(certInput, officialSha256));
                            } catch (Throwable t) {
                                param.setResult(false);
                            }
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "hasSigningCertificate", hasSigningCertHook);
            if (pmsClass != android.content.pm.PackageManager.class) {
                HookUtils.hookAllMethods(android.content.pm.PackageManager.class, "hasSigningCertificate", hasSigningCertHook);
            }

            // Hook checkSignatures(String, String) & checkSignatures(int, int)
            XC_MethodHook checkSignaturesHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    Object a1 = param.args[0];
                    Object a2 = param.args[1];
                    String hostPkg = lpparam.packageName != null ? lpparam.packageName : "com.tencent.mobileqq";

                    if (a1 instanceof String && a2 instanceof String) {
                        String p1 = (String) a1;
                        String p2 = (String) a2;
                        if (isSuspiciousPackage(p1) || isSuspiciousPackage(p2)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(android.content.pm.PackageManager.SIGNATURE_UNKNOWN_PACKAGE); // -4
                            return;
                        }
                        if ((hostPkg.equals(p1) || "com.tencent.mobileqq".equals(p1)) &&
                            (hostPkg.equals(p2) || "com.tencent.mobileqq".equals(p2))) {
                            param.setResult(android.content.pm.PackageManager.SIGNATURE_MATCH); // 0
                        }
                    } else if (a1 instanceof Integer && a2 instanceof Integer) {
                        int u1 = (Integer) a1;
                        int u2 = (Integer) a2;
                        int myUid = android.os.Process.myUid();
                        if (u1 == myUid && u2 == myUid) {
                            param.setResult(android.content.pm.PackageManager.SIGNATURE_MATCH); // 0
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "checkSignatures", checkSignaturesHook);

            // Hook QQ 内部 PackageUtil 全套探测函数，彻底封堵 Bugly 及风控反查
            Class<?> pkgUtilClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.mobileqq.utils.PackageUtil", lpparam.classLoader);
            if (pkgUtilClass != null) {
                // 1. isAppInstalled(Context, String) -> false
                HookUtils.hookAllMethods(pkgUtilClass, "isAppInstalled", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                            String pkg = (String) param.args[1];
                            if (isCallerQAuxv()) return;
                            if (isSuspiciousPackage(pkg)) {
                                param.setResult(false);
                            }
                        }
                    }
                });

                // 2. checkAppInstalled(Context, String) -> "0"
                HookUtils.hookAllMethods(pkgUtilClass, "checkAppInstalled", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                            String pkg = (String) param.args[1];
                            if (isCallerQAuxv()) return;
                            if (isSuspiciousPackage(pkg)) {
                                param.setResult("0");
                            }
                        }
                    }
                });

                // 3. checkAppInstalledBatch(Context, String) -> 仅净化敏感包对应槽位，保留正常包结果
                HookUtils.hookAllMethods(pkgUtilClass, "checkAppInstalledBatch", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (isCallerQAuxv()) return;
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String && param.getResult() instanceof String) {
                            String req = (String) param.args[1];
                            String res = (String) param.getResult();
                            String[] reqParts = req.split("\\|");
                            String[] resParts = res.split("\\|", -1);
                            boolean modified = false;
                            for (int i = 0; i < reqParts.length; i++) {
                                if (isSuspiciousPackage(reqParts[i].trim())) {
                                    if (i < resParts.length) {
                                        resParts[i] = "0";
                                        modified = true;
                                    }
                                }
                            }
                            if (modified) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < resParts.length; i++) {
                                    if (i > 0) sb.append("|");
                                    sb.append(resParts[i]);
                                }
                                param.setResult(sb.toString());
                            }
                        }
                    }
                });

                // 4. isAppInstalledBatch(Context, String) -> 仅净化敏感包对应槽位
                HookUtils.hookAllMethods(pkgUtilClass, "isAppInstalledBatch", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (isCallerQAuxv()) return;
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String && param.getResult() instanceof String) {
                            String req = (String) param.args[1];
                            String res = (String) param.getResult();
                            String[] reqParts = req.split("\\|");
                            String[] resParts = res.split("\\|", -1);
                            boolean modified = false;
                            for (int i = 0; i < reqParts.length; i++) {
                                if (isSuspiciousPackage(reqParts[i].trim())) {
                                    if (i < resParts.length) {
                                        resParts[i] = "0";
                                        modified = true;
                                    }
                                }
                            }
                            if (modified) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < resParts.length; i++) {
                                    if (i > 0) sb.append("|");
                                    sb.append(resParts[i]);
                                }
                                param.setResult(sb.toString());
                            }
                        }
                    }
                });

                // 5. getAppsVerionCodeBatch(Context, String) -> 仅净化敏感包对应槽位
                HookUtils.hookAllMethods(pkgUtilClass, "getAppsVerionCodeBatch", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (isCallerQAuxv()) return;
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String && param.getResult() instanceof String) {
                            String req = (String) param.args[1];
                            String res = (String) param.getResult();
                            String[] reqParts = req.split("\\|");
                            String[] resParts = res.split("\\|", -1);
                            boolean modified = false;
                            for (int i = 0; i < reqParts.length; i++) {
                                if (isSuspiciousPackage(reqParts[i].trim())) {
                                    if (i < resParts.length) {
                                        resParts[i] = "0";
                                        modified = true;
                                    }
                                }
                            }
                            if (modified) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < resParts.length; i++) {
                                    if (i > 0) sb.append("|");
                                    sb.append(resParts[i]);
                                }
                                param.setResult(sb.toString());
                            }
                        }
                    }
                });

                // 6. verifyInstalledApp(Context, String, String) -> false in afterHookedMethod
                HookUtils.hookAllMethods(pkgUtilClass, "verifyInstalledApp", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                            String pkg = (String) param.args[1];
                            if (isCallerQAuxv()) return;
                            if (isSuspiciousPackage(pkg) && param.getResult() == Boolean.TRUE) {
                                param.setResult(false);
                            }
                        }
                    }
                });
            }

            // Hook queryIntentActivities & queryIntentActivitiesAsUser
            XC_MethodHook queryActivitiesHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        boolean isFileIntent = isFileShareOrViewIntent(param.args);
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (isMtManagerPackage(pkg)) {
                                    if (isFileIntent) {
                                        filtered.add(item);
                                        continue;
                                    }
                                }
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            };
            HookUtils.hookAllMethods(pmsClass, "queryIntentActivities", queryActivitiesHook);
            HookUtils.hookAllMethods(pmsClass, "queryIntentActivitiesAsUser", queryActivitiesHook);

            // Hook queryIntentServices
            HookUtils.hookAllMethods(pmsClass, "queryIntentServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.serviceInfo != null ? ri.serviceInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryBroadcastReceivers
            HookUtils.hookAllMethods(pmsClass, "queryBroadcastReceivers", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryContentProviders
            HookUtils.hookAllMethods(pmsClass, "queryContentProviders", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ProviderInfo) {
                                android.content.pm.ProviderInfo pi = (android.content.pm.ProviderInfo) item;
                                if (!isSuspiciousPackage(pi.packageName)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook resolveContentProvider
            HookUtils.hookAllMethods(pmsClass, "resolveContentProvider", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.ProviderInfo) {
                        android.content.pm.ProviderInfo pi = (android.content.pm.ProviderInfo) res;
                        if (isSuspiciousPackage(pi.packageName) || (pi.authority != null && (pi.authority.contains("qauxv") || pi.authority.contains("lsposed") || pi.authority.contains("lspatch") || pi.authority.contains("moe.ono") || pi.authority.contains("lzlnb") || pi.authority.contains("libcnm") || pi.authority.contains("cnm0")))) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            // Hook resolveService
            HookUtils.hookAllMethods(pmsClass, "resolveService", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.ResolveInfo) {
                        android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) res;
                        String pkg = ri.serviceInfo != null ? ri.serviceInfo.packageName : null;
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            // Hook resolveActivity
            HookUtils.hookAllMethods(pmsClass, "resolveActivity", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof android.content.pm.ResolveInfo) {
                        android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) res;
                        String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                        if (isMtManagerPackage(pkg)) {
                            if (isFileShareOrViewIntent(param.args)) {
                                return;
                            }
                        }
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook getInstalledPackages: " + t.getMessage());
        }
    }

    public static final String OFFICIAL_QQ_SIGNATURE_B64 =
        "MIICUzCCAbygAwIBAgIES7sDYTANBgkqhkiG9w0BAQUFADBtMQ4wDAYDVQQGEwVDaGluYTEPMA0GA1UE" +
        "CAwG5YyX5LqsMQ8wDQYDVQQHDAbljJfkuqwxDzANBgNVBAoMBuiFvuiurzEbMBkGA1UECwwS5peg57q/" +
        "5Lia5Yqh57O757ufMQswCQYDVQQDEwJRUTAgFw0xMDA0MDYwOTQ4MTdaGA8yMjg0MDEyMDA5NDgxN1ow" +
        "bTEOMAwGA1UEBhMFQ2hpbmExDzANBgNVBAgMBuWMl+S6rDEPMA0GA1UEBwwG5YyX5LqsMQ8wDQYDVQQK" +
        "DAbohb7orq8xGzAZBgNVBAsMEuaXoOe6v+S4muWKoeezu+e7nzELMAkGA1UEAxMCUVEwgZ8wDQYJKoZI" +
        "hvcNAQEBBQADgY0AMIGJAoGBAKFel1Yhb2lMWRXgtSkJUlQ2fE5k+u/weuE0iNlGYVpY3cMaQV9xfQGe" +
        "3G0wuWA9Pip7PeCrfgz1Lf7jk3O8Ry+plwJ9eY1Z+B1SWmns8Vbohf0eJ5CSQ4ayIwzJDjt63JVgPdz0" +
        "xAvccvItsPIWqZw3HTv4nLpleMYGmeig1TaVAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAlKm4DoBpFkXd" +
        "QtZhF3WoVfcbzU13y2Co4pQEA1peALIbzF1KViSCEmvZG2sOUHCTd86574wu/RLMixav2aFZ81C7JwsU" +
        "IE/wZdhDgycgcC4otBSR+8OiBfXy9CUm1n8XYU2Kl03mSHsshm7+3jtOSaD5FrqjwTNv0u4bFillIEk=";

    private static boolean isSignatureFlagRequested(Object[] args) {
        if (args == null || args.length < 2) return false;
        for (int i = 1; i < args.length; i++) {
            Object arg = args[i];
            if (arg instanceof Integer) {
                int flags = (Integer) arg;
                if ((flags & 0x00000040) != 0 || (flags & 0x08000000) != 0) {
                    return true;
                }
            } else if (arg instanceof Long) {
                long flags = (Long) arg;
                if ((flags & 0x00000040L) != 0 || (flags & 0x08000000L) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void hookSystemProperties() {
        try {
            HookUtils.hookAllMethods("android.os.SystemProperties", "get", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    Object raw = param.getResult();
                    String res = raw instanceof String ? (String) raw : "";
                    if ("ro.debuggable".equals(key)) {
                        if (!"0".equals(res)) param.setResult("0");
                    } else if ("ro.secure".equals(key)) {
                        if (!"1".equals(res)) param.setResult("1");
                    } else if ("ro.build.tags".equals(key)) {
                        if (res.contains("test-keys")) param.setResult("release-keys");
                    } else if ("ro.boot.flash.locked".equals(key)) {
                        if (!"1".equals(res)) param.setResult("1");
                    } else if ("ro.boot.vbmeta.device_state".equals(key)) {
                        if (!"locked".equals(res)) param.setResult("locked");
                    } else if ("ro.boot.verifiedbootstate".equals(key)) {
                        if (!"green".equals(res)) param.setResult("green");
                    } else if ("persist.sys.adb.engineermode".equals(key)) {
                        if (!"0".equals(res)) param.setResult("0");
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key) || "persist.sys.usb.config".equals(key)) {
                        if (res.contains("adb")) {
                            String cleaned = res.replace(",adb", "").replace("adb,", "").replace("adb", "");
                            param.setResult(cleaned.isEmpty() ? "none" : cleaned);
                        }
                    } else if ("init.svc.adbd".equals(key)) {
                        if (!"stopped".equals(res)) param.setResult("stopped");
                    } else if (key.contains("magisk") || key.contains("kernelsu") || key.contains("ksud") || key.contains("ro.boot.ksu") || key.contains("ro.apatch") || key.contains("apatchd")) {
                        String def = param.args.length > 1 && param.args[1] instanceof String ? (String) param.args[1] : "";
                        param.setResult(def);
                    }
                }
            });

            HookUtils.hookAllMethods("android.os.SystemProperties", "getInt", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    Object raw = param.getResult();
                    if ("ro.debuggable".equals(key)) {
                        if (raw instanceof Integer && ((Integer) raw) != 0) param.setResult(0);
                    } else if ("ro.secure".equals(key)) {
                        if (raw instanceof Integer && ((Integer) raw) != 1) param.setResult(1);
                    } else if ("ro.boot.flash.locked".equals(key)) {
                        if (raw instanceof Integer && ((Integer) raw) != 1) param.setResult(1);
                    } else if ("persist.sys.adb.engineermode".equals(key)) {
                        if (raw instanceof Integer && ((Integer) raw) != 0) param.setResult(0);
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key)) {
                        if (raw instanceof Integer && ((Integer) raw) != 0) param.setResult(0);
                    }
                }
            });

            HookUtils.hookAllMethods("android.os.SystemProperties", "getBoolean", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || !(param.args[0] instanceof String)) return;
                    String key = (String) param.args[0];
                    Object raw = param.getResult();
                    if ("ro.debuggable".equals(key)) {
                        if (Boolean.TRUE.equals(raw)) param.setResult(false);
                    } else if ("ro.secure".equals(key)) {
                        if (Boolean.FALSE.equals(raw)) param.setResult(true);
                    } else if ("persist.sys.adb.engineermode".equals(key)) {
                        if (Boolean.TRUE.equals(raw)) param.setResult(false);
                    } else if ("sys.usb.config".equals(key) || "sys.usb.state".equals(key)) {
                        if (Boolean.TRUE.equals(raw)) param.setResult(false);
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook SystemProperties: " + t.getMessage());
        }

        // Java System properties hook to sanitize module indicators (e.g. moe.ono.startup.StartupAgent)
        try {
            HookUtils.hookMethod(System.class, "getProperty", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if (isSuspiciousPropertyKey(key)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            HookUtils.hookMethod(System.class, "getProperty", String.class, String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if (isSuspiciousPropertyKey(key)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(param.args[1]);
                        }
                    }
                }
            });

            HookUtils.hookMethod(System.class, "getProperties", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof java.util.Properties) {
                        java.util.Properties orig = (java.util.Properties) res;
                        boolean hasSuspicious = false;
                        for (String key : orig.stringPropertyNames()) {
                            if (isSuspiciousPropertyKey(key)) {
                                hasSuspicious = true;
                                break;
                            }
                        }
                        if (hasSuspicious) {
                            if (isCallerQAuxv()) return;
                            java.util.Properties clean = new java.util.Properties();
                            for (String key : orig.stringPropertyNames()) {
                                if (!isSuspiciousPropertyKey(key)) {
                                    clean.setProperty(key, orig.getProperty(key));
                                }
                            }
                            param.setResult(clean);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedEntry.log("Failed to hook System.getProperty: " + t.getMessage());
        }
    }

    private static boolean isSuspiciousPropertyKey(String key) {
        if (key == null) return false;
        String lower = key.toLowerCase();
        return lower.contains("moe.ono") || lower.contains("lzlnb")
            || lower.contains("libcnm") || lower.contains("cnm0") || lower.contains("xposed")
            || lower.contains("lspatch") || lower.contains("qauxv")
            || lower.contains("qqbypass") || lower.contains("dexkit");
    }

    private static void hookSettingsSecureAndGlobal() {
        try {
            XC_MethodHook adbSettingsHook = new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String name = (String) param.args[1];
                        if ("adb_enabled".equals(name) || "development_settings_enabled".equals(name)) {
                            Object res = param.getResult();
                            if (res instanceof Integer && ((Integer) res) != 0) {
                                param.setResult(0);
                            } else if (res instanceof String && !"0".equals(res)) {
                                param.setResult("0");
                            } else if (res instanceof Number && ((Number) res).longValue() != 0L) {
                                param.setResult(0L);
                            }
                        } else if ("enabled_accessibility_services".equals(name)) {
                            Object res = param.getResult();
                            if (res instanceof String && !((String) res).isEmpty()) {
                                String s = (String) res;
                                if (isSuspiciousPackage(s)) {
                                    param.setResult("");
                                }
                            }
                        }
                    }
                }
            };

            HookUtils.hookAllMethods("android.provider.Settings.Global", "getInt", adbSettingsHook);
            HookUtils.hookAllMethods("android.provider.Settings.Global", "getString", adbSettingsHook);
            HookUtils.hookAllMethods("android.provider.Settings.Secure", "getInt", adbSettingsHook);
            HookUtils.hookAllMethods("android.provider.Settings.Secure", "getString", adbSettingsHook);
            XposedEntry.log("[DynamicRoot] Hooked Settings.Global & Settings.Secure adb_enabled/development_settings_enabled");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook Settings: " + t.getMessage());
        }
    }

    private static void hookProcessExecution() {
        try {
            HookUtils.hookMethod(ProcessBuilder.class, "start", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                    List<String> command = pb.command();
                    if (command != null && !command.isEmpty()) {
                        for (String arg : command) {
                            if (arg == null) continue;
                            String lower = arg.toLowerCase();
                            if (lower.equals("su") || lower.endsWith("/su") || lower.contains("busybox")
                                    || lower.contains("magisk") || lower.contains("ksud")
                                    || lower.contains("which su") || lower.contains("type su")) {
                                if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProbe("ProcessExec", arg, "blocked with IOException");
                                }
                                throw new java.io.IOException("Cannot run program \"" + arg + "\": error=2, No such file or directory");
                            }
                        }
                    }
                }
            });

            HookUtils.hookAllMethods(Runtime.class, "exec", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    if (param.args == null || param.args.length == 0) return;
                    Object cmdObj = param.args[0];
                    if (cmdObj instanceof String) {
                        String cmd = ((String) cmdObj).toLowerCase();
                        if (cmd.equals("su") || cmd.startsWith("su ") || cmd.endsWith("/su")
                                || cmd.contains("busybox") || cmd.contains("magisk") || cmd.contains("ksud")
                                || cmd.contains("type su") || cmd.contains("which su")) {
                            if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProbe("ProcessExec", String.valueOf(cmdObj), "blocked with IOException");
                            }
                            throw new java.io.IOException("Cannot run program \"" + cmdObj + "\": error=2, No such file or directory");
                        }
                    } else if (cmdObj instanceof String[]) {
                        String[] cmdarray = (String[]) cmdObj;
                        for (String arg : cmdarray) {
                            if (arg == null) continue;
                            String lower = arg.toLowerCase();
                            if (lower.equals("su") || lower.endsWith("/su") || lower.contains("busybox")
                                    || lower.contains("magisk") || lower.contains("ksud")
                                    || lower.contains("which su") || lower.contains("type su")) {
                                if (io.github.xalsace.qqbypass.config.CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProbe("ProcessExec", arg, "blocked with IOException");
                                }
                                throw new java.io.IOException("Cannot run program \"" + arg + "\": error=2, No such file or directory");
                            }
                        }
                    }
                }
            });
            XposedEntry.log("[DynamicRoot] Hooked ProcessBuilder.start & Runtime.exec");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook ProcessBuilder/Runtime.exec: " + t.getMessage());
        }
    }

    private static void hookActivityManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> amClass = android.app.ActivityManager.class;

            // Hook getRunningAppProcesses
            HookUtils.hookAllMethods(amClass, "getRunningAppProcesses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
                                android.app.ActivityManager.RunningAppProcessInfo pi =
                                    (android.app.ActivityManager.RunningAppProcessInfo) item;
                                if (isSuspiciousPackage(pi.processName)) continue;
                                boolean hasSuspPkg = false;
                                if (pi.pkgList != null) {
                                    for (String p : pi.pkgList) {
                                        if (isSuspiciousPackage(p)) {
                                            hasSuspPkg = true;
                                            break;
                                        }
                                    }
                                }
                                if (hasSuspPkg) continue;
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunningTasks
            HookUtils.hookAllMethods(amClass, "getRunningTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningTaskInfo) {
                                android.app.ActivityManager.RunningTaskInfo ti =
                                    (android.app.ActivityManager.RunningTaskInfo) item;
                                String topPkg = ti.topActivity != null ? ti.topActivity.getPackageName() : null;
                                String basePkg = ti.baseActivity != null ? ti.baseActivity.getPackageName() : null;
                                if (isSuspiciousPackage(topPkg) || isSuspiciousPackage(basePkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRecentTasks
            HookUtils.hookAllMethods(amClass, "getRecentTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RecentTaskInfo) {
                                android.app.ActivityManager.RecentTaskInfo rti =
                                    (android.app.ActivityManager.RecentTaskInfo) item;
                                String pkg = rti.baseIntent != null && rti.baseIntent.getComponent() != null ?
                                    rti.baseIntent.getComponent().getPackageName() : null;
                                if (isSuspiciousPackage(pkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunningServices
            HookUtils.hookAllMethods(amClass, "getRunningServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningServiceInfo) {
                                android.app.ActivityManager.RunningServiceInfo rsi =
                                    (android.app.ActivityManager.RunningServiceInfo) item;
                                String pkg = rsi.service != null ? rsi.service.getPackageName() : null;
                                if (isSuspiciousPackage(pkg) || isSuspiciousPackage(rsi.process)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });
            XposedEntry.log("[DynamicRoot] Hooked ActivityManager running processes/tasks/services");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook ActivityManager: " + t.getMessage());
        }
    }

    private static void hookInstalledAppListMonitor(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> monitorClass = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "com.tencent.qmethod.pandoraex.monitor.InstalledAppListMonitor", lpparam.classLoader);
            if (monitorClass == null) return;

            // Hook getRunningAppProcesses
            HookUtils.hookAllMethods(monitorClass, "getRunningAppProcesses", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
                                android.app.ActivityManager.RunningAppProcessInfo pi =
                                    (android.app.ActivityManager.RunningAppProcessInfo) item;
                                if (isSuspiciousPackage(pi.processName)) continue;
                                boolean hasSuspPkg = false;
                                if (pi.pkgList != null) {
                                    for (String p : pi.pkgList) {
                                        if (isSuspiciousPackage(p)) {
                                            hasSuspPkg = true;
                                            break;
                                        }
                                    }
                                }
                                if (hasSuspPkg) continue;
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getRunTasks
            HookUtils.hookAllMethods(monitorClass, "getRunTasks", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.ActivityManager.RunningTaskInfo) {
                                android.app.ActivityManager.RunningTaskInfo ti =
                                    (android.app.ActivityManager.RunningTaskInfo) item;
                                String topPkg = ti.topActivity != null ? ti.topActivity.getPackageName() : null;
                                String basePkg = ti.baseActivity != null ? ti.baseActivity.getPackageName() : null;
                                if (isSuspiciousPackage(topPkg) || isSuspiciousPackage(basePkg)) {
                                    continue;
                                }
                                filtered.add(item);
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledPackages
            HookUtils.hookAllMethods(monitorClass, "getInstalledPackages", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getInstalledApplications
            HookUtils.hookAllMethods(monitorClass, "getInstalledApplications", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getPackageInfo
            HookUtils.hookAllMethods(monitorClass, "getPackageInfo", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String pkg = (String) param.args[1];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setThrowable(new android.content.pm.PackageManager.NameNotFoundException(pkg));
                        }
                    }
                }
            });

            // Hook getLaunchIntentForPackage
            HookUtils.hookAllMethods(monitorClass, "getLaunchIntentForPackage", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1 && param.args[1] instanceof String) {
                        String pkg = (String) param.args[1];
                        if (isSuspiciousPackage(pkg)) {
                            if (isCallerQAuxv()) return;
                            param.setResult(null);
                        }
                    }
                }
            });

            // Hook queryIntentActivities
            HookUtils.hookAllMethods(monitorClass, "queryIntentActivities", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        boolean isFileIntent = isFileShareOrViewIntent(param.args);
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.activityInfo != null ? ri.activityInfo.packageName : null;
                                if (isMtManagerPackage(pkg)) {
                                    if (isFileIntent || !isCallerSecurityComponent()) {
                                        filtered.add(item);
                                        continue;
                                    }
                                }
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook queryIntentServices
            HookUtils.hookAllMethods(monitorClass, "queryIntentServices", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ResolveInfo) {
                                android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                                String pkg = ri.serviceInfo != null ? ri.serviceInfo.packageName : null;
                                if (!isSuspiciousPackage(pkg)) {
                                    filtered.add(item);
                                }
                            } else {
                                filtered.add(item);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            // Hook getLastApplicationInfoList & getLastPackageInfoList
            HookUtils.hookAllMethods(monitorClass, "getLastApplicationInfoList", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.ApplicationInfo) {
                                String pn = ((android.content.pm.ApplicationInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });

            HookUtils.hookAllMethods(monitorClass, "getLastPackageInfoList", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (isCallerQAuxv()) return;
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.content.pm.PackageInfo) {
                                String pn = ((android.content.pm.PackageInfo) item).packageName;
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });

            XposedEntry.log("[DynamicRoot] Hooked InstalledAppListMonitor");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook InstalledAppListMonitor: " + t.getMessage());
        }
    }

    private static void hookUsageStatsManager(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> usmClass = android.app.usage.UsageStatsManager.class;
            HookUtils.hookAllMethods(usmClass, "queryUsageStats", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof List) {
                        List<?> list = (List<?>) res;
                        List<Object> filtered = new java.util.ArrayList<>();
                        for (Object item : list) {
                            if (item instanceof android.app.usage.UsageStats) {
                                String pn = ((android.app.usage.UsageStats) item).getPackageName();
                                if (!isSuspiciousPackage(pn)) filtered.add(item);
                            } else filtered.add(item);
                        }
                        param.setResult(filtered);
                    }
                }
            });
            HookUtils.hookAllMethods(usmClass, "queryAndAggregateUsageStats", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, android.app.usage.UsageStats> map =
                            (java.util.Map<String, android.app.usage.UsageStats>) res;
                        java.util.Map<String, android.app.usage.UsageStats> filtered = new java.util.HashMap<>();
                        for (java.util.Map.Entry<String, android.app.usage.UsageStats> entry : map.entrySet()) {
                            if (!isSuspiciousPackage(entry.getKey())) {
                                filtered.put(entry.getKey(), entry.getValue());
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });
            XposedEntry.log("[DynamicRoot] Hooked UsageStatsManager");
        } catch (Throwable t) {
            XposedEntry.log("[DynamicRoot] Failed to hook UsageStatsManager: " + t.getMessage());
        }
    }

    public static boolean isCallerQAuxv() {
        try {
            DynamicXposedDetectionHook.bypassStackFilter.set(true);
            String tName = Thread.currentThread().getName();
            if (tName != null) {
                String lt = tName.toLowerCase();
                if (lt.contains("qauxv") || lt.contains("ioctl") || lt.contains("singleneuron")
                        || lt.contains("lspatch") || lt.contains("lsposed") || lt.contains("xposed")
                        || lt.contains("moe.ono") || lt.contains("ono_") || lt.contains("ono-") || lt.contains("lzlnb") || lt.contains("libcnm") || lt.contains("cnm0")
                        || lt.contains("se-dexkit")) {
                    return true;
                }
            }
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            if (cl != null) {
                String clStr = cl.toString().toLowerCase();
                if (clStr.contains("qauxv") || clStr.contains("lspatch") || clStr.contains("lsposed")
                        || clStr.contains("moe.ono") || clStr.contains("ono_") || clStr.contains("ono-") || clStr.contains("lzlnb") || clStr.contains("libcnm") || clStr.contains("cnm0")) {
                    return true;
                }
            }
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls != null && (
                    cls.startsWith("org.lsposed.") ||
                    cls.startsWith("top.canyie.") ||
                    cls.startsWith("io.github.qauxv.") ||
                    cls.startsWith("cc.ioctl.") ||
                    cls.startsWith("me.singleneuron.") ||
                    cls.startsWith("nep.timeline.") ||
                    cls.startsWith("me.ketal.") ||
                    cls.startsWith("me.hd.") ||
                    cls.startsWith("xyz.nextalone.") ||
                    cls.startsWith("top.linl.") ||
                    cls.startsWith("net.bytebuddy.") ||
                    cls.startsWith("io.github.libxposed.") ||
                    cls.startsWith("com.android.dx.") ||
                    cls.startsWith("android.content.res.XResources") ||
                    cls.startsWith("de.robv.android.xposed.") ||
                    cls.startsWith("moe.ono.") ||
                    cls.startsWith("lzlnb.cnm.") ||
                    cls.startsWith("cnm0.") ||
                    cls.startsWith("lzlnb.") ||
                    cls.startsWith("org.luckypray.dexkit.") ||
                    cls.startsWith("io.github.xalsace.qqbypass.")
                )) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            DynamicXposedDetectionHook.bypassStackFilter.set(false);
        }
        return false;
    }

    public static boolean isCallerSecurityComponent() {
        try {
            DynamicXposedDetectionHook.bypassStackFilter.set(true);
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            for (StackTraceElement elem : stack) {
                String cls = elem.getClassName();
                if (cls == null) continue;
                String lower = cls.toLowerCase();
                if (lower.contains(".qsec.") || lower.contains(".turing") || lower.contains(".tfd.") || lower.contains(".beacon.")
                        || lower.contains(".pandora") || lower.contains(".bugly.")
                        || lower.contains(".feedback.") || lower.contains("gathererga")
                        || lower.contains("camerasdk.avreport")
                        || lower.contains(".mobileqq.msf.")
                        || lower.contains("oicq.wlogin_sdk")
                        || lower.contains(".qqperf.")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            DynamicXposedDetectionHook.bypassStackFilter.set(false);
        }
        return false;
    }

    public static boolean isMtManagerPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();
        return lower.contains("bin.mt.") || lower.equals("bin.mt") || lower.contains("bin.mt.plus")
                || lower.contains("bin.mt.manager") || lower.contains("bin.mt.termex");
    }

    public static boolean isFileShareOrViewIntent(Object[] args) {
        if (args == null) return false;
        for (Object arg : args) {
            if (arg instanceof android.content.Intent) {
                android.content.Intent intent = (android.content.Intent) arg;
                String action = intent.getAction();
                if (action == null) {
                    if (intent.getData() != null || intent.getType() != null) return true;
                    continue;
                }
                if (android.content.Intent.ACTION_VIEW.equals(action)
                        || android.content.Intent.ACTION_SEND.equals(action)
                        || android.content.Intent.ACTION_SEND_MULTIPLE.equals(action)
                        || android.content.Intent.ACTION_EDIT.equals(action)
                        || android.content.Intent.ACTION_CHOOSER.equals(action)
                        || action.contains("OPEN") || action.contains("SHARE")
                        || action.contains("VIEW") || action.contains("SEND")) {
                    return true;
                }
                if (intent.getData() != null || intent.getType() != null) {
                    return true;
                }
                if (intent.hasExtra(android.content.Intent.EXTRA_INTENT)) {
                    try {
                        @SuppressWarnings("deprecation")
                        android.os.Parcelable p = intent.getParcelableExtra(android.content.Intent.EXTRA_INTENT);
                        if (p instanceof android.content.Intent) {
                            return isFileShareOrViewIntent(new Object[]{p});
                        }
                    } catch (Throwable ignored) {}
                }
            }
        }
        return false;
    }

    public static boolean isSuspiciousPrefName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.contains("sesearchcache") ||
               lower.contains("qnotified") ||
               lower.contains("ono_") ||
               lower.contains("moe.ono") ||
               lower.contains("lzlnb") ||
               lower.contains("qauxv") ||
               (lower.equals("global_config") || lower.startsWith("qauxv_global_config")) ||
               lower.contains("xposed") ||
               lower.contains("lsposed");
    }

    public static boolean isSuspiciousPath(String path) {
        if (path == null) return false;

        // NEVER block installed APKs in /data/app/ (including QAuxiliary and system packages)
        if (path.contains("/data/app/")) {
            return false;
        }

        String lower = path.toLowerCase();

        // QAuxiliary storage and private directories: allow QAuxv, hide from ALL other callers in QQ
        if (lower.contains("qa_mmkv") || lower.contains("tmp_qa_")
                || lower.contains("qa_dyn_lib") || lower.contains("qa_misc")
                || lower.contains("io.github.qauxv") || lower.contains("libqauxv")
                || lower.contains("qnotified") || (lower.contains("global_config") && !lower.contains("ar_global_config") && (lower.contains("qa_mmkv/global_config") || lower.endsWith("/global_config.xml") || lower.endsWith("/global_config") || lower.contains("qauxv_global_config")))
                || lower.contains("oat_inline_deopt_cache") || lower.contains("last_use_emoticon_time")
                || lower.contains("sdumptg_") || lower.contains("qauxv_")) {
            if (isCallerQAuxv()) {
                return false;
            }
            return true;
        }

        // LSPatch private cache/files directories: allow LSPatch/modules, hide from QQ scanners
        if (lower.contains("lspatch")) {
            if (isCallerQAuxv()) {
                return false;
            }
            return true;
        }

        // ovo (moe.ono) private storage, mmkv, and preferences
        if (lower.contains("ono_mmkv") || lower.contains("ono_hcb_") || lower.contains("moe.ono")
                || lower.contains("ono_bubble_cache") || lower.contains("ono_image_tag")
                || lower.contains("ono_need_find_method") || lower.contains("/ono/")
                || lower.endsWith("/ono") || lower.equals("ono")) {
            if (isCallerQAuxv()) {
                return false;
            }
            return true;
        }

        // 模了个块 (lzlnb.cnm.hook) private cache and files
        if (lower.contains("files/.se") || lower.contains(".se/kc.dat")
                || lower.contains("kc.dat") || lower.contains(".sys_cache")
                || lower.contains("config/pz") || lower.contains("sesearchcache")
                || lower.contains("lzlnb") || lower.contains("libcnm.so")
                || lower.contains("liball-jni.so")) {
            if (isCallerQAuxv()) {
                return false;
            }
            return true;
        }

        // MT Manager paths & storage: hide from QQ
        if (lower.contains("bin.mt.plus") || lower.contains("bin.mt.manager")
                || lower.contains("bin.mt.termex") || lower.contains("bin.mt.")
                || lower.contains("/mt2") || lower.contains("/sdcard/mt2")) {
            return true;
        }

        if (lower.contains("top.nkbe.npatch") || lower.contains("npatch")
                || lower.contains("org.lsposed.manager") || lower.contains("lspilot")) {
            return true;
        }

        for (String suPath : SU_PATHS) {
            if (lower.contains(suPath)) return true;
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("kernelsu")
            || lower.contains("ksud") || lower.contains("/ksu/")
            || lower.contains("libapatch") || lower.contains("/apatch/")
            || lower.contains("me.bmax.apatch") || lower.contains("apatchd")
            || lower.contains("shamiko")
            || lower.contains("mountify") || lower.contains("tricky_store")
            || lower.contains("zygisksu") || lower.contains("metamodule")
            || lower.contains("xposed") || lower.contains("lsposed")
            || lower.contains("frida") || lower.contains("/data/adb")
            || lower.contains("dexkit") || lower.contains("sandhook")
            || lower.contains("yahfa") || lower.contains("liblspd")
            || lower.contains("qqbypass") || lower.contains("native-bypass")
            || lower.contains("bytehook") || lower.contains("xalsace")
            || lower.contains("fusehide") || lower.contains("simplehook")
            || lower.contains("libchecker") || lower.contains("shizuku")
            || lower.contains("vtools") || lower.contains("thanos")
            || lower.contains("puredupan") || lower.contains("developertools")
            || lower.contains("moe.ono") || lower.contains("lzlnb")
            || lower.contains("libcnm") || lower.contains("cnm0")
            || lower.contains("liball-jni")
            || lower.contains("duckusb") || lower.contains("termux")
            || lower.contains(".android_system_config.prop") || lower.contains("microvirtd")
            || lower.contains("ku.sud") || lower.contains("shuamesu")
            || lower.contains("cufsdosck") || lower.contains("cufsmgr")
            || lower.contains("cufaevdd") || lower.contains("conbb")
            || lower.contains("daemonsu") || lower.contains("permmgrd")
            || lower.contains("360sguard");
    }

    public static boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) return false;
        String lower = pkg.toLowerCase();

        // MT Manager: hidden from all general app queries, allowed only in file intents
        if (isMtManagerPackage(lower)) {
            return true;
        }

        return lower.contains("magisk") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("xposed")
            || lower.contains("lsposed") || lower.contains("edxposed")
            || lower.contains("lspatch") || lower.contains("top.canyie") || lower.contains("canyie")
            || lower.contains("kernelsu") || lower.contains(".apatch") || lower.startsWith("apatch")
            || lower.contains("shamiko") || lower.contains("frida")
            || lower.contains("me.weishu") || lower.contains("me.bmax")
            || lower.contains("sandhook") || lower.contains("taichi")
            || lower.contains("top.canyie") || lower.contains("xalsace")
            || lower.contains("qqbypass") || lower.contains("dexkit")
            || lower.contains("top.nkbe.npatch") || lower.contains("npatch")
            || lower.contains("org.lsposed.manager") || lower.contains("lspilot")
            || lower.contains("youqu.android.todesk") || lower.contains("com.netease.uuremote")
            || lower.contains("com.topjohnwu.magisk")
            || lower.contains("io.github.qauxv") || lower.contains("qauxv")
            || lower.contains("qnotified") || lower.contains("cc.ioctl")
            || lower.contains("me.singleneuron") || lower.contains("nep.timeline")
            || lower.contains("disableflagsecure") || lower.contains("disable_flag_secure")
            || lower.contains("fusehide") || lower.contains("lively.xp")
            || lower.contains("simplehook") || lower.contains("gptweaks")
            || lower.contains("naipinghook") || lower.contains("hma_oss")
            || lower.contains("hooknext") || lower.contains("hookvip")
            || lower.contains("fckvip") || lower.contains("hujiayucc.hook")
            || lower.contains("shizuku") || lower.contains("vtools")
            || lower.contains("merxury.blocker") || lower.contains("thanos")
            || lower.contains("pan123.enhance") || lower.contains("puredupan")
            || lower.contains("tiktokplugin") || lower.contains("dsmod.probe")
            || lower.contains("x1y9.probe") || lower.contains("developertools")
            || lower.contains("layoutinspect") || lower.contains("devcheck")
            || lower.contains("libchecker") || lower.contains("luckytool")
            || lower.contains("duckusb") || lower.contains("droidvnc")
            || lower.contains("moe.ono") || lower.contains("lzlnb")
            || lower.contains("libcnm") || lower.contains("cnm0")
            || lower.contains("applisto") || lower.contains("kingroot")
            || lower.contains("kinguser") || lower.contains("oneclickroot")
            || lower.contains("rootgenius") || lower.contains("shuame")
            || lower.contains("termux") || lower.contains(".hook")
            || lower.contains("substrate") || lower.contains("cydia")
            || lower.contains("sukisu") || lower.contains("ksunext");
    }
}
