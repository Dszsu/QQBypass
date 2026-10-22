package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;
import java.util.Map;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Network Report Interception Hook (Deep Non-intrusive Protocol Architecture)
 *
 * Provides a low-level, layered interception and synthetic response system:
 * - Layer 0: ChannelManager.sendMessage choke point (pre-proxy, avoids checkMethod anti-hook)
 * - Layer 1: ChannelProxyExt.sendMessage (synthesizes 5-arg onNativeReceive callback)
 * - Layer 2: MSFKernelBridge.CppProxy.sendPacket (native MSF packet choke point)
 * - Layer 3: MsfCore.sendSsoMsg (service layer, synthesizes FromServiceMsg for waiters)
 * - Layer 4: TuringFD /proc scanner neutralization
 * - Layer 5: Wlogin device report
 */
public class NetworkReportHook {

    // Strict Whitelist: never block or intercept critical protocol, session, and key-exchange commands
    private static final String[] SAFE_WHITELIST = {
        "trpc.msg.",
        "trpc.o3.ecdh_access.",
        "trpc.o3.full_social_lock_punish.",
        "trpc.o3.mobile_security.",
        "Heartbeat.",
        "StatSvc.",
        "MessageSvc.",
        "RegPrxySvc."
    };

    /**
     * Fast-path identification of core messaging, sync, and session keepalives.
     * Core functional messages MUST pass through instantly with ZERO reflection,
     * ZERO audit logging, and ZERO thread latency to eliminate sync stalls ("接收中...").
     */
    public static boolean isCoreProtocolCommand(String command) {
        if (command == null || command.isEmpty()) return false;
        return command.startsWith("trpc.msg.") ||
               command.startsWith("MessageSvc.") ||
               command.startsWith("RegPrxySvc.") ||
               command.startsWith("Heartbeat.") ||
               command.startsWith("OnlinePush.") ||
               command.startsWith("ConfigPushSvc.") ||
               command.startsWith("ProfileService.") ||
               command.startsWith("Friendlist.") ||
               command.startsWith("trpc.login.ecdh.access") ||
               command.startsWith("trpc.group_mall.") ||
               (command.startsWith("StatSvc.") && !command.contains("Offline")) ||
               (command.startsWith("OidbSvc.") && !command.contains("0xd79"));
    }

    // Targeted block: only pure telemetry and security report commands
    // Note: trpc.o3.report.Report.SsoReport and SsoEventReport are NOT blocked here because
    // they carry official sanitized APK signature baseline reports (0df00071646) required by the server.
    private static final String[] TELEMETRY_BLOCK_COMMANDS = {
        "trpc.ilive_cdn.report",
        "trpc.qq_security.",
        "OidbSvc.0xd79",
        "trpc.login.ecdh.report",
        "QQProtect.SecReport",
        "SecCheck.Report",
        "DevLockAuth.SecReport",
        "0ac00056535",
        "LOAD_RESULT_PATCH_LOADER_FAIL",
        "trpc.atta."
    };

    private static final java.util.Set<String> sHookedNetworkClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        // Layer 0 - 3: Channel / MSF report auditing & optional interception
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT || HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookChannelManager(cl);
            hookChannelProxyExt(cl);
            hookMSFKernelBridge(cl);
            hookMsfCore(cl);
        }

        // Layer 4 & 5: StatisticCollector & ReportController telemetry auditing
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookStatisticCollector(cl);
            hookReportController(cl);
            hookKickAudit(lpparam);
            hookWlogin(cl);
            hookTuringD1Network(cl);
        }

        // Inspection checks (TuringFD /proc scanner neutralization)
        hookTuringFD(lpparam);
        hookTuringEridanus(cl);
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookKickAuditInternal(cl);
            hookWlogin(cl);
            hookTuringD1Network(cl);
        }
        hookTuringEridanus(cl);

        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT || HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookChannelManager(cl);
            hookChannelProxyExt(cl);
            hookMSFKernelBridge(cl);
            hookMsfCore(cl);
        }

        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookStatisticCollector(cl);
            hookReportController(cl);
        }
    }

    /**
     * Synthesize clean success response to FEKit / ChannelManager native engine.
     * In QQ NT / 9.3.x, onNativeReceive expects 5 parameters:
     * (String cmd, byte[] data, boolean isSuccess, int resultCode, long callbackId)
     * Passing 1000 indicates SUCCESS and cleanly finishes the native async request.
     */
    public static void injectNativeReceiveSuccess(ClassLoader cl, String command, long callbackId) {
        try {
            Class<?> cmClass = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelManager", cl);
            if (cmClass == null) return;
            Object cmInstance = XposedHelpers.callStaticMethod(cmClass, "getInstance");
            if (cmInstance == null) return;

            // 1. Try 5-arg onNativeReceive(String, byte[], boolean, int, long)
            try {
                XposedHelpers.callMethod(cmInstance, "onNativeReceive",
                    command, new byte[0], true, 1000, callbackId);
                return;
            } catch (Throwable ignored) { }

            // 2. Try 5-arg onReceive(String, byte[], boolean, int, long)
            try {
                XposedHelpers.callMethod(cmInstance, "onReceive",
                    command, new byte[0], true, 1000, callbackId);
                return;
            } catch (Throwable ignored) { }

            // 3. Fallback for older overloads
            try {
                XposedHelpers.callMethod(cmInstance, "onNativeReceive",
                    command, new byte[0], callbackId);
            } catch (Throwable ignored) { }
        } catch (Throwable t) {
            XposedEntry.log("[NetworkReport] injectNativeReceive error: " + t.getMessage());
        }
    }

    /**
     * Layer 0: Hook ChannelManager.sendMessage directly.
     * Audits all outgoing FEKit / C++ security messages, and selectively neutralizes
     * when ENABLE_NETWORK_INTERCEPT is enabled.
     */
    private static void hookChannelManager(ClassLoader cl) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelManager", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_ChannelManager")) return;

        HookUtils.hookAllMethods(clazz, "sendMessage",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) return;

                    String command = (String) param.args[0];
                    if (isCoreProtocolCommand(command)) {
                        return; // Zero overhead fast-path: core messaging & sync pass through immediately
                    }

                    long callbackId = 0L;
                    if (param.args.length >= 3 && param.args[2] instanceof Number) {
                        callbackId = ((Number) param.args[2]).longValue();
                    }
                    byte[] data = null;
                    int dataLen = 0;
                    if (param.args.length >= 2 && param.args[1] instanceof byte[]) {
                        data = (byte[]) param.args[1];
                        dataLen = data.length;
                    }

                    // Always audit outgoing ChannelManager reports if report recording is enabled
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordChannelManager(command, callbackId, dataLen, data);
                    }

                    if (HookConfig.ENABLE_NETWORK_INTERCEPT && shouldBlock(command)) {
                        injectNativeReceiveSuccess(cl, command, callbackId);
                        param.setResult(null);
                        XposedEntry.log("Intercepted & fulfilled ChannelManager.sendMessage: "
                            + command + " (callbackId=" + callbackId + ")");
                    }
                }
            });
        XposedEntry.log("[NetworkReport] Installed ChannelManager.sendMessage hook on loader " + cl);
    }

    /**
     * Layer 1: ChannelProxyExt.sendMessage fallback.
     */
    private static void hookChannelProxyExt(ClassLoader cl) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelProxyExt", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_ChannelProxyExt")) return;

        String[] methodNames = {"sendMessageInner", "sendMessage", "send"};
        HookUtils.hookCandidateMethods("com.tencent.mobileqq.channel.ChannelProxyExt", methodNames, cl,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) return;

                    String command = (String) param.args[0];
                    if (isCoreProtocolCommand(command)) {
                        return; // Zero overhead fast-path
                    }

                    long callbackId = 0L;
                    for (int i = param.args.length - 1; i >= 1; i--) {
                        if (param.args[i] instanceof Number) {
                            callbackId = ((Number) param.args[i]).longValue();
                            break;
                        }
                    }

                    // Always audit if report recording is enabled
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReport("ChannelProxyExt", command, null, "callbackId=" + callbackId, 0);
                    }

                    if (HookConfig.ENABLE_NETWORK_INTERCEPT && shouldBlock(command)) {
                        Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                        if (returnType.isPrimitive() && returnType != void.class) {
                            return;
                        }

                        injectNativeReceiveSuccess(cl, command, callbackId);
                        param.setResult(null);
                        XposedEntry.log("Intercepted & fulfilled ChannelProxyExt: "
                            + command + " (callbackId=" + callbackId + ")");
                    }
                }
            });
        XposedEntry.log("[NetworkReport] Installed ChannelProxyExt hook on loader " + cl);
    }

    /**
     * Layer 2: MSFKernelBridge$CppProxy.sendPacket.
     * Low-level choke point where packets are submitted to libMSFKernel.so native engine.
     */
    private static void hookMSFKernelBridge(ClassLoader cl) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msfcore.MSFKernelBridge$CppProxy", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_MSFKernelBridge")) return;

        HookUtils.hookAllMethods(clazz, "sendPacket",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || param.args[0] == null) return;
                    Object adapter = param.args[0];
                    try {
                        String cmd = (String) XposedHelpers.callMethod(adapter, "getCmd");
                        if (cmd == null || isCoreProtocolCommand(cmd)) {
                            return; // Fast path: zero reflection / audit overhead for message sync
                        }
                        int seq = 0;
                        try {
                            seq = ((Number) XposedHelpers.callMethod(adapter, "getSeq")).intValue();
                        } catch (Throwable ignored) { }

                        // Always audit if report recording is enabled
                        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReport("MSFKernelBridge", cmd, null, "seq=" + seq, 0);
                        }

                        if (HookConfig.ENABLE_NETWORK_INTERCEPT && shouldBlock(cmd)) {
                            param.setResult(seq);
                            XposedEntry.log("Neutralized MSFKernelBridge.sendPacket: " + cmd + " (seq=" + seq + ")");
                        }
                    } catch (Throwable ignored) { }
                }
            });
        XposedEntry.log("[NetworkReport] Installed MSFKernelBridge hook on loader " + cl);
    }

    /**
     * Layer 3: MsfCore.sendSsoMsg.
     * Service layer SSO dispatcher. Audits all SSO outgoing traffic and optional interception.
     */
    private static void hookMsfCore(ClassLoader cl) {
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.MsfCore", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_MsfCore")) return;

        HookUtils.hookAllMethods(clazz, "sendSsoMsg",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1 || param.args[0] == null) return;

                    Object toServiceMsg = param.args[0];
                    Object cmdObj = XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                    String command = cmdObj == null ? null : cmdObj.toString();
                    if (command == null || isCoreProtocolCommand(command)) {
                        return; // Zero overhead fast-path: never delay or touch message sync
                    }

                    String uin = "";
                    int ssoSeq = 0;
                    boolean needResp = false;
                    java.util.Map<?, ?> attrs = null;
                    byte[] wup = null;
                    try {
                        uin = (String) XposedHelpers.callMethod(toServiceMsg, "getUin");
                        ssoSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                        needResp = (boolean) XposedHelpers.callMethod(toServiceMsg, "isNeedResp");
                        attrs = (java.util.Map<?, ?>) XposedHelpers.callMethod(toServiceMsg, "getAttributes");
                        wup = (byte[]) XposedHelpers.callMethod(toServiceMsg, "getWupBuffer");
                    } catch (Throwable ignored) {}

                    // Always audit outgoing SSO messages if enabled (excluding Heartbeat.Alive to prevent log flood)
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT && command != null && !command.startsWith("Heartbeat.")) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordMsfSso(command, uin, ssoSeq, needResp, attrs, wup);
                    }

                    if (HookConfig.ENABLE_NETWORK_INTERCEPT && shouldBlock(command)) {
                        // Check if it's a FEKit security message with security callback id
                        try {
                            Object cbObj = XposedHelpers.callMethod(toServiceMsg, "getAttribute", "attr_key_security_callback_id");
                            if (cbObj instanceof Number) {
                                long cbId = ((Number) cbObj).longValue();
                                injectNativeReceiveSuccess(cl, command, cbId);
                            }
                        } catch (Throwable ignored) { }

                        // If caller needs a response, synthesize FromServiceMsg
                        try {
                            if (needResp) {
                                int appSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getAppSeq");
                                int appId = (int) XposedHelpers.callMethod(toServiceMsg, "getAppId");
                                Object msfCmd = XposedHelpers.callMethod(toServiceMsg, "getMsfCommand");

                                Class<?> fromMsgClass = XposedHelpers.findClassIfExists(
                                    "com.tencent.qphone.base.remote.FromServiceMsg", cl);
                                if (fromMsgClass != null) {
                                    Object fromMsg = XposedHelpers.newInstance(fromMsgClass, uin != null ? uin : "0", command);
                                    XposedHelpers.callMethod(fromMsg, "setMsgSuccess");
                                    XposedHelpers.callMethod(fromMsg, "setBusinessFailCode", 1000);
                                    XposedHelpers.callMethod(fromMsg, "setRequestSsoSeq", ssoSeq);
                                    XposedHelpers.callMethod(fromMsg, "setAppSeq", appSeq);
                                    XposedHelpers.callMethod(fromMsg, "setAppId", appId);
                                    XposedHelpers.callMethod(fromMsg, "setMsfCommand", msfCmd);
                                    XposedHelpers.callMethod(fromMsg, "putWupBuffer", new byte[0]);

                                    try {
                                        XposedHelpers.callMethod(param.thisObject, "addRespToQuque", toServiceMsg, fromMsg);
                                    } catch (Throwable ignored) { }
                                }
                            }
                        } catch (Throwable ignored) { }

                        Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                        if (returnType == int.class) {
                            param.setResult(ssoSeq);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        } else if (returnType == long.class) {
                            param.setResult((long) ssoSeq);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        } else if (returnType == void.class) {
                            param.setResult(null);
                            XposedEntry.log("Neutralized MsfCore: " + command);
                        }
                    }
                }
            });
        XposedEntry.log("[NetworkReport] Installed MsfCore.sendSsoMsg hook on loader " + cl);
    }

    /**
     * Layer 4: StatisticCollector performance & error report auditing.
     */
    private static void hookStatisticCollector(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.statistics.StatisticCollector", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_StatisticCollector")) return;

        HookUtils.hookAllMethods(clazz, "collectPerformance",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    String uin = param.args[0] != null ? param.args[0].toString() : "";
                    String tagName = param.args[1] != null ? param.args[1].toString() : "";
                    boolean success = param.args.length > 2 && param.args[2] instanceof Boolean ? (Boolean) param.args[2] : true;
                    long duration = param.args.length > 3 && param.args[3] instanceof Number ? ((Number) param.args[3]).longValue() : 0L;
                    long size = param.args.length > 4 && param.args[4] instanceof Number ? ((Number) param.args[4]).longValue() : 0L;
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, String> params = param.args.length > 5 && param.args[5] instanceof java.util.Map ? (java.util.Map<String, String>) param.args[5] : null;
                    String res = param.args.length > 6 && param.args[6] != null ? param.args[6].toString() : "";
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordStatisticCollector(uin, tagName, success, duration, size, params, res);
                }
            });
        XposedEntry.log("[NetworkReport] Installed StatisticCollector hook on loader " + cl);
    }

    /**
     * Layer 5: ReportController business & security reporting auditing.
     */
    private static void hookReportController(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.statistics.ReportController", cl);
        if (clazz == null || !sHookedNetworkClasses.add(cl.hashCode() + "_ReportController")) return;

        HookUtils.hookAllMethods(clazz, "b",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 5) return;
                    String tag = param.args[1] != null ? param.args[1].toString() : "";
                    String subTag = param.args[2] != null ? param.args[2].toString() : "";
                    String opType = param.args.length > 5 && param.args[5] != null ? param.args[5].toString() : "";
                    String opName = param.args.length > 6 && param.args[6] != null ? param.args[6].toString() : "";
                    int res = param.args.length > 7 && param.args[7] instanceof Number ? ((Number) param.args[7]).intValue() : 0;
                    String r2 = param.args.length > 8 && param.args[8] != null ? param.args[8].toString() : "";
                    String r3 = param.args.length > 9 && param.args[9] != null ? param.args[9].toString() : "";
                    String r4 = param.args.length > 10 && param.args[10] != null ? param.args[10].toString() : "";
                    String r5 = param.args.length > 11 && param.args[11] != null ? param.args[11].toString() : "";
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReportController(tag, subTag, opType, opName, res, r2, r3, r4, r5);
                }
            });
        XposedEntry.log("[NetworkReport] Installed ReportController hook on loader " + cl);
    }

    /**
     * Layer 6: Outbound TuringFD Network Dispatcher (d1.a).
     * Audits raw packed Turing packets dispatched over network sockets.
     */
    private static void hookTuringD1Network(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;
        String[] d1Classes = {
            "com.tencent.turingfd.sdk.xq.d1",
            "com.tencent.tfd.sdk.wxa.d1"
        };
        for (String d1ClsName : d1Classes) {
            Class<?> d1Cls = XposedHelpers.findClassIfExists(d1ClsName, cl);
            if (d1Cls != null && sHookedNetworkClasses.add(cl.hashCode() + "_" + d1ClsName)) {
                HookUtils.hookAllMethods(d1Cls, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 4 && param.args[3] instanceof byte[]) {
                            int cmd1 = param.args[0] instanceof Number ? ((Number) param.args[0]).intValue() : 0;
                            int cmd2 = param.args[1] instanceof Number ? ((Number) param.args[1]).intValue() : 0;
                            int cmd3 = param.args[2] instanceof Number ? ((Number) param.args[2]).intValue() : 0;
                            byte[] bArr = (byte[]) param.args[3];
                            long timeout = param.args.length >= 5 && param.args[4] instanceof Number ? ((Number) param.args[4]).longValue() : 0L;
                            String extra = "cmd=" + cmd1 + "/" + cmd2 + "/" + cmd3 + ", timeout=" + timeout + "ms";
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                "TuringFD.Network", "d1.a", bArr, extra, 6);
                        }
                    }
                });
                XposedEntry.log("[NetworkReport] Hooked TuringFD outbound network dispatcher on " + d1ClsName);
            }
        }
    }

    /**
     * Block TuringFD's process-enumeration readers (/proc scanners).
     */
    private static void hookTuringFD(XC_LoadPackage.LoadPackageParam lpparam) {
        new Thread(() -> {
            try {
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("[TuringFD] DexKit not available, skip proc-reader hook");
                    return;
                }

                List<DexMethodData> procReaders = DexKitDetector.findTuringFdProcReaders();

                final String legitimateProcName = (lpparam != null && lpparam.processName != null) ? lpparam.processName : "com.tencent.mobileqq";
                for (DexMethodData md : procReaders) {
                    try {
                        Member method = md.getMethodInstance(lpparam.classLoader);
                        if (!(method instanceof java.lang.reflect.Method)) continue;
                        Class<?> ret = ((java.lang.reflect.Method) method).getReturnType();
                        if (ret != String.class) continue;

                        HookUtils.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object res = param.getResult();
                                if (res == null || "".equals(res)) {
                                    param.setResult(legitimateProcName);
                                    return;
                                }
                                if (res instanceof String) {
                                    String str = (String) res;
                                    if (isSensitiveTuringPath(str)) {
                                        param.setResult(legitimateProcName);
                                    }
                                }
                            }
                        });
                    } catch (Throwable t) {
                        XposedEntry.log("[TuringFD] failed to hook proc reader: " + t.getMessage());
                    }
                }
            } catch (Throwable t) {
                XposedEntry.log("[TuringFD] proc-reader lookup failed: " + t.getMessage());
            }
        }).start();
    }

    private static boolean isSensitiveTuringPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("/system/bin/su") || lower.contains("/system/xbin/su") ||
               lower.contains("/sbin/su") || lower.contains("/data/local/su") ||
               lower.contains("/data/adb") || lower.contains("magisk") ||
               lower.contains("kernelsu") || lower.contains("ksud") ||
               lower.contains("libapatch") || lower.contains("/apatch/") || lower.contains("me.bmax.apatch") || lower.contains("apatchd") ||
               lower.contains("xposed") || lower.contains("lsposed") ||
               lower.contains("qauxv") || lower.contains("busybox") ||
               lower.contains("mountify") || lower.contains("tricky_store") ||
               lower.contains("zygisksu") || lower.contains("metamodule") ||
               lower.contains("frida") || lower.contains("bin.mt") || lower.contains("daemonsu") ||
               lower.contains("qa_mmkv") || lower.contains("tmp_qa_") ||
               lower.contains("qa_dyn_lib") || lower.contains("qa_misc") ||
               lower.contains("ono_mmkv") || lower.contains("ono_hcb_") || lower.contains("moe.ono") ||
               lower.contains("sesearchcache");
    }

    private static void hookTuringEridanus(ClassLoader cl) {
        if (cl == null) return;
        String[] eridanusClasses = {
            "com.tencent.turingfd.sdk.xq.Eridanus",
            "com.tencent.tfd.sdk.wxa.Eridanus"
        };
        for (String clsName : eridanusClasses) {
            Class<?> clazz = XposedHelpers.findClassIfExists(clsName, cl);
            if (clazz != null) {
                XC_MethodHook byteReaderHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || !(param.args[0] instanceof String)) {
                            return;
                        }
                        String path = (String) param.args[0];
                        if (path == null) return;

                        if (isSensitiveTuringPath(path)) {
                            XposedEntry.log("[TuringEridanus] Blocked sensitive file read: " + path);
                            param.setResult(null);
                            return;
                        }

                        byte[] fakeBytes = null;
                        if (path.contains("/status") && path.startsWith("/proc/")) {
                            XposedEntry.log("[TuringEridanus] Sanitized status read: " + path);
                            String fakeStatus = "Name:\tcom.tencent.mobileqq\nState:\tS (sleeping)\nTgid:\t" 
                                + android.os.Process.myPid() + "\nPid:\t" + android.os.Process.myPid() 
                                + "\nPPid:\t1\nTracerPid:\t0\nUid:\t10361\t10361\t10361\t10361\nGid:\t10361\t10361\t10361\t10361\n";
                            fakeBytes = fakeStatus.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("/cmdline") && path.startsWith("/proc/")) {
                            fakeBytes = "com.tencent.mobileqq\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("selinux/enforce")) {
                            fakeBytes = "1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("net/unix")) {
                            fakeBytes = "".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        } else if (path.contains("net/tcp") || path.contains("net/tcp6")) {
                            fakeBytes = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        }

                        if (fakeBytes != null) {
                            int maxLen = -1;
                            if (param.args.length >= 2 && param.args[1] instanceof Number) {
                                maxLen = ((Number) param.args[1]).intValue();
                            }
                            if (maxLen > 0 && fakeBytes.length > maxLen) {
                                fakeBytes = java.util.Arrays.copyOf(fakeBytes, maxLen);
                            }
                            if (param.method instanceof java.lang.reflect.Method) {
                                Class<?> ret = ((java.lang.reflect.Method) param.method).getReturnType();
                                if (ret == byte[].class) {
                                    param.setResult(fakeBytes);
                                } else if (ret == String.class) {
                                    param.setResult(new String(fakeBytes, java.nio.charset.StandardCharsets.UTF_8));
                                } else if (ret == void.class) {
                                    param.setResult(null);
                                } else {
                                    param.setResult(fakeBytes);
                                }
                            } else {
                                param.setResult(fakeBytes);
                            }
                            return;
                        }
                    }
                };
                HookUtils.hookAllMethods(clazz, "a", byteReaderHook);
                HookUtils.hookAllMethods(clazz, "b", byteReaderHook);
                XposedEntry.log("[TuringFD] Hooked Eridanus byte readers on " + clsName);
            }
        }
    }

    private static void hookWlogin(ClassLoader cl) {
        if (cl == null) return;
        Class<?> wCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.request.w", cl);
        if (wCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_wlogin_w")) {
            HookUtils.hookAllMethods(wCls, "h",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        XposedEntry.log("[Wlogin] Intercepted Wlogin device fingerprint on " + wCls.getName());
                    }
                });
        }
    }

    private static final java.util.Set<String> sKickAuditedClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    public static boolean isKickOrTokenFailCode(int code) {
        if (code == 2001 || code == 2008 || code == 2009 || code == 2011 ||
            code == 2012 || code == 2013 || code == 2014 || code == 2903 || code == 3003) {
            return true;
        }
        if (code == -10001 || code == -10003 || code == -10004 || code == -10005 ||
            code == -10006 || code == -10009 || code == -10101 || code == -10102 ||
            code == -10103 || code == -10104 || code == -10105 || code == -10106 ||
            code == -10135 || code == -10136 || code == -12003 || code == 210) {
            return true;
        }
        if (code > -10300 && code < -10200) {
            return true; // Security error range (com.tencent.mobileqq.msf.core.security.a)
        }
        return false;
    }

    public static boolean isKickCmd(String cmd) {
        if (cmd == null || cmd.isEmpty()) return false;
        return "StatSvc.ReqMSFOffline".equals(cmd) ||
               "StatSvc.ReqForceOffline".equals(cmd) ||
               "StatSvc.RspMSFForceOffline".equals(cmd) ||
               "MessageSvc.PushForceOffline".equals(cmd) ||
               cmd.startsWith("trpc.login.ecdh.report") ||
               "ConfigPushSvc.PushReq".equals(cmd) ||
               "cmd_forceLogout".equals(cmd);
    }

    private static void hookErrorHandlerClass(Class<?> ehCls) {
        if (ehCls == null || !sKickAuditedClasses.add(ehCls.getName())) return;

        String[] kickMethods = {
            "onUserTokenExpired", "onKickedAndClearToken", "onKicked",
            "onInterceptKicked", "onKickedInternal", "onGrayError",
            "onServerSuspended", "onInvalidSign", "onNoTestEnvPermission"
        };
        for (String mName : kickMethods) {
            HookUtils.hookAllMethods(ehCls, mName, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object fromServiceMsg = null;
                    Object toServiceMsg = null;
                    if (param.args != null) {
                        for (Object arg : param.args) {
                            if (arg != null) {
                                String cName = arg.getClass().getName();
                                if (cName.contains("FromServiceMsg")) {
                                    fromServiceMsg = arg;
                                } else if (cName.contains("ToServiceMsg")) {
                                    toServiceMsg = arg;
                                }
                            }
                        }
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "ErrorHandler." + param.method.getName() + " (Read-Only Audit)",
                        fromServiceMsg, toServiceMsg, "UI process kick handler triggered on " + ehCls.getSimpleName());
                }
            });
        }

        HookUtils.hookAllMethods(ehCls, "popupNotification", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                StringBuilder details = new StringBuilder("popupNotification called with args: [");
                if (param.args != null) {
                    for (int i = 0; i < param.args.length; i++) {
                        if (i > 0) details.append(", ");
                        details.append(param.args[i]);
                    }
                }
                details.append("]");
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                    "ErrorHandler.popupNotification (Read-Only Audit)",
                    null, details.toString());
            }
        });

        HookUtils.hookAllMethods(ehCls, "popupNotificationEx", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                StringBuilder details = new StringBuilder("popupNotificationEx (SecKick) called with args: [");
                if (param.args != null) {
                    for (int i = 0; i < param.args.length; i++) {
                        if (i > 0) details.append(", ");
                        details.append(param.args[i]);
                    }
                }
                details.append("]");
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                    "ErrorHandler.popupNotificationEx (Read-Only Audit)",
                    null, details.toString());
            }
        });

        XposedEntry.log("[KickAudit] Installed read-only kick audit on error handler: " + ehCls.getName());
    }

    private static void hookKickAudit(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookKickAuditInternal(cl);
    }

    private static void hookKickAuditInternal(ClassLoader cl) {
        if (cl == null) return;

        // 1. MSF process core offline push & SSO fail receiver (com.tencent.mobileqq.msf.core.t.a)
        Class<?> msfTCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.t", cl);
        if (msfTCls != null && sKickAuditedClasses.add("msf.core.t")) {
            HookUtils.hookAllMethods(msfTCls, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args == null || p.args.length < 1) return;
                    Object fromMsg = null;
                    Object toMsg = null;
                    for (Object arg : p.args) {
                        if (arg != null) {
                            String cName = arg.getClass().getName();
                            if ("com.tencent.qphone.base.remote.FromServiceMsg".equals(cName)) {
                                fromMsg = arg;
                            } else if ("com.tencent.qphone.base.remote.ToServiceMsg".equals(cName)) {
                                toMsg = arg;
                            }
                        }
                    }
                    if (fromMsg != null) {
                        String cmd = "";
                        int failCode = 0;
                        try {
                            cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                            failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                        } catch (Throwable ignored) {}

                        if (isKickCmd(cmd) || isKickOrTokenFailCode(failCode)) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "MSF.core.t.a (Read-Only Audit)", fromMsg, toMsg,
                                "MSF push/sso response received: cmd=" + cmd + ", failCode=" + failCode);
                        }
                    }
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on com.tencent.mobileqq.msf.core.t.a");
        }

        // 2. Client-side MSF SDK IPC response handler (com.tencent.mobileqq.msf.sdk.g / h method e)
        for (String msfClsName : new String[]{"com.tencent.mobileqq.msf.sdk.g", "com.tencent.mobileqq.msf.sdk.h"}) {
            Class<?> sdkCls = XposedHelpers.findClassIfExists(msfClsName, cl);
            if (sdkCls != null && sKickAuditedClasses.add(msfClsName)) {
                HookUtils.hookAllMethods(sdkCls, "e", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1) return;
                        Object fromServiceMsg = null;
                        Object toServiceMsg = null;
                        for (Object arg : param.args) {
                            if (arg != null) {
                                String cName = arg.getClass().getName();
                                if ("com.tencent.qphone.base.remote.FromServiceMsg".equals(cName)) {
                                    fromServiceMsg = arg;
                                } else if ("com.tencent.qphone.base.remote.ToServiceMsg".equals(cName)) {
                                    toServiceMsg = arg;
                                }
                            }
                        }
                        if (fromServiceMsg == null) return;

                        try {
                            int failCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode");
                            String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");

                            if (isKickOrTokenFailCode(failCode) || isKickCmd(cmd)) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    msfClsName + ".e (Read-Only Audit)", fromServiceMsg, toServiceMsg,
                                    "Client kick dispatch: cmd=" + cmd + ", failCode=" + failCode);
                            }
                        } catch (Throwable ignored) {}
                    }
                });
                XposedEntry.log("[KickAudit] Installed read-only kick audit on " + msfClsName + ".e");
            }
        }

        // 3. Main process UI error handler (mqq.app.MainService$MyErrorHandler)
        Class<?> myErrorHandlerCls = XposedHelpers.findClassIfExists("mqq.app.MainService$MyErrorHandler", cl);
        if (myErrorHandlerCls != null) {
            hookErrorHandlerClass(myErrorHandlerCls);
        }

        // 3.1 MainService constructor, kick, and setCustomErrorHandler
        Class<?> mainServiceCls = XposedHelpers.findClassIfExists("mqq.app.MainService", cl);
        if (mainServiceCls != null && sKickAuditedClasses.add("MainService")) {
            HookUtils.hookAllConstructors(mainServiceCls, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Object eh = XposedHelpers.getObjectField(param.thisObject, "errorHandler");
                        if (eh != null) {
                            hookErrorHandlerClass(eh.getClass());
                        }
                    } catch (Throwable ignored) {}
                }
            });

            HookUtils.hookAllMethods(mainServiceCls, "setCustomErrorHandler", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] != null) {
                        hookErrorHandlerClass(param.args[0].getClass());
                    }
                }
            });

            HookUtils.hookAllMethods(mainServiceCls, "kick", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object kickParams = param.args != null && param.args.length > 0 ? param.args[0] : null;
                    Object toMsg = null;
                    Object fromMsg = null;
                    if (kickParams != null) {
                        try {
                            toMsg = XposedHelpers.getObjectField(kickParams, "toServiceMsg");
                            fromMsg = XposedHelpers.getObjectField(kickParams, "fromServiceMsg");
                        } catch (Throwable ignored) {}
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "MainService.kick (Read-Only Audit)", fromMsg, toMsg, "MainService.kick called with " + kickParams);
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on MainService");
        }

        // 3.2 AppRuntime logout audit
        Class<?> appRuntimeCls = XposedHelpers.findClassIfExists("mqq.app.AppRuntime", cl);
        if (appRuntimeCls != null && sKickAuditedClasses.add("AppRuntime")) {
            HookUtils.hookAllMethods(appRuntimeCls, "logout", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object reason = param.args != null && param.args.length > 0 ? param.args[0] : null;
                    Object isUserSet = param.args != null && param.args.length > 1 ? param.args[1] : null;
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "AppRuntime.logout (Read-Only Audit)", null, "reason=" + reason + ", isUserSet=" + isUserSet);
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on AppRuntime.logout");
        }

        // 3.3 NotificationActivity onCreate audit
        Class<?> notifActivityCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.activity.NotificationActivity", cl);
        if (notifActivityCls != null && sKickAuditedClasses.add("NotificationActivity")) {
            HookUtils.hookAllMethods(notifActivityCls, "onCreate", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        android.app.Activity act = (android.app.Activity) param.thisObject;
                        android.content.Intent intent = act.getIntent();
                        String action = intent != null ? intent.getAction() : "null";
                        StringBuilder extraDump = new StringBuilder("NotificationActivity started. Action=").append(action);
                        if (intent != null && intent.getExtras() != null) {
                            android.os.Bundle extras = intent.getExtras();
                            extraDump.append(", Extras: {");
                            for (String key : extras.keySet()) {
                                extraDump.append(key).append("=").append(extras.get(key)).append(", ");
                            }
                            extraDump.append("}");
                        }
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "NotificationActivity.onCreate (Read-Only Audit)", null, extraDump.toString());
                    } catch (Throwable ignored) {}
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on NotificationActivity.onCreate");
        }

        // 4. WTLogin Token Clear Audit (oicq.wlogin_sdk.request.WtloginHelper)
        Class<?> wtHelperCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.request.WtloginHelper", cl);
        if (wtHelperCls != null && sKickAuditedClasses.add("WtloginHelper")) {
            HookUtils.hookAllMethods(wtHelperCls, "ClearUserLoginData", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String uin = param.args != null && param.args.length > 0 ? String.valueOf(param.args[0]) : "unknown";
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "WtloginHelper.ClearUserLoginData (Read-Only Audit)",
                        null, "ClearUserLoginData called for uin=" + uin);
                }
            });

            HookUtils.hookAllMethods(wtHelperCls, "reportClearSig", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String uin = param.args != null && param.args.length > 0 ? String.valueOf(param.args[0]) : "";
                    String scene = param.args != null && param.args.length > 1 ? String.valueOf(param.args[1]) : "";
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "WtloginHelper.reportClearSig (Read-Only Audit)",
                        null, "reportClearSig called: uin=" + uin + ", clearFrom=" + scene);
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on WtloginHelper");
        }

        // 5. Crossplatform NewSender / kickedAndCleanTokenResp Audit (Direct c$a & reflective inner class)
        Class<?> cpInnerCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.service.crossplatform.c$a", cl);
        if (cpInnerCls != null && sKickAuditedClasses.add("crossplatform.c$a")) {
            HookUtils.hookAllMethods(cpInnerCls, "run", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Object toMsg = XposedHelpers.getObjectField(param.thisObject, "a");
                        if (toMsg != null) {
                            Object cmd = XposedHelpers.callMethod(toMsg, "getMsfCommand");
                            if (cmd != null && "_msf_kickedAndCleanTokenResp".equals(cmd.toString())) {
                                String serviceCmd = (String) XposedHelpers.callMethod(toMsg, "getServiceCmd");
                                Object fromServiceMsg = serviceCmd != null ? XposedHelpers.callMethod(toMsg, "getAttribute", serviceCmd) : null;
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    "crossplatform.c$a.run (Read-Only Audit)",
                                    fromServiceMsg, "_msf_kickedAndCleanTokenResp executing");
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on crossplatform.c$a.run");
        }

        Class<?> cpCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.service.crossplatform.c", cl);
        if (cpCls != null && sKickAuditedClasses.add("crossplatform.c")) {
            for (Class<?> inner : cpCls.getDeclaredClasses()) {
                if (Runnable.class.isAssignableFrom(inner)) {
                    HookUtils.hookAllMethods(inner, "run", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            try {
                                Object toMsg = XposedHelpers.getObjectField(param.thisObject, "a");
                                if (toMsg != null) {
                                    Object cmd = XposedHelpers.callMethod(toMsg, "getMsfCommand");
                                    if (cmd != null && "_msf_kickedAndCleanTokenResp".equals(cmd.toString())) {
                                        String serviceCmd = (String) XposedHelpers.callMethod(toMsg, "getServiceCmd");
                                        Object fromServiceMsg = serviceCmd != null ? XposedHelpers.callMethod(toMsg, "getAttribute", serviceCmd) : null;
                                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                            "crossplatform.c$Runnable.run (Read-Only Audit)",
                                            fromServiceMsg, "_msf_kickedAndCleanTokenResp executing");
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    });
                    XposedEntry.log("[KickAudit] Installed read-only kick audit on crossplatform.c inner runnable");
                    break;
                }
            }
        }

        // 6. WTLogin Beacon Report Funnel Audit (oicq.wlogin_sdk.report.c.b.a)
        Class<?> oicqReportCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.report.c.b", cl);
        if (oicqReportCls != null && sKickAuditedClasses.add("oicq.wlogin_sdk.report.c.b")) {
            HookUtils.hookAllMethods(oicqReportCls, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0 || param.args[0] == null) return;
                    if (param.args.length > 1) return; // a(a, int) delegates to a(a)
                    try {
                        Object aVar = param.args[0];
                        String event = (String) XposedHelpers.getObjectField(aVar, "a");
                        String uin = (String) XposedHelpers.getObjectField(aVar, "f");
                        Map<?, ?> map = (Map<?, ?>) XposedHelpers.getObjectField(aVar, "g");
                        if ("wt_all_sig_clear".equals(event) || (map != null && map.containsKey("clearFrom"))) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "oicq.wlogin_sdk.report.c.b.a (Read-Only Audit)",
                                null, "wt_all_sig_clear: uin=" + uin + ", params=" + map);
                        }
                    } catch (Throwable ignored) {}
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on oicq.wlogin_sdk.report.c.b.a");
        }

        // 7. LoginReporterImpl Clear Login Data Audit
        Class<?> loginReporterCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.login.api.impl.LoginReporterImpl", cl);
        if (loginReporterCls != null && sKickAuditedClasses.add("LoginReporterImpl")) {
            HookUtils.hookAllMethods(loginReporterCls, "reportClearLoginData", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String uin = param.args != null && param.args.length > 0 ? String.valueOf(param.args[0]) : "";
                    String from = param.args != null && param.args.length > 1 ? String.valueOf(param.args[1]) : "";
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "LoginReporterImpl.reportClearLoginData (Read-Only Audit)",
                        null, "reportClearLoginData called: uin=" + uin + ", from=" + from);
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on LoginReporterImpl.reportClearLoginData");
        }
    }

    public static boolean shouldBlock(String command) {
        if (command == null) return false;

        // Whitelist check: strictly pass-through critical protocol and key-exchange commands
        for (String whiteCmd : SAFE_WHITELIST) {
            if (command.contains(whiteCmd)) {
                return false;
            }
        }

        // Targeted block: only pure telemetry and risk detection reports
        for (String blockCmd : TELEMETRY_BLOCK_COMMANDS) {
            if (command.contains(blockCmd)) {
                return true;
            }
        }
        return false;
    }
}
