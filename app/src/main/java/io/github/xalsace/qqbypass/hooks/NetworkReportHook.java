package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;

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

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        // Layer 0 - 3: Channel / MSF report auditing & optional interception
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT || HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookChannelManager(lpparam);
            hookChannelProxyExt(lpparam);
            hookMSFKernelBridge(lpparam);
            hookMsfCore(lpparam);
        }

        // Layer 4 & 5: StatisticCollector & ReportController telemetry auditing
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookStatisticCollector(lpparam);
            hookReportController(lpparam);
            hookKickAudit(lpparam);
        }

        // Inspection checks (TuringFD /proc scanner neutralization)
        hookTuringFD(lpparam);
        hookTuringEridanus(lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader());
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookKickAuditInternal(cl);
        }
        hookTuringEridanus(cl);
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
    private static void hookChannelManager(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelManager", "sendMessage",
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
                        injectNativeReceiveSuccess(lpparam.classLoader, command, callbackId);
                        param.setResult(null);
                        XposedEntry.log("Intercepted & fulfilled ChannelManager.sendMessage: "
                            + command + " (callbackId=" + callbackId + ")");
                    }
                }
            });
    }

    /**
     * Layer 1: ChannelProxyExt.sendMessage fallback.
     */
    private static void hookChannelProxyExt(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] methodNames = {"sendMessageInner", "sendMessage", "send"};
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();

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

                        injectNativeReceiveSuccess(lpparam.classLoader, command, callbackId);
                        param.setResult(null);
                        XposedEntry.log("Intercepted & fulfilled ChannelProxyExt: "
                            + command + " (callbackId=" + callbackId + ")");
                    }
                }
            });
    }

    /**
     * Layer 2: MSFKernelBridge$CppProxy.sendPacket.
     * Low-level choke point where packets are submitted to libMSFKernel.so native engine.
     */
    private static void hookMSFKernelBridge(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.msfcore.MSFKernelBridge$CppProxy", "sendPacket",
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
    }

    /**
     * Layer 3: MsfCore.sendSsoMsg.
     * Service layer SSO dispatcher. Audits all SSO outgoing traffic and optional interception.
     */
    private static void hookMsfCore(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("com.tencent.mobileqq.msf.core.MsfCore", "sendSsoMsg",
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
                    int bufLen = 0;
                    try {
                        uin = (String) XposedHelpers.callMethod(toServiceMsg, "getUin");
                        ssoSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                        needResp = (boolean) XposedHelpers.callMethod(toServiceMsg, "isNeedResp");
                        attrs = (java.util.Map<?, ?>) XposedHelpers.callMethod(toServiceMsg, "getAttributes");
                        byte[] wup = (byte[]) XposedHelpers.callMethod(toServiceMsg, "getWupBuffer");
                        if (wup != null) bufLen = wup.length;
                    } catch (Throwable ignored) {}

                    // Always audit outgoing SSO messages if enabled (excluding Heartbeat.Alive to prevent log flood)
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT && command != null && !command.startsWith("Heartbeat.")) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordMsfSso(command, uin, ssoSeq, needResp, attrs, bufLen);
                    }

                    if (HookConfig.ENABLE_NETWORK_INTERCEPT && shouldBlock(command)) {
                        // Check if it's a FEKit security message with security callback id
                        try {
                            Object cbObj = XposedHelpers.callMethod(toServiceMsg, "getAttribute", "attr_key_security_callback_id");
                            if (cbObj instanceof Number) {
                                long cbId = ((Number) cbObj).longValue();
                                injectNativeReceiveSuccess(lpparam.classLoader, command, cbId);
                            }
                        } catch (Throwable ignored) { }

                        // If caller needs a response, synthesize FromServiceMsg
                        try {
                            if (needResp) {
                                int appSeq = (int) XposedHelpers.callMethod(toServiceMsg, "getAppSeq");
                                int appId = (int) XposedHelpers.callMethod(toServiceMsg, "getAppId");
                                Object msfCmd = XposedHelpers.callMethod(toServiceMsg, "getMsfCommand");

                                Class<?> fromMsgClass = XposedHelpers.findClassIfExists(
                                    "com.tencent.qphone.base.remote.FromServiceMsg", lpparam.classLoader);
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
    }

    /**
     * Layer 4: StatisticCollector performance & error report auditing.
     */
    private static void hookStatisticCollector(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) return;
        HookUtils.hookAllMethods("com.tencent.mobileqq.statistics.StatisticCollector", "collectPerformance",
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
    }

    /**
     * Layer 5: ReportController business & security reporting auditing.
     */
    private static void hookReportController(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) return;
        HookUtils.hookAllMethods("com.tencent.mobileqq.statistics.ReportController", "b",
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
               lower.contains("kernelsu") || lower.contains("apatch") ||
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

    private static void hookWlogin(XC_LoadPackage.LoadPackageParam lpparam) {
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    XposedEntry.log("Intercepted Wlogin device fingerprint");
                }
            });
    }

    private static final java.util.Set<String> sKickAuditedClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static void hookKickAudit(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookKickAuditInternal(cl);
    }

    private static void hookKickAuditInternal(ClassLoader cl) {
        if (cl == null) return;

        // 1. MSF process core offline push receiver (com.tencent.mobileqq.msf.core.t.a)
        Class<?> msfTCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.t", cl);
        if (msfTCls != null && sKickAuditedClasses.add("msf.core.t")) {
            HookUtils.hookAllMethods(msfTCls, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args == null || p.args.length < 1) return;
                    Object fromMsg = null;
                    for (Object arg : p.args) {
                        if (arg != null && "com.tencent.qphone.base.remote.FromServiceMsg".equals(arg.getClass().getName())) {
                            fromMsg = arg;
                            break;
                        }
                    }
                    if (fromMsg != null) {
                        String cmd = "";
                        int failCode = 0;
                        try {
                            cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                            failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                        } catch (Throwable ignored) {}

                        boolean isKickCmd = "StatSvc.ReqMSFOffline".equals(cmd) ||
                                            "StatSvc.ReqForceOffline".equals(cmd) ||
                                            "MessageSvc.PushForceOffline".equals(cmd);
                        boolean isKickFail = (failCode == 2012 || failCode == 2001 || failCode == 2011 ||
                                              failCode == 2013 || failCode == 2014 || failCode == -10103 ||
                                              failCode == -10104 || failCode == 2008 || failCode == 2009);

                        if (isKickCmd || isKickFail) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "MSF.core.t.a (Read-Only Audit)", fromMsg,
                                "MSF push received: cmd=" + cmd + ", failCode=" + failCode);
                        }
                    }
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on com.tencent.mobileqq.msf.core.t.a");
        }

        // 2. Client-side MSF SDK IPC response handler (com.tencent.mobileqq.msf.sdk.g / h)
        for (String msfClsName : new String[]{"com.tencent.mobileqq.msf.sdk.g", "com.tencent.mobileqq.msf.sdk.h"}) {
            Class<?> sdkCls = XposedHelpers.findClassIfExists(msfClsName, cl);
            if (sdkCls != null && sKickAuditedClasses.add(msfClsName)) {
                HookUtils.hookAllMethods(sdkCls, "e", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || param.args[0] == null) return;
                        Object fromServiceMsg = param.args[0];
                        if (!"com.tencent.qphone.base.remote.FromServiceMsg".equals(fromServiceMsg.getClass().getName())) return;

                        try {
                            int failCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode");
                            String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");
                            boolean isKickFailCode = (failCode == 2001 || failCode == 2011 || failCode == 2012 ||
                                                      failCode == 2013 || failCode == 2014 || failCode == 2008 ||
                                                      failCode == 2009 || failCode == 2903 || failCode == 3003);
                            boolean isKickCmd = "StatSvc.ReqMSFOffline".equals(cmd) ||
                                                "StatSvc.ReqForceOffline".equals(cmd) ||
                                                "MessageSvc.PushForceOffline".equals(cmd);

                            if (isKickFailCode || isKickCmd) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    msfClsName + ".e (Read-Only Audit)", fromServiceMsg,
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
        if (myErrorHandlerCls != null && sKickAuditedClasses.add("MyErrorHandler")) {
            String[] kickMethods = {"onKickedAndClearToken", "onInterceptKicked", "onKickedInternal", "onUserTokenExpired"};
            for (String mName : kickMethods) {
                HookUtils.hookAllMethods(myErrorHandlerCls, mName, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Object fromServiceMsg = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "MyErrorHandler." + param.method.getName() + " (Read-Only Audit)",
                            fromServiceMsg, "UI process kick handler triggered");
                    }
                });
            }

            HookUtils.hookAllMethods(myErrorHandlerCls, "popupNotification", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Object action = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                        "MyErrorHandler.popupNotification (Read-Only Audit)",
                        null, "Action=" + action);
                }
            });
            XposedEntry.log("[KickAudit] Installed read-only kick audit on MainService$MyErrorHandler");
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

        // 5. Crossplatform NewSender / kickedAndCleanTokenResp Audit
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
                                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                            "crossplatform.c$Runnable.run (Read-Only Audit)",
                                            null, "_msf_kickedAndCleanTokenResp executing");
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
