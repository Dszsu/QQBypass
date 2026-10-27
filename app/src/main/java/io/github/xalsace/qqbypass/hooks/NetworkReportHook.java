package io.github.xalsace.qqbypass.hooks;

import android.content.Intent;
import android.os.Bundle;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;
import java.util.Locale;
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
        "trpc.qq_new_tech.status_svc.",
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
               command.startsWith("trpc.group_pro.") ||
               command.startsWith("trpc.qq_new_tech.status_svc.") ||
               command.startsWith("trpc.o3.ecdh_access.") ||
               command.startsWith("trpc.qlive.") ||
               command.startsWith("trpc.aio.") ||
               command.startsWith("MessageSvc.") ||
               command.startsWith("RegPrxySvc.") ||
               command.startsWith("Heartbeat.") ||
               command.startsWith("OnlinePush.") ||
               command.startsWith("ConfigPushSvc.") ||
               command.startsWith("ProfileService.") ||
               command.startsWith("Friendlist.") ||
               command.startsWith("trpc.login.ecdh.access") ||
               command.startsWith("trpc.group_mall.") ||
               command.startsWith("OidbSvcTrpcTcp.") ||
               (command.startsWith("StatSvc.") && !command.contains("Offline")) ||
               (command.startsWith("OidbSvc.") && !command.contains("0xd79"));
    }

    /**
     * Fast-path identification of TRPC and OIDB TRPC commands.
     */
    public static boolean isTrpcCommand(String cmd) {
        if (cmd == null) return false;
        String c = cmd.toLowerCase(Locale.ROOT);
        return c.startsWith("trpc.") || c.contains("trpc") || c.startsWith("oidbsvctrpc");
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
        // Layer 0 - 3: Channel / MSF report normalization, auditing & optional interception
        hookChannelManager(cl);
        hookChannelProxyExt(cl);
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT || HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookMSFKernelBridge(cl);
        }
        hookMsfCore(cl);

        // Layer 4 & 5: StatisticCollector & ReportController telemetry auditing
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            hookStatisticCollector(cl);
            hookReportController(cl);
            hookKickAudit(lpparam);
            hookWlogin(cl);
            hookTuringD1Network(cl);
            hookInboundResponses(cl);
            hookPlaintextSecurityDispatches(cl);
            hookFEKitNativeLog(cl);
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
            hookInboundResponses(cl);
            hookPlaintextSecurityDispatches(cl);
            hookFEKitNativeLog(cl);
        }
        hookTuringEridanus(cl);

        hookChannelManager(cl);
        hookChannelProxyExt(cl);
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT || HookConfig.ENABLE_NETWORK_INTERCEPT) {
            hookMSFKernelBridge(cl);
        }
        hookMsfCore(cl);

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
            XposedEntry.logError("[NetworkReport] injectNativeReceive error: " + t.getMessage(), t);
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

                    // Transparently sanitize trpc.o3.report.Report.SsoReport failure telemetry (Rule 4.2 compliant)
                    if ("trpc.o3.report.Report.SsoReport".equals(command)) {
                        byte[] sanitized = io.github.xalsace.qqbypass.hooks.QQ950PatchHook.sanitizeSsoReportPayload(data);
                        if (sanitized != data) {
                            param.args[1] = sanitized;
                            data = sanitized;
                            dataLen = sanitized.length;
                        }
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

        // Neutralize ChannelManager.checkMethod reflection scanner on ChannelProxy
        HookUtils.hookCandidateMethods("com.tencent.mobileqq.channel.ChannelManager", new String[]{"checkMethod"}, cl, XC_MethodReplacement.DO_NOTHING);
        XposedEntry.log("[NetworkReport] Installed ChannelManager.sendMessage & checkMethod hooks on loader " + cl);
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

                    byte[] data = null;
                    if (param.args.length >= 2 && param.args[1] instanceof byte[]) {
                        data = (byte[]) param.args[1];
                    }

                    // Transparently sanitize trpc.o3.report.Report.SsoReport failure telemetry (Rule 4.2 compliant)
                    if ("trpc.o3.report.Report.SsoReport".equals(command)) {
                        byte[] sanitized = io.github.xalsace.qqbypass.hooks.QQ950PatchHook.sanitizeSsoReportPayload(data);
                        if (sanitized != data) {
                            param.args[1] = sanitized;
                            data = sanitized;
                        }
                    }

                    // Always audit if report recording is enabled
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                        if (data != null && data.length > 0) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                "ChannelProxyExt", command, data, "callbackId=" + callbackId, 6);
                        } else {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReport(
                                "ChannelProxyExt", command, null, "callbackId=" + callbackId, 0);
                        }
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
                            byte[] data = null;
                            byte[] secSign = null;
                            byte[] secDevToken = null;
                            byte[] secExtra = null;
                            java.util.Map<?, ?> transInfo = null;
                            String uin = null;
                            try {
                                data = (byte[]) XposedHelpers.callMethod(adapter, "getData");
                            } catch (Throwable ignored) {}
                            try {
                                secSign = (byte[]) XposedHelpers.callMethod(adapter, "getSecSign");
                            } catch (Throwable ignored) {}
                            try {
                                secDevToken = (byte[]) XposedHelpers.callMethod(adapter, "getSecDeviceToken");
                            } catch (Throwable ignored) {}
                            try {
                                secExtra = (byte[]) XposedHelpers.callMethod(adapter, "getSecExtra");
                            } catch (Throwable ignored) {}
                            try {
                                transInfo = (java.util.Map<?, ?>) XposedHelpers.callMethod(adapter, "getTransInfo");
                            } catch (Throwable ignored) {}
                            try {
                                uin = (String) XposedHelpers.callMethod(adapter, "getUin");
                            } catch (Throwable ignored) {}

                            StringBuilder extra = new StringBuilder();
                            extra.append("seq=").append(seq);
                            if (uin != null && !uin.isEmpty() && !"0".equals(uin)) {
                                extra.append(", uin=").append(uin);
                            }
                            if (secSign != null && secSign.length > 0) {
                                extra.append(", secSignLen=").append(secSign.length);
                            }
                            if (secDevToken != null && secDevToken.length > 0) {
                                extra.append(", secDevTokenLen=").append(secDevToken.length);
                            }
                            if (secExtra != null && secExtra.length > 0) {
                                extra.append(", secExtraLen=").append(secExtra.length);
                            }
                            if (transInfo != null && !transInfo.isEmpty()) {
                                extra.append(", transKeys=").append(transInfo.keySet());
                            }

                            boolean isTrpc = isTrpcCommand(cmd);
                            if (!isTrpc) {
                                if (data != null && data.length > 0) {
                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                        "MSFKernelBridge", cmd, data, extra.toString(), 6);
                                } else {
                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReport(
                                        "MSFKernelBridge", cmd, null, extra.toString(), 0);
                                }
                            } else {
                                // For TRPC commands, payload was already audited and dumped in plaintext before encryption
                                // at upper layers (ProtoServlet.onSend, QQSecuritySign.getSign, FEKit.dispatchEventPB).
                                // At MSFKernelBridge, data is already encrypted ciphertext; avoid dumping duplicate ciphertext.
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordReport(
                                    "MSFKernelBridge (TRPC Outbound)", cmd, null, extra.toString(), 0);
                            }

                            if (cmd != null && (isKickCmd(cmd) || "StatSvc.RspMSFForceOffline".equals(cmd))) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    "MSFKernelBridge.sendPacket (" + cmd + ")",
                                    null,
                                    adapter,
                                    "Native packet dispatched: seq=" + seq + ", uin=" + uin
                                );
                            }
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
                        if ((wup == null || wup.length == 0) && attrs != null) {
                            for (Object v : attrs.values()) {
                                if (v instanceof byte[]) {
                                    byte[] b = (byte[]) v;
                                    if (b.length > 0) {
                                        wup = b;
                                        break;
                                    }
                                }
                            }
                        }

                        // Transparently sanitize trpc.o3.report.Report.SsoReport if it carries failure telemetry (Rule 4.2 compliant)
                        if ("trpc.o3.report.Report.SsoReport".equals(command)) {
                            byte[] sanitized = io.github.xalsace.qqbypass.hooks.QQ950PatchHook.sanitizeSsoReportPayload(wup);
                            if (sanitized != wup) {
                                try {
                                    XposedHelpers.callMethod(toServiceMsg, "putWupBuffer", (Object) sanitized);
                                    wup = sanitized;
                                } catch (Throwable ignored) {}
                            }
                        }
                    } catch (Throwable ignored) {}

                    // Always audit outgoing SSO messages if enabled (excluding Heartbeat.Alive to prevent log flood)
                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT && command != null && !command.startsWith("Heartbeat.")) {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordMsfSso(command, uin, ssoSeq, needResp, attrs, wup);
                    }

                    if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT && command != null && (isKickCmd(command) || "StatSvc.RspMSFForceOffline".equals(command))) {
                        Object attachedFromMsg = null;
                        try {
                            attachedFromMsg = XposedHelpers.callMethod(toServiceMsg, "getAttribute", command);
                            if (attachedFromMsg == null) {
                                attachedFromMsg = XposedHelpers.callMethod(toServiceMsg, "getAttribute", "StatSvc.RspMSFForceOffline");
                            }
                            if (attachedFromMsg == null) {
                                attachedFromMsg = XposedHelpers.callMethod(toServiceMsg, "getAttribute", "StatSvc.ReqMSFOffline");
                            }
                        } catch (Throwable ignored) {}

                        String decodedKickDetails = decodeForceOfflineDetails(cl, attachedFromMsg != null ? attachedFromMsg : toServiceMsg);
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "MsfCore.sendSsoMsg (" + command + ")",
                            attachedFromMsg != null ? attachedFromMsg : toServiceMsg,
                            toServiceMsg,
                            "MSF ForceOffline ACK dispatched: " + decodedKickDetails
                        );
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
                            if (bArr != null && bArr.length > 0) {
                                byte[] cleanBArr = QQ950PatchHook.sanitizeTuringJceNativePayload(bArr);
                                if (cleanBArr != null && cleanBArr != bArr) {
                                    param.args[3] = cleanBArr;
                                    bArr = cleanBArr;
                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSanitizationEvent(
                                        "TuringFD.Network", "d1.a",
                                        java.util.Arrays.asList(
                                            "d1.a_Key129_Scrubbed(tun0/ap0/vgate/dummy/ifb)",
                                            "d1.a_MountTable_Scrubbed(debugfs/overlays/loop/dm)",
                                            "d1.a_BootState_Normalized(locked:1/green:1/enforcing:1)",
                                            "d1.a_ArtIntegrity_Normalized(memory_opcodes=disk_opcodes)"
                                        )
                                    );
                                    XposedEntry.log("[NetworkReport] Sanitized multi-vector risk telemetry in d1.a payload");
                                }
                            }
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
                                if (param.args != null && param.args.length > 0 && param.args[0] instanceof Integer) {
                                    int pid = (Integer) param.args[0];
                                    if (pid == android.os.Process.myPid()) {
                                        if (res == null || "".equals(res) || isSensitiveTuringPath(res.toString())) {
                                            param.setResult(legitimateProcName);
                                            return;
                                        }
                                    }
                                }
                                if (res instanceof String) {
                                    String str = (String) res;
                                    if (isSensitiveTuringPath(str)) {
                                        param.setResult("com.android.systemui");
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
               lower.contains("sesearchcache") ||
               lower.contains("termux") || lower.contains("com.termux") ||
               lower.contains("antigravity") || lower.contains(".gemini");
    }

    private static void hookTuringEridanus(ClassLoader cl) {
        if (cl == null) return;
        String[] eridanusClasses = {
            "com.tencent.turingfd.sdk.xq.Eridanus",
            "com.tencent.tfd.sdk.wxa.Ara",
            "com.tencent.tfd.sdk.wxa.Nectarine",
            "com.tencent.tfd.sdk.wxa.this",
            "com.tencent.turingcam.F2BEC",
            "com.tencent.turingcam.Ckq8l",
            "com.tencent.turingcam.JD1Ej",
            "com.tencent.turingcam.FLlEM",
            "com.tencent.turingcam.FxCVY"
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
                            if (param.method instanceof java.lang.reflect.Method) {
                                Class<?> ret = ((java.lang.reflect.Method) param.method).getReturnType();
                                if (ret == boolean.class) {
                                    param.setResult(false);
                                } else {
                                    param.setResult(null);
                                }
                            } else {
                                param.setResult(null);
                            }
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof byte[] && param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                            String path = (String) param.args[0];
                            byte[] data = (byte[]) res;
                            if (path.contains("/status") && path.startsWith("/proc/")) {
                                String s = new String(data, java.nio.charset.StandardCharsets.UTF_8);
                                if (s.contains("TracerPid:")) {
                                    String cleaned = s.replaceAll("TracerPid:\\s+[1-9][0-9]*", "TracerPid:\t0");
                                    if (!cleaned.equals(s)) {
                                        param.setResult(cleaned.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                                        XposedEntry.log("[TuringEridanus] Sanitized TracerPid in status read: " + path);
                                    }
                                }
                            }
                        }
                    }
                };
                HookUtils.hookAllMethodsIfExists(clazz, "a", byteReaderHook);
                HookUtils.hookAllMethodsIfExists(clazz, "b", byteReaderHook);
                XposedEntry.log("[TuringFD] Hooked Eridanus byte readers on " + clsName);
            }
        }

        // Process status probers (Pomegranate, Blueberry, oqKCa)
        String[] statusProbers = {
            "com.tencent.turingfd.sdk.xq.Pomegranate",
            "com.tencent.tfd.sdk.wxa.Blueberry",
            "com.tencent.turingcam.oqKCa"
        };
        for (String proberCls : statusProbers) {
            Class<?> clazz = XposedHelpers.findClassIfExists(proberCls, cl);
            if (clazz != null) {
                HookUtils.hookAllMethodsIfExists(clazz, "b", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res != null) {
                            try {
                                for (java.lang.reflect.Field f : res.getClass().getDeclaredFields()) {
                                    if (f.getType() == int.class) {
                                        f.setAccessible(true);
                                        String fname = f.getName();
                                        if (fname.equals("c") || fname.equals("f1003c") || fname.equals("f1167c")) {
                                            f.setInt(res, 0); // TracerPid = 0
                                        }
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringFD] Hooked status prober on " + proberCls);
            }
        }

        // Process status POJO constructors (Plum, Blueberry$Cdo, oqKCa$spXPg)
        String[] statusPojos = {
            "com.tencent.turingfd.sdk.xq.Plum",
            "com.tencent.tfd.sdk.wxa.Blueberry$Cdo",
            "com.tencent.turingcam.oqKCa$spXPg"
        };
        for (String pojoCls : statusPojos) {
            Class<?> clazz = XposedHelpers.findClassIfExists(pojoCls, cl);
            if (clazz != null) {
                HookUtils.hookAllConstructors(clazz, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 4) {
                            if (param.args[3] instanceof Integer) {
                                param.args[3] = 0; // TracerPid = 0
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringFD] Hooked status POJO constructor on " + pojoCls);
            }
        }
    }

    private static final byte[] OFFICIAL_TENCENT_PKG_SIG_MD5 = new byte[] {
        (byte) 0xa6, (byte) 0xb7, (byte) 0x45, (byte) 0xbf,
        (byte) 0x24, (byte) 0xa2, (byte) 0xc2, (byte) 0x77,
        (byte) 0x52, (byte) 0x77, (byte) 0x16, (byte) 0xf6,
        (byte) 0xf3, (byte) 0x6e, (byte) 0xb6, (byte) 0x8d
    };

    private static void hookWlogin(ClassLoader cl) {
        if (cl == null) return;
        Class<?> wCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.request.w", cl);
        if (wCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_wlogin_w")) {
            HookUtils.hookAllMethods(wCls, "h",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            XposedHelpers.setStaticObjectField(wCls, "J", OFFICIAL_TENCENT_PKG_SIG_MD5.clone());
                            XposedHelpers.setStaticIntField(wCls, "Y", 0);
                            XposedEntry.log("[Wlogin] Intercepted Wlogin device fingerprint on " + wCls.getName() + " -> enforced clean signature & w.Y=0");
                        } catch (Throwable ignored) {}
                    }
                });
        }

        Class<?> utilCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.tools.util", cl);
        if (utilCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_wlogin_util")) {
            HookUtils.hookAllMethods(utilCls, "getPkgSigFromApkName",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(OFFICIAL_TENCENT_PKG_SIG_MD5.clone());
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
               "cmd_forceLogout".equals(cmd);
    }

    public static String decodeForceOfflineDetails(ClassLoader cl, Object msg) {
        if (msg == null) return "null";
        StringBuilder sb = new StringBuilder();
        try {
            byte[] wupBuf = (byte[]) XposedHelpers.callMethod(msg, "getWupBuffer");
            if (wupBuf != null && wupBuf.length > 0) {
                try {
                    Class<?> uniPacketCls = XposedHelpers.findClassIfExists("com.qq.jce.wup.UniPacket", cl);
                    Class<?> reqCls = XposedHelpers.findClassIfExists("com.tencent.msf.service.protocol.push.RequestMSFForceOffline", cl);
                    if (uniPacketCls != null && reqCls != null) {
                        Object packet = uniPacketCls.getConstructor(boolean.class).newInstance(true);
                        XposedHelpers.callMethod(packet, "setEncodeName", "utf-8");
                        XposedHelpers.callMethod(packet, "decode", (Object) wupBuf);
                        Object reqObj = XposedHelpers.callMethod(packet, "getByClass", "RequestMSFForceOffline", reqCls.newInstance());
                        if (reqObj != null) {
                            long lUin = XposedHelpers.getLongField(reqObj, "lUin");
                            long iSeqno = XposedHelpers.getLongField(reqObj, "iSeqno");
                            byte bKickType = XposedHelpers.getByteField(reqObj, "bKickType");
                            String strTitle = (String) XposedHelpers.getObjectField(reqObj, "strTitle");
                            String strInfo = (String) XposedHelpers.getObjectField(reqObj, "strInfo");
                            byte bSigKick = XposedHelpers.getByteField(reqObj, "bSigKick");
                            byte[] vecSigKickData = (byte[]) XposedHelpers.getObjectField(reqObj, "vecSigKickData");
                            byte bSameDevice = XposedHelpers.getByteField(reqObj, "bSameDevice");

                            sb.append("RequestMSFForceOffline{lUin=").append(lUin)
                              .append(", iSeqno=").append(iSeqno)
                              .append(", bKickType=").append(bKickType)
                              .append(", strTitle='").append(strTitle).append('\'')
                              .append(", strInfo='").append(strInfo).append('\'')
                              .append(", bSigKick=").append(bSigKick)
                              .append(", bSameDevice=").append(bSameDevice)
                              .append(", vecSigKickDataLen=").append(vecSigKickData != null ? vecSigKickData.length : 0)
                              .append("}");
                            return sb.toString();
                        }
                    }
                } catch (Throwable t) {
                    sb.append("UniPacket decode: ").append(t.getMessage());
                }
            }
        } catch (Throwable ignored) {}
        return sb.length() > 0 ? sb.toString() : "raw";
    }

    private static void hookErrorHandlerClass(Class<?> ehCls) {
        if (ehCls == null || !sKickAuditedClasses.add(ehCls.getName())) return;

        String[] kickMethods = {
            "onUserTokenExpired", "onKickedAndClearToken", "onKicked",
            "onInterceptKicked", "onKickedInternal", "onGrayError",
            "onServerSuspended", "onInvalidSign", "onNoTestEnvPermission",
            "onRecvServerTip"
        };
        for (String mName : kickMethods) {
            HookUtils.hookIfMethodExists(ehCls, mName, new XC_MethodHook() {
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

        HookUtils.hookIfMethodExists(ehCls, "popupNotification", new XC_MethodHook() {
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

        HookUtils.hookIfMethodExists(ehCls, "popupNotificationEx", new XC_MethodHook() {
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
                            String kickDetail = decodeForceOfflineDetails(cl, fromMsg);
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "MSF.core.t.a (Read-Only Audit)", fromMsg, toMsg,
                                "MSF push/sso response received: cmd=" + cmd + ", failCode=" + failCode + ", detail=" + kickDetail);
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
                                if (fromServiceMsg == null) {
                                    fromServiceMsg = XposedHelpers.callMethod(toMsg, "getAttribute", "StatSvc.RspMSFForceOffline");
                                }
                                if (fromServiceMsg == null) {
                                    fromServiceMsg = XposedHelpers.callMethod(toMsg, "getAttribute", "StatSvc.ReqMSFOffline");
                                }
                                String detail = decodeForceOfflineDetails(cl, fromServiceMsg != null ? fromServiceMsg : toMsg);
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    "crossplatform.c$a.run (Read-Only Audit)",
                                    fromServiceMsg != null ? fromServiceMsg : toMsg,
                                    toMsg,
                                    "_msf_kickedAndCleanTokenResp executing: " + detail);
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
                                        if (fromServiceMsg == null) {
                                            fromServiceMsg = XposedHelpers.callMethod(toMsg, "getAttribute", "StatSvc.RspMSFForceOffline");
                                        }
                                        if (fromServiceMsg == null) {
                                            fromServiceMsg = XposedHelpers.callMethod(toMsg, "getAttribute", "StatSvc.ReqMSFOffline");
                                        }
                                        String detail = decodeForceOfflineDetails(cl, fromServiceMsg != null ? fromServiceMsg : toMsg);
                                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                            "crossplatform.c$Runnable.run (Read-Only Audit)",
                                            fromServiceMsg != null ? fromServiceMsg : toMsg,
                                            toMsg,
                                            "_msf_kickedAndCleanTokenResp executing: " + detail);
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

    /**
     * Inbound Server Response Auditing.
     * Intercepts server responses from MSF kernel callbacks, ChannelManager native callbacks,
     * and high-level servlets to detect return codes, failure tips, and decoded response payloads.
     */
    private static void hookInboundResponses(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;

        // 1. IMSFCallbackBridge: onMSFPacketState, onMSFError, onSSORetError
        String[] cbClasses = {
            "com.tencent.mobileqq.msf.core.service.crossplatform.b$e",
            "com.tencent.mobileqq.msfcore.IMSFCallbackBridge"
        };
        for (String cbName : cbClasses) {
            Class<?> cbCls = XposedHelpers.findClassIfExists(cbName, cl);
            if (cbCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_" + cbName)) {
                HookUtils.hookAllMethods(cbCls, "onMSFPacketState", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 1 || param.args[0] == null) return;
                        Object adapter = param.args[0];
                        try {
                            String cmd = (String) XposedHelpers.callMethod(adapter, "getCmd");
                            if (cmd == null || isCoreProtocolCommand(cmd)) return;

                            int seq = 0;
                            int ssoRet = 0;
                            int trpcRet = 0;
                            String ssoErr = null;
                            String trpcErr = null;
                            byte[] recvData = null;
                            String uin = null;

                            try { seq = ((Number) XposedHelpers.callMethod(adapter, "getSeq")).intValue(); } catch (Throwable ignored) {}
                            try { ssoRet = ((Number) XposedHelpers.callMethod(adapter, "getSsoRet")).intValue(); } catch (Throwable ignored) {}
                            try { trpcRet = ((Number) XposedHelpers.callMethod(adapter, "getTrpcRetcode")).intValue(); } catch (Throwable ignored) {}
                            try { ssoErr = (String) XposedHelpers.callMethod(adapter, "getSsoErrTips"); } catch (Throwable ignored) {}
                            try {
                                Object rawTrpcErr = XposedHelpers.callMethod(adapter, "getTrpcErrMsg");
                                if (rawTrpcErr instanceof byte[]) {
                                    byte[] trpcBytes = (byte[]) rawTrpcErr;
                                    if (trpcBytes.length > 0) {
                                        trpcErr = new String(trpcBytes, java.nio.charset.StandardCharsets.UTF_8);
                                    }
                                } else if (rawTrpcErr != null) {
                                    trpcErr = rawTrpcErr.toString();
                                }
                            } catch (Throwable ignored) {}
                            try { recvData = (byte[]) XposedHelpers.callMethod(adapter, "getRecvData"); } catch (Throwable ignored) {}
                            try { uin = (String) XposedHelpers.callMethod(adapter, "getUin"); } catch (Throwable ignored) {}

                            StringBuilder extra = new StringBuilder();
                            if (uin != null && !uin.isEmpty() && !"0".equals(uin)) {
                                extra.append("uin=").append(uin);
                            }
                            if (trpcRet != 0) {
                                if (extra.length() > 0) extra.append(", ");
                                extra.append("trpcRetcode=").append(trpcRet);
                            }
                            if (trpcErr != null && !trpcErr.isEmpty()) {
                                if (extra.length() > 0) extra.append(", ");
                                extra.append("trpcErrMsg=\"").append(trpcErr).append("\"");
                            }

                            boolean isSec = io.github.xalsace.qqbypass.utils.ReportAuditManager.isSecurityOrEnvironmentEvent("MSFCallbackBridge", cmd, null, null);
                            if (isSec || ssoRet != 0 || trpcRet != 0 || isKickOrTokenFailCode(ssoRet) || isKickOrTokenFailCode(trpcRet)) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                                    "MSFCallbackBridge.onMSFPacketState",
                                    cmd, seq, ssoRet, ssoErr, recvData, extra.toString(), 6);
                            }
                        } catch (Throwable ignored) {}
                    }
                });

                HookUtils.hookAllMethods(cbCls, "onMSFError", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 5) return;
                        int errCode = param.args[0] instanceof Number ? ((Number) param.args[0]).intValue() : 0;
                        String str1 = String.valueOf(param.args[1]);
                        String errTitle = String.valueOf(param.args[2]);
                        String errContent = String.valueOf(param.args[3]);
                        String extInfo = String.valueOf(param.args[4]);
                        String detail = "errTitle=\"" + errTitle + "\", errContent=\"" + errContent + "\", extInfo=\"" + extInfo + "\", str1=" + str1;
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                            "MSFCallbackBridge.onMSFError", "onMSFError", 0, errCode, errTitle + ": " + errContent, null, detail, 6);
                    }
                });

                HookUtils.hookAllMethods(cbCls, "onSSORetError", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args == null || param.args.length < 4) return;
                        int errCode = param.args[0] instanceof Number ? ((Number) param.args[0]).intValue() : 0;
                        String cmd = String.valueOf(param.args[1]);
                        String ssoErrTips = String.valueOf(param.args[2]);
                        String detail = "ssoErrTips=\"" + ssoErrTips + "\", extra=" + param.args[3];
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                            "MSFCallbackBridge.onSSORetError", cmd, 0, errCode, ssoErrTips, null, detail, 6);
                    }
                });

                XposedEntry.log("[NetworkReport] Hooked IMSFCallbackBridge methods on " + cbName);
            }
        }

        // 2. ChannelManager: onReceive & onNativeReceive
        Class<?> cmCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelManager", cl);
        if (cmCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_ChannelManager_onReceive")) {
            XC_MethodHook onReceiveHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    String cmd = param.args[0] instanceof String ? (String) param.args[0] : "unknown";
                    if (cmd.startsWith("trpc.o3.ecdh_access.")) {
                        long callbackId = 0L;
                        if (param.args.length >= 5 && param.args[4] instanceof Number) {
                            callbackId = ((Number) param.args[4]).longValue();
                        } else if (param.args.length == 4 && param.args[3] instanceof Number) {
                            callbackId = ((Number) param.args[3]).longValue();
                        }
                        byte[] data = param.args[1] instanceof byte[] ? (byte[]) param.args[1] : null;
                        int resCode = (param.args.length >= 4 && param.args[3] instanceof Number) ? ((Number) param.args[3]).intValue() : 1000;
                        XposedEntry.log("[FEKit_ECDH] Inbound " + param.method.getName() + " cmd=" + cmd
                            + ", resCode=" + resCode + ", callbackId=" + callbackId + ", dataLen=" + (data != null ? data.length : 0));
                    }
                    if (isCoreProtocolCommand(cmd)) return;

                    byte[] data = param.args[1] instanceof byte[] ? (byte[]) param.args[1] : null;
                    boolean isSuccess = true;
                    int resultCode = 1000;
                    long callbackId = 0L;

                    if (param.args.length >= 3 && param.args[2] instanceof Boolean) {
                        isSuccess = (Boolean) param.args[2];
                    }
                    if (param.args.length >= 4 && param.args[3] instanceof Number) {
                        resultCode = ((Number) param.args[3]).intValue();
                    }
                    if (param.args.length >= 5 && param.args[4] instanceof Number) {
                        callbackId = ((Number) param.args[4]).longValue();
                    } else if (param.args.length == 4 && param.args[3] instanceof Number) {
                        callbackId = ((Number) param.args[3]).longValue();
                    }

                    String extra = "isSuccess=" + isSuccess + ", callbackId=" + callbackId;
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                        "ChannelManager." + param.method.getName(),
                        cmd, (int) callbackId, resultCode, null, data, extra, 4);
                }
            };
            HookUtils.hookAllMethods(cmCls, "onReceive", onReceiveHook);
            HookUtils.hookAllMethods(cmCls, "onNativeReceive", onReceiveHook);
            XposedEntry.log("[NetworkReport] Hooked ChannelManager onReceive/onNativeReceive on loader " + cl);
        }

        // 3. FEKitManager (com.tencent.mobileqq.msf.core.security.a) response handler
        Class<?> feKitMgrCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.security.a", cl);
        if (feKitMgrCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKitManager_a")) {
            HookUtils.hookAllMethods(feKitMgrCls, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    Object toMsg = null;
                    Object fromMsg = null;
                    for (Object arg : param.args) {
                        if (arg != null) {
                            String cName = arg.getClass().getName();
                            if (cName.contains("ToServiceMsg")) toMsg = arg;
                            else if (cName.contains("FromServiceMsg")) fromMsg = arg;
                        }
                    }
                    if (fromMsg != null) {
                        try {
                            String cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                            if (cmd == null || (isCoreProtocolCommand(cmd) && !isTrpcCommand(cmd))) return;
                            int failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                            String failMsg = (String) XposedHelpers.callMethod(fromMsg, "getBusinessFailMsg");
                            int ssoSeq = ((Number) XposedHelpers.callMethod(fromMsg, "getRequestSsoSeq")).intValue();
                            byte[] wupBuf = (byte[]) XposedHelpers.callMethod(fromMsg, "getWupBuffer");
                            String extra = "resCode=" + XposedHelpers.callMethod(fromMsg, "getResultCode");
                            if (failCode == 1002 && cmd != null && cmd.startsWith("trpc.o3.ecdh_access.")) {
                                XposedEntry.log("[FEKitDefense] Detected deep-sleep timeout (1002) on " + cmd + " (seq=" + ssoSeq + "), FEKit retry will be normalized");
                            }
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                                "FEKitManager.handleSecServiceResp",
                                cmd, ssoSeq, failCode, failMsg, wupBuf, extra, 4);
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[NetworkReport] Hooked FEKitManager security response handler on loader " + cl);
        }

        // 4. O3BusinessHandler.onReceive
        Class<?> o3HandlerCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.web.O3BusinessHandler", cl);
        if (o3HandlerCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_O3BusinessHandler_onReceive")) {
            HookUtils.hookAllMethods(o3HandlerCls, "onReceive", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    Object fromMsg = param.args[1];
                    if (fromMsg != null && fromMsg.getClass().getName().contains("FromServiceMsg")) {
                        try {
                            String cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                            int failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                            String failMsg = (String) XposedHelpers.callMethod(fromMsg, "getBusinessFailMsg");
                            int ssoSeq = ((Number) XposedHelpers.callMethod(fromMsg, "getRequestSsoSeq")).intValue();
                            byte[] wupBuf = (byte[]) XposedHelpers.callMethod(fromMsg, "getWupBuffer");
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                                "O3BusinessHandler.onReceive",
                                cmd, ssoSeq, failCode, failMsg, wupBuf, null, 4);
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[NetworkReport] Hooked O3BusinessHandler onReceive on loader " + cl);
        }

        // 5. O3MsfServlet.onReceive
        Class<?> o3ServletCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.web.O3MsfServlet", cl);
        if (o3ServletCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_O3MsfServlet")) {
            HookUtils.hookAllMethods(o3ServletCls, "onReceive", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    Object fromMsg = param.args[1];
                    if (fromMsg != null && fromMsg.getClass().getName().contains("FromServiceMsg")) {
                        try {
                            String cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                            int failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                            String failMsg = (String) XposedHelpers.callMethod(fromMsg, "getBusinessFailMsg");
                            int ssoSeq = ((Number) XposedHelpers.callMethod(fromMsg, "getRequestSsoSeq")).intValue();
                            byte[] wupBuf = (byte[]) XposedHelpers.callMethod(fromMsg, "getWupBuffer");
                            Object attrs = XposedHelpers.callMethod(fromMsg, "getAttributes");
                            String extra = attrs != null ? "attrs=" + attrs : "";
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
                                "O3MsfServlet.onReceive",
                                cmd, ssoSeq, failCode, failMsg, wupBuf, extra, 4);
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[NetworkReport] Hooked O3MsfServlet onReceive on loader " + cl);
        }
    }

    /**
     * Pre-Encryption Plaintext Security Dispatch Auditing.
     * Captures plaintext JSON configuration, tokens, and verification arguments
     * before native obfuscation / encryption by libFEKit.so, libfekit_sec.so, or libQSec.so.
     */
    private static void hookPlaintextSecurityDispatches(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;

        // 1. O3BusinessHandler: P2, Q2, S2
        Class<?> o3HandlerCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.web.O3BusinessHandler", cl);
        if (o3HandlerCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_O3BusinessHandler_dispatches")) {
            XC_MethodHook o3Hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    String event = param.args[0] != null ? param.args[0].toString() : "unknown";
                    if (isCoreProtocolCommand(event) && !isTrpcCommand(event)) return;
                    String params = param.args[1] != null ? param.args[1].toString() : null;
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "O3BusinessHandler." + param.method.getName(),
                        event, params, null, null);
                }
            };
            HookUtils.hookAllMethodsIfExists(o3HandlerCls, "P2", o3Hook);
            HookUtils.hookAllMethodsIfExists(o3HandlerCls, "Q2", o3Hook);
            HookUtils.hookAllMethodsIfExists(o3HandlerCls, "S2", o3Hook);
            XposedEntry.log("[NetworkReport] Hooked O3BusinessHandler P2/Q2/S2 plaintext dispatchers on loader " + cl);
        }

        // 2. FEKit: dispatchEvent & dispatchEventPB
        Class<?> feKitCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.FEKit", cl);
        if (feKitCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKit_dispatchEvent")) {
            XC_MethodHook feKitHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1) return;
                    String event = param.args[0] != null ? param.args[0].toString() : "unknown";
                    if (isCoreProtocolCommand(event) && !isTrpcCommand(event)) return;
                    byte[] data = null;
                    String strParams = null;
                    if (param.args.length >= 2) {
                        if (param.args[1] instanceof byte[]) {
                            data = (byte[]) param.args[1];
                        } else if (param.args[1] != null) {
                            strParams = param.args[1].toString();
                            if (param.args.length >= 3 && param.args[2] != null) {
                                strParams += ", arg2=" + param.args[2];
                            }
                        }
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "FEKit." + param.method.getName(),
                        event, strParams, data, null);
                }
            };
            HookUtils.hookAllMethodsIfExists(feKitCls, "dispatchEvent", feKitHook);
            HookUtils.hookAllMethodsIfExists(feKitCls, "dispatchEventPB", feKitHook);
            XposedEntry.log("[NetworkReport] Hooked FEKit dispatchEvent/dispatchEventPB on loader " + cl);
        }

        // 3. Dtn: mainProcessDispatch
        Class<?> dtnCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.Dtn", cl);
        if (dtnCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_Dtn")) {
            XC_MethodHook dtnHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1) return;
                    String event = param.args[0] != null ? param.args[0].toString() : "unknown";
                    if (isCoreProtocolCommand(event) && !isTrpcCommand(event)) return;
                    byte[] data = null;
                    String strParams = null;
                    if (param.args.length >= 2) {
                        if (param.args[1] instanceof byte[]) {
                            data = (byte[]) param.args[1];
                        } else if (param.args[1] != null) {
                            strParams = param.args[1].toString();
                        }
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "Dtn." + param.method.getName(),
                        event, strParams, data, null);
                }
            };
            HookUtils.hookAllMethods(dtnCls, "mainProcessDispatch", dtnHook);
            XposedEntry.log("[NetworkReport] Hooked Dtn mainProcessDispatch on loader " + cl);
        }

        // 4. QQSecuritySign: getSign & dispatchEvent
        Class<?> secSignCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.sign.QQSecuritySign", cl);
        if (secSignCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_QQSecuritySign")) {
            HookUtils.hookAllMethods(secSignCls, "getSign", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    String uin = "";
                    String cmd = "";
                    byte[] buffer = null;

                    // Deterministic parameter extraction based on method overload:
                    // 6-arg native getSign: (QSec, String mExtra, String cmd, byte[] bArr, byte[] bArr2, String uin)
                    // 5-arg Java getSign: (QSec, String cmd, byte[] bArr, byte[] bArr2, String uin)
                    if (param.args.length >= 6) {
                        cmd = param.args[2] instanceof String ? (String) param.args[2] : "";
                        buffer = param.args[3] instanceof byte[] ? (byte[]) param.args[3] : null;
                        uin = param.args[5] instanceof String ? (String) param.args[5] : "";
                    } else if (param.args.length == 5) {
                        cmd = param.args[1] instanceof String ? (String) param.args[1] : "";
                        buffer = param.args[2] instanceof byte[] ? (byte[]) param.args[2] : null;
                        uin = param.args[4] instanceof String ? (String) param.args[4] : "";
                    } else {
                        // Dynamic fallback heuristic
                        for (Object arg : param.args) {
                            if (arg instanceof String) {
                                String s = (String) arg;
                                if (s.contains(".") || s.contains("_") || s.length() > 5) {
                                    if (cmd.isEmpty()) cmd = s;
                                } else if (uin.isEmpty() && s.matches("\\d+")) {
                                    uin = s;
                                }
                            } else if (arg instanceof byte[] && buffer == null) {
                                buffer = (byte[]) arg;
                            }
                        }
                    }

                    if (cmd.isEmpty()) return;
                    if (isCoreProtocolCommand(cmd)) {
                        boolean isSec = io.github.xalsace.qqbypass.utils.ReportAuditManager.isSecurityOrEnvironmentEvent("QQSecuritySign.getSign", cmd, null, null);
                        if (!isSec && !isTrpcCommand(cmd)) {
                            return;
                        }
                    }

                    Object signResult = param.getResult();
                    StringBuilder extra = new StringBuilder();
                    if (!uin.isEmpty()) extra.append("uin=").append(uin).append(", ");
                    extra.append("cmd=").append(cmd);

                    if (signResult != null) {
                        try {
                            Object sign = XposedHelpers.getObjectField(signResult, "sign");
                            Object token = XposedHelpers.getObjectField(signResult, "token");
                            Object extraObj = XposedHelpers.getObjectField(signResult, "extra");
                            if (sign instanceof byte[]) extra.append(", signLen=").append(((byte[]) sign).length);
                            if (token instanceof byte[]) extra.append(", tokenLen=").append(((byte[]) token).length);
                            if (extraObj instanceof byte[]) extra.append(", extraLen=").append(((byte[]) extraObj).length);
                        } catch (Throwable ignored) {}
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "QQSecuritySign.getSign", cmd, null, buffer, extra.toString());
                }
            });

            XC_MethodHook secDispatchHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 1) return;
                    String event = param.args[0] != null ? param.args[0].toString() : "unknown";
                    if (isCoreProtocolCommand(event) && !isTrpcCommand(event)) return;
                    byte[] data = null;
                    String strParams = null;
                    if (param.args.length >= 2) {
                        if (param.args[1] instanceof byte[]) {
                            data = (byte[]) param.args[1];
                        } else if (param.args[1] != null) {
                            strParams = param.args[1].toString();
                        }
                    }
                    if (param.args.length >= 3 && param.args[2] instanceof byte[]) {
                        data = (byte[]) param.args[2];
                    }
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "QQSecuritySign." + param.method.getName(),
                        event, strParams, data, null);
                }
            };
            HookUtils.hookAllMethodsIfExists(secSignCls, "dispatchEvent", secDispatchHook);
            HookUtils.hookAllMethodsIfExists(secSignCls, "dispatchEventPB", secDispatchHook);
            XposedEntry.log("[NetworkReport] Hooked QQSecuritySign getSign/dispatchEvent on loader " + cl);
        }

        // 5. ProtoServlet & TrpcProtoServlet: pre-encryption onSend & post-decryption onReceive
        Class<?> protoServletCls = XposedHelpers.findClassIfExists("com.tencent.biz.ProtoServlet", cl);
        if (protoServletCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_ProtoServlet")) {
            HookUtils.hookAllMethods(protoServletCls, "onSend", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length < 2) return;
                    if (!(param.args[0] instanceof Intent)) return;
                    Intent intent = (Intent) param.args[0];
                    String cmd = intent.getStringExtra("cmd");
                    if (cmd == null || cmd.isEmpty()) return;
                    byte[] data = intent.getByteArrayExtra("data");
                    if (data == null || io.github.xalsace.qqbypass.utils.ReportAuditManager.isEmptyPayload(data)) return;

                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPlaintextSecurityDispatch(
                        "ProtoServlet.onSend", cmd, "intentSeq=" + intent.getIntExtra("seq", 0), data, "timeout=" + intent.getLongExtra("timeout", 0));
                }
            });

            HookUtils.hookAllMethods(protoServletCls, "onReceive", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    auditProtoServletReceive("ProtoServlet.onReceive", param);
                }
            });
            XposedEntry.log("[NetworkReport] Hooked ProtoServlet on loader " + cl);
        }

        Class<?> trpcServletCls = XposedHelpers.findClassIfExists("com.tencent.biz.TrpcProtoServlet", cl);
        if (trpcServletCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_TrpcProtoServlet")) {
            HookUtils.hookAllMethods(trpcServletCls, "onReceive", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    auditProtoServletReceive("TrpcProtoServlet.onReceive", param);
                }
            });
            XposedEntry.log("[NetworkReport] Hooked TrpcProtoServlet on loader " + cl);
        }
    }

    private static void auditProtoServletReceive(String tag, XC_MethodHook.MethodHookParam param) {
        if (param.args == null || param.args.length < 2) return;
        if (!(param.args[0] instanceof Intent)) return;
        Intent intent = (Intent) param.args[0];
        String cmd = null;
        Object fromMsg = param.args[1];
        int retCode = 0;
        String errMsg = null;
        int ssoSeq = intent.getIntExtra("seq", 0);
        if (fromMsg != null) {
            try {
                cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                retCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                errMsg = (String) XposedHelpers.callMethod(fromMsg, "getBusinessFailMsg");
                ssoSeq = ((Number) XposedHelpers.callMethod(fromMsg, "getRequestSsoSeq")).intValue();
            } catch (Throwable ignored) {}
        }
        if (cmd == null || cmd.isEmpty()) {
            cmd = intent.getStringExtra("cmd");
        }
        if (cmd == null || cmd.isEmpty()) return;

        Bundle extras = intent.getExtras();
        byte[] data = extras != null ? extras.getByteArray("data") : intent.getByteArrayExtra("data");
        if (data == null || io.github.xalsace.qqbypass.utils.ReportAuditManager.isEmptyPayload(data)) return;

        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordInboundResponse(
            tag, cmd, ssoSeq, retCode, errMsg, data, "intentSeq=" + intent.getIntExtra("seq", 0), 4);
    }

    /**
     * Captures internal diagnostic and kick telemetry logs emitted by libFEKit.so / libfekit_sec.so.
     */
    private static void hookFEKitNativeLog(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT || cl == null) return;

        XC_MethodHook logHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args == null || param.args.length < 3) return;
                String tag = param.args[0] != null ? param.args[0].toString() : "";
                String msg = param.args[2] != null ? param.args[2].toString() : "";
                String level = param.method.getName().toUpperCase(java.util.Locale.ROOT);
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordFEKitInternalLog(level, tag, msg);
            }
        };

        String[] levels = {"d", "e", "i", "v", "w"};

        // 1. Hook com.tencent.mobileqq.fe.c$a (Main process FEKit default logger)
        Class<?> feCInnerCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.c$a", cl);
        if (feCInnerCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKit_c$a")) {
            for (String lvl : levels) {
                HookUtils.hookAllMethods(feCInnerCls, lvl, logHook);
            }
            XposedEntry.log("[NetworkReport] Hooked main process FEKit logger (com.tencent.mobileqq.fe.c$a)");
        }

        // 2. Hook com.tencent.mobileqq.msf.core.security.a$c (MSF process FEKit default logger)
        Class<?> msfSecInnerCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.security.a$c", cl);
        if (msfSecInnerCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKit_a$c")) {
            for (String lvl : levels) {
                HookUtils.hookAllMethods(msfSecInnerCls, lvl, logHook);
            }
            XposedEntry.log("[NetworkReport] Hooked MSF process FEKit logger (com.tencent.mobileqq.msf.core.security.a$c)");
        }

        // 3. Hook dynamic IFEKitLog setters (FEKit.initLog and c.d)
        Class<?> feKitCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.FEKit", cl);
        if (feKitCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKit_initLog")) {
            HookUtils.hookAllMethods(feKitCls, "initLog", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] != null) {
                        Class<?> customLogCls = param.args[0].getClass();
                        if (sHookedNetworkClasses.add(cl.hashCode() + "_" + customLogCls.getName())) {
                            for (String lvl : levels) {
                                HookUtils.hookAllMethods(customLogCls, lvl, logHook);
                            }
                            XposedEntry.log("[NetworkReport] Hooked custom IFEKitLog: " + customLogCls.getName());
                        }
                    }
                }
            });
        }

        Class<?> feCCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.c", cl);
        if (feCCls != null && sHookedNetworkClasses.add(cl.hashCode() + "_FEKit_c_d")) {
            HookUtils.hookAllMethods(feCCls, "d", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] != null) {
                        Class<?> customLogCls = param.args[0].getClass();
                        if (sHookedNetworkClasses.add(cl.hashCode() + "_" + customLogCls.getName())) {
                            for (String lvl : levels) {
                                HookUtils.hookAllMethods(customLogCls, lvl, logHook);
                            }
                            XposedEntry.log("[NetworkReport] Hooked custom IFEKitLog via c.d: " + customLogCls.getName());
                        }
                    }
                }
            });
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
