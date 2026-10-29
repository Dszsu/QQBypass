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
        "RegPrxySvc.",
        "SharpSvr.",
        "MultiVideo.",
        "VideoSvc.",
        "AVChatSvr.",
        "VoipService.",
        "trpc.voip.",
        "trpc.group_av.",
        "ImgStore.",
        "PttStore.",
        "PttCenter.",
        "ShortVideo.",
        "OfflineFvr."
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
               command.startsWith("RegisterProxy.") ||
               command.startsWith("Heartbeat.") ||
               command.startsWith("OnlinePush.") ||
               command.startsWith("ConfigPushSvc.") ||
               command.startsWith("ProfileService.") ||
               command.startsWith("Friendlist.") ||
               command.startsWith("SharpSvr.") ||
               command.startsWith("MultiVideo.") ||
               command.startsWith("VideoSvc.") ||
               command.startsWith("AVChatSvr.") ||
               command.startsWith("VoipService.") ||
               command.startsWith("trpc.voip.") ||
               command.startsWith("trpc.group_av.") ||
               command.startsWith("ImgStore.") ||
               command.startsWith("PttStore.") ||
               command.startsWith("PttCenter.") ||
               command.startsWith("ShortVideo.") ||
               command.startsWith("OfflineFvr.") ||
               command.startsWith("trpc.login.") ||
               command.startsWith("login.") ||
               command.startsWith("wtlogin.") ||
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
        // Layer 0 - 3: Channel / MSF report normalization
        hookChannelManager(cl);
        hookChannelProxyExt(cl);
        hookMsfCore(cl);

        // UI kick notification audit (strictly high-level UI NotificationActivity, zero MSF/WTLogin touch)
        hookKickAudit(lpparam);

        // Inspection checks (TuringFD /proc scanner neutralization)
        hookTuringFD(lpparam);
        hookTuringEridanus(cl);
        hookTuringD1Network(cl);
    }

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        hookTuringEridanus(cl);
        hookTuringD1Network(cl);
        hookChannelManager(cl);
        hookChannelProxyExt(cl);
        hookMsfCore(cl);
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
     * Determines whether an IP address belongs to RFC 2544 Fake-IP range (198.18.0.0/15) used by TUN proxies.
     * Note: Legitimate RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback
     * are authentic device network characteristics and must NEVER be treated as Fake-IP or modified.
     */
    public static boolean isFakeIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        int colon = ip.indexOf(':');
        String cleanIp = (colon > 0 && ip.indexOf(':', colon + 1) < 0) ? ip.substring(0, colon) : ip;
        cleanIp = cleanIp.trim();
        return cleanIp.startsWith("198.18.") || cleanIp.startsWith("198.19.");
    }

    @Deprecated
    public static boolean isFakeOrPrivateIp(String ip) {
        return isFakeIp(ip);
    }

    @Deprecated
    public static String getFallbackSsoAddress(Object msfCore) {
        return "111.30.169.83";
    }

    /**
     * MsfCore.sendSsoMsg:
     * Only transparently normalizes SsoReport failure telemetry (Rule 4.2 compliant).
     * Strictly zero intervention into any other command, official session state machine, or error code.
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
                    if (!"trpc.o3.report.Report.SsoReport".equals(command)) {
                        return; // Fast path: zero reflection, zero audit overhead, zero intervention
                    }

                    try {
                        byte[] wup = (byte[]) XposedHelpers.callMethod(toServiceMsg, "getWupBuffer");
                        if (wup == null || wup.length == 0) {
                            java.util.Map<?, ?> attrs = (java.util.Map<?, ?>) XposedHelpers.callMethod(toServiceMsg, "getAttributes");
                            if (attrs != null) {
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
                        }

                        // Transparently sanitize trpc.o3.report.Report.SsoReport if it carries failure telemetry (Rule 4.2 compliant)
                        byte[] sanitized = io.github.xalsace.qqbypass.hooks.QQ950PatchHook.sanitizeSsoReportPayload(wup);
                        if (sanitized != wup) {
                            try {
                                XposedHelpers.callMethod(toServiceMsg, "putWupBuffer", (Object) sanitized);
                            } catch (Throwable ignored) {}
                        }
                    } catch (Throwable ignored) {}
                }
            });
        XposedEntry.log("[NetworkReport] Installed MsfCore.sendSsoMsg hook on loader " + cl);
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

    private static final java.util.Set<String> sKickAuditedClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static void hookKickAudit(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;
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
                            "NotificationActivity.onCreate (UI Read-Only Audit)", null, extraDump.toString());
                    } catch (Throwable ignored) {}
                }
            });
            XposedEntry.log("[KickAudit] Installed UI kick notification audit on NotificationActivity.onCreate");
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
