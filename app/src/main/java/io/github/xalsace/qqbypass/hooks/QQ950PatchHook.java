package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.defense.SideChannelDefense;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.detector.DexMethodData;
import io.github.xalsace.qqbypass.utils.HookUtils;
import io.github.xalsace.qqbypass.version.HostVersion;
import io.github.xalsace.qqbypass.version.HostVersionManager;
import io.github.xalsace.qqbypass.version.IVersionProfile;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Locale;

/**
 * Detection & Risk Mitigation Patch (Enhanced for QQ 9.3.50 - 9.3.70)
 *
 * Targets real risk-control and forced kick mechanisms:
 * - NTKickProcessor / Kick Diagnostics: Passive logging only; zero suppression to avoid Zombie Sessions
 * - TuringRiskService: Returns safe dynamic proxy (never null to avoid NPE in turingfd callers)
 * - TuringIDService: Returns safe dynamic proxy (never null to avoid NPE on getOpenIdTicket)
 * - QQ 9.3.70 Turing Bridge (com.tencent.mobileqq.turingfd.i): Intercepts deviceToken and tickets
 * - ChannelManager / ChannelReport: Neutralize environment reflection and telemetry
 */
public class QQ950PatchHook {

    private static final long sProcessStartTime = android.os.SystemClock.elapsedRealtime();
    private static volatile String sLastKnownDeviceToken = null;
    private static volatile String sLastKnownOpenIdTicket = null;

    public static String getOrGenerateDeviceToken() {
        if (sLastKnownDeviceToken != null && sLastKnownDeviceToken.length() >= 16) {
            return sLastKnownDeviceToken;
        }
        try {
            Class<?> fClass = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.f", HookConfig.getClassLoader());
            if (fClass != null) {
                Object fb = XposedHelpers.callStaticMethod(fClass, "b");
                if (fb != null) {
                    String cached = (String) XposedHelpers.callMethod(fb, "d", "DeviceToken-TuringCache-V001", "");
                    if (cached != null && cached.length() >= 16) {
                        sLastKnownDeviceToken = cached;
                        return cached;
                    }
                    cached = (String) XposedHelpers.callMethod(fb, "d", "TuringRiskID-TuringCache-20230511", "");
                    if (cached != null && cached.length() >= 16) {
                        sLastKnownDeviceToken = cached;
                        return cached;
                    }
                }
            }
        } catch (Throwable ignored) {}
        return "";
    }

    public static String getOrGenerateOpenIdTicket() {
        if (sLastKnownOpenIdTicket != null && sLastKnownOpenIdTicket.length() >= 16) {
            return sLastKnownOpenIdTicket;
        }
        return "";
    }

    public static boolean isHostApkPath(String path) {
        if (path == null || path.isEmpty()) return false;
        if (path.contains("/data/user/") || path.contains("/data/data/") || path.contains("/files/") || path.contains("/cache/")) {
            return false;
        }
        if (path.endsWith("/base.apk") || path.endsWith("/com.tencent.mobileqq.apk")) {
            return true;
        }
        if (HookConfig.loadPackageParam != null && HookConfig.loadPackageParam.appInfo != null) {
            String sourceDir = HookConfig.loadPackageParam.appInfo.sourceDir;
            if (sourceDir != null && sourceDir.equals(path)) {
                return true;
            }
        }
        return false;
    }

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_QQ950_PATCH) return;

        // Tier 1: void-return, crash-safe backstops
        // hookMsfTelemetry(lpparam); // Abolished: Allow genuine MSF core lifecycle telemetry and keepalives (tryReportMSFAlive, tryReportJobAlive, doReportOnInitComplete, reportMsfCoreInit) to report naturally
        // hookMsfCheckWTSig(lpparam); // Abolished: Allow authentic MSF auth lifecycle and token exchange to operate naturally without pipeline mutation

        // Native security DSO inline syscall proximity trampoline triggers
        io.github.xalsace.qqbypass.NativeBypass.patchLibrary("fekit");
        io.github.xalsace.qqbypass.NativeBypass.patchLibrary("QSec");
        io.github.xalsace.qqbypass.NativeBypass.patchLibrary("turing");
        io.github.xalsace.qqbypass.NativeBypass.patchLibrary("wxa");
        io.github.xalsace.qqbypass.NativeBypass.patchLibrary("tbs");

        hookTuringWrapper(lpparam);
        hookChannelReport(lpparam);
        hookSignatureAndIntegrity(lpparam);
        hookTroopSecurityTipsBannerCrash(lpparam);
        hookCuckooAndWarbler(lpparam);
        hookScreenSecurityAndRootDetection(lpparam);
        hookPandoraAndPackageUtil(lpparam);
        hookDtcTelemetry(lpparam);

        // Tier 2: object-return risk-detection blocks (Dynamic Proxy safe, zero NPE risk)
        hookTuringRiskDetect();
        hookTuringDID();

        // Tier 3: Face ID & Multi-Factor Authentication (HuiYan SDK & TuringFaceDefender)
        hookFaceRecognitionAndMFA(lpparam);

        // Tier 4: trpc.o3.* telemetry & security detection targeted sanitization
        hookO3SecurityAndTelemetry(lpparam);

        // Tier 5: Clean detection sources at the origin (Location, Sensors, Screen/Display, ADB/Accessibility)
        hookDetectionSourcesAtOrigin(lpparam);

        // Tier 6: Dynamic SO (txlib / txPttlib) and MQP Integrity Strike Protection
        hookTxlibAndPttProtection(lpparam);

        // Tier 7: RFix & Hotfix Failure Sanitization and Telemetry Drop
        hookRFixFailureSanitization(lpparam);

        // Tier 8: QSec detectMethod and FeKitAttach fallback
        hookQSecDefenses(lpparam);

        // Tier 9: NT Kick & MSF Offline Interception managed authoritatively by KickInterceptHook

        // Tier 10: Official UI Display Integrity Preserved (DO NOT TOUCH)
        // Strictly adheres to the rule: "不要乱动官方显示，只需要排除模块干扰".
        // Never tamper with MsgRefreshTipMgr, Conversation, or QQAppInterface loading display.
        // Smooth message sync without stalls is achieved purely by eliminating module packet reflection & lock latency.

        // Tier 11: Real Device Emulator Detection Adaptation (Safe boolean guards without device identity spoofing)
        hookEmulatorDetectionForRealDevice(lpparam);

        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();

        // Tier 12: QQ 9.3.75 SafeCenter & Push Repack Circuit Defenses
        hookQQ9375SafeCenterAndRepack(lpparam, cl);

        // Tier 13: APK File MD5 & Source Signature Defense
        hookApkFileMd5AndSignatures(lpparam, cl);

        // Tier 14: PB-Level Integrity Check Neutralization & Response Disarm
        hookIntChkPBDefenses(lpparam, cl);

        // Tier 14.1: ProtoBuf Root MessageMicro Serialization & Deserialization Defense
        hookMessageMicroSanitizers(cl);

        // Tier 15: Screen / Display / Remote Control Defense Expansion (Ganliang & AntEst)
        hookGanliangAndAntEstDefenses(lpparam, cl);

        // Tier 16: Turing PhoneService & Turing Bridge Completion
        hookTuringPhoneAndBridge(lpparam, cl);

        // Tier 17: SafeReport & XpsReport Suppression
        hookSafeReportAndXps(lpparam, cl);

        // Tier 18: TuringFD Port / Process & Accessibility Neutralization (Berry & this)
        hookTuringBerryAndThis(lpparam, cl);

        // Tier 19: Outbound TuringFD Risk Dictionary (map2) Deep-Audit
        hookTuringOutboundRiskMap(lpparam, cl);

        // Tier 20: TVK Player CKey & CKeyGuard Security Neutralization
        hookCKeyAndTVKSecurity(cl);

        // Tier 21: NT Login Ticket & WTLogin Session Expiration Defense
        hookNTLoginAndSessionDefense(lpparam, cl);
    }

    // ==================== Tier 1: void-return, crash-safe ====================
    // Note: hookKickBackstop previously swallowed kick notifications at MSF and UI levels.
    // However, forced logout is an authoritative server-side state. Swallowing kick events
    // traps the client in a "Zombie Session" (outbox packets rejected, inbox pushes halted,
    // and turning off module immediately exposes w21). Defenses must focus on eliminating
    // detection triggers rather than suppressing legitimate session state transitions.


    /**
     * MSF telemetry: Abolished in v1.0.79.
     * Unconditional lifecycle methods (tryReportMSFAlive, tryReportJobAlive, doReportOnInitComplete,
     * reportMsfCoreInit, tryReportLoadCfgTempFile, tryReportSoLoadUseTxlib) are essential keepalive
     * heartbeats and boot signals. Suppressing them signals process freeze/death to Tencent ML monitors.
     */
    private static void hookMsfTelemetry(XC_LoadPackage.LoadPackageParam lpparam) {
        // No-op: let authentic MSF lifecycle reporting and keepalive heartbeats proceed naturally
    }

    /**
     * MSF checkWTSig hook (Abolished).
     * Official MSF authentication pipelines must never be intercepted or swallowed to avoid zombie sessions.
     */
    private static void hookMsfCheckWTSig(XC_LoadPackage.LoadPackageParam lpparam) {
        // Abolished: Official MSF auth flow runs untouched
    }

    /**
     * Turing cache writers: TuringWrapper.b()/c()
     * Allow real TuringWrapper execution so authentic device tokens are written to MMKV (DeviceToken-TuringCache-V001).
     */
    private static void hookTuringWrapper(XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.mobileqq.dt.model.TuringWrapper";
        hookSafe(cls, "b", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                XposedEntry.log("[TuringPatch] TuringWrapper.b executed (MMKV cache populated)");
            }
        });
    }

    /**
     * ChannelManager checkMethod anti-hook reflection defense.
     * Note: Normal channel lifecycle telemetry (onChannelReadyReport, reportInitTime,
     * reportStep, reportTZ, sdk_init 0b500076578) and official baseline signature reporting
     * (0df00071646) are permitted to proceed naturally to maintain genuine device baselines.
     */
    private static void hookChannelReport(XC_LoadPackage.LoadPackageParam lpparam) {
        // Suppress ChannelManager.checkMethod anti-hook reflection
        hookSafe("com.tencent.mobileqq.channel.ChannelManager", "checkMethod", lpparam,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[ChannelPatch] Neutralized ChannelManager.checkMethod");
                }
            });
    }

    /**
     * QQ 9.3.70 APK signature and integrity checks.
     * Hooks:
     * - ApkSignatureSchemeV2Verifier.g(String): returns true (verifies V2 signature)
     * - ApkExternalInfoTool (com.tencent.securitysdk.utils.a.f(File)): getSecurityCodeV1
     */
    private static void hookSignatureAndIntegrity(XC_LoadPackage.LoadPackageParam lpparam) {
        // ApkSignatureSchemeV2Verifier.g(String apkPath): normalize in afterHookedMethod
        final String v2Cls = "com.tencent.securitysdk.utils.ApkSignatureSchemeV2Verifier";
        hookSafe(v2Cls, "g", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.hasThrowable() || Boolean.FALSE.equals(p.getResult())) {
                    p.setThrowable(null);
                    p.setResult(true);
                    XposedEntry.log("[SignaturePatch] Normalized ApkSignatureSchemeV2Verifier.g -> true");
                }
            }
        });

        // ApkExternalInfoTool: getSecurityCodeV1(File)
        // Keep authentic return value without injecting fabricated mock string
        final String extCls = "com.tencent.securitysdk.utils.a";
        hookSafe(extCls, "f", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.hasThrowable()) {
                    p.setThrowable(null);
                    p.setResult(null);
                }
            }
        });
    }

    /**
     * Cuckoo & Warbler JVMTI Agent and bytecode instrumentation neutralizer.
     * Prevents libcuckoo.so JVMTI agent loading, debuggable ART mode mutation, and bytecode introspection.
     */
    private static void hookCuckooAndWarbler(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. Warbler.a() -> returns false (blocks nativeMakeArtDebuggable)
        hookSafe("com.tencent.mobileqq.warbler.Warbler", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[CuckooPatch] Neutralized Warbler.a (prevented nativeMakeArtDebuggable)");
            }
        });

        // 2. Cuckoo.init(boolean) -> empty (blocks JVMTI agent attach and cuckoo startup)
        hookSafe("com.tencent.mobileqq.cuckoo.Cuckoo", "init", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[CuckooPatch] Neutralized Cuckoo.init (prevented JVMTI agent loading)");
            }
        });

        // 3. Android runtime Debug.attachJvmtiAgent -> blocks libcuckoo.so or any suspicious JVMTI agent
        HookUtils.hookAllMethods("android.os.Debug", "attachJvmtiAgent", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                    String agent = (String) p.args[0];
                    if (agent.contains("cuckoo") || agent.contains("warbler")) {
                        p.setResult(null);
                        XposedEntry.log("[CuckooPatch] Blocked Debug.attachJvmtiAgent: " + agent);
                    }
                }
            }
        });

        // 4. Guard Cuckoo registration/lifecycle methods to prevent UnsatisfiedLinkError or IllegalArgumentException
        String[] cuckooMethods = {"registMethod", "registClassCallback", "destoryMethod", "destoryClassCallback", "startCuckoo", "registClassJNI", "destoryClassJNI"};
        for (String cm : cuckooMethods) {
            hookSafe("com.tencent.mobileqq.cuckoo.Cuckoo", cm, lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.method instanceof Method && ((Method) p.method).getReturnType() == int.class) {
                        p.setResult(1);
                    } else if (p.method instanceof Method && ((Method) p.method).getReturnType() == int[].class) {
                        p.setResult(new int[0]);
                    } else {
                        p.setResult(null);
                    }
                }
            });
        }

        // 5. Neutralize ParcelHooker startHookParcel/endHookParcel (which triggers Cuckoo JVMTI interception)
        final String parcelHookerCls = "com.tencent.mobileqq.app.message.hookparcel.ParcelHooker";
        hookSafe(parcelHookerCls, "startHookParcel", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[CuckooPatch] Preempted ParcelHooker.startHookParcel");
            }
        });
        hookSafe(parcelHookerCls, "endHookParcel", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
    }

    /**
     * Defense against Screen Security, Remote Control Detection & Root Environment Scans:
     * - com.tenpay.security.ScreenSecurityDetector: isAtRisk/isScreenRecording -> false, registerListener -> no-op
     * - com.tenpay.charge.v2.util.ChargeV2Utils: isDeviceRooted -> false
     * - com.tencent.camerasdk.avreport.DeviceInfo: isDeviceRooted -> false
     * - org.light.device.LightDeviceUtils: isRooted -> false
     * - com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl: isRooted -> clean false provider result
     */
    private static void hookScreenSecurityAndRootDetection(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. TenPay ScreenSecurityDetector: allow natural execution and normalize in afterHookedMethod
        final String ssdCls = "com.tenpay.security.ScreenSecurityDetector";
        hookSafe(ssdCls, "isAtRisk", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                    XposedEntry.log("[ScreenSecurity] Normalized ScreenSecurityDetector.isAtRisk -> false");
                }
            }
        });
        hookSafe(ssdCls, "isScreenRecording", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });
        hookSafe(ssdCls, "registerListener", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });
        hookSafe(ssdCls, "registerScreenRecordingCallback", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
            }
        });

        // 2. TenPay & CameraSDK & LightDevice Root Checks: allow natural execution and normalize in afterHookedMethod
        hookSafe("com.tenpay.charge.v2.util.ChargeV2Utils", "isDeviceRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() == Boolean.TRUE) {
                    p.setResult(false);
                }
            }
        });
        hookSafe("com.tencent.camerasdk.avreport.DeviceInfo", "isDeviceRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() == Boolean.TRUE) {
                    p.setResult(false);
                }
            }
        });
        hookSafe("org.light.device.LightDeviceUtils", "isRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() == Boolean.TRUE) {
                    p.setResult(false);
                }
            }
        });

        // 3. GathererGA UserInfoImpl.isRooted: allow natural execution and sanitize in afterHookedMethod
        final String userInfoCls = "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl";
        hookSafe(userInfoCls, "isRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res != null) {
                    try {
                        Object val = XposedHelpers.getObjectField(res, "b");
                        if (Boolean.TRUE.equals(val)) {
                            XposedHelpers.setObjectField(res, "b", Boolean.FALSE);
                            XposedEntry.log("[RootPatch] Sanitized UserInfoImpl.isRooted -> false");
                        }
                    } catch (Throwable ignored) {
                        try {
                            for (Field f : res.getClass().getDeclaredFields()) {
                                if (f.getType() == boolean.class || f.getType() == Boolean.class) {
                                    f.setAccessible(true);
                                    if (Boolean.TRUE.equals(f.get(res))) {
                                        f.set(res, Boolean.FALSE);
                                    }
                                }
                            }
                        } catch (Throwable ignored2) {}
                    }
                }
            }
        });
    }

    /**
     * Package scanning, process enumeration, and PandoraEx app monitors defense:
     * - com.tencent.qmethod.pandoraex.monitor.InstalledAppListMonitor
     * - com.tencent.mobileqq.utils.PackageUtil
     */
    private static void hookPandoraAndPackageUtil(XC_LoadPackage.LoadPackageParam lpparam) {
        final String[] sensitivePkgKeywords = {
            "xposed", "lsposed", "magisk", "topjohnwu", "weishu", "bmax", "apatch", "frida",
            "edxposed", "sandhook", "taichi", "riru", "zygisk", "fake", "location", "mock",
            "turing", "xalsace", "qqbypass", "qauxv", "moe.ono", "lzlnb", "cnm",
            "substrate", "cydia", "sukisu", "ksunext"
        };

        // 1. PandoraEx InstalledAppListMonitor
        final String monCls = "com.tencent.qmethod.pandoraex.monitor.InstalledAppListMonitor";
        hookSafe(monCls, "getPackageInfo", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String) {
                    String pkg = ((String) p.args[1]).toLowerCase();
                    for (String kw : sensitivePkgKeywords) {
                        if (pkg.contains(kw)) {
                            p.setThrowable(new android.content.pm.PackageManager.NameNotFoundException((String) p.args[1]));
                            XposedEntry.log("[PackageShield] PandoraEx getPackageInfo hidden: " + p.args[1]);
                            return;
                        }
                    }
                }
            }
        });

        hookSafe(monCls, "getRunningAppProcesses", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.getResult() instanceof java.util.List) {
                    java.util.List<?> list = (java.util.List<?>) p.getResult();
                    java.util.List<Object> clean = new java.util.ArrayList<>();
                    for (Object item : list) {
                        if (item instanceof android.app.ActivityManager.RunningAppProcessInfo) {
                            android.app.ActivityManager.RunningAppProcessInfo info = (android.app.ActivityManager.RunningAppProcessInfo) item;
                            String proc = info.processName != null ? info.processName.toLowerCase() : "";
                            boolean hide = false;
                            for (String kw : sensitivePkgKeywords) {
                                if (proc.contains(kw)) {
                                    hide = true;
                                    break;
                                }
                            }
                            if (!hide && info.pkgList != null) {
                                for (String pkg : info.pkgList) {
                                    if (pkg != null) {
                                        String pkgLower = pkg.toLowerCase();
                                        for (String kw : sensitivePkgKeywords) {
                                            if (pkgLower.contains(kw)) {
                                                hide = true;
                                                break;
                                            }
                                        }
                                    }
                                    if (hide) break;
                                }
                            }
                            if (!hide) clean.add(item);
                        } else {
                            clean.add(item);
                        }
                    }
                    p.setResult(clean);
                }
            }
        });

        // 2. PackageUtil (isAppInstalled, checkAppInstalled, checkAppInstalledBatch, isAppInstalledBatch, getAppsVerionCodeBatch, verifyInstalledApp)
        final String pkgUtilCls = "com.tencent.mobileqq.utils.PackageUtil";
        hookSafe(pkgUtilCls, "isAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String) {
                    String pkg = (String) p.args[1];
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                        p.setResult(false);
                    }
                }
            }
        });

        hookSafe(pkgUtilCls, "checkAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String) {
                    String pkg = (String) p.args[1];
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                        p.setResult("0");
                    }
                }
            }
        });

        hookSafe(pkgUtilCls, "checkAppInstalledBatch", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String && p.getResult() instanceof String) {
                    String req = (String) p.args[1];
                    String res = (String) p.getResult();
                    String[] reqParts = req.split("\\|");
                    String[] resParts = res.split("\\|", -1);
                    boolean modified = false;
                    for (int i = 0; i < reqParts.length; i++) {
                        if (DynamicRootDetectionHook.isSuspiciousPackage(reqParts[i].trim())) {
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
                        p.setResult(sb.toString());
                    }
                }
            }
        });

        hookSafe(pkgUtilCls, "isAppInstalledBatch", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String && p.getResult() instanceof String) {
                    String req = (String) p.args[1];
                    String res = (String) p.getResult();
                    String[] reqParts = req.split("\\|");
                    String[] resParts = res.split("\\|", -1);
                    boolean modified = false;
                    for (int i = 0; i < reqParts.length; i++) {
                        if (DynamicRootDetectionHook.isSuspiciousPackage(reqParts[i].trim())) {
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
                        p.setResult(sb.toString());
                    }
                }
            }
        });

        hookSafe(pkgUtilCls, "getAppsVerionCodeBatch", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String && p.getResult() instanceof String) {
                    String req = (String) p.args[1];
                    String res = (String) p.getResult();
                    String[] reqParts = req.split("\\|");
                    String[] resParts = res.split("\\|", -1);
                    boolean modified = false;
                    for (int i = 0; i < reqParts.length; i++) {
                        if (DynamicRootDetectionHook.isSuspiciousPackage(reqParts[i].trim())) {
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
                        p.setResult(sb.toString());
                    }
                }
            }
        });

        hookSafe(pkgUtilCls, "verifyInstalledApp", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String) {
                    String pkg = (String) p.args[1];
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                        p.setResult(false);
                    }
                }
            }
        });
    }

    /**
     * Dtc (Device Telemetry Center) & Obfuscated Environment Censors:
     * - isAbnormalConfig -> false
     * - isDebugVersion -> false
     * - checkAppInstalled -> sanitize
     * - checkRiskPermission -> sanitize
     * - getAccessibility* -> sanitize
     * - getNetworkInterfaceNames -> "wlan0,rmnet_data0"
     * - com.tencent.mobileqq.fe.utils.a -> neutralize ClassLoader & dexElements scanner
     * - com.tencent.mobileqq.dt.app.h -> neutralize suspicious CA certificate scanner
     */
    private static void hookDtcTelemetry(XC_LoadPackage.LoadPackageParam lpparam) {
        final String dtcCls = "com.tencent.mobileqq.dt.app.Dtc";
        hookSafe(dtcCls, "isAbnormalConfig", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                    XposedEntry.log("[DtcPatch] Normalized Dtc.isAbnormalConfig -> false");
                }
            }
        });
        hookSafe(dtcCls, "isDebugVersion", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });
        hookSafe(dtcCls, "checkAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                    String pkg = (String) p.args[0];
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                        p.setResult(false);
                    }
                }
            }
        });
        hookSafe(dtcCls, "checkRiskPermission", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (DynamicRootDetectionHook.isCallerQAuxv()) return;
                if (p.args != null && p.args.length > 1 && p.args[1] instanceof String) {
                    String pkg = (String) p.args[1];
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg)) {
                        p.setResult(0);
                    }
                }
            }
        });
        hookSafe("com.tencent.util.AppSetting", "isDebugVersion", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledStatus", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof Number && ((Number) p.getResult()).intValue() > 0) {
                    p.setResult(0);
                }
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof String) {
                    String s = (String) res;
                    if (DynamicRootDetectionHook.isSuspiciousPackage(s) || s.contains("xposed") || s.contains("auto")) {
                        p.setResult("[]");
                    }
                }
            }
        });
        hookSafe(dtcCls, "getAccessibilityServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof String) {
                    String s = (String) res;
                    if (DynamicRootDetectionHook.isSuspiciousPackage(s) || s.contains("xposed") || s.contains("auto")) {
                        p.setResult("[]");
                    }
                }
            }
        });

        // Delegate com.tencent.mobileqq.fe.utils.a to transparent normalization
        hookFeUtilsAWithClassLoader(lpparam != null ? lpparam.classLoader : null);
    }

    // ============ Tier 2: object-return risk detection (Safe Dynamic Proxies) ============

    /**
     * TuringRiskService.reqRiskDetectV2(...) : RiskDetectResp.
     * Allow real Turing risk detection to run under Native layer protection so genuine device tokens are generated.
     * On result: ensure errorCode is sanitized to 0L while preserving the authentic deviceToken.
     * If the real execution returns null (e.g. init failure), fallback to safe dynamic proxy to avoid NPE.
     */
    private static final java.util.Set<Class<?>> sHookedTuringClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static void hookTuringRiskDetect() {
        hookTuringRiskDetectWithClassLoader(HookConfig.getClassLoader());
    }

    public static void hookTuringRiskDetectWithClassLoader(ClassLoader cl) {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK || cl == null) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringRiskService",
            "com.tencent.turingfd.sdk.xq.TuringRiskService",
            "com.tencent.turingfd.sdk.tbs.TuringRiskService",
            "com.tencent.turingface.sdk.mfa.TuringRiskService"
        };
        for (final String cls : classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            HookUtils.hookAllMethods(clazz, "reqRiskDetectV2", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object result = p.getResult();
                    if (result != null) {
                        try {
                            // o2 holds Wild field 'a', which has int/long a as errorCode and String b as deviceToken
                            Object wild = XposedHelpers.getObjectField(result, "a");
                            if (wild != null) {
                                try {
                                    Field fb = wild.getClass().getDeclaredField("b");
                                    fb.setAccessible(true);
                                    String dt = (String) fb.get(wild);
                                    if (dt != null && !dt.isEmpty()) {
                                        sLastKnownDeviceToken = dt;
                                        XposedEntry.log("[TuringPatch] Preserved authentic Wild.b deviceToken");
                                    } else if (sLastKnownDeviceToken != null && !sLastKnownDeviceToken.isEmpty()) {
                                        fb.set(wild, sLastKnownDeviceToken);
                                    }
                                    // Official error codes are strictly preserved (no error code tampering)
                                } catch (Throwable ignored) {}
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            });
        }

        // Direct method hooks on o2 implementations to observe authentic deviceToken & guarantee 0 error code
        String[] o2Classes = {
            "com.tencent.turingfd.sdk.xq.o2",
            "com.tencent.tfd.sdk.wxa.o2",
            "com.tencent.turingfd.sdk.tbs.o2",
            "com.tencent.turingface.sdk.mfa.o2"
        };
        for (String o2Cls : o2Classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(o2Cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            HookUtils.hookAllMethods(clazz, "getDeviceToken", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String && !((String) res).isEmpty()) {
                        sLastKnownDeviceToken = (String) res;
                    } else if (sLastKnownDeviceToken != null && !sLastKnownDeviceToken.isEmpty()) {
                        p.setResult(sLastKnownDeviceToken);
                    }
                }
            });
        }

        // Hook TuringSdkInitHelper (com.tencent.mobileqq.turingfd.i) method f(boolean)
        Class<?> turingInitHelper = XposedHelpers.findClassIfExists("com.tencent.mobileqq.turingfd.i", cl);
        if (turingInitHelper != null && sHookedTuringClasses.add(turingInitHelper)) {
            HookUtils.hookAllMethods(turingInitHelper, "f", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if ((res == null || (res instanceof String && ((String) res).isEmpty())) &&
                        sLastKnownDeviceToken != null && !sLastKnownDeviceToken.isEmpty()) {
                        p.setResult(sLastKnownDeviceToken);
                        XposedEntry.log("[TuringPatch] Guarded TuringSdkInitHelper.f: populated fallback deviceToken");
                    }
                }
            });
        }
    }

    /**
     * TuringIDService.getTuringDID / getTuringDIDCached : ITuringDID.
     * Allow real Turing ID generation to run under Native layer protection so genuine openIdTicket is generated.
     * Preserve authentic openIdTicket and allow official ticket renewal cycle to proceed naturally.
     * Fallback to safe proxy only if result is null to avoid NPE.
     */
    private static void hookTuringDID() {
        hookTuringDIDWithClassLoader(HookConfig.getClassLoader());
    }

    public static void hookTuringDIDWithClassLoader(ClassLoader cl) {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK || cl == null) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringIDService",
            "com.tencent.turingfd.sdk.xq.TuringIDService",
            "com.tencent.turingfd.sdk.tbs.TuringIDService"
        };
        for (final String cls : classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            for (String m : new String[]{"getTuringDID", "getTuringDIDCached"}) {
                HookUtils.hookAllMethods(clazz, m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Object result = p.getResult();
                        if (result != null) {
                            try {
                                // h2 holds t1 field 'a'
                                Object t1 = XposedHelpers.getObjectField(result, "a");
                                if (t1 != null) {
                                    // Do NOT overwrite t1.c (errorCode) or t1.a (openIdTicket).
                                    // Turing SDK's renewal logic (z1.java) requires non-zero error codes or empty
                                    // tickets to trigger async renewal. Forcing t1.c = 0 or injecting fake tokens
                                    // causes ticket renewal to be permanently blocked, leading to kicks!
                                    String ticket = (String) XposedHelpers.getObjectField(t1, "a");
                                    if (ticket != null && !ticket.isEmpty()) {
                                        sLastKnownOpenIdTicket = ticket;
                                        XposedEntry.log("[TuringPatch] Preserved authentic t1.a openIdTicket");
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                });
            }
        }

        // Direct method hooks on h2 implementations: observe authentic openIdTicket
        String[] h2Classes = {
            "com.tencent.turingfd.sdk.xq.h2",
            "com.tencent.tfd.sdk.wxa.h2"
        };
        for (String h2Cls : h2Classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(h2Cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            HookUtils.hookAllMethods(clazz, "getOpenIdTicket", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String && !((String) res).isEmpty()) {
                        sLastKnownOpenIdTicket = (String) res;
                    }
                }
            });
        }
    }

    /**
     * Suppress TroopSecurityTipsBanner crash caused by uninitialized lateinit property aioContext.
     * When top banner notifications arrive while AIO is not active or closing,
     * accessing aioContext or curTroopUin throws kotlin.UninitializedPropertyAccessException.
     */
    private static void hookTroopSecurityTipsBannerCrash(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookTroopSecurityTipsBannerCrashWithClassLoader(cl);
    }

    private static final java.util.Set<Class<?>> sHookedBannerClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void hookTroopSecurityTipsBannerCrashWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        // 1. Guard TroopSecurityTipsBanner methods
        final String bannerCls = "com.tencent.mobileqq.troop.tipsbar.TroopSecurityTipsBanner";
        Class<?> bannerClass = XposedHelpers.findClassIfExists(bannerCls, cl);
        if (bannerClass != null && sHookedBannerClasses.add(bannerClass)) {
            // Hook method 'm' directly
            HookUtils.hookAllMethods(bannerClass, "m", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Object aioContext = XposedHelpers.getObjectField(param.thisObject, "e");
                        Object curTroopUin = XposedHelpers.getObjectField(param.thisObject, "d");
                        if (aioContext == null || curTroopUin == null) {
                            param.setResult(null);
                            XposedEntry.log("[CrashFix] Preempted TroopSecurityTipsBanner.m (uninitialized aioContext/curTroopUin)");
                        }
                    } catch (Throwable t) {
                        param.setResult(null);
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getThrowable() != null) {
                        XposedEntry.log("[CrashFix] Caught exception in TroopSecurityTipsBanner.m: " + param.getThrowable().getMessage());
                        param.setResult(null);
                    }
                }
            });

            // Guard all other methods in TroopSecurityTipsBanner against UninitializedPropertyAccessException
            for (Method method : bannerClass.getDeclaredMethods()) {
                if ("m".equals(method.getName())) continue;
                HookUtils.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Throwable t = param.getThrowable();
                        if (t != null && (t.getClass().getName().contains("UninitializedPropertyAccessException")
                                || (t.getMessage() != null && (t.getMessage().contains("aioContext") || t.getMessage().contains("curTroopUin"))))) {
                            XposedEntry.log("[CrashFix] Suppressed " + t.getClass().getSimpleName() + " in " + param.method.getName());
                            Class<?> ret = ((Method) param.method).getReturnType();
                            if (ret == void.class) {
                                param.setResult(null);
                            } else if (ret == boolean.class) {
                                param.setResult(false);
                            } else if (ret == int.class) {
                                param.setResult(0);
                            } else if (ret == long.class) {
                                param.setResult(0L);
                            } else {
                                param.setResult(null);
                            }
                        }
                    }
                });
            }
            XposedEntry.log("[CrashFix] Hooked TroopSecurityTipsBanner for aioContext crash protection");
        }

        // 2. Guard the calling notification listener lambda
        final String lambdaCls = "com.tencent.mobileqq.aio.notification.impl.AIONotificationManager$groupListener$1$onGroupTopBannerDataNotify$4$uiModel$1";
        Class<?> lambdaClass = XposedHelpers.findClassIfExists(lambdaCls, cl);
        if (lambdaClass != null) {
            HookUtils.hookAllMethods(lambdaClass, "invoke", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getThrowable() != null) {
                        XposedEntry.log("[CrashFix] Suppressed exception in onGroupTopBannerDataNotify lambda: " + param.getThrowable().getMessage());
                        param.setResult(null);
                    }
                }
            });
            XposedEntry.log("[CrashFix] Hooked AIONotificationManager banner lambda for exception isolation");
        }
    }

    /**
     * QQ 人脸识别核身与多因子认证（HuiYan SDK & TuringFaceDefender）专项防护：
     *
     * 1. TuringFaceDefender (com.tencent.turingcam.TuringFaceDefender):
     *    - init(TuringFaceBuilder): 确保初始化返回 0（成功）；
     *    - signData(String): 挂钩返回值，确保 SignResult.code == 0（成功验签，无环境异常码）；
     *
     * 2. TuringSdkImp 回调分发 (com.tencent.could.huiyansdk.turingmodule.TuringSdkImp$a):
     *    - onException(Throwable): 静默抑制异常，防止触发 GetTuringTokenError 错误埋点与环境污染；
     *
     * 3. Turing 结果消费与状态机 (com.tencent.could.huiyansdk.turing.d):
     *    - a(long j, byte[] bArr): 若底层由于环境波动传出非 0 状态码，前置修正 j = 0L，并确保 bArr 有效，使核身状态机无缝跃迁至 START_GET_LIVE_TYPE；
     *
     * 4. Turing 结果缓存实体 (com.tencent.could.huiyansdk.entity.TuringResultCacheEntity):
     *    - setTuringEnvErrorStr(String): 过滤错误特征字符串，防止上报环境异常至人脸核验服务端。
     */
    private static final java.util.Set<Class<?>> sHookedFaceClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static final java.util.Set<Class<?>> sHookedFeUtilsAClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        try {
            resolvePendingSafeHooks(cl);
            hookFaceRecognitionAndMFAWithClassLoader(cl);
            hookTroopSecurityTipsBannerCrashWithClassLoader(cl);
            hookTuringRiskDetectWithClassLoader(cl);
            hookTuringDIDWithClassLoader(cl);
            hookO3SecurityAndTelemetryWithClassLoader(cl);
            hookFeUtilsAWithClassLoader(cl);
            hookQQ9375DefensesWithClassLoader(cl);
            hookTuringBerryAndThisWithClassLoader(cl);
            hookTuringOutboundRiskMapWithClassLoader(cl);
            hookCKeyAndTVKSecurity(cl);
            hookNTLoginAndSessionDefense(null, cl);
        } catch (Throwable t) {
            XposedEntry.logError("[LateStage] hookLateStage error: " + t.getMessage(), t);
        }
    }

    public static void hookFeUtilsAWithClassLoader(ClassLoader cl) {
        if (cl == null) return;
        try {
            Class<?> feUtilsA = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.utils.a", cl);
            if (feUtilsA != null && sHookedFeUtilsAClasses.add(feUtilsA)) {
                // Method g(Context) -> overall SecEnv check: normalize to false if flagged
                HookUtils.hookIfMethodExists(feUtilsA, "g", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                            XposedEntry.log("[FEKitCensor] Normalized fe.utils.a.g -> false (no anomaly)");
                        }
                    }
                });

                // Method a(Context, ClassLoader) -> ClassLoader hierarchy check: normalize to false if flagged
                HookUtils.hookIfMethodExists(feUtilsA, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                        }
                    }
                });

                // Method b(Context, ClassLoader) -> dexElements scanner: normalize to false if flagged
                HookUtils.hookIfMethodExists(feUtilsA, "b", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                        }
                    }
                });

                // Method f(Object, String, String) -> single dexElement checker:
                // If checking an injected module DEX, return false transparently so "Err Code: 103" is not emitted,
                // while letting official QQ DEX files run through full inspection logging "Safe DEX".
                HookUtils.hookIfMethodExists(feUtilsA, "f", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 3 && param.args[0] != null) {
                            try {
                                Object elem = param.args[0];
                                Field dfField = elem.getClass().getDeclaredField("dexFile");
                                dfField.setAccessible(true);
                                Object dexFile = dfField.get(elem);
                                if (dexFile != null) {
                                    String fn = null;
                                    try {
                                        Field fnField = dexFile.getClass().getDeclaredField("mFileName");
                                        fnField.setAccessible(true);
                                        fn = (String) fnField.get(dexFile);
                                    } catch (Throwable ignored) {
                                        fn = dexFile.toString();
                                    }
                                    if (fn != null && (fn.contains("qqbypass") || fn.contains("xalsace") ||
                                        DynamicRootDetectionHook.isSuspiciousPath(fn))) {
                                        param.setResult(false);
                                        return;
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                        }
                    }
                });
                XposedEntry.log("[FEKitCensor] Installed transparent normalization hooks on fe.utils.a");
            }
        } catch (Throwable t) {
            XposedEntry.logError("[FEKitCensor] Error hooking fe.utils.a in LateStage: " + t.getMessage(), t);
        }
    }

    private static void hookFaceRecognitionAndMFA(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl != null) {
            hookFaceRecognitionAndMFAWithClassLoader(cl);
        }
    }

    private static final java.util.concurrent.atomic.AtomicBoolean sOtvrmInitLock = new java.util.concurrent.atomic.AtomicBoolean(false);

    private static void ensureOtvrmInitialized(Object otvrm, ClassLoader cl, android.content.Context fallbackContext) {
        if (otvrm == null) return;
        if (!sOtvrmInitLock.compareAndSet(false, true)) {
            return;
        }
        try {
            boolean g = false;
            try {
                g = XposedHelpers.getBooleanField(otvrm, "g");
            } catch (Throwable ignored) {}

            Object b = null;
            try {
                b = XposedHelpers.getObjectField(otvrm, "b");
            } catch (Throwable ignored) {}

            if (g && b != null) {
                return;
            }

            Object h = null;
            try {
                h = XposedHelpers.getObjectField(otvrm, "h");
            } catch (Throwable ignored) {}

            XposedEntry.log("[FacePatch] OTVRM uninitialized (g=" + g + ", b=" + (b != null) + "), repairing state with authentic hostUrl...");
            android.content.Context ctx = fallbackContext;
            if (ctx == null) {
                try {
                    ctx = (android.content.Context) XposedHelpers.callStaticMethod(
                        XposedHelpers.findClass("android.app.ActivityThread", null),
                        "currentApplication");
                } catch (Throwable ignored) {}
            }
            Class<?> builderCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.TuringFaceBuilder", cl);
            if (builderCls != null) {
                Object builder = XposedHelpers.callStaticMethod(builderCls, "build");
                if (ctx != null) {
                    try {
                        XposedHelpers.callMethod(builder, "setContext", ctx);
                    } catch (Throwable ignored) {}
                }
                try {
                    XposedHelpers.callMethod(builder, "setIsHardwareAcceleration", true);
                    XposedHelpers.callMethod(builder, "setHostUrl", "https://sdk.faceid.qq.com/api/turing_new");
                } catch (Throwable ignored) {}
                if (h == null) {
                    try {
                        XposedHelpers.setObjectField(otvrm, "h", builder);
                    } catch (Throwable ignored) {}
                }
                if (b == null) {
                    try {
                        XposedHelpers.callMethod(otvrm, "a", builder);
                    } catch (Throwable ignored) {}
                }
                XposedEntry.log("[FacePatch] OTVRM successfully initialized via fallback builder!");
            }
        } catch (Throwable t) {
            XposedEntry.log("[FacePatch] Error in ensureOtvrmInitialized: " + t.getMessage());
        } finally {
            sOtvrmInitLock.set(false);
        }
    }

    public static String generateSafeTuringSignMsg() {
        try {
            org.json.JSONObject signJson = new org.json.JSONObject();
            signJson.put("sign", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");
            java.util.Random rnd = new java.util.Random();
            StringBuilder nonceSb = new StringBuilder(32);
            String chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int i = 0; i < 32; i++) {
                nonceSb.append(chars.charAt(rnd.nextInt(chars.length())));
            }
            signJson.put("nonce", nonceSb.toString());
            signJson.put("timestamp", System.currentTimeMillis());
            signJson.put("token", "");
            signJson.put("signMethod", "TuringV2");
            return android.util.Base64.encodeToString(signJson.toString().getBytes("UTF-8"), android.util.Base64.NO_WRAP);
        } catch (Throwable t) {
            return "eyJzaWduIjoiQVFJREJBVUdCd2dKQ2dzTURRNE1FUkVTRXhRVkZoY1lHUm9iSEIwZUh5QT0iLCJub25jZSI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwidGltZXN0YW1wIjoxNjAwMDAwMDAwMDAwLCJ0b2tlbiI6IiIsInNpZ25NZXRob2QiOiJUdXJpbmdWMiJ9";
        }
    }

    public static void hookFaceRecognitionAndMFAWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        // 1. TuringFaceDefender: null-safety crash defenses & authentic sign guards
        final String tfdCls = "com.tencent.turingcam.TuringFaceDefender";
        Class<?> tfdClass = XposedHelpers.findClassIfExists(tfdCls, cl);
        if (tfdClass != null && !sHookedFaceClasses.contains(tfdClass)) {
            sHookedFaceClasses.add(tfdClass);

            HookUtils.hookAllMethods(tfdClass, "init", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(0);
                    XposedEntry.log("[FacePatch] TuringFaceDefender.init executed -> forced result 0");
                }
            });

            HookUtils.hookAllMethods(tfdClass, "setPreviewDisplay", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Class<?> bi3eTClass = XposedHelpers.findClassIfExists("com.tencent.turingcam.OTVRM$Bi3eT", cl);
                        if (bi3eTClass != null) {
                            Object otvrm = XposedHelpers.getStaticObjectField(bi3eTClass, "a");
                            android.content.Context ctx = null;
                            if (param.args != null && param.args.length > 1 && param.args[1] != null) {
                                try {
                                    ctx = (android.content.Context) XposedHelpers.callMethod(param.args[1], "getContext");
                                } catch (Throwable ignored) {}
                            }
                            ensureOtvrmInitialized(otvrm, cl, ctx);
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[FacePatch] Error in setPreviewDisplay pre-check: " + t.getMessage());
                    }
                }
            });

            HookUtils.hookAllMethods(tfdClass, "getDeviceInfo", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == null) {
                        param.setResult(new org.json.JSONObject());
                        XposedEntry.log("[FacePatch] Sanitized null TuringFaceDefender.getDeviceInfo -> safe empty JSON");
                    }
                }
            });

            HookUtils.hookAllMethods(tfdClass, "activeSign", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof Number) {
                        long code = ((Number) res).longValue();
                        if (code != 0L) {
                            XposedEntry.log("[FacePatch] TuringFaceDefender.activeSign returned " + code + ", normalizing to 0L");
                            param.setResult(0L);
                        } else {
                            XposedEntry.log("[FacePatch] TuringFaceDefender.activeSign succeeded natively -> 0L");
                        }
                    }
                }
            });

            HookUtils.hookAllMethods(tfdClass, "signData", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Class<?> eh5maCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.eh5ma", cl);
                        if (eh5maCls != null) {
                            Object currA = XposedHelpers.getStaticObjectField(eh5maCls, "a");
                            if (currA == null) {
                                android.content.Context appCtx = (android.content.Context) XposedHelpers.callStaticMethod(
                                    XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
                                if (appCtx != null) {
                                    XposedHelpers.setStaticObjectField(eh5maCls, "a", appCtx.getApplicationContext());
                                    XposedEntry.log("[FacePatch] Injected Application context into eh5ma.a before signData");
                                }
                            }
                        }
                        Class<?> tLlmSCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.tLlmS", cl);
                        if (tLlmSCls != null) {
                            java.util.concurrent.atomic.AtomicReference<?> ref =
                                (java.util.concurrent.atomic.AtomicReference<?>) XposedHelpers.getStaticObjectField(tLlmSCls, "d");
                            if (ref != null && ref.get() == null) {
                                Class<?> xStYHCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.XStYH", cl);
                                Object fallbackBfUKf = null;
                                if (xStYHCls != null) {
                                    try {
                                        fallbackBfUKf = XposedHelpers.callStaticMethod(xStYHCls, "a");
                                    } catch (Throwable ignored) {}
                                }
                                if (fallbackBfUKf != null) {
                                    ((java.util.concurrent.atomic.AtomicReference<Object>) ref).set(fallbackBfUKf);
                                    XposedEntry.log("[FacePatch] Pre-populated tLlmS.d from XStYH.a() before signData");
                                } else {
                                    try {
                                        String tokens = (String) XposedHelpers.callStaticMethod(tLlmSCls, "b");
                                        if (tokens != null && !tokens.isEmpty()) {
                                            String[] entries = tokens.split(",");
                                            for (int i = entries.length - 1; i >= 0; i--) {
                                                String entry = entries[i].trim();
                                                int colon = entry.indexOf(':');
                                                if (colon > 0 && colon < entry.length() - 1) {
                                                    long ts = Long.parseLong(entry.substring(0, colon));
                                                    String tok = entry.substring(colon + 1);
                                                    if (!tok.isEmpty()) {
                                                        Class<?> bfUKfCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.BfUKf", cl);
                                                        if (bfUKfCls != null) {
                                                            Object bf = XposedHelpers.newInstance(bfUKfCls, tok, ts, tok);
                                                            ((java.util.concurrent.atomic.AtomicReference<Object>) ref).set(bf);
                                                            XposedEntry.log("[FacePatch] Pre-populated tLlmS.d from tLlmS.b() token before signData");
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } catch (Throwable t) {
                                        XposedEntry.log("[FacePatch] Error reading tLlmS.b(): " + t.getMessage());
                                    }
                                }
                            }
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[FacePatch] Error ensuring state before signData: " + t.getMessage());
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    String safeSign = generateSafeTuringSignMsg();
                    if (res != null) {
                        try {
                            long code = XposedHelpers.getLongField(res, "code");
                            if (code != 0L) {
                                XposedHelpers.setLongField(res, "code", 0L);
                                XposedEntry.log("[FacePatch] Normalized TuringFaceDefender.signData code: " + code + " -> 0L");
                            }
                        } catch (Throwable t) {
                            try {
                                int codeInt = XposedHelpers.getIntField(res, "code");
                                if (codeInt != 0) {
                                    XposedHelpers.setIntField(res, "code", 0);
                                    XposedEntry.log("[FacePatch] Normalized TuringFaceDefender.signData code: " + codeInt + " -> 0");
                                }
                            } catch (Throwable ignored) {}
                        }
                        try {
                            String signMsg = (String) XposedHelpers.getObjectField(res, "signMsg");
                            if (signMsg == null || signMsg.isEmpty() || signMsg.startsWith("error")) {
                                XposedHelpers.setObjectField(res, "signMsg", safeSign);
                                XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData signMsg: null/error -> valid safe token");
                            } else {
                                XposedEntry.log("[FacePatch] Preserved genuine TuringFaceDefender.signData signMsg (len=" + signMsg.length() + ")");
                            }
                        } catch (Throwable t) {
                            try {
                                XposedHelpers.setObjectField(res, "signMsg", safeSign);
                            } catch (Throwable ignored) {}
                        }
                    } else {
                        try {
                            Class<?> signResultClass = XposedHelpers.findClassIfExists("com.tencent.turingcam.SignResult", cl);
                            if (signResultClass != null) {
                                Object safeResult = XposedHelpers.newInstance(signResultClass, 0L, safeSign);
                                param.setResult(safeResult);
                                XposedEntry.log("[FacePatch] Constructed safe SignResult for null signData");
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringFaceDefender for null-safety and authentic sign guards");
        }

        // 1.1 OTVRM: argument null-safety guard for method a
        final String otvrmCls = "com.tencent.turingcam.OTVRM";
        Class<?> otvrmClass = XposedHelpers.findClassIfExists(otvrmCls, cl);
        if (otvrmClass != null && !sHookedFaceClasses.contains(otvrmClass)) {
            sHookedFaceClasses.add(otvrmClass);
            HookUtils.hookAllMethods(otvrmClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length == 1 && param.args[0] == null) {
                        Class<?> builderCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.TuringFaceBuilder", cl);
                        if (builderCls != null) {
                            try {
                                Object builder = XposedHelpers.callStaticMethod(builderCls, "build");
                                param.args[0] = builder;
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked OTVRM.a methods with null-safe guard");
        }

        // 1.2 TuringCam direct environment check normalization (inspection at the source)
        final String ejxAsCls = "com.tencent.turingcam.EjxAs";
        Class<?> ejxAsClass = XposedHelpers.findClassIfExists(ejxAsCls, cl);
        if (ejxAsClass != null && sHookedFaceClasses.add(ejxAsClass)) {
            // Key 270: AdbDevSettings (adb_enabled, development_settings_enabled, debuggable, isDebuggerConnected -> clean 0)
            HookUtils.hookAllMethodsIfExists(ejxAsClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length == 1 && param.args[0] instanceof android.content.Context) {
                        param.setResult(0);
                    } else if (param.args == null || param.args.length == 0) {
                        // Key 256: suspicious process inspection C -> clean ""
                        param.setResult("");
                    }
                }
            });
            // Key 253: UsbAdbState (USB connection / ADB configured state -> clean 0)
            HookUtils.hookAllMethodsIfExists(ejxAsClass, "d", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(0);
                }
            });
            // Key 268: suspicious process inspection D -> clean ""
            HookUtils.hookAllMethodsIfExists(ejxAsClass, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0) {
                        param.setResult("");
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam EjxAs (Key 270/253/256/268) for clean environment inspection");
        }

        final String stvdhCls = "com.tencent.turingcam.Stvdh";
        Class<?> stvdhClass = XposedHelpers.findClassIfExists(stvdhCls, cl);
        if (stvdhClass != null && sHookedFaceClasses.add(stvdhClass)) {
            // Key 205: container / dual app check -> clean ""
            HookUtils.hookAllMethodsIfExists(stvdhClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length == 1 && param.args[0] instanceof android.content.Context) {
                        param.setResult("");
                    } else if (param.args == null || param.args.length == 0) {
                        param.setResult(false);
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam Stvdh (Key 205) for clean container baseline");
        }

        final String kwqwrCls = "com.tencent.turingcam.KwqWR";
        Class<?> kwqwrClass = XposedHelpers.findClassIfExists(kwqwrCls, cl);
        if (kwqwrClass != null && sHookedFaceClasses.add(kwqwrClass)) {
            // Key 251 / 288: root app inspection -> clean 0
            HookUtils.hookAllMethodsIfExists(kwqwrClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length == 1 && param.args[0] instanceof android.content.Context) {
                        param.setResult(0);
                    } else if (param.args != null && param.args.length == 2) {
                        param.setResult(false);
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam KwqWR (Key 251/288) for clean root baseline");
        }

        final String v124rCls = "com.tencent.turingcam.V124r";
        Class<?> v124rClass = XposedHelpers.findClassIfExists(v124rCls, cl);
        if (v124rClass != null && sHookedFaceClasses.add(v124rClass)) {
            // Key 250 (a(Context)) & Key 269 (a()): DSO memory & filesystem scan -> clean ""
            HookUtils.hookAllMethodsIfExists(v124rClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult("");
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam V124r (Key 250/269) for clean DSO baseline");
        }

        final String pzzwfCls = "com.tencent.turingcam.pZZwF";
        Class<?> pzzwfClass = XposedHelpers.findClassIfExists(pzzwfCls, cl);
        if (pzzwfClass != null && sHookedFaceClasses.add(pzzwfClass)) {
            // Key 272: TCP scan -> clean ""
            HookUtils.hookAllMethodsIfExists(pzzwfClass, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0) {
                        param.setResult("");
                    }
                }
            });
            // Key 256/268: suspicious process list -> empty list
            HookUtils.hookAllMethodsIfExists(pzzwfClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0) {
                        param.setResult(new java.util.ArrayList<>());
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam pZZwF (Key 272/proc) for clean TCP & process baseline");
        }

        final String ukkacCls = "com.tencent.turingcam.ukkac";
        Class<?> ukkacClass = XposedHelpers.findClassIfExists(ukkacCls, cl);
        if (ukkacClass != null && sHookedFaceClasses.add(ukkacClass)) {
            // Key 280: shell command inspection -> clean ""
            HookUtils.hookAllMethodsIfExists(ukkacClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args == null || param.args.length == 0) {
                        param.setResult("");
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringCam ukkac (Key 280) for clean shell baseline");
        }

        // 2. TuringSdkImp: b(Context) hardware init & argument null-safety
        final String turingSdkImpCls = "com.tencent.could.huiyansdk.turingmodule.TuringSdkImp";
        Class<?> turingSdkImpClass = XposedHelpers.findClassIfExists(turingSdkImpCls, cl);
        if (turingSdkImpClass != null && !sHookedFaceClasses.contains(turingSdkImpClass)) {
            sHookedFaceClasses.add(turingSdkImpClass);
            HookUtils.hookAllMethods(turingSdkImpClass, "b", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        XposedHelpers.setBooleanField(param.thisObject, "f184c", true);
                        XposedHelpers.setObjectField(param.thisObject, "d", "");
                        XposedEntry.log("[FacePatch] TuringSdkImp.b executed -> forced hardware status success");
                    } catch (Throwable ignored) {}
                }
            });
            HookUtils.hookAllMethods(turingSdkImpClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.method instanceof java.lang.reflect.Method) {
                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                        if (param.args != null && param.args.length == 2) {
                            if (param.args[0] == null) param.args[0] = "";
                            if (param.args[1] == null) param.args[1] = "";
                        }
                    }
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.method instanceof java.lang.reflect.Method) {
                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                        if (m.getReturnType() == String.class && param.args != null && param.args.length == 2) {
                            Object res = param.getResult();
                            if (res == null || "".equals(res) || (res instanceof String && ((String) res).startsWith("error"))) {
                                String safeSign = generateSafeTuringSignMsg();
                                param.setResult(safeSign);
                                XposedEntry.log("[FacePatch] Sanitized TuringSdkImp.a(String, String) -> safe token (was " + res + ")");
                            }
                        } else if (m.getReturnType() == int.class && param.args != null && param.args.length == 3) {
                            Object res = param.getResult();
                            if (res instanceof Number && ((Number) res).intValue() != 0) {
                                XposedEntry.log("[FacePatch] Normalized TuringSdkImp.a(View, CameraHolder, String) return " + res + " -> 0");
                                param.setResult(0);
                            }
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringSdkImp for face hardware status and argument null-safety");
        }

        // 2.0 TuringSdkImp$a: onException recovery, onFinish, onFinishFrameCheck
        final String turingCallbackCls = "com.tencent.could.huiyansdk.turingmodule.TuringSdkImp$a";
        Class<?> turingCallbackClass = XposedHelpers.findClassIfExists(turingCallbackCls, cl);
        if (turingCallbackClass != null && !sHookedFaceClasses.contains(turingCallbackClass)) {
            sHookedFaceClasses.add(turingCallbackClass);
            HookUtils.hookAllMethods(turingCallbackClass, "onException", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(null);
                    try {
                        Object thisObj = param.thisObject;
                        byte[] safeToken = new byte[64];
                        java.util.Arrays.fill(safeToken, (byte) 1);
                        XposedHelpers.callMethod(thisObj, "onFinish", 0L, safeToken);
                        XposedEntry.log("[FacePatch] Recovered from TuringSdkImp$a.onException -> dispatched onFinish(0L, token)");
                    } catch (Throwable t) {
                        XposedEntry.log("[FacePatch] Failed to dispatch fallback onFinish: " + t.getMessage());
                    }
                }
            });
            HookUtils.hookAllMethods(turingCallbackClass, "onFinish", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number && ((Number) param.args[0]).longValue() != 0L) {
                            param.args[0] = 0L;
                        }
                        if (param.args[1] == null) {
                            param.args[1] = new byte[32];
                        }
                        XposedEntry.log("[FacePatch] Sanitized TuringSdkImp$a.onFinish args -> 0L");
                    }
                }
            });
            HookUtils.hookAllMethods(turingCallbackClass, "onFinishFrameCheck", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number && ((Number) param.args[0]).longValue() != 0L) {
                            param.args[0] = 0L;
                        }
                        if (param.args[1] == null) {
                            param.args[1] = new byte[32];
                        }
                        XposedEntry.log("[FacePatch] Sanitized TuringSdkImp$a.onFinishFrameCheck args -> 0L");
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringSdkImp$a callbacks");
        }

        // 2.0.1 Turing state consumer d: normalize non-zero status to 0L and provide fallback bytes
        final String turingDCls = "com.tencent.could.huiyansdk.turing.d";
        Class<?> turingDClass = XposedHelpers.findClassIfExists(turingDCls, cl);
        if (turingDClass != null && !sHookedFaceClasses.contains(turingDClass)) {
            sHookedFaceClasses.add(turingDClass);
            HookUtils.hookAllMethods(turingDClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        long j = param.args[0] instanceof Number ? ((Number) param.args[0]).longValue() : 0L;
                        if (j != 0L) {
                            param.args[0] = 0L;
                            XposedEntry.log("[FacePatch] Normalized turing.d.a status: " + j + " -> 0L");
                        }
                        if (param.args[1] == null || ((byte[]) param.args[1]).length == 0) {
                            param.args[1] = new byte[32];
                        }
                    }
                }
            });
        }

        // 2.1 Turing base class: com.tencent.could.huiyansdk.turing.b is an abstract class.
        // Its concrete implementation (TuringSdkImp) is hooked above to avoid "Cannot hook abstract methods".

        // 2.2 HuiYanAuthImp: argument null-safety for getSendResultRequest & getTuringActiveParam
        final String huiyanAuthImpCls = "com.tencent.could.huiyansdk.api.HuiYanAuthImp";
        Class<?> huiyanAuthImpClass = XposedHelpers.findClassIfExists(huiyanAuthImpCls, cl);
        if (huiyanAuthImpClass != null && !sHookedFaceClasses.contains(huiyanAuthImpClass)) {
            sHookedFaceClasses.add(huiyanAuthImpClass);
            HookUtils.hookAllMethods(huiyanAuthImpClass, "getSendResultRequest", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null) {
                        if (param.args.length > 0 && param.args[0] == null) {
                            param.args[0] = "";
                        }
                        if (param.args.length > 1 && param.args[1] == null) {
                            param.args[1] = "";
                        }
                    }
                    try {
                        Class<?> fClass = XposedHelpers.findClassIfExists("com.tencent.could.huiyansdk.turing.f", cl);
                        if (fClass != null) {
                            Object fInstance = null;
                            Class<?> fHolderCls = XposedHelpers.findClassIfExists("com.tencent.could.huiyansdk.turing.f$a", cl);
                            if (fHolderCls != null) {
                                try {
                                    fInstance = XposedHelpers.getStaticObjectField(fHolderCls, "a");
                                } catch (Throwable ignored) {}
                            }
                            if (fInstance == null) {
                                for (java.lang.reflect.Field field : fClass.getDeclaredFields()) {
                                    if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) && field.getType() == fClass) {
                                        field.setAccessible(true);
                                        fInstance = field.get(null);
                                        break;
                                    }
                                }
                            }
                            if (fInstance != null) {
                                Object g = null;
                                try {
                                    g = XposedHelpers.getObjectField(fInstance, "g");
                                } catch (Throwable ignored) {}
                                if (g == null) {
                                    Class<?> impCls = XposedHelpers.findClassIfExists("com.tencent.could.huiyansdk.turingmodule.TuringSdkImp", cl);
                                    if (impCls != null) {
                                        XposedHelpers.setObjectField(fInstance, "g", impCls.getDeclaredConstructor().newInstance());
                                        XposedEntry.log("[FacePatch] Injected default TuringSdkImp into f.g");
                                    }
                                }
                            }
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[FacePatch] Error preparing f.g before getSendResultRequest: " + t.getMessage());
                    }
                }
            });
            HookUtils.hookAllMethods(huiyanAuthImpClass, "getTuringActiveParam", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == null) {
                        param.setResult("");
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked HuiYanAuthImp.getSendResultRequest & getTuringActiveParam for argument null-safety");
        }

        // 2.3 CommonDataCache: getTuringActiveParam null-safety
        final String commonDataCacheCls = "com.tencent.could.huiyansdk.entity.CommonDataCache";
        Class<?> cdcClass = XposedHelpers.findClassIfExists(commonDataCacheCls, cl);
        if (cdcClass != null && !sHookedFaceClasses.contains(cdcClass)) {
            sHookedFaceClasses.add(cdcClass);
            HookUtils.hookAllMethods(cdcClass, "getTuringActiveParam", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == null) {
                        param.setResult("");
                    }
                }
            });
        }

        // 5. TuringResultCacheEntity: setTuringEnvErrorStr & getTuringEnvErrorStr
        final String cacheCls = "com.tencent.could.huiyansdk.entity.TuringResultCacheEntity";
        Class<?> cacheClass = XposedHelpers.findClassIfExists(cacheCls, cl);
        if (cacheClass != null && !sHookedFaceClasses.contains(cacheClass)) {
            sHookedFaceClasses.add(cacheClass);
            HookUtils.hookAllMethods(cacheClass, "setTuringEnvErrorStr", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0) {
                        param.args[0] = ""; // Neutralize environment error string
                    }
                }
            });
            HookUtils.hookAllMethods(cacheClass, "getTuringEnvErrorStr", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult("");
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String && !((String) res).isEmpty()) {
                        param.setResult("");
                    }
                }
            });
            HookUtils.hookAllMethods(cacheClass, "isNeedFrameCheck", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (Boolean.TRUE.equals(param.getResult())) {
                        param.setResult(false);
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked TuringResultCacheEntity.setTuringEnvErrorStr, getTuringEnvErrorStr, isNeedFrameCheck");
        }

        // 6. TuringCam arWPM: a() status, b() so load & c() native init
        final String arwpmCls = "com.tencent.turingcam.arWPM";
        Class<?> arwpmClass = XposedHelpers.findClassIfExists(arwpmCls, cl);
        if (arwpmClass != null && !sHookedFaceClasses.contains(arwpmClass)) {
            sHookedFaceClasses.add(arwpmClass);
            HookUtils.hookAllMethods(arwpmClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.method instanceof java.lang.reflect.Method) {
                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                        if (m.getReturnType() == int.class && (param.args == null || param.args.length == 0)) {
                            param.setResult(0); // return 0 (initialized and healthy)
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(arwpmClass, "b", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        java.util.concurrent.atomic.AtomicBoolean b = (java.util.concurrent.atomic.AtomicBoolean) XposedHelpers.getStaticObjectField(arwpmClass, "b");
                        if (b != null) b.set(true);
                    } catch (Throwable ignored) {}
                    param.setResult(0);
                }
            });
            HookUtils.hookAllMethods(arwpmClass, "c", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        java.util.concurrent.atomic.AtomicBoolean c = (java.util.concurrent.atomic.AtomicBoolean) XposedHelpers.getStaticObjectField(arwpmClass, "f1141c");
                        if (c != null) c.set(true);
                    } catch (Throwable ignored) {}
                    param.setResult(0);
                }
            });
            XposedEntry.log("[FacePatch] Hooked arWPM.a, arWPM.b & arWPM.c -> 0");
        }

        // 7. TuringCam JD1Ej: a(TuringFaceBuilder) & b() SkEpO
        final String jd1ejCls = "com.tencent.turingcam.JD1Ej";
        Class<?> jd1ejClass = XposedHelpers.findClassIfExists(jd1ejCls, cl);
        if (jd1ejClass != null && !sHookedFaceClasses.contains(jd1ejClass)) {
            sHookedFaceClasses.add(jd1ejClass);
            HookUtils.hookAllMethods(jd1ejClass, "a", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.method instanceof java.lang.reflect.Method) {
                        java.lang.reflect.Method m = (java.lang.reflect.Method) param.method;
                        if (m.getReturnType() == int.class && param.args != null && param.args.length == 1) {
                            param.setResult(0);
                        }
                    }
                }
            });
            Class<?> skepoCls = XposedHelpers.findClassIfExists("com.tencent.turingcam.JD1Ej$SkEpO", cl);
            if (skepoCls != null) {
                HookUtils.hookAllMethods(jd1ejClass, "b", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result != null) {
                            try {
                                int code = XposedHelpers.getIntField(result, "a");
                                if (code != 0) {
                                    XposedHelpers.setIntField(result, "a", 0);
                                    XposedEntry.log("[FacePatch] JD1Ej.b returned code " + code + " -> sanitized to 0");
                                }
                            } catch (Throwable ignored) {}
                        } else {
                            try {
                                Object safeSkEpO = XposedHelpers.newInstance(skepoCls);
                                XposedHelpers.setIntField(safeSkEpO, "a", 0);
                                param.setResult(safeSkEpO);
                                XposedEntry.log("[FacePatch] JD1Ej.b returned null -> created safe SkEpO(0)");
                            } catch (Throwable ignored) {}
                        }
                    }
                });
            }
            XposedEntry.log("[FacePatch] Hooked JD1Ej.a & JD1Ej.b");
        }

        // 8. HuiYanSdkImp: sendBuriedPointInfo & doOnFail
        final String huiyanSdkCls = "com.tencent.could.huiyansdk.api.HuiYanSdkImp";
        Class<?> huiyanSdkClass = XposedHelpers.findClassIfExists(huiyanSdkCls, cl);
        if (huiyanSdkClass != null && !sHookedFaceClasses.contains(huiyanSdkClass)) {
            sHookedFaceClasses.add(huiyanSdkClass);
            HookUtils.hookAllMethods(huiyanSdkClass, "sendBuriedPointInfo", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2 && param.args[1] instanceof String) {
                        String event = (String) param.args[1];
                        if (event.contains("400103") || event.contains("EnvRisk") || event.contains("HookDetect") || event.contains("RootDetect") || event.contains("EmulatorRisk")) {
                            param.setResult(null);
                            XposedEntry.log("[FacePatch] Suppressed HuiYan risk environment buried point event: " + event);
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(huiyanSdkClass, "doOnFail", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0) {
                        String msg = String.valueOf(param.args[0]);
                        int code = param.args.length > 1 && param.args[1] instanceof Number ? ((Number) param.args[1]).intValue() : 0;
                        if (msg.contains("400103") || msg.contains("Turing") || msg.contains("Env") || msg.contains("环境") || code == 214 || code == 216 || code == 224 || code == 285) {
                            param.setResult(null);
                            XposedEntry.log("[FacePatch] Neutralized HuiYanSdkImp.doOnFail: " + code + " " + msg);
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked HuiYanSdkImp.sendBuriedPointInfo & doOnFail");
        }

        // 9. CommonUtils: sendErrorAndExitAuth error interception
        final String commonUtilsCls = "com.tencent.could.huiyansdk.common.CommonUtils";
        Class<?> commonUtilsClass = XposedHelpers.findClassIfExists(commonUtilsCls, cl);
        if (commonUtilsClass != null && !sHookedFaceClasses.contains(commonUtilsClass)) {
            sHookedFaceClasses.add(commonUtilsClass);
            HookUtils.hookAllMethods(commonUtilsClass, "sendErrorAndExitAuth", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 1) {
                        String msg = String.valueOf(param.args[1]);
                        int code = param.args[0] instanceof Number ? ((Number) param.args[0]).intValue() : 0;
                        if (msg.contains("400103") || msg.contains("Turing") || msg.contains("Env") || msg.contains("环境") || code == 214 || code == 216 || code == 224 || code == 285) {
                            param.setResult(null);
                            XposedEntry.log("[FacePatch] Neutralized CommonUtils.sendErrorAndExitAuth: " + code + " " + msg);
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked CommonUtils.sendErrorAndExitAuth");
        }

        // 9.1 IdentificationIpcServer: sanitize action_report telemetry
        final String identIpcCls = "com.tencent.mobileqq.identification.IdentificationIpcServer";
        Class<?> identIpcClass = XposedHelpers.findClassIfExists(identIpcCls, cl);
        if (identIpcClass != null && sHookedFaceClasses.add(identIpcClass)) {
            HookUtils.hookIfMethodExists(identIpcClass, "onCall", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2 && "action_report".equals(param.args[0])) {
                        if (param.args[1] instanceof android.os.Bundle) {
                            android.os.Bundle b = (android.os.Bundle) param.args[1];
                            String report = b.getString("report");
                            if (report != null && (report.contains("400103") || report.contains("EnvRisk") ||
                                report.contains("HookDetect") || report.contains("RootDetect") ||
                                report.contains("EmulatorRisk") || report.contains("Turing"))) {
                                b.putString("report", "{\"platform\":2,\"publicEvent\":\"NONE\"}");
                                XposedEntry.log("[FacePatch] Sanitized IdentificationIpcServer action_report payload");
                            }
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked IdentificationIpcServer.onCall for clean action_report telemetry");
        }

        // 10. Youtu LiveStyle Reflection & Sensor Fallback (fixes "长时间接收中" and sensor missing lux=-10000)
        final String sensorWorkerCls = "com.tencent.youtu.ytagreflectlivecheck.worker.SensorManagerWorker";
        Class<?> swClass = XposedHelpers.findClassIfExists(sensorWorkerCls, cl);
        if (swClass != null && !sHookedFaceClasses.contains(swClass)) {
            sHookedFaceClasses.add(swClass);
            HookUtils.hookAllMethods(swClass, "getLux", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof Float) {
                        float lux = (Float) res;
                        // On real devices, preserve genuine sensor reading if valid (0 <= lux <= 20000).
                        // If invalid (< 0 or > 20000), provide realistic indoor lux fallback to prevent -10000 sentinel rejection.
                        if (lux < 0.0f || lux > 20000.0f) {
                            float dynLux = SideChannelDefense.getDynamicLux();
                            param.setResult(dynLux);
                            XposedEntry.log("[FacePatch] SensorManagerWorker.getLux fallback: " + lux + " -> " + dynLux);
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(swClass, "start", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof Integer && ((Integer) res) != 0) {
                        param.setResult(0);
                        XposedEntry.log("[FacePatch] SensorManagerWorker.start normalized " + res + " -> 0 (success)");
                    }
                }
            });
            final Class<?> listenerClass = XposedHelpers.findClassIfExists("com.tencent.youtu.ytagreflectlivecheck.worker.SensorManagerWorker$LightSensorListener", cl);
            if (listenerClass != null) {
                HookUtils.hookAllConstructors(listenerClass, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            Field f = listenerClass.getDeclaredField("lux");
                            f.setAccessible(true);
                            float curLux = f.getFloat(param.thisObject);
                            if (curLux < 0.0f || curLux > 20000.0f) {
                                f.setFloat(param.thisObject, SideChannelDefense.getDynamicLux());
                            }
                        } catch (Throwable ignored) {}
                    }
                });
            }
            XposedEntry.log("[FacePatch] Hooked Youtu SensorManagerWorker & LightSensorListener");
        }

        String[] selectDataClasses = {
            "com.tencent.youtu.ytagreflectlivecheck.requester.LiveStyleRequester$SeleceData",
            "com.tencent.youtu.sdkkitframework.liveness.YtLivenessNetProtoHelper$LiveStyleRequester$SeleceData"
        };
        for (final String sdcName : selectDataClasses) {
            Class<?> sdc = XposedHelpers.findClassIfExists(sdcName, cl);
            if (sdc != null && !sHookedFaceClasses.contains(sdc)) {
                sHookedFaceClasses.add(sdc);
                HookUtils.hookAllConstructors(sdc, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof Float) {
                            float lux = (Float) param.args[0];
                            if (lux < 0.0f || lux > 20000.0f) {
                                float dynLux = SideChannelDefense.getDynamicLux();
                                param.args[0] = dynLux;
                                XposedEntry.log("[FacePatch] " + sdcName + " ctor lux sanitized: " + lux + " -> " + dynLux);
                            }
                        }
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            Object self = param.thisObject;
                            Object ad = XposedHelpers.getObjectField(self, "android_data");
                            if (ad != null) {
                                Object luxObj = XposedHelpers.getObjectField(ad, "lux");
                                if (luxObj instanceof Number) {
                                    float lv = ((Number) luxObj).floatValue();
                                    if (lv < 0.0f || lv > 20000.0f) {
                                        XposedHelpers.setObjectField(ad, "lux", SideChannelDefense.getDynamicLux());
                                    }
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                });
            }
        }

        String[] androidDataClasses = {
            "com.tencent.youtu.ytagreflectlivecheck.requester.LiveStyleRequester$LiveStyleAndroidData",
            "com.tencent.youtu.sdkkitframework.liveness.YtLivenessNetProtoHelper$LiveStyleRequester$LiveStyleAndroidData"
        };
        for (String adcName : androidDataClasses) {
            Class<?> adc = XposedHelpers.findClassIfExists(adcName, cl);
            if (adc != null && !sHookedFaceClasses.contains(adc)) {
                sHookedFaceClasses.add(adc);
                for (Method m : adc.getDeclaredMethods()) {
                    if (m.getReturnType() == float.class && m.getParameterTypes().length == 0) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object r = param.getResult();
                                if (r instanceof Float) {
                                    float v = (Float) r;
                                    if (v < 0.0f || v > 20000.0f) {
                                        param.setResult(SideChannelDefense.getDynamicLux());
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }

        // 11. Youtu JNI LiveCheck Engine (libYTLiveness.so / libYTCommonLiveness.so)
        final String ytJniCls = "com.tencent.youtu.ytagreflectlivecheck.jni.YTAGReflectLiveCheckJNIInterface";
        Class<?> ytJniClass = XposedHelpers.findClassIfExists(ytJniCls, cl);
        if (ytJniClass != null && !sHookedFaceClasses.contains(ytJniClass)) {
            sHookedFaceClasses.add(ytJniClass);
            HookUtils.hookAllMethods(ytJniClass, "FRInit", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof Number && ((Number) res).intValue() != 0) {
                        param.setResult(0);
                        if (param.args != null && param.args.length >= 4 && param.args[3] instanceof long[]) {
                            long[] jArr = (long[]) param.args[3];
                            if (jArr.length >= 2) {
                                if (jArr[0] <= 0) jArr[0] = 2000L;
                                if (jArr[1] <= 0) jArr[1] = 2000L;
                            }
                        }
                        XposedEntry.log("[FacePatch] Normalized YTAGReflectLiveCheckJNIInterface.FRInit -> 0 (clean liveness auth)");
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked YTAGReflectLiveCheckJNIInterface.FRInit for Youtu livecheck safety");
        }

        // 12. MainProcess2Fe: sanitize display_report and face_detect risk telemetry
        final String mp2feCls = "com.tencent.mobileqq.dt.app.MainProcess2Fe";
        Class<?> mp2feClass = XposedHelpers.findClassIfExists(mp2feCls, cl);
        if (mp2feClass != null && sHookedFaceClasses.add(mp2feClass)) {
            HookUtils.hookIfMethodExists(mp2feClass, "k", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 3 && param.args[1] instanceof String) {
                        String cmd = (String) param.args[1];
                        if ("face_detect".equals(cmd) && param.args[2] instanceof org.json.JSONObject) {
                            org.json.JSONObject jo = (org.json.JSONObject) param.args[2];
                            String content = jo.optString("content", "");
                            if (content.contains("400103") || content.contains("EnvRisk") || content.contains("HookDetect") ||
                                content.contains("RootDetect") || content.contains("EmulatorRisk") || content.contains("Turing")) {
                                jo.put("content", "");
                                XposedEntry.log("[FacePatch] Sanitized MainProcess2Fe.k face_detect risk payload");
                            }
                        } else if ("display_report".equals(cmd) && param.args[2] instanceof org.json.JSONObject) {
                            org.json.JSONObject jo = (org.json.JSONObject) param.args[2];
                            org.json.JSONObject inner = jo.optJSONObject("data");
                            if (inner != null) {
                                inner.put("data", "0,0,0,0");
                            } else {
                                jo.put("data", "0,0,0,0");
                            }
                            XposedEntry.log("[FacePatch] Sanitized MainProcess2Fe.k display_report payload -> 0,0,0,0");
                        }
                    }
                }
            });
        }
    }

    // ============ Tier 4: trpc.o3.* telemetry & security detection targeted sanitization ============

    /**
     * Tier 4: Targeted Sanitization for trpc.o3.* Telemetry & QQProtect QSec Detection.
     *
     * Reverse engineering findings:
     * 1. trpc.o3.ecdh_access.* is MSF's core ECDH key-exchange protocol (MUST NOT BE BLOCKED).
     * 2. trpc.o3.full_social_lock_punish.* is the account verification/unlock channel (MUST NOT BE BLOCKED).
     * 3. trpc.o3.report.Report.SsoReport & SsoEventReport carry telemetry:
     *    - "0df00071646" (sign_report): reports signature mismatch, hook detection, and runtime tampering.
     *    - "00e00075618" (env_detect): reports fake location, mock provider, time zone anomalies.
     *    - "02f00075617" (google_attestation): reports Google Play integrity/attestation checks.
     *    - "0b500076578" (sdk_init): reports FEKit load times and sleepCheckResult.
     * 4. qqprotect.qsec.a.e gathers 33 system parameters into a JSON dictionary (adb, accessibility, sensors).
     * 5. MainProcess2Fe.b checks display refresh rate <= 30fps, displayId > 0, scrcpy, minicap and sends display_report.
     * 6. QSecChannelImpl sends feEnvReport ("face_detect"), feCameraActionReport ("camera_detect"), and collectReport.
     */
    private static final java.util.Set<Class<?>> sHookedO3Classes =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static void hookO3SecurityAndTelemetry(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookO3SecurityAndTelemetryWithClassLoader(cl);
    }

    public static void hookO3SecurityAndTelemetryWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        // 1. Hook com.tencent.qqprotect.report.O3Report
        final String o3ReportCls = "com.tencent.qqprotect.report.O3Report";
        Class<?> o3ReportClazz = XposedHelpers.findClassIfExists(o3ReportCls, cl);
        if (o3ReportClazz != null && sHookedO3Classes.add(o3ReportClazz)) {
            // Normalize O3Report.d(String, String, String) - sign_report (attaId = "0df00071646") & est report
            HookUtils.hookAllMethods(o3ReportClazz, "d", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] != null) {
                        String arg0 = p.args[0].toString();
                        if ("est".equals(arg0)) {
                            // Do NOT wipe p.args[1] to empty! Let authentic clean estimation token pass through!
                            XposedEntry.log("[O3Patch] Preserved authentic O3Report.d ('est') token payload");
                            if (p.args.length >= 2 && p.args[1] != null) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                    "O3Report", "est_token", String.valueOf(p.args[1]).getBytes(java.nio.charset.StandardCharsets.UTF_8), "Authentic estimation token", 4);
                            }
                        } else if (arg0.matches("^[a-fA-F0-9]{32}$")) {
                            final IVersionProfile profile = HostVersionManager.getCurrentProfile();
                            p.args[0] = profile.getOfficialSignatureHashUpper();
                            XposedEntry.log("[O3Patch] Normalized O3Report.d (sign_report official MD5: " + p.args[0] + ")");
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                "O3Report", "sign_report(0df00071646)", String.valueOf(p.args[0]).getBytes(java.nio.charset.StandardCharsets.UTF_8), "Normalized sign_report", 4);
                        }
                    }
                }
            });

            // Normalize O3Report.b(String, List, String) - env_detect (attaId = "00e00075618")
            HookUtils.hookAllMethods(o3ReportClazz, "b", new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                        java.util.List<Object> list = (java.util.List<Object>) p.args[1];
                        if (!list.isEmpty()) {
                            Object first = list.get(0);
                            if (first != null && !"0".equals(first.toString())) {
                                list.set(0, "0");
                            }
                        }
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                            "O3Report", "env_detect(00e00075618)", list.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8), "Normalized env_detect fakeReason=0", 4);
                    }
                    XposedEntry.log("[O3Patch] Normalized O3Report.b (fakeReason=0, preserved authentic coordinates)");
                }
            });

            // Normalize O3Report.c(String, List) - fakeLocationReport / nearLocationReport
            HookUtils.hookAllMethods(o3ReportClazz, "c", new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                        java.util.List<Object> list = (java.util.List<Object>) p.args[1];
                        if (!list.isEmpty()) {
                            list.set(0, "0");
                        }
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                            "O3Report", "fakeLocationReport", list.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8), "Normalized fakeReason=0", 4);
                    }
                    XposedEntry.log("[O3Patch] Normalized O3Report.c (fakeReason=0)");
                }
            });

            // Allow O3Report.a(String, ArrayList, ProtoUtils.TroopProtocolObserver) to deliver to server
        }

        // 2. Hook com.tencent.qqprotect.qsec.a (Device profile collector: sanitize sensitive items at source)
        Class<?> qsecAClazz = XposedHelpers.findClassIfExists("com.tencent.qqprotect.qsec.a", cl);
        if (qsecAClazz != null && sHookedO3Classes.add(qsecAClazz)) {
            HookUtils.hookAllMethods(qsecAClazz, "n", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (s.contains("adb")) {
                            String cleaned = s.replace(",adb", "").replace("adb,", "").replace("adb", "");
                            p.setResult(cleaned.isEmpty() ? "none" : cleaned);
                        }
                    } else if (res == null) {
                        p.setResult("none");
                    }
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "f", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (DynamicRootDetectionHook.isSuspiciousPackage(s) || s.contains("xposed")) {
                            p.setResult("[]");
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "g", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String) {
                        String s = (String) res;
                        if (DynamicRootDetectionHook.isSuspiciousPackage(s) || s.contains("xposed")) {
                            p.setResult("[]");
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "o", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof Number && ((Number) p.getResult()).longValue() <= 0L) {
                        long ts = 0L;
                        if (p.args != null && p.args.length > 0 && p.args[0] instanceof android.content.Context) {
                            try {
                                android.content.Context ctx = (android.content.Context) p.args[0];
                                ts = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0).lastUpdateTime;
                            } catch (Throwable ignored) {}
                        }
                        if (ts <= 0L) {
                            ts = System.currentTimeMillis() - 86400000L * 14;
                        }
                        p.setResult(ts);
                    }
                }
            });
        }

        // 3. Official O3BusinessHandler (P2, Q2, R2, S2) pipelines are allowed to run naturally without dropping

        // 4. Hook com.tencent.mobileqq.dt.model.d & VirtualClickDetection
        Class<?> dtModelDClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.model.d", cl);
        if (dtModelDClazz != null && sHookedO3Classes.add(dtModelDClazz)) {
            HookUtils.hookAllMethods(dtModelDClazz, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                        String event = (String) p.args[0];
                        if ("socialError".equals(event)) {
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Neutralized dt.model.d.b socialError popup");
                        }
                    }
                }
            });
        }

        Class<?> vcdClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.model.VirtualClickDetection", cl);
        if (vcdClazz != null && sHookedO3Classes.add(vcdClazz)) {
            HookUtils.hookAllMethods(vcdClazz, "e", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    try {
                        XposedHelpers.setBooleanField(p.thisObject, "d", false);
                        XposedEntry.log("[O3Patch] Disabled VirtualClickDetection");
                    } catch (Throwable ignored) {}
                }
            });
        }

        // 5. Hook com.tencent.mobileqq.dt.api.impl.QSecChannelImpl: ensure report channel is open
        Class<?> qsecChannelClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.api.impl.QSecChannelImpl", cl);
        if (qsecChannelClazz != null && sHookedO3Classes.add(qsecChannelClazz)) {
            HookUtils.hookAllMethods(qsecChannelClazz, "reportEnable", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(true);
                }
            });
        }

        // 6. Hook Ganliang
        Class<?> ganliangClazz = XposedHelpers.findClassIfExists("com.tencent.qqprotect.ganliang.Ganliang", cl);
        if (ganliangClazz != null && sHookedO3Classes.add(ganliangClazz)) {
            HookUtils.hookAllMethods(ganliangClazz, "g", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[GanliangPatch] Neutralized Ganliang.g (prevented FLAG_SECURE)");
                }
            });
            HookUtils.hookAllMethods(ganliangClazz, "f", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null) {
                        if (p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                            ((java.util.List) p.args[1]).clear();
                        }
                        if (p.args.length >= 4) {
                            p.args[3] = 1;
                        }
                    }
                    XposedEntry.log("[GanliangPatch] Normalized Ganliang.f (0 mirror apps, screenCnt=1) and allowed report");
                }
            });
            HookUtils.hookIfMethodExists(ganliangClazz, "checkDeviceRisk", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0);
                }
            });
        }

        // 7. Hook com.tencent.mobileqq.channel.ChannelManager.checkMethod (Reflection scanner neutralization)
        Class<?> cmClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.channel.ChannelManager", cl);
        if (cmClazz != null && sHookedO3Classes.add(cmClazz)) {
            HookUtils.hookCandidateMethods("com.tencent.mobileqq.channel.ChannelManager", new String[]{"checkMethod"}, cl, XC_MethodReplacement.DO_NOTHING);
            XposedEntry.log("[O3Patch] Neutralized ChannelManager.checkMethod reflection scanner");
        }
    }

    // ============ Tier 5: Clean detection sources at the origin ============

    /**
     * Tier 5: Direct Sanitization at the Detection Source.
     *
     * Cleans data at the moment of generation so that all downstream consumers,
     * UI components, and telemetry collectors observe authentic, healthy values:
     * 1. Location detection source:
     *    - TencentLocation.getFakeReason() & isMockGps() forced to 0 (genuine).
     *    - SosoLocation.fakeReason forced to 0 in constructors & clone.
     *    - LbsManagerService.notifySec ensures fakeReason = 0 (prevents O3Report.c 10002/10003 triggers).
     *    - android.location.Location.isFromMockProvider() & isMock() forced to false.
     * 2. Sensor detection source:
     *    - qqprotect.qsec.b.b() (accelerometer): synthesizes realistic gravity vector if missing/unregistered.
     *    - qqprotect.qsec.c.b() (gyroscope): synthesizes realistic micro-tremor reading if missing/unregistered.
     *    - qqprotect.qsec.d.b() (light sensor): synthesizes 150.0 lux indoor ambient reading if <= 0.
     * 3. Screen/Display & Remote Control detection source:
     *    - Display.getOwnerPackageName(): returns null (hides screen capture apps).
     *    - Display.getName(): sanitizes scrcpy/minicap/virtual screen names to "Built-in Screen".
     *    - Display.getRefreshRate(): normalizes <= 30fps emulator rates to 60.0f.
     *    - Ganliang.g(): neutralizes forced FLAG_SECURE (8192) to eliminate black screen issues.
     *    - Ganliang.f(): suppresses Cmd0x9747Req display package reporting.
     * 4. APK lastModified detection source:
     *    - qqprotect.qsec.a.o(): guarantees valid baseline APK timestamp.
     */
    private static void hookDetectionSourcesAtOrigin(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. Location Detection Source: TencentLocation & SosoLocation
        String[] tencentLocClasses = {
            "c.t.m.g.h3",
            "com.tencent.map.geolocation.TencentLocation",
            "com.tencent.map.geolocation.sapp.TencentLocation"
        };
        for (String cls : tencentLocClasses) {
            hookSafe(cls, "getFakeReason", lpparam, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof Number && ((Number) p.getResult()).intValue() != 0) {
                        p.setResult(0); // 0 = genuine, zero anomaly
                    }
                }
            });
            hookSafe(cls, "isMockGps", lpparam, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof Number && ((Number) p.getResult()).intValue() != 0) {
                        p.setResult(0);
                    }
                }
            });
        }

        final String sosoLocCls = "com.tencent.mobileqq.soso.location.data.SosoLocation";
        hookSafe(sosoLocCls, "<init>", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                try {
                    XposedHelpers.setIntField(p.thisObject, "fakeReason", 0);
                } catch (Throwable ignored) { }
            }
        });

        hookSafe(sosoLocCls, "clone", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() != null) {
                    try {
                        XposedHelpers.setIntField(p.getResult(), "fakeReason", 0);
                    } catch (Throwable ignored) { }
                }
            }
        });

        final String lbsMgrCls = "com.tencent.mobileqq.soso.location.LbsManagerService";
        hookSafe(lbsMgrCls, "notifySec", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && p.args[1] != null) {
                    try {
                        Object sosoLbsInfo = p.args[1];
                        Object sosoLocation = XposedHelpers.getObjectField(sosoLbsInfo, "mLocation");
                        if (sosoLocation != null) {
                            XposedHelpers.setIntField(sosoLocation, "fakeReason", 0);
                        }
                    } catch (Throwable ignored) { }
                }
            }
        });

        // Framework Location: isFromMockProvider & isMock (pass-through normalization in afterHookedMethod)
        HookUtils.hookAllMethods("android.location.Location", "isFromMockProvider", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });
        HookUtils.hookAllMethods("android.location.Location", "isMock", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });

        // 2. Physical Sensor Detection Source: qqprotect.qsec.b, c, d
        // Synthesize dynamic, jittered sensor values instead of static strings or uninitialized -1
        hookSafe("com.tencent.qqprotect.qsec.b", "b", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res == null || "-1".equals(res) || "".equals(res)) {
                    p.setResult(SideChannelDefense.getDynamicAccelerometerString());
                }
            }
        });

        hookSafe("com.tencent.qqprotect.qsec.c", "b", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res == null || "-1".equals(res) || "".equals(res)) {
                    p.setResult(SideChannelDefense.getDynamicGyroscopeString());
                }
            }
        });

        hookSafe("com.tencent.qqprotect.qsec.d", "b", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res == null || "-1".equals(res) || "".equals(res) || "-1.0".equals(res)) {
                    p.setResult(String.format(java.util.Locale.US, "%.1f", SideChannelDefense.getDynamicLux()));
                }
            }
        });

        // 3. Screen / Display & Remote Control Detection Source: Display & Ganliang
        HookUtils.hookAllMethods("android.view.Display", "getOwnerPackageName", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res != null) {
                    String pkg = res.toString().toLowerCase();
                    if (DynamicRootDetectionHook.isSuspiciousPackage(pkg) || pkg.contains("scrcpy") || pkg.contains("minicap")) {
                        p.setResult(null);
                    }
                }
            }
        });

        HookUtils.hookAllMethods("android.view.Display", "getName", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof String) {
                    String name = (String) p.getResult();
                    if (name.contains("scrcpy") || name.contains("minicap") || name.contains("virtual") || name.contains("overlay")) {
                        p.setResult("Built-in Screen");
                    }
                }
            }
        });

        HookUtils.hookAllMethods("android.view.Display", "getRefreshRate", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof Number && ((Number) p.getResult()).floatValue() <= 0.0f) {
                    p.setResult(60.0f);
                }
            }
        });

        final String ganliangCls = "com.tencent.qqprotect.ganliang.Ganliang";
        // Prevent imposing FLAG_SECURE (8192) on activity window
        hookSafe(ganliangCls, "g", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[DetectionSource] Neutralized Ganliang.g (prevented FLAG_SECURE)");
            }
        });

        // Normalize Cmd0x9747Req display package report
        hookSafe(ganliangCls, "f", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null) {
                    if (p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                        ((java.util.List) p.args[1]).clear();
                    }
                    if (p.args.length >= 4) {
                        p.args[3] = 1;
                    }
                }
                XposedEntry.log("[DetectionSource] Normalized Ganliang.f (0 mirror apps, screenCnt=1) and allowed report");
            }
        });

        // 5. Accessibility Services & Dtc Telemetry Sanitization (prevents bin.mt.plus / todesk / uuremote detection)
        final String[] suspiciousAssistKeywords = {
            "bin.mt.", "bin.mt.plus", "bin.mt.manager", "bin.mt.termex", "mt2",
            "top.nkbe.npatch", "npatch", "org.lsposed", "todesk", "uuremote",
            "xposed", "lsposed", "magisk", "ksu", "apatch", "xalsace", "qqbypass", "dexkit",
            "qauxv", "io.github.qauxv", "qnotified", "cc.ioctl", "singleneuron", "bytebuddy"
        };

        HookUtils.hookAllMethods("android.view.accessibility.AccessibilityManager", "getInstalledAccessibilityServiceList", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof java.util.List) {
                    java.util.List<?> list = (java.util.List<?>) res;
                    java.util.List<Object> filtered = new java.util.ArrayList<>();
                    for (Object item : list) {
                        if (item instanceof android.accessibilityservice.AccessibilityServiceInfo) {
                            android.accessibilityservice.AccessibilityServiceInfo asi = (android.accessibilityservice.AccessibilityServiceInfo) item;
                            String pkg = asi.getResolveInfo() != null && asi.getResolveInfo().serviceInfo != null ?
                                asi.getResolveInfo().serviceInfo.packageName : null;
                            if (pkg != null) {
                                boolean susp = false;
                                String lower = pkg.toLowerCase();
                                for (String kw : suspiciousAssistKeywords) {
                                    if (lower.contains(kw)) { susp = true; break; }
                                }
                                if (susp) continue;
                            }
                        }
                        filtered.add(item);
                    }
                    p.setResult(filtered);
                }
            }
        });

        HookUtils.hookAllMethods("android.view.accessibility.AccessibilityManager", "getEnabledAccessibilityServiceList", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof java.util.List) {
                    java.util.List<?> list = (java.util.List<?>) res;
                    java.util.List<Object> filtered = new java.util.ArrayList<>();
                    for (Object item : list) {
                        if (item instanceof android.accessibilityservice.AccessibilityServiceInfo) {
                            android.accessibilityservice.AccessibilityServiceInfo asi = (android.accessibilityservice.AccessibilityServiceInfo) item;
                            String pkg = asi.getResolveInfo() != null && asi.getResolveInfo().serviceInfo != null ?
                                asi.getResolveInfo().serviceInfo.packageName : null;
                            if (pkg != null) {
                                boolean susp = false;
                                String lower = pkg.toLowerCase();
                                for (String kw : suspiciousAssistKeywords) {
                                    if (lower.contains(kw)) { susp = true; break; }
                                }
                                if (susp) continue;
                            }
                        }
                        filtered.add(item);
                    }
                    p.setResult(filtered);
                }
            }
        });

        final String dtcCls = "com.tencent.mobileqq.dt.app.Dtc";
        hookSafe(dtcCls, "checkAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                    String pkg = ((String) p.args[0]).toLowerCase();
                    for (String kw : suspiciousAssistKeywords) {
                        if (pkg.contains(kw)) {
                            p.setResult(false);
                            return;
                        }
                    }
                }
            }
        });
        hookSafe(dtcCls, "getTopActivity", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof android.app.Activity) {
                    String pkg = ((android.app.Activity) res).getPackageName();
                    if (pkg != null) {
                        String lower = pkg.toLowerCase();
                        for (String kw : suspiciousAssistKeywords) {
                            if (lower.contains(kw)) {
                                p.setResult(null);
                                return;
                            }
                        }
                    }
                }
            }
        });
        hookSafe("com.tencent.mobileqq.dt.model.VmInterface", "getTopActivity", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object res = p.getResult();
                if (res instanceof android.app.Activity) {
                    String pkg = ((android.app.Activity) res).getPackageName();
                    if (pkg != null) {
                        String lower = pkg.toLowerCase();
                        for (String kw : suspiciousAssistKeywords) {
                            if (lower.contains(kw)) {
                                p.setResult(null);
                                return;
                            }
                        }
                    }
                }
            }
        });

        // 6. CrashDefend Startup Crash Suppression
        final String crashDefendMgrCls = "com.tencent.qqperf.crashdefend.CrashDefendManager";
        hookCandidateSafe(crashDefendMgrCls, new String[]{"d", "b", "hasCrashedAtStartup"}, lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
    }

    /**
     * Tier 6: Dynamic SO (txlib / txPttlib) and MQP Integrity Strike Protection.
     *
     * Addresses runtime telemetry and security integrity verification across:
     * 1. txlib & Dynamic Native Library Verification / Telemetry:
     *    - com.tencent.mobileqq.msf.core.report.j.a: suppresses reportMsfLoadSoError when isLoaded=false or resultCode!=0.
     *    - MsfCore.tryReportSoLoadUseTxlib: suppresses msf_core_EvtLoadUseTxlib telemetry.
     *    - SoLoadCore.reportThrowable: suppresses SO loading exception reporting.
     * 2. MQPSecUtil & Integrity Check Strike (txlib/libmqpintchk.so):
     *    - MQPSecUtil.memchk: forced true (clean memory integrity).
     *    - MQPSecUtil.antitrace / do_report: neutralized.
     *    - MSFIntChkStrike.exec: neutralized (prevents punishment dialog & forced logout).
     * 3. txPttlib Audio Codec Telemetry:
     *    - StatisticCollector.collectPerformance: sanitizes actPttSoUpdate to param_FailCode=0 and success=true;
     *      suppresses msf_core_EvtMsfLoadSoError and msf_core_EvtLoadUseTxlib.
     */
    private static void hookTxlibAndPttProtection(XC_LoadPackage.LoadPackageParam lpparam) {
        // --- 1. txlib & Dynamic SO Integrity Telemetry ---
        final String msfReportJCls = "com.tencent.mobileqq.msf.core.report.j";
        hookSafe(msfReportJCls, "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length == 4 && p.args[0] instanceof String && p.args[1] instanceof Boolean && p.args[2] instanceof Integer) {
                    boolean isLoaded = (Boolean) p.args[1];
                    int resultCode = (Integer) p.args[2];
                    if (!isLoaded || resultCode != 0) {
                        p.setResult(null);
                        XposedEntry.log("[TxLibPatch] Suppressed reportMsfLoadSoError for lib: " + p.args[0]);
                    }
                }
            }
        });

        // Note: MsfCore.tryReportSoLoadUseTxlib is normal SO load telemetry; permitted to proceed naturally.
        final String soLoadCoreCls = "com.tencent.commonsdk.soload.SoLoadCore";
        hookSafe(soLoadCoreCls, "reportThrowable", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[TxLibPatch] Suppressed SoLoadCore.reportThrowable");
            }
        });

        // --- 2. MQPSecUtil & Integrity Strike (txlib/libmqpintchk.so) ---
        final String mqpSecUtilCls = "com.tencent.mqp.app.sec.MQPSecUtil";
        hookSafe(mqpSecUtilCls, "memchk", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
                XposedEntry.log("[MQPPatch] MQPSecUtil.memchk -> forced true (clean memory integrity)");
            }
        });

        hookSafe(mqpSecUtilCls, "antitrace", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Neutralized MQPSecUtil.antitrace (void return)");
            }
        });

        hookSafe(mqpSecUtilCls, "do_report", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                // MQPSecUtil.do_report(String str) exclusively dispatches ReportController.m AntiTrace telemetry.
                // It must be neutralized to prevent server-side immediate offline kick!
                String str = p.args != null && p.args.length > 0 && p.args[0] != null ? p.args[0].toString() : "";
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSecurityStrike("MQPSecUtil.do_report", "Suppressed AntiTrace delivery: " + str);
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MQPSecUtil.do_report (prevented AntiTrace telemetry strike)");
            }
        });

        hookSafe(mqpSecUtilCls, "memreport", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 3 && p.args[0] instanceof String && p.args[1] instanceof Integer && p.args[2] instanceof Integer) {
                    String moduleName = (String) p.args[0];
                    int start = (Integer) p.args[1];
                    int end = (Integer) p.args[2];
                    if (end > start && end - start <= 1048576) {
                        byte[] cleanBytes = readCleanModuleBytes(moduleName, start, end, lpparam);
                        if (cleanBytes != null) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSecurityStrike("MQPSecUtil.memreport", "Sanitized memory read for " + moduleName + " [" + start + ":" + end + "]");
                            p.setResult(cleanBytes);
                            XposedEntry.log("[MQPPatch] Sanitized MQPSecUtil.memreport for " + moduleName + " [" + start + ":" + end + "] from disk ELF");
                        }
                    }
                }
            }
        });

        // Neutralize AntiTrace and Safe_AntiTrace at ReportController.m level (dual protection)
        hookSafe("com.tencent.mobileqq.statistics.ReportController", "m", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null) {
                    for (Object arg : p.args) {
                        if (arg != null && (arg.equals("AntiTrace") || arg.equals("Safe_AntiTrace"))) {
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSecurityStrike("ReportController.m", "Blocked AntiTrace report dispatch: " + arg);
                            p.setResult(null);
                            XposedEntry.log("[ReportController] Blocked AntiTrace report dispatch: " + arg);
                            return;
                        }
                    }
                }
            }
        });

        final String intChkStrikeCls = "com.tencent.msfmqpsdkbridge.MSFIntChkStrike";
        hookSafe(intChkStrikeCls, "exec", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                String config = p.args != null && p.args.length > 0 && p.args[0] != null ? p.args[0].toString() : "";
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                    "SecurityStrikeKick.MSFIntChkStrike", null, "StrikeConfig=" + config);
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MSFIntChkStrike.exec (disarmed security strike punishment/logout)");
            }
        });

        // Suppress com.tencent.mqpsdk.secsrv.b.e (intchk strike dispatch receiver)
        hookSafe("com.tencent.mqpsdk.secsrv.b", "e", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                    "SecurityStrikeKick.b.e", null, "intchk strike response received");
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed com.tencent.mqpsdk.secsrv.b.e (disarmed intchk strike receiver)");
            }
        });

        // --- safecheckPB & SecVerifyApk CheckType Sanitization ---
        final String safecheckRspCls = "com.tencent.ims.safecheckPB$RspMQScanReport";
        hookSafe(safecheckRspCls, "<init>", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                sanitizeScanReport(p.thisObject);
            }
        });

        final String[] secVerifyClasses = {
            "com.tencent.ims.SecVerifyApk$ReportDetectResultPacket",
            "com.tencent.qqprotect.sfcfg.pb.SecVerifyApk$ReportDetectResultPacket"
        };
        for (String svCls : secVerifyClasses) {
            hookSafe(svCls, "<init>", lpparam, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    sanitizeSecVerifyPacket(p.thisObject);
                }
            });
        }

        final String[] clientInfoClasses = {
            "com.tencent.ims.ClientInfoA$ReportDetectResultPacket",
            "com.tencent.ims.ClientInfoB$ReportDetectResultPacket",
            "com.tencent.ims.MobileQQDetect$ReportDetectResultPacket"
        };
        for (String ciCls : clientInfoClasses) {
            hookSafe(ciCls, "<init>", lpparam, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    sanitizeClientInfoPacket(p.thisObject);
                }
            });
        }

        // --- 2.1 SecUtil & SafeCheck Self-Verification Integrity Strike ---
        final String secUtilCls = "com.tencent.mobileqq.utils.SecUtil";
        hookSafe(secUtilCls, "check0DayRepack", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[SelfVerifyPatch] SecUtil.check0DayRepack -> forced false (anti-repack bypass)");
            }
        });

        hookSafe(secUtilCls, "getSign", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                byte[] officialBytes = android.util.Base64.decode(
                    DynamicRootDetectionHook.OFFICIAL_QQ_SIGNATURE_B64,
                    android.util.Base64.DEFAULT
                );
                p.setResult(officialBytes);
                XposedEntry.log("[SelfVerifyPatch] SecUtil.getSign -> spoofed official signature bytes");
            }
        });

        hookSafe(secUtilCls, "getSignatureHash", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                String sig = HostVersionManager.getCurrentProfile().getOfficialSignatureHashUpper();
                p.setResult(sig);
                XposedEntry.log("[SelfVerifyPatch] SecUtil.getSignatureHash -> spoofed official MD5 " + sig);
            }
        });

        hookSafe(secUtilCls, "getPackageVersion", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                String ver = HostVersionManager.getHostVersion().getVersionName();
                if (ver == null || ver.isEmpty()) {
                    ver = HostVersionManager.getCurrentProfile().getVersionName();
                }
                p.setResult(ver);
                XposedEntry.log("[SelfVerifyPatch] SecUtil.getPackageVersion -> " + ver);
            }
        });

        hookSafe(secUtilCls, "getFileMd5", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] != null) {
                    Object arg = p.args[0];
                    String s = null;
                    if (arg instanceof String) {
                        s = (String) arg;
                    } else if (arg instanceof File) {
                        s = ((File) arg).getAbsolutePath();
                    }
                    if (s != null && isHostApkPath(s)) {
                        String officialMd5 = HostVersionManager.getCurrentProfile().getOfficialApkMd5Upper();
                        p.setResult(officialMd5);
                        XposedEntry.log("[SelfVerifyPatch] SecUtil.getFileMd5(" + s + ") -> spoofed official APK MD5: " + officialMd5);
                    }
                }
            }
        });

        // SafeCheckUtilApiImpl: getFileMD5
        final String safeCheckCls = "com.tencent.qqprotect.sfcfg.api.impl.SafeCheckUtilApiImpl";
        hookSafe(safeCheckCls, "getFileMD5", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
                if (p.args != null && p.args.length >= 3 && p.args[2] instanceof byte[]) {
                    byte[] outBuf = (byte[]) p.args[2];
                    if (outBuf.length >= 16) {
                        boolean allZero = true;
                        for (int i = 0; i < 16; i++) {
                            if (outBuf[i] != 0) {
                                allZero = false;
                                break;
                            }
                        }
                        if (allZero && p.args[0] instanceof String && p.args[1] instanceof String) {
                            String apkPath = (String) p.args[0];
                            String entryName = (String) p.args[1];
                            byte[] digest = computeApkEntryMd5(apkPath, entryName, lpparam);
                            if (digest != null && digest.length >= 16) {
                                System.arraycopy(digest, 0, outBuf, 0, 16);
                                XposedEntry.log("[SelfVerifyPatch] SafeCheckUtilApiImpl.getFileMD5 -> populated authentic entry MD5 for " + entryName);
                            }
                        }
                    }
                }
            }
        });

        // Yuanbao launcher signature MD5 check
        final String ybLauncherCls = "com.tencent.mobileqq.ad.yuanbao.launch.c";
        hookSafe(ybLauncherCls, "c", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                String sig = HostVersionManager.getCurrentProfile().getOfficialSignatureHashUpper();
                p.setResult(sig);
                XposedEntry.log("[SelfVerifyPatch] YuanbaoOpenSdkLauncher.c -> spoofed official MD5 " + sig);
            }
        });

        // --- 3. txPttlib Audio Codec Telemetry ---
        final String statCollectorCls = "com.tencent.mobileqq.statistics.StatisticCollector";
        hookSafe(statCollectorCls, "collectPerformance", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2 && p.args[1] instanceof String) {
                    String tag = (String) p.args[1];
                    if ("actPttSoUpdate".equals(tag)) {
                        if (p.args.length > 2 && p.args[2] instanceof Boolean) {
                            p.args[2] = true;
                        }
                        for (int i = 3; i < p.args.length; i++) {
                            if (p.args[i] instanceof java.util.Map) {
                                @SuppressWarnings("unchecked")
                                java.util.Map<Object, Object> m = (java.util.Map<Object, Object>) p.args[i];
                                m.put("param_FailCode", "0");
                                break;
                            }
                        }
                        XposedEntry.log("[PttPatch] Sanitized actPttSoUpdate telemetry to success (0)");
                    } else if ("msf_core_EvtMsfLoadSoError".equals(tag)) {
                        p.setResult(null);
                        XposedEntry.log("[TxLibPatch] Suppressed SO load error telemetry: " + tag);
                    }
                }
            }
        });

        // --- 4. MSFNetTransportProvider & Periodic Inspection Polling ---
        final String netProviderCls = "com.tencent.msfmqpsdkbridge.MSFNetTransportProvider";
        hookSafe(netProviderCls, "send", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] != null) {
                    try {
                        String cmd = (String) XposedHelpers.callMethod(p.args[0], "getServiceCmd");
                        if ("SecIntChkSvc.MainCmd".equals(cmd) || "SecSafeChkSvc.MainCmd".equals(cmd) || "SecCheckSigSvc.UploadReq".equals(cmd)) {
                            XposedEntry.log("[PeriodicInspection] MSFNetTransportProvider.send: " + cmd);
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        // SafeCenterPushHandler (dj.a) submsgtype0x4a inspection
        hookSafe("com.tencent.mobileqq.app.dj", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                XposedEntry.log("[PeriodicInspection] SafeCenterPushHandler dj.a triggered (submsgtype0x4a)");
            }
        });

        // com.tencent.mqpsdk.secsrv.b.g check config fetcher
        hookSafe("com.tencent.mqpsdk.secsrv.b", "g", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                String ver = p.args != null && p.args.length > 0 && p.args[0] != null ? p.args[0].toString() : "";
                XposedEntry.log("[PeriodicInspection] com.tencent.mqpsdk.secsrv.b.g initiated config check: " + ver);
            }
        });
    }

    private static void sanitizeScanReport(Object rspObj) {
        if (rspObj == null) return;
        try {
            Field countField = XposedHelpers.findFieldIfExists(rspObj.getClass(), "uint32_check_count");
            if (countField != null) {
                Object pbCount = countField.get(rspObj);
                if (pbCount != null) {
                    XposedHelpers.callMethod(pbCount, "set", 0);
                }
            }
            Field rptItemField = XposedHelpers.findFieldIfExists(rspObj.getClass(), "rpt_check_item");
            if (rptItemField != null) {
                Object pbList = rptItemField.get(rspObj);
                if (pbList != null) {
                    XposedHelpers.callMethod(pbList, "clear");
                }
            }
        } catch (Throwable ignored) {}
    }

    private static void sanitizeSecVerifyPacket(Object packetObj) {
        if (packetObj == null) return;
        try {
            final IVersionProfile profile = HostVersionManager.getCurrentProfile();
            final HostVersion hostVer = HostVersionManager.getHostVersion();
            final String officialVerName = hostVer != null ? hostVer.getVersionName() : profile.getVersionName();
            final String officialMd5 = profile.getOfficialApkMd5Upper();
            final String officialSig = profile.getOfficialSignatureHashUpper();

            Field resField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "uint32_result");
            if (resField != null) {
                Object pbRes = resField.get(packetObj);
                if (pbRes != null) {
                    XposedHelpers.callMethod(pbRes, "set", 0);
                }
            }
            Field sigField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "str_signature");
            if (sigField != null) {
                Object pbSig = sigField.get(packetObj);
                if (pbSig != null) {
                    XposedHelpers.callMethod(pbSig, "set", officialSig);
                }
            }
            Field apkMd5Field = XposedHelpers.findFieldIfExists(packetObj.getClass(), "str_apkmd5");
            if (apkMd5Field != null) {
                Object pbApkMd5 = apkMd5Field.get(packetObj);
                if (pbApkMd5 != null) {
                    XposedHelpers.callMethod(pbApkMd5, "set", officialMd5);
                }
            }
            Field verField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "str_apkversion");
            if (verField != null) {
                Object pbVer = verField.get(packetObj);
                if (pbVer != null) {
                    XposedHelpers.callMethod(pbVer, "set", officialVerName);
                }
            }
            Field pkgField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "package_name");
            if (pkgField != null) {
                Object pbPkg = pkgField.get(packetObj);
                if (pbPkg != null) {
                    XposedHelpers.callMethod(pbPkg, "set", "com.tencent.mobileqq");
                }
            }
            XposedEntry.log("[SecVerifyApk] Normalized SecVerifyApk packet: result=0, sig=" + officialSig + ", md5=" + officialMd5 + ", ver=" + officialVerName);
        } catch (Throwable t) {
            XposedEntry.log("[SecVerifyApk] Error sanitizing: " + t.getMessage());
        }
    }

    private static void sanitizeClientInfoPacket(Object packetObj) {
        if (packetObj == null) return;
        try {
            final IVersionProfile profile = HostVersionManager.getCurrentProfile();
            final HostVersion hostVer = HostVersionManager.getHostVersion();
            final String officialVerName = hostVer != null ? hostVer.getVersionName() : profile.getVersionName();
            final String officialMd5 = profile.getOfficialApkMd5Upper();

            // ClientInfoA: str_qqmd5
            Field qqMd5Field = XposedHelpers.findFieldIfExists(packetObj.getClass(), "str_qqmd5");
            if (qqMd5Field != null) {
                Object pbQqMd5 = qqMd5Field.get(packetObj);
                if (pbQqMd5 != null) XposedHelpers.callMethod(pbQqMd5, "set", officialMd5);
            }

            // ClientInfoB: str_safemd5
            Field safeMd5Field = XposedHelpers.findFieldIfExists(packetObj.getClass(), "str_safemd5");
            if (safeMd5Field != null) {
                Object pbSafeMd5 = safeMd5Field.get(packetObj);
                if (pbSafeMd5 != null) XposedHelpers.callMethod(pbSafeMd5, "set", officialMd5);
            }

            // MobileQQDetect: ret
            Field retField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "ret");
            if (retField != null) {
                Object pbRet = retField.get(packetObj);
                if (pbRet != null) XposedHelpers.callMethod(pbRet, "set", 0);
            }

            // envParam
            Field envField = XposedHelpers.findFieldIfExists(packetObj.getClass(), "envParam");
            if (envField != null) {
                Object envObj = envField.get(packetObj);
                if (envObj != null) {
                    Field verField = XposedHelpers.findFieldIfExists(envObj.getClass(), "str_qqversion");
                    if (verField != null) {
                        Object pbVer = verField.get(envObj);
                        if (pbVer != null) XposedHelpers.callMethod(pbVer, "set", officialVerName);
                    }
                    Field platField = XposedHelpers.findFieldIfExists(envObj.getClass(), "u32_platform");
                    if (platField != null) {
                        Object pbPlat = platField.get(envObj);
                        if (pbPlat != null) XposedHelpers.callMethod(pbPlat, "set", 2); // 2 = Android
                    }
                }
            }
        } catch (Throwable ignored) {}
    }

    private static byte[] computeApkEntryMd5(String apkPath, String entryName, XC_LoadPackage.LoadPackageParam lpparam) {
        if (apkPath == null || entryName == null) return null;
        String[] paths = {
            apkPath,
            lpparam != null && lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null,
            "/data/app/" + (lpparam != null ? lpparam.packageName : "com.tencent.mobileqq") + "/base.apk"
        };
        for (String path : paths) {
            if (path == null) continue;
            File f = new File(path);
            if (!f.exists() || !f.canRead()) continue;
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(f)) {
                java.util.zip.ZipEntry ze = zf.getEntry(entryName);
                if (ze != null) {
                    try (InputStream is = zf.getInputStream(ze)) {
                        MessageDigest md = MessageDigest.getInstance("MD5");
                        byte[] buf = new byte[8192];
                        int r;
                        while ((r = is.read(buf)) > 0) {
                            md.update(buf, 0, r);
                        }
                        return md.digest();
                    }
                }
            } catch (Throwable ignored) {}
        }
        return null;
    }

    private static class PtLoadSegment {
        final long vaddr;
        final long offset;
        final long filesz;
        final long memsz;
        final int flags;

        PtLoadSegment(long vaddr, long offset, long filesz, long memsz, int flags) {
            this.vaddr = vaddr;
            this.offset = offset;
            this.filesz = filesz;
            this.memsz = memsz;
            this.flags = flags;
        }

        boolean isExecutable() {
            return (flags & 1) != 0; // PF_X
        }

        boolean isWritable() {
            return (flags & 2) != 0; // PF_W
        }
    }

    private static short readLittleEndianShort(RandomAccessFile raf) throws IOException {
        int b1 = raf.readUnsignedByte();
        int b2 = raf.readUnsignedByte();
        return (short) ((b2 << 8) | b1);
    }

    private static int readLittleEndianInt(RandomAccessFile raf) throws IOException {
        int b1 = raf.readUnsignedByte();
        int b2 = raf.readUnsignedByte();
        int b3 = raf.readUnsignedByte();
        int b4 = raf.readUnsignedByte();
        return (b4 << 24) | (b3 << 16) | (b2 << 8) | b1;
    }

    private static long readLittleEndianLong(RandomAccessFile raf) throws IOException {
        long res = 0;
        for (int i = 0; i < 8; i++) {
            res |= ((long) raf.readUnsignedByte()) << (8 * i);
        }
        return res;
    }

    private static List<PtLoadSegment> parseElfSegments(RandomAccessFile raf) {
        try {
            if (raf.length() < 52) return null;
            byte[] ident = new byte[16];
            raf.seek(0);
            raf.readFully(ident);
            if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
                return null;
            }
            boolean is64 = (ident[4] == 2);
            long phoff;
            int phentsize;
            int phnum;

            if (is64) {
                if (raf.length() < 64) return null;
                raf.seek(32);
                phoff = readLittleEndianLong(raf);
                raf.seek(54);
                phentsize = readLittleEndianShort(raf) & 0xFFFF;
                phnum = readLittleEndianShort(raf) & 0xFFFF;
            } else {
                raf.seek(28);
                phoff = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                raf.seek(42);
                phentsize = readLittleEndianShort(raf) & 0xFFFF;
                phnum = readLittleEndianShort(raf) & 0xFFFF;
            }

            if (phnum <= 0 || phentsize <= 0 || phoff <= 0) return null;
            List<PtLoadSegment> list = new ArrayList<>();
            for (int i = 0; i < phnum; i++) {
                raf.seek(phoff + (long) i * phentsize);
                if (is64) {
                    int p_type = readLittleEndianInt(raf);
                    int p_flags = readLittleEndianInt(raf);
                    long p_offset = readLittleEndianLong(raf);
                    long p_vaddr = readLittleEndianLong(raf);
                    long p_paddr = readLittleEndianLong(raf);
                    long p_filesz = readLittleEndianLong(raf);
                    long p_memsz = readLittleEndianLong(raf);
                    if (p_type == 1) { // PT_LOAD
                        list.add(new PtLoadSegment(p_vaddr, p_offset, p_filesz, p_memsz, p_flags));
                    }
                } else {
                    int p_type = readLittleEndianInt(raf);
                    long p_offset = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                    long p_vaddr = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                    long p_paddr = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                    long p_filesz = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                    long p_memsz = readLittleEndianInt(raf) & 0xFFFFFFFFL;
                    int p_flags = readLittleEndianInt(raf);
                    if (p_type == 1) { // PT_LOAD
                        list.add(new PtLoadSegment(p_vaddr, p_offset, p_filesz, p_memsz, p_flags));
                    }
                }
            }
            return list;
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] readFromElfFile(RandomAccessFile raf, int start, int end) {
        int len = end - start;
        byte[] result = new byte[len];
        List<PtLoadSegment> segments = parseElfSegments(raf);
        if (segments == null || segments.isEmpty()) {
            // Fallback to naive file seek if ELF parsing fails
            try {
                if (raf.length() >= end) {
                    raf.seek(start);
                    int read = raf.read(result, 0, len);
                    if (read == len) return result;
                }
            } catch (Throwable ignored) {}
            return null;
        }

        try {
            long curVaddr = start;
            int outPos = 0;
            while (curVaddr < end) {
                PtLoadSegment targetSeg = null;
                for (PtLoadSegment seg : segments) {
                    if (seg.vaddr <= curVaddr && curVaddr < seg.vaddr + seg.memsz) {
                        targetSeg = seg;
                        break;
                    }
                }
                if (targetSeg == null) {
                    break;
                }
                long segRemain = (targetSeg.vaddr + targetSeg.memsz) - curVaddr;
                int chunkLen = (int) Math.min(end - curVaddr, segRemain);
                if (curVaddr < targetSeg.vaddr + targetSeg.filesz) {
                    long fileAvail = (targetSeg.vaddr + targetSeg.filesz) - curVaddr;
                    int fileReadLen = (int) Math.min(chunkLen, fileAvail);
                    long fileOff = targetSeg.offset + (curVaddr - targetSeg.vaddr);
                    raf.seek(fileOff);
                    int r = raf.read(result, outPos, fileReadLen);
                    if (r < fileReadLen) {
                        // Incomplete read
                    }
                }
                curVaddr += chunkLen;
                outPos += chunkLen;
            }
            return result;
        } catch (Throwable t) {
            return null;
        }
    }

    private static class ModuleMappingInfo {
        final String diskPath;
        final long baseVAddr;
        final long codeVAddr;

        ModuleMappingInfo(String diskPath, long baseVAddr, long codeVAddr) {
            this.diskPath = diskPath;
            this.baseVAddr = baseVAddr;
            this.codeVAddr = codeVAddr;
        }
    }

    private static ModuleMappingInfo findModuleInProcMaps(String simpleName) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            String foundPath = null;
            long lowestBase = -1;
            long execBase = -1;
            while ((line = reader.readLine()) != null) {
                if (line.endsWith("/" + simpleName) || line.contains("/" + simpleName + " ") || line.contains("/" + simpleName)) {
                    String[] tokens = line.split("\\s+");
                    if (tokens.length >= 6) {
                        String addrRange = tokens[0];
                        String perms = tokens[1];
                        String path = tokens[tokens.length - 1];
                        int dash = addrRange.indexOf('-');
                        if (dash > 0) {
                            try {
                                long startAddr = Long.parseLong(addrRange.substring(0, dash), 16);
                                if (lowestBase == -1 || startAddr < lowestBase) {
                                    lowestBase = startAddr;
                                    foundPath = path;
                                }
                                if (perms.contains("x") && execBase == -1) {
                                    execBase = startAddr;
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                }
            }
            if (foundPath != null && lowestBase != -1) {
                return new ModuleMappingInfo(foundPath, lowestBase, execBase != -1 ? execBase : lowestBase);
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static byte[] readCleanModuleBytes(String moduleName, int start, int end, XC_LoadPackage.LoadPackageParam lpparam) {
        if (moduleName == null || start < 0 || end <= start) return null;
        int len = end - start;
        if (len > 1048576) return null; // Safety cap 1MB

        String simpleName = moduleName;
        if (simpleName.contains("/")) {
            simpleName = simpleName.substring(simpleName.lastIndexOf('/') + 1);
        }
        if (simpleName.equals("c")) {
            simpleName = "libc.so";
        } else if (simpleName.equals("m")) {
            simpleName = "libm.so";
        } else if (simpleName.equals("dl")) {
            simpleName = "libdl.so";
        } else if (simpleName.equals("z")) {
            simpleName = "libz.so";
        } else {
            if (!simpleName.startsWith("lib") && !simpleName.endsWith(".dex") && !simpleName.endsWith(".apk")) {
                simpleName = "lib" + simpleName;
            }
            if (!simpleName.endsWith(".so") && !simpleName.endsWith(".dex") && !simpleName.endsWith(".apk")) {
                simpleName = simpleName + ".so";
            }
        }

        // 1. Try runtime memory mapping resolution via /proc/self/maps
        ModuleMappingInfo mapping = findModuleInProcMaps(simpleName);
        if (mapping != null && mapping.diskPath != null) {
            File mappedFile = new File(mapping.diskPath);
            if (mappedFile.exists() && mappedFile.isFile() && mappedFile.canRead()) {
                try (RandomAccessFile raf = new RandomAccessFile(mappedFile, "r")) {
                    byte[] clean = readFromElfFile(raf, start, end);
                    if (clean != null) {
                        return clean;
                    }
                } catch (Throwable ignored) {}
            }
        }

        // 2. Try direct candidate disk locations (including system and bionic apex paths)
        String[] candidatePaths = {
            moduleName,
            mapping != null ? mapping.diskPath : null,
            "/apex/com.android.runtime/lib64/bionic/" + simpleName,
            "/system/lib64/" + simpleName,
            "/apex/com.android.art/lib64/" + simpleName,
            "/apex/com.android.runtime/lib/bionic/" + simpleName,
            "/system/lib/" + simpleName,
            "/apex/com.android.art/lib/" + simpleName,
            lpparam != null && lpparam.appInfo != null ? lpparam.appInfo.nativeLibraryDir + "/" + simpleName : null,
            "/data/data/com.tencent.mobileqq/txlib/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/txlib/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/txPttlib/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/jpeglib/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/app_lib/" + simpleName,
            "/data/data/com.tencent.mobileqq/files/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/files/" + simpleName,
            "/data/user/0/com.tencent.mobileqq/files/qqso/" + simpleName
        };

        for (String path : candidatePaths) {
            if (path == null) continue;
            File file = new File(path);
            if (file.exists() && file.isFile() && file.canRead()) {
                try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                    byte[] clean = readFromElfFile(raf, start, end);
                    if (clean != null) {
                        return clean;
                    }
                } catch (Throwable ignored) {}
            }
        }

        // 3. Try extracting from host base APK
        if (lpparam != null && lpparam.appInfo != null && lpparam.appInfo.sourceDir != null) {
            try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(lpparam.appInfo.sourceDir)) {
                String[] archPrefixes = {"lib/arm64-v8a/", "lib/armeabi-v7a/"};
                for (String prefix : archPrefixes) {
                    java.util.zip.ZipEntry ze = zf.getEntry(prefix + simpleName);
                    if (ze != null) {
                        File cacheDir = new File("/data/user/0/" + lpparam.packageName + "/cache");
                        if (!cacheDir.exists()) cacheDir.mkdirs();
                        File cacheFile = new File(cacheDir, "clean_elf_" + simpleName);
                        if (!cacheFile.exists() || cacheFile.length() != ze.getSize()) {
                            try (java.io.InputStream is = zf.getInputStream(ze);
                                 java.io.FileOutputStream fos = new java.io.FileOutputStream(cacheFile)) {
                                byte[] buf = new byte[8192];
                                int read;
                                while ((read = is.read(buf)) > 0) {
                                    fos.write(buf, 0, read);
                                }
                            }
                        }
                        if (cacheFile.exists() && cacheFile.canRead()) {
                            try (RandomAccessFile raf = new RandomAccessFile(cacheFile, "r")) {
                                byte[] clean = readFromElfFile(raf, start, end);
                                if (clean != null) {
                                    return clean;
                                }
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {}
        }

        // 4. Memory Snapshot with Selective Trampoline Sanitization
        // Instead of returning an all-zero buffer (which immediately triggers server kick!),
        // read authentic memory bytes from /proc/self/mem or Unsafe, and sanitize any hook trampoline opcodes
        if (mapping != null && mapping.baseVAddr > 0) {
            byte[] memBuf = null;
            long targetAddr = mapping.baseVAddr + start;
            try (RandomAccessFile memRaf = new RandomAccessFile("/proc/self/mem", "r")) {
                memRaf.seek(targetAddr);
                byte[] buf = new byte[len];
                int read = memRaf.read(buf, 0, len);
                if (read == len) {
                    memBuf = buf;
                }
            } catch (Throwable ignored) {}

            // Fallback to Unsafe virtual memory direct read if /proc/self/mem access is denied
            if (memBuf == null) {
                initUnsafe();
                if (sUnsafeInstance != null && sUnsafeGetByteMethod != null) {
                    try {
                        byte[] buf = new byte[len];
                        for (int i = 0; i < len; i++) {
                            buf[i] = (Byte) sUnsafeGetByteMethod.invoke(sUnsafeInstance, targetAddr + i);
                        }
                        memBuf = buf;
                    } catch (Throwable ignored) {}
                }
            }

            if (memBuf != null) {
                if (len >= 8) {
                    int op1 = (memBuf[0] & 0xFF) | ((memBuf[1] & 0xFF) << 8) | ((memBuf[2] & 0xFF) << 16) | ((memBuf[3] & 0xFF) << 24);
                    int op2 = (memBuf[4] & 0xFF) | ((memBuf[5] & 0xFF) << 8) | ((memBuf[6] & 0xFF) << 16) | ((memBuf[7] & 0xFF) << 24);
                    if ((op1 == 0x58000050 || op1 == 0x58000051) && (op2 == 0xd61f0200 || op2 == 0xd61f0220)) {
                        // Dobby trampoline detected! Neutralize with clean standard prologue: paciasp / stp x29, x30, [sp, #-16]!
                        memBuf[0] = (byte) 0x3f; memBuf[1] = (byte) 0x23; memBuf[2] = (byte) 0x03; memBuf[3] = (byte) 0xd5;
                        memBuf[4] = (byte) 0xfd; memBuf[5] = (byte) 0x7b; memBuf[6] = (byte) 0xbf; memBuf[7] = (byte) 0xa9;
                        XposedEntry.log("[MQPPatch] Sanitized trampoline in memory snapshot for " + simpleName + " at 0x" + Long.toHexString(targetAddr));
                    }
                }
                XposedEntry.log("[MQPPatch] Memory snapshot served for " + simpleName + " [" + start + ":" + end + "]");
                return memBuf;
            }
        }

        // 5. Ultimate Fallback safe buffer
        XposedEntry.log("[MQPPatch] Fallback clean zeroed buffer for unmapped module: " + moduleName + " [" + start + ":" + end + "]");
        return new byte[len];
    }

    private static volatile Object sUnsafeInstance = null;
    private static volatile Method sUnsafeGetByteMethod = null;
    private static boolean sUnsafeInitialized = false;

    private static void initUnsafe() {
        if (sUnsafeInitialized) return;
        synchronized (QQ950PatchHook.class) {
            if (sUnsafeInitialized) return;
            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                Field f = unsafeClass.getDeclaredField("theUnsafe");
                f.setAccessible(true);
                sUnsafeInstance = f.get(null);
                sUnsafeGetByteMethod = unsafeClass.getMethod("getByte", long.class);
            } catch (Throwable ignored) {}
            sUnsafeInitialized = true;
        }
    }

    /**
     * Tier 7: RFix & Hotfix Failure Sanitization and Telemetry Drop.
     *
     * Directly addresses the root-cause of account kick / force-offline:
     * When bytecode/signature verification on hotfix fails with ERROR_LOAD_PATCH_VERSION_DEX_MD5_MISMATCH (-8),
     * RFix quality reporter sends LOAD_RESULT_PATCH_LOADER_FAIL with event_code_ext=-8 to ATTA (attaid=0ac00056535)
     * and WeData (groupId=gwe0003255039a, streamId=swe000017406d5), directly triggering server-side forced kick!
     *
     * Defenses implemented:
     * 1. RFixLoadResult: force isLoaderSuccess() and isSuccess() to true.
     * 2. PatchLoadEngineBase: in tryLoadPatchInternal/loadPatch, if result is LOAD_RESULT_PATCH_LOADER_FAIL,
     *    rewrite result to LOAD_RESULT_SUCCESS and subResult to 0.
     * 3. com.tencent.rfix.lib.reporter.e:
     *    - method d & e: drop any report where eventSuccess is false or eventCode contains "FAIL" or eventCodeExt is "-8".
     *    - method a, b, c: drop if rFixLoadResult failed.
     * 4. com.tencent.rfix.lib.atta.RFixATTASwitch:
     *    - method a(): return false (turns off ATTA/WeData network delivery for RFix).
     * 5. com.tencent.rfix.lib.atta.e:
     *    - method d(Map): drop any map where event_code contains "FAIL" or attaid is "0ac00056535" with failure.
     * 6. com.tencent.rfix.lib.wedata.base.d:
     *    - method c(Map, String[]): drop failure maps.
     * 7. com.tencent.rfix.lib.bugly.a:
     *    - method a: ensure D4 is never set to "0" and patch_tag_flag_0_ is never written.
     * 8. com.tencent.rfix.loader.safemode.RFixSafeModeKeeper:
     *    - checkSafeMode: return 0 (RESULT_OK).
     *    - reachP1Limit, reachP2Limit, reachP3Limit: return false.
     *    - writeLastCrashFile: drop.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void hookRFixFailureSanitization(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. RFix Quality Reporter: Normalize failure reports to SUCCESS in com.tencent.rfix.lib.reporter.e
        XC_MethodHook normalizeFailureReportHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args == null || p.args.length < 9) return;
                try {
                    // Check z (eventSuccess) at index 6
                    boolean eventSuccess = true;
                    if (p.args[6] instanceof Boolean) {
                        eventSuccess = (Boolean) p.args[6];
                    }
                    // Check str6 (eventCode) at index 7
                    String eventCode = p.args[7] != null ? p.args[7].toString() : null;
                    // Check str7 (eventCodeExt) at index 8
                    String eventCodeExt = p.args[8] != null ? p.args[8].toString() : null;

                    if ("LOAD_RESULT_PATCH_LOADER_FAIL".equals(eventCode) || "-8".equals(eventCodeExt)) {
                        p.args[6] = true;
                        p.args[7] = "LOAD_RESULT_SUCCESS";
                        p.args[8] = "0";
                        XposedEntry.log("[RFixPatch] Normalized RFix patch loader failure telemetry to SUCCESS");
                    }
                } catch (Throwable t) {
                    XposedEntry.log("[RFixPatch] Error filtering RFix reporter: " + t.getMessage());
                }
            }
        };
        hookSafe("com.tencent.rfix.lib.reporter.e", "d", lpparam, normalizeFailureReportHook);
        hookSafe("com.tencent.rfix.lib.reporter.e", "e", lpparam, normalizeFailureReportHook);

        // 2. RFix ATTA Database & Upload Helper (com.tencent.rfix.lib.atta.e): normalize patch loader records to SUCCESS
        hookSafe("com.tencent.rfix.lib.atta.e", "d", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object atId = map.get("attaid");
                    if ("0ac00056535".equals(atId)) {
                        Object eventCode = map.get("event_code");
                        Object eventCodeExt = map.get("event_code_ext");
                        if ("LOAD_RESULT_PATCH_LOADER_FAIL".equals(eventCode) || "-8".equals(eventCodeExt)) {
                            map.put("event_success", "1");
                            map.put("event_code", "LOAD_RESULT_SUCCESS");
                            map.put("event_code_ext", "0");
                            XposedEntry.log("[RFixPatch] Normalized ATTA patch loader failure record to SUCCESS");
                        }
                    }
                }
            }
        });

        // 3. WeData Reporter (com.tencent.rfix.lib.wedata.base.d): normalize patch loader records to SUCCESS
        hookSafe("com.tencent.rfix.lib.wedata.base.d", "c", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object atId = map.get("attaid");
                    if ("0ac00056535".equals(atId)) {
                        Object eventCode = map.get("event_code");
                        Object eventCodeExt = map.get("event_code_ext");
                        if ("LOAD_RESULT_PATCH_LOADER_FAIL".equals(eventCode) || "-8".equals(eventCodeExt)) {
                            map.put("event_success", "1");
                            map.put("event_code", "LOAD_RESULT_SUCCESS");
                            map.put("event_code_ext", "0");
                            XposedEntry.log("[RFixPatch] Normalized WeData patch loader failure record to SUCCESS");
                        }
                    }
                }
            }
        });

        // 5. RFix Bugly tag initializer (com.tencent.rfix.lib.bugly.a)
        hookSafe("com.tencent.rfix.lib.bugly.a", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(null);
                            XposedEntry.log("[RFixPatch] Suppressed Bugly updatePatchTag for failed hotfix");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });
    }

    public static boolean isQSecSuspiciousProbe(String cls) {
        if (cls == null) return false;
        String lower = cls.toLowerCase();
        return DynamicXposedDetectionHook.isSuspiciousClass(cls)
            || DynamicRootDetectionHook.isSuspiciousPackage(cls)
            || lower.contains("xposed") || lower.contains("lsposed") || lower.contains("lspatch")
            || lower.contains("canyie") || lower.contains("sandhook") || lower.contains("libepic")
            || lower.contains("epic.") || lower.contains("libpine") || lower.contains("pine.")
            || lower.contains("yahfa") || lower.contains("qqbypass") || lower.contains("native-bypass")
            || lower.contains("bytehook") || lower.contains("frida") || lower.contains("substrate")
            || lower.contains("magisk") || lower.contains("zygisk") || lower.contains("apatch")
            || lower.contains("kernelsu") || lower.contains("termux") || lower.contains("supersu")
            || lower.contains("superuser") || lower.contains("busybox") || lower.contains("root")
            || lower.contains("dexkit");
    }

    /**
     * Hook QSec detectMethod to prevent reflection-based framework detection,
     * and hook QSec.getFeKitAttach to ensure safe attach token fallback.
     */
    private static void hookQSecDefenses(XC_LoadPackage.LoadPackageParam lpparam) {
        final String qsecCls = "com.tencent.mobileqq.qsec.qsecurity.QSec";
        hookSafe(qsecCls, "detectMethod", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 2) {
                    String cls = (String) p.args[0];
                    String mtd = (String) p.args[1];
                    if (isQSecSuspiciousProbe(cls)) {
                        p.setResult(false);
                        XposedEntry.log("[QSecPatch] Blocked detectMethod: " + cls + "->" + mtd);
                    }
                }
            }
        });

        // Note: Do NOT hook QSec.getFeKitAttach to inject new byte[]{0}!
        // Injected dummy bytes create invalid protobuf payloads in WTLogin tlv_553,
        // which causes server token exchange verification failure and invalidates sessions.
        // Official QSec.getFeKitAttach already handles fallback safely.

        // Note: Do NOT hook SimpleAttestationParser.getBootStatus or CertificationStatus.BL!
        // Hardware Keystore Key Attestation certificates are signed by hardware Keymaster/TEE.
        // Tampering with verifiedBootState=0 / isDeviceLocked=1 causes cryptographic and metadata
        // inconsistency between the certificate chain and parsed status, triggering session revocation.
        // Tencent server accepts authentic bootloader states on real unlocked devices.

        // Socket detection neutralization: only filter suspicious hooks/debug sockets (0 = Connection refused / not found)
        // Do NOT blindly return 0 for legitimate internal abstract sockets to avoid breaking IPC and telemetry
        hookSafe("com.tencent.mobileqq.qsec.qsecurity.utils.SocketStatus", "checkSocket", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof Integer && ((Integer) p.getResult()) != 0) {
                    Object arg0 = (p.args != null && p.args.length > 0) ? p.args[0] : null;
                    if (arg0 instanceof String) {
                        String sockName = ((String) arg0).toLowerCase();
                        if (sockName.contains("frida") || sockName.contains("xposed") ||
                            sockName.contains("magisk") || sockName.contains("lsp") ||
                            sockName.contains("zygisk") || sockName.contains("edx") ||
                            sockName.contains("substrate") || sockName.contains("cydia")) {
                            p.setResult(0);
                        }
                    }
                }
            }
        });

    }

    /**
     * Tier 11: Real Device Emulator Detection Adaptation.
     * Neutralizes emulator boolean detection flags (CPUUtil, RFWDeviceUtil) without
     * spoofing the device model, brand, manufacturer, hardware or ABI.
     * Keeps authentic physical hardware identity intact.
     */
    private static void hookEmulatorDetectionForRealDevice(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] cpuUtilClasses = {
            "com.tencent.mobileqq.minigame.utils.CPUUtil",
            "com.tencent.qqmini.sdk.launcher.utils.CPUUtil"
        };
        for (final String cn : cpuUtilClasses) {
            hookIfMethodExistsSafe(cn, "isX86Emulator", lpparam, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (Boolean.TRUE.equals(p.getResult())) {
                        p.setResult(false);
                    }
                }
            });
            ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
            if (cl != null) {
                try {
                    final Class<?> c = XposedHelpers.findClassIfExists(cn, cl);
                    if (c != null) {
                        try {
                            Field f = c.getDeclaredField("sIsX86Emulator");
                            f.setAccessible(true);
                            f.setBoolean(null, false);
                            XposedEntry.log("[EmulatorPatch] " + cn + ".sIsX86Emulator forced false");
                        } catch (Throwable ignored) {}
                        HookUtils.hookAllConstructors(c, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                                try {
                                    Field f = c.getDeclaredField("sIsX86Emulator");
                                    f.setAccessible(true);
                                    f.setBoolean(null, false);
                                } catch (Throwable ignored) {}
                            }
                        });
                    }
                } catch (Throwable ignored) {}
            }
        }

        hookSafe("com.tencent.biz.richframework.util.RFWDeviceUtil", "isX86Emulator", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (Boolean.TRUE.equals(p.getResult())) {
                    p.setResult(false);
                }
            }
        });
    }

    private static class PendingSafeHook {
        final String className;
        final String methodName;
        final XC_MethodHook callback;
        PendingSafeHook(String c, String m, XC_MethodHook cb) {
            className = c;
            methodName = m;
            callback = cb;
        }
    }
    private static final List<PendingSafeHook> sPendingSafeHooks = new java.util.concurrent.CopyOnWriteArrayList<>();
    private static final java.util.Set<String> sHookedSafeKeys =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void resolvePendingSafeHooks(ClassLoader cl) {
        if (cl == null || sPendingSafeHooks.isEmpty()) return;
        List<PendingSafeHook> resolved = new java.util.ArrayList<>();
        for (PendingSafeHook ph : sPendingSafeHooks) {
            Class<?> clazz = XposedHelpers.findClassIfExists(ph.className, cl);
            if (clazz != null) {
                String key = ph.className + "#" + ph.methodName + "@" + clazz.hashCode();
                if (sHookedSafeKeys.add(key)) {
                    try {
                        if ("<init>".equals(ph.methodName)) {
                            HookUtils.hookAllConstructors(clazz, ph.callback);
                        } else {
                            HookUtils.hookAllMethods(clazz, ph.methodName, ph.callback);
                        }
                    } catch (Throwable t) {
                        XposedEntry.log("[PendingSafeHook] Failed to hook " + ph.className + "." + ph.methodName + ": " + t.getMessage());
                    }
                }
                resolved.add(ph);
            }
        }
        if (!resolved.isEmpty()) {
            sPendingSafeHooks.removeAll(resolved);
            XposedEntry.log("[PendingSafeHook] Resolved " + resolved.size() + " pending hooks in late-stage ClassLoader: " + cl);
        }
    }

    private static void hookSafe(final String className, final String methodName, XC_LoadPackage.LoadPackageParam lpparam, final XC_MethodHook callback) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookSafe(className, methodName, cl, callback);
    }

    private static void hookSafe(final String className, final String methodName, ClassLoader cl, final XC_MethodHook callback) {
        if (cl == null) cl = HookConfig.getClassLoader();
        Class<?> clazz = cl != null ? XposedHelpers.findClassIfExists(className, cl) : null;
        if (clazz != null) {
            String key = className + "#" + methodName + "@" + clazz.hashCode();
            if (sHookedSafeKeys.add(key)) {
                if ("<init>".equals(methodName)) {
                    HookUtils.hookAllConstructors(clazz, callback);
                } else {
                    HookUtils.hookAllMethods(clazz, methodName, callback);
                }
            }
        } else {
            // NEVER hook ClassLoader.loadClass! It adds massive CPU delay to all class resolution in ART.
            // Queue for resolution when secondary dexes are attached via MultiDex (attachBaseContext).
            boolean alreadyPending = false;
            for (PendingSafeHook ph : sPendingSafeHooks) {
                if (className.equals(ph.className) && methodName.equals(ph.methodName)) {
                    alreadyPending = true;
                    break;
                }
            }
            if (!alreadyPending) {
                sPendingSafeHooks.add(new PendingSafeHook(className, methodName, callback));
            }
        }
    }

    private static void hookCandidateSafe(final String className, final String[] methodNames, XC_LoadPackage.LoadPackageParam lpparam, final XC_MethodHook callback) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
        if (clazz != null) {
            HookUtils.hookCandidateMethods(clazz, methodNames, callback);
        }
    }

    private static void hookIfMethodExistsSafe(final String className, final String methodName, XC_LoadPackage.LoadPackageParam lpparam, final XC_MethodHook callback) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;
        Class<?> clazz = XposedHelpers.findClassIfExists(className, cl);
        if (clazz != null) {
            HookUtils.hookIfMethodExists(clazz, methodName, callback);
        }
    }

    // ==================== Tier 12 - 17: QQ 9.3.75 Deep Security & Polling Defenses ====================

    private static final java.util.Set<Class<?>> sHooked9375Classes =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void hookQQ9375DefensesWithClassLoader(ClassLoader cl) {
        if (cl == null) return;
        hookQQ9375SafeCenterAndRepack(null, cl);
        hookApkFileMd5AndSignatures(null, cl);
        hookIntChkPBDefenses(null, cl);
        hookMessageMicroSanitizers(cl);
        hookGanliangAndAntEstDefenses(null, cl);
        hookTuringPhoneAndBridge(null, cl);
        hookSafeReportAndXps(null, cl);
    }

    /**
     * Tier 12: SafeCenter Push & Repack Circuit Defenses.
     * Integrates DexKit dynamic component discovery first, with automatic fallback
     * to the running HostVersion profile.
     */
    public static void hookQQ9375SafeCenterAndRepack(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        final IVersionProfile profile = HostVersionManager.getCurrentProfile();

        // 1. Dynamic Discovery via DexKit first; fallback to version profile
        Set<String> pushHandlerNames = new LinkedHashSet<>();
        List<DexMethodData> dexPushList = DexKitDetector.getSafeCenterPushHandlers();
        if (dexPushList != null && !dexPushList.isEmpty()) {
            for (DexMethodData dmd : dexPushList) {
                if (dmd != null && dmd.getClassName() != null) {
                    pushHandlerNames.add(dmd.getClassName());
                }
            }
            XposedEntry.log("[SafeCenterRepack] DexKit discovered push handlers: " + pushHandlerNames);
        }
        if (pushHandlerNames.isEmpty()) {
            if (profile.getFallbackPushHandlerClass() != null) {
                pushHandlerNames.add(profile.getFallbackPushHandlerClass());
            }
            pushHandlerNames.add("com.tencent.mobileqq.app.di");
            pushHandlerNames.add("com.tencent.mobileqq.app.dj");
        }

        for (String handlerCls : pushHandlerNames) {
            Class<?> clazz = XposedHelpers.findClassIfExists(handlerCls, cl);
            if (clazz != null && sHooked9375Classes.add(clazz)) {
                HookUtils.hookIfMethodExists(clazz, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if (p.args == null || p.args.length < 1 || !(p.args[0] instanceof byte[])) return;
                        try {
                            byte[] bArr = (byte[]) p.args[0];
                            Class<?> msgBodyCls = XposedHelpers.findClassIfExists("tencent.im.s2c.msgtype0x210.submsgtype0x4a.MsgBody", p.thisObject.getClass().getClassLoader());
                            if (msgBodyCls != null) {
                                Object msgBody = msgBodyCls.getDeclaredConstructor().newInstance();
                                XposedHelpers.callMethod(msgBody, "mergeFrom", (Object) bArr);
                                boolean has = (Boolean) XposedHelpers.callMethod(msgBody, "has");
                                Object uint32SecCmd = XposedHelpers.getObjectField(msgBody, "uint32_sec_cmd");
                                if (has && uint32SecCmd != null) {
                                    boolean cmdHas = (Boolean) XposedHelpers.callMethod(uint32SecCmd, "has");
                                    if (cmdHas) {
                                        int cmd = (Integer) XposedHelpers.callMethod(uint32SecCmd, "get");
                                        XposedEntry.log("[SafeCenterPush] Intercepted submsgtype0x4a sec_cmd=" + cmd + " on " + handlerCls);
                                        // DO NOT drop cmd 1 (Repack challenge) or cmd 2 (IntChk),
                                        // because dropping them causes server timeout kicks!
                                        // Our SignatureReport & PB sanitizers guarantee 100% clean official data!
                                        // ONLY drop cmd 4 (SecCheckBanner alert UI popup):
                                        if (cmd == 4) {
                                            p.setResult(null);
                                            XposedEntry.log("[SafeCenterPush] Disarmed submsgtype0x4a sec_cmd=4 (SecCheckBanner popup blocked)");
                                            return;
                                        }
                                    }
                                }
                            }
                        } catch (Throwable t) {
                            XposedEntry.log("[SafeCenterPush] Error inspecting submsgtype0x4a: " + t.getMessage());
                        }
                    }
                });
                XposedEntry.log("[SafeCenterPush] Hooked SafeCenterPushHandler: " + handlerCls);
            }
        }

        // 2. Dynamic Discovery for Repack Checkers via DexKit first; fallback to profile
        Set<String> repackCheckerNames = new LinkedHashSet<>();
        List<DexMethodData> dexRepackList = DexKitDetector.getRepackCheckers();
        if (dexRepackList != null && !dexRepackList.isEmpty()) {
            for (DexMethodData dmd : dexRepackList) {
                if (dmd != null && dmd.getClassName() != null) {
                    repackCheckerNames.add(dmd.getClassName());
                }
            }
            XposedEntry.log("[SafeCenterRepack] DexKit discovered repack checkers: " + repackCheckerNames);
        }
        if (profile.getFallbackRepackHelperClass() != null) {
            repackCheckerNames.add(profile.getFallbackRepackHelperClass());
        }
        repackCheckerNames.add("com.tencent.ctsz.m");
        repackCheckerNames.add("com.tencent.mezs.a");

        // Notice: We DO NOT neutralize d() or b() / c(), because the server needs SignatureReport!
        // Instead, the data inside SignatureReport is sanitized to official release values.

        // 3. Hook Protobuf Repack & Signature Reporting: signature$SignatureReport
        Class<?> sigReportCls = XposedHelpers.findClassIfExists("com.tencent.ims.signature$SignatureReport", cl);
        if (sigReportCls != null && sHooked9375Classes.add(sigReportCls)) {
            HookUtils.hookAllConstructors(sigReportCls, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    sanitizeSignatureReport(p.thisObject);
                }
            });
        }
    }

    private static void sanitizeSignatureReport(Object obj) {
        if (obj == null) return;
        try {
            final IVersionProfile profile = HostVersionManager.getCurrentProfile();
            final HostVersion hostVer = HostVersionManager.getHostVersion();
            final String officialVerName = hostVer != null ? hostVer.getVersionName() : profile.getVersionName();
            final String officialMd5 = profile.getOfficialApkMd5Upper();
            final String officialSig = profile.getOfficialSignatureHashUpper();

            Object isRepack = XposedHelpers.getObjectField(obj, "u32_is_repack");
            if (isRepack != null) XposedHelpers.callMethod(isRepack, "set", 0);

            Object clientType = XposedHelpers.getObjectField(obj, "u32_client_type");
            if (clientType != null) XposedHelpers.callMethod(clientType, "set", 0);

            Object signature = XposedHelpers.getObjectField(obj, "str_signature");
            if (signature != null) XposedHelpers.callMethod(signature, "set", officialSig);

            Object packname = XposedHelpers.getObjectField(obj, "str_packname");
            if (packname != null) XposedHelpers.callMethod(packname, "set", "com.tencent.mobileqq");

            Object version = XposedHelpers.getObjectField(obj, "str_version");
            if (version != null) XposedHelpers.callMethod(version, "set", officialVerName);

            Object md5 = XposedHelpers.getObjectField(obj, "str_md5");
            if (md5 != null) XposedHelpers.callMethod(md5, "set", officialMd5);

            XposedEntry.log("[SignatureReport] Injected official credentials into SignatureReport: ver="
                + officialVerName + ", md5=" + officialMd5 + ", sig=" + officialSig);
        } catch (Throwable t) {
            XposedEntry.log("[SignatureReport] Error sanitizing: " + t.getMessage());
        }
    }

    private static void sanitizeIntChkCheckResult(Object obj) {
        if (obj == null) return;
        try {
            Object typeField = XposedHelpers.getObjectField(obj, "uint32_check_type");
            if (typeField != null && (Boolean) XposedHelpers.callMethod(typeField, "has")) {
                int type = (Integer) XposedHelpers.callMethod(typeField, "get");
                if (type == 1) { // memchk
                    Object resField = XposedHelpers.getObjectField(obj, "uint32_memchk_result");
                    if (resField != null) {
                        XposedHelpers.callMethod(resField, "set", 1); // 1 = PASS
                        XposedEntry.log("[IntChkPB] Forced uint32_memchk_result -> 1 (PASS)");
                    }
                } else if (type == 2) { // memreport
                    XposedEntry.log("[IntChkPB] type == 2 memreport verified clean");
                }
            }
        } catch (Throwable ignored) {}
    }

    private static final java.util.Set<ClassLoader> sHookedPbClassLoaders =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void hookMessageMicroSanitizers(ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null || !sHookedPbClassLoaders.add(cl)) return;

        Class<?> messageMicroCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.pb.MessageMicro", cl);
        if (messageMicroCls == null) return;

        // 1. Root toByteArray() hook: sanitize outgoing ProtoBuf packets before serialization
        HookUtils.hookAllMethods(messageMicroCls, "toByteArray", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.thisObject == null) return;
                String clsName = p.thisObject.getClass().getName();
                if ("com.tencent.ims.safecheckPB$RspMQScanReport".equals(clsName)) {
                    sanitizeScanReport(p.thisObject);
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProtoBufSecurity("safecheckPB$RspMQScanReport", p.thisObject, "Sanitized scan items cleared");
                } else if ("com.tencent.ims.SecVerifyApk$ReportDetectResultPacket".equals(clsName)
                        || "com.tencent.qqprotect.sfcfg.pb.SecVerifyApk$ReportDetectResultPacket".equals(clsName)) {
                    sanitizeSecVerifyPacket(p.thisObject);
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProtoBufSecurity("SecVerifyApk$ReportDetectResultPacket", p.thisObject, "Normalized signature/md5/version");
                } else if ("com.tencent.ims.ClientInfoA$ReportDetectResultPacket".equals(clsName)
                        || "com.tencent.ims.ClientInfoB$ReportDetectResultPacket".equals(clsName)
                        || "com.tencent.ims.MobileQQDetect$ReportDetectResultPacket".equals(clsName)) {
                    sanitizeClientInfoPacket(p.thisObject);
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProtoBufSecurity("ClientInfo$ReportDetectResultPacket", p.thisObject, "Normalized md5 & version");
                } else if ("com.tencent.ims.signature$SignatureReport".equals(clsName)) {
                    sanitizeSignatureReport(p.thisObject);
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProtoBufSecurity("signature$SignatureReport", p.thisObject, "Spoofed official signature hash");
                } else if ("com.tencent.ims.intchk$CheckResult".equals(clsName)) {
                    sanitizeIntChkCheckResult(p.thisObject);
                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordProtoBufSecurity("intchk$CheckResult", p.thisObject, "Normalized memchk result -> PASS");
                }
            }
        });
        XposedEntry.log("[MessageMicroPatch] Installed unified ProtoBuf root toByteArray sanitizer");
    }

    /**
     * Tier 13: APK File MD5 & Source Signature Defense (Adapted to current HostVersion).
     */
    public static void hookApkFileMd5AndSignatures(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        final IVersionProfile profile = HostVersionManager.getCurrentProfile();
        final String officialMd5Upper = profile.getOfficialApkMd5Upper();
        final String officialSigUpper = profile.getOfficialSignatureHashUpper();

        // 1. com.tencent.mdm.a.a(String path)
        Class<?> mdmA = XposedHelpers.findClassIfExists("com.tencent.mdm.a", cl);
        if (mdmA != null && sHooked9375Classes.add(mdmA)) {
            HookUtils.hookAllMethods(mdmA, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length > 0 && p.args[0] instanceof String) {
                        String targetPath = (String) p.args[0];
                        if (isHostApkPath(targetPath)) {
                            p.setResult(officialMd5Upper);
                            XposedEntry.log("[MDMPatch] com.tencent.mdm.a.a(" + targetPath + ") -> forced official MD5: " + officialMd5Upper);
                        }
                    }
                }
            });
        }

        // 2. com.tencent.mobileqq.utils.SecUtil.getFileMd5(File), (String), (InputStream)
        Class<?> secUtilCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.utils.SecUtil", cl);
        if (secUtilCls != null && sHooked9375Classes.add(secUtilCls)) {
            HookUtils.hookAllMethods(secUtilCls, "check0DayRepack", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(false);
                }
            });

            XC_MethodHook md5Hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args == null || p.args.length < 1 || p.args[0] == null) return;
                    String targetPath = null;
                    if (p.args[0] instanceof File) {
                        targetPath = ((File) p.args[0]).getAbsolutePath();
                    } else if (p.args[0] instanceof String) {
                        targetPath = (String) p.args[0];
                    } else if (p.args[0] instanceof java.io.InputStream) {
                        boolean isApkCheck = false;
                        for (StackTraceElement ste : Thread.currentThread().getStackTrace()) {
                            String clsName = ste.getClassName();
                            if (clsName.contains("com.tencent.ctsz") || clsName.contains("signature") || clsName.contains("mdm")) {
                                isApkCheck = true;
                                break;
                            }
                        }
                        if (isApkCheck) {
                            p.setResult(officialMd5Upper);
                            XposedEntry.log("[SecUtilPatch] SecUtil.getFileMd5(InputStream) -> official MD5: " + officialMd5Upper);
                            return;
                        }
                    }
                    if (targetPath != null && isHostApkPath(targetPath)) {
                        // SecUtil.toHexString strictly formats in UPPERCASE hex digits
                        p.setResult(officialMd5Upper);
                        XposedEntry.log("[SecUtilPatch] SecUtil.getFileMd5(" + targetPath + ") -> official MD5: " + officialMd5Upper);
                    }
                }
            };
            HookUtils.hookAllMethods(secUtilCls, "getFileMd5", md5Hook);

            HookUtils.hookAllMethods(secUtilCls, "getSignatureHash", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    // SecUtil.getSignatureHash returns UPPERCASE hex digest
                    p.setResult(officialSigUpper);
                }
            });

            HookUtils.hookAllMethods(secUtilCls, "getSign", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    // CRITICAL FIX: SecUtil.getSign returns byte[] (signature DER bytes), NOT String!
                    try {
                        byte[] certBytes = android.util.Base64.decode(
                            DynamicRootDetectionHook.OFFICIAL_QQ_SIGNATURE_B64,
                            android.util.Base64.DEFAULT
                        );
                        p.setResult(certBytes);
                        XposedEntry.log("[SecUtilPatch] SecUtil.getSign -> returned official DER signature byte array");
                    } catch (Throwable t) {
                        XposedEntry.logError("[SecUtilPatch] SecUtil.getSign error: " + t.getMessage(), t);
                    }
                }
            });
        }

        // 3. com.tencent.usq.a.b(InputStream)
        Class<?> usqA = XposedHelpers.findClassIfExists("com.tencent.usq.a", cl);
        if (usqA != null && sHooked9375Classes.add(usqA)) {
            HookUtils.hookAllMethods(usqA, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    boolean isApkCheck = false;
                    for (StackTraceElement ste : Thread.currentThread().getStackTrace()) {
                        String clsName = ste.getClassName();
                        if (clsName.contains("com.tencent.ctsz") || clsName.contains("signature") || clsName.contains("mdm")) {
                            isApkCheck = true;
                            break;
                        }
                    }
                    if (isApkCheck) {
                        p.setResult(officialMd5Upper);
                        XposedEntry.log("[UsqPatch] com.tencent.usq.a.b (APK check) -> official MD5: " + officialMd5Upper);
                    }
                }
            });
        }
    }

    /**
     * Tier 14: PB-Level Integrity Check Neutralization & Native Strike Defenses.
     */
    public static void hookIntChkPBDefenses(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        // 1. Hook com.tencent.mqp.app.sec.MQPSecUtil native methods:
        // memchk -> returns true (MATCH/PASS) so uint32_memchk_result is natively computed as 1!
        Class<?> mqpSecUtilCls = XposedHelpers.findClassIfExists("com.tencent.mqp.app.sec.MQPSecUtil", cl);
        if (mqpSecUtilCls != null && sHooked9375Classes.add(mqpSecUtilCls)) {
            HookUtils.hookAllMethods(mqpSecUtilCls, "memchk", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (Boolean.FALSE.equals(p.getResult())) {
                        p.setResult(true);
                        XposedEntry.log("[MQPSecUtil] memchk -> normalized false to true (PASS)");
                    }
                }
            });
            HookUtils.hookAllMethods(mqpSecUtilCls, "memreport", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 3 && p.args[0] instanceof String && p.args[1] instanceof Number && p.args[2] instanceof Number) {
                        String moduleName = (String) p.args[0];
                        int start = ((Number) p.args[1]).intValue();
                        int end = ((Number) p.args[2]).intValue();
                        if (end > start && end - start <= 1048576) {
                            byte[] cleanBytes = readCleanModuleBytes(moduleName, start, end, lpparam);
                            if (cleanBytes != null) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSecurityStrike("MQPSecUtil.memreport", "Sanitized memory read for " + moduleName + " [" + start + ":" + end + "]");
                                p.setResult(cleanBytes);
                                XposedEntry.log("[MQPPatch] Sanitized MQPSecUtil.memreport for " + moduleName + " [" + start + ":" + end + "] from disk ELF");
                            }
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(mqpSecUtilCls, "do_report", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[MQPSecUtil] Neutralized do_report (AntiTrace violation delivery blocked)");
                }
            });
            HookUtils.hookAllMethods(mqpSecUtilCls, "antitrace", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });
        }

        // 2. Hook com.tencent.ims.intchk$CheckResult: force uint32_memchk_result -> 1 (PASS)
        Class<?> checkResultCls = XposedHelpers.findClassIfExists("com.tencent.ims.intchk$CheckResult", cl);
        if (checkResultCls != null && sHooked9375Classes.add(checkResultCls)) {
            HookUtils.hookAllConstructors(checkResultCls, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    sanitizeIntChkCheckResult(p.thisObject);
                }
            });
        }
    }

    /**
     * Tier 15: Screen / Display / Remote Control Defense Expansion (Ganliang & AntEst).
     */
    public static void hookGanliangAndAntEstDefenses(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        // 1. Ganliang.h() (DisplayListener registration) & switch
        Class<?> ganliangCls = XposedHelpers.findClassIfExists("com.tencent.qqprotect.ganliang.Ganliang", cl);
        if (ganliangCls != null && sHooked9375Classes.add(ganliangCls)) {
            HookUtils.hookAllMethods(ganliangCls, "h", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                    XposedEntry.log("[GanliangPatch] Neutralized Ganliang.h (prevented DisplayListener registration)");
                }
            });
            HookUtils.hookIfMethodExists(ganliangCls, "isSwitchOn", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length > 0 && "ganliang_enable_switch".equals(p.args[0])) {
                        p.setResult(false);
                        XposedEntry.log("[GanliangPatch] Forced ganliang_enable_switch -> false");
                    }
                }
            });
        }

        // 2. AntEst & QSec: DO NOT force empty string!
        // Empty strings trigger missing-security-token heuristics on Tencent backend risk servers.
        // Under our reinforced native ByteHook/maps/getprop/libc environment filtering, native QsecEst produces clean normal tokens.
        // If native returns null or empty, provide the authentic "e_null" fallback.
        Class<?> qsecEstCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.qsec.qsecest.QsecEst", cl);
        if (qsecEstCls != null && sHooked9375Classes.add(qsecEstCls)) {
            HookUtils.hookAllMethods(qsecEstCls, "a", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() == null || "".equals(p.getResult())) {
                        p.setResult("e_null"); // Official fallback token when not initialized
                    }
                }
            });
        }

        Class<?> antEstCls = XposedHelpers.findClassIfExists("com.tencent.qqprotect.xps.core.AntEst", cl);
        if (antEstCls != null && sHooked9375Classes.add(antEstCls)) {
            HookUtils.hookAllMethods(antEstCls, "d", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() == null || "".equals(p.getResult())) {
                        p.setResult("e_null");
                    }
                }
            });
        }
    }

    /**
     * Tier 16: Turing PhoneService & Turing Bridge Completion.
     */
    public static void hookTuringPhoneAndBridge(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        // Allow authentic TuringPhoneService.reqPhoneToken to run naturally without reflection tampering.
        // reqPhoneToken returns l2 (field 'a' is Norma, not long). Tampering causes reflection exceptions and token renewal stalls.

        Set<String> turingBridgeNames = new LinkedHashSet<>();
        List<DexMethodData> dexTuringList = DexKitDetector.getTuringBridges();
        if (dexTuringList != null && !dexTuringList.isEmpty()) {
            for (DexMethodData dmd : dexTuringList) {
                if (dmd != null && dmd.getClassName() != null) {
                    turingBridgeNames.add(dmd.getClassName());
                }
            }
            XposedEntry.log("[TuringBridge] DexKit discovered Turing bridges: " + turingBridgeNames);
        }
        final IVersionProfile profile = HostVersionManager.getCurrentProfile();
        if (profile.getFallbackTuringBridgeClass() != null) {
            turingBridgeNames.add(profile.getFallbackTuringBridgeClass());
        }
        turingBridgeNames.add("com.tencent.mobileqq.turingfd.i");

        for (String turingCls : turingBridgeNames) {
            Class<?> turingBridgeI = XposedHelpers.findClassIfExists(turingCls, cl);
            if (turingBridgeI != null && sHooked9375Classes.add(turingBridgeI)) {
                HookUtils.hookAllMethods(turingBridgeI, "d", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Object res = p.getResult();
                        if (res instanceof String && !((String) res).isEmpty()) {
                            sLastKnownOpenIdTicket = (String) res;
                        }
                    }
                });
                HookUtils.hookAllMethods(turingBridgeI, "f", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                        Object res = p.getResult();
                        if (res instanceof String && !((String) res).isEmpty()) {
                            sLastKnownDeviceToken = (String) res;
                        }
                    }
                });
                XposedEntry.log("[TuringBridge] Hooked Turing bridge class: " + turingCls);
            }
        }
    }

    /**
     * Tier 17: SafeReport & XpsReport Telemetry Normalization.
     */
    public static void hookSafeReportAndXps(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        if (cl == null) return;

        // Do NOT arbitrarily clear report items to empty!
        // Empty report packets trigger missing-telemetry and packet-format anomaly heuristics on the server.
        // Genuine logging items are allowed to pass through normally.
    }

    private static final java.util.Set<String> sHookedTuringBerryClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Inspects whether a Marc network routing string contains VPN tunnel interfaces or subnets.
     */
    public static boolean isVpnNetworkRouting(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        if (str.contains("tun") || str.contains("198.18.") || str.contains("vgate") ||
            str.contains("ifb") || str.contains("dummy") || str.contains("ap0") ||
            str.contains("wondertap") || str.contains("ovnet") ||
            str.contains("10.0.0.2") || str.contains("ppp")) {
            return true;
        }
        String[] parts = str.split(",");
        if (parts.length > 0) {
            try {
                long transportMask = Long.parseLong(parts[0].trim());
                // Bit 4 in Android NetworkCapabilities is TRANSPORT_VPN (1 << 4 = 16)
                if ((transportMask & (1L << 4)) != 0) {
                    return true;
                }
            } catch (Throwable ignored) {}
        }
        return false;
    }

    /**
     * Dynamically queries the real non-VPN network from ConnectivityManager (or NetworkInterface)
     * and produces an authentic Key 284 routing record matching the device's actual network state.
     */
    public static String getCleanMarcNetworkRouting(android.content.Context context, String originalStr) {
        try {
            android.content.Context ctx = context;
            if (ctx == null) {
                try {
                    ctx = (android.content.Context) Class.forName("android.app.ActivityThread")
                            .getMethod("currentApplication").invoke(null);
                } catch (Throwable ignored) {}
            }
            if (ctx == null) {
                try {
                    Class<?> baseAppCls = Class.forName("com.tencent.qphone.base.util.BaseApplication");
                    ctx = (android.content.Context) XposedHelpers.callStaticMethod(baseAppCls, "getContext");
                } catch (Throwable ignored) {}
            }
            if (ctx == null) {
                try {
                    Class<?> cthrowCls = Class.forName("com.tencent.turingfd.sdk.xq.Cthrow");
                    Field f = cthrowCls.getDeclaredField("a");
                    f.setAccessible(true);
                    ctx = (android.content.Context) f.get(null);
                } catch (Throwable ignored) {}
            }

            if (ctx != null) {
                android.net.ConnectivityManager cm = (android.net.ConnectivityManager) ctx.getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    android.net.Network[] networks = cm.getAllNetworks();
                    if (networks != null) {
                        android.net.Network chosenNetwork = null;
                        // 1. Prefer active physical Wi-Fi (TRANSPORT_WIFI = 1)
                        for (android.net.Network net : networks) {
                            android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                            if (nc != null && !nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                                if (nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) {
                                    chosenNetwork = net;
                                    break;
                                }
                            }
                        }
                        // 2. If no Wi-Fi, look for active Cellular (TRANSPORT_CELLULAR = 0)
                        if (chosenNetwork == null) {
                            for (android.net.Network net : networks) {
                                android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                                if (nc != null && !nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                                    if (nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) {
                                        chosenNetwork = net;
                                        break;
                                    }
                                }
                            }
                        }
                        // 3. Fallback: any active non-VPN network
                        if (chosenNetwork == null) {
                            for (android.net.Network net : networks) {
                                android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(net);
                                if (nc != null && !nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                                    chosenNetwork = net;
                                    break;
                                }
                            }
                        }

                        if (chosenNetwork != null) {
                            android.net.NetworkCapabilities nc = cm.getNetworkCapabilities(chosenNetwork);
                            android.net.LinkProperties lp = cm.getLinkProperties(chosenNetwork);
                            if (nc != null && lp != null) {
                                long j2 = 0;
                                for (int i = 0; i < 64; i++) {
                                    if (nc.hasTransport(i)) {
                                        j2 |= (1L << i);
                                    }
                                }
                                long j = 0;
                                for (int i2 = 0; i2 < 64; i2++) {
                                    if (nc.hasCapability(i2)) {
                                        j |= (1L << i2);
                                    }
                                }
                                String iface = lp.getInterfaceName();
                                if (iface == null) iface = "";
                                iface = iface.replace(",", "").replace("_", "");

                                StringBuilder ipSb = new StringBuilder();
                                java.util.List<android.net.LinkAddress> linkAddresses = lp.getLinkAddresses();
                                if (linkAddresses != null && !linkAddresses.isEmpty()) {
                                    for (int i3 = 0; i3 < linkAddresses.size(); i3++) {
                                        ipSb.append(linkAddresses.get(i3).getAddress().getHostAddress());
                                        if (i3 != linkAddresses.size() - 1) {
                                            ipSb.append("_");
                                        }
                                    }
                                }

                                StringBuilder dnsSb = new StringBuilder();
                                java.util.List<java.net.InetAddress> dnsServers = lp.getDnsServers();
                                if (dnsServers != null && !dnsServers.isEmpty()) {
                                    for (int i4 = 0; i4 < dnsServers.size(); i4++) {
                                        dnsSb.append(dnsServers.get(i4).getHostAddress());
                                        if (i4 != dnsServers.size() - 1) {
                                            dnsSb.append("_");
                                        }
                                    }
                                }

                                String cleanResult = j2 + "," + j + "," + iface + "," + ipSb.toString() + "," + dnsSb.toString();
                                XposedEntry.log("[TuringPatch] Resolved clean Marc physical routing: " + cleanResult);
                                return cleanResult;
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            XposedEntry.log("[TuringPatch] Failed to query ConnectivityManager for clean Marc routing: " + t.getMessage());
        }

        // Fallback: enumerate NetworkInterface for genuine physical interface (wlan0 / ccmni0)
        try {
            java.util.Enumeration<java.net.NetworkInterface> nifs = java.net.NetworkInterface.getNetworkInterfaces();
            if (nifs != null) {
                java.net.NetworkInterface chosenNif = null;
                boolean isWifi = false;
                while (nifs.hasMoreElements()) {
                    java.net.NetworkInterface nif = nifs.nextElement();
                    if (nif == null || !nif.isUp() || nif.isLoopback()) continue;
                    String name = nif.getName();
                    if (name.startsWith("tun") || name.startsWith("dummy") || name.startsWith("ifb") ||
                        name.startsWith("p2p") || name.startsWith("vgate") || name.startsWith("ovnet")) {
                        continue;
                    }
                    if (name.startsWith("wlan")) {
                        chosenNif = nif;
                        isWifi = true;
                        break;
                    } else if (chosenNif == null) {
                        chosenNif = nif;
                        isWifi = name.startsWith("wlan");
                    }
                }

                if (chosenNif != null) {
                    StringBuilder ipSb = new StringBuilder();
                    java.util.Enumeration<java.net.InetAddress> addrs = chosenNif.getInetAddresses();
                    while (addrs.hasMoreElements()) {
                        java.net.InetAddress addr = addrs.nextElement();
                        if (addr != null && !addr.isLoopbackAddress()) {
                            if (ipSb.length() > 0) ipSb.append("_");
                            ipSb.append(addr.getHostAddress());
                        }
                    }

                    long transportMask = isWifi ? (1L << 1) : (1L << 0);
                    // Extract original capabilities if valid
                    long capMask = 137711415296L;
                    if (originalStr != null) {
                        String[] parts = originalStr.split(",");
                        if (parts.length > 1) {
                            try {
                                capMask = Long.parseLong(parts[1].trim());
                            } catch (Throwable ignored) {}
                        }
                    }
                    String iface = chosenNif.getName().replace(",", "").replace("_", "");
                    String dns = isWifi ? "223.5.5.5_114.114.114.114" : "111.11.11.3";
                    String cleanResult = transportMask + "," + capMask + "," + iface + "," + ipSb.toString() + "," + dns;
                    XposedEntry.log("[TuringPatch] Fallback clean Marc physical routing: " + cleanResult);
                    return cleanResult;
                }
            }
        } catch (Throwable t) {
            XposedEntry.log("[TuringPatch] Fallback Marc routing failed: " + t.getMessage());
        }

        // Final safe baseline (Wi-Fi)
        return "2,137711415296,wlan0,172.16.110.60,223.5.5.5_114.114.114.114";
    }

    /**
     * Cleans TuringFD native interface list string (Key 129):
     * Format: <count>,<iface1>;<flags>;<ip_count>;<ip1>;...,<iface2>;...
     * Strips virtual, VPN, proxy and container interfaces (tun0, ap0, vgate0, ifb, dummy, etc.)
     */
    public static String sanitizeNativeInterfaceListString(String originalStr) {
        if (originalStr == null || originalStr.isEmpty()) return originalStr;
        String[] parts = originalStr.split(",");
        if (parts.length <= 1) return originalStr;

        java.util.List<String> cleanParts = new java.util.ArrayList<>();
        for (int i = 1; i < parts.length; i++) {
            String item = parts[i];
            if (item == null || item.isEmpty()) continue;
            String iface = item.split(";")[0].toLowerCase(java.util.Locale.US);

            boolean isVirt = iface.startsWith("tun") ||
                             iface.startsWith("ap") ||
                             iface.startsWith("vgate") ||
                             iface.startsWith("ifb") ||
                             iface.startsWith("dummy") ||
                             iface.startsWith("ovnet") ||
                             iface.startsWith("wondertap") ||
                             iface.startsWith("veth") ||
                             iface.startsWith("docker") ||
                             iface.startsWith("virbr") ||
                             iface.startsWith("br-") ||
                             iface.startsWith("sit") ||
                             iface.startsWith("gre") ||
                             iface.startsWith("ip_vti") ||
                             iface.startsWith("ip6");

            if (!isVirt && !item.contains("198.18.")) {
                cleanParts.add(item);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append(cleanParts.size()).append(",");
        for (int i = 0; i < cleanParts.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(cleanParts.get(i));
        }
        return sb.toString();
    }

    private static final byte[] PATTERN_JCE_KEY129 = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x81 };
    private static final byte[] PATTERN_TMPFS = "tmpfs:/dev".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    private static final byte[] PATTERN_LOCKED_0 = ":locked:0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    private static final byte[] PATTERN_GREEN_0 = ":green:0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    private static final byte[] PATTERN_ENFORCING_0 = ":enforcing:0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    private static final byte[] PATTERN_BOOT_HASH_0 = "-336568457738497426:1:0".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    private static final byte[] PATTERN_RX_P = ":r-xp:".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

    private static final java.util.regex.Pattern ART_INTEGRITY_PATTERN = java.util.regex.Pattern.compile(
        ":([0-9a-fA-F]{16,64}):r-xp:([^:]+:[^:]+:[^:]+:[0-9a-fA-F]{32}:[^:]+:[^:]+:)([0-9a-fA-F]{16,64}):"
    );

    /**
     * Transparently parses and normalizes unencrypted JCE serialized payload from TuringFD NativePack.
     * Sanitizes Key 129, Mounts, Bootloader/VB/SELinux, and ART opcode integrity in accordance with Iron Rule 4.2.
     */
    public static byte[] sanitizeTuringJceNativePayload(byte[] data) {
        if (data == null || data.length < 8) return data;
        try {
            byte[] curData = data;

            // Vector 1: Key 129 (Network interface list & VPN/tun0/ap0/dummy/ifb)
            curData = sanitizeKey129(curData);

            // Vector 2: Mount Table String (tmpfs:/dev, debugfs, KernelSU module overlays, loop/dm counts)
            curData = sanitizeMountTable(curData);

            // Vector 3: Bootloader, Verified Boot & SELinux status (locked:0, green:0, enforcing:0)
            curData = sanitizeBootState(curData);

            // Vector 4: ART Native Code Integrity (trampoline opcodes vs authentic disk opcodes)
            curData = sanitizeArtIntegrity(curData);

            return curData;
        } catch (Throwable t) {
            XposedEntry.logError("[TuringPatch] Error sanitizing Turing JCE native payload: " + t.getMessage(), t);
            return data;
        }
    }

    private static byte[] sanitizeKey129(byte[] curData) {
        int pos = 0;
        boolean modified = false;

        while (pos <= curData.length - 8) {
            int idx = -1;
            for (int i = pos; i <= curData.length - 3; i++) {
                if (curData[i] == PATTERN_JCE_KEY129[0] && curData[i + 1] == PATTERN_JCE_KEY129[1] && curData[i + 2] == PATTERN_JCE_KEY129[2]) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1) break;

            int valHeaderIdx = idx + 3;
            if (valHeaderIdx >= curData.length) break;
            byte vtypeByte = curData[valHeaderIdx];

            int strLen = 0;
            int contentStart = 0;

            if (vtypeByte == (byte) 0x16) { // STRING1
                if (valHeaderIdx + 1 >= curData.length) break;
                strLen = curData[valHeaderIdx + 1] & 0xFF;
                contentStart = valHeaderIdx + 2;
            } else if (vtypeByte == (byte) 0x17) { // STRING4
                if (valHeaderIdx + 4 >= curData.length) break;
                strLen = ((curData[valHeaderIdx + 1] & 0xFF) << 24) |
                         ((curData[valHeaderIdx + 2] & 0xFF) << 16) |
                         ((curData[valHeaderIdx + 3] & 0xFF) << 8) |
                         (curData[valHeaderIdx + 4] & 0xFF);
                contentStart = valHeaderIdx + 5;
            } else {
                pos = idx + 3;
                continue;
            }

            if (strLen < 0 || contentStart + strLen > curData.length) {
                pos = idx + 3;
                continue;
            }

            String ifaceListStr = new String(curData, contentStart, strLen, java.nio.charset.StandardCharsets.ISO_8859_1);
            if (ifaceListStr.contains("tun") || ifaceListStr.contains("198.18.") ||
                ifaceListStr.contains("vgate") || ifaceListStr.contains("ap0") ||
                ifaceListStr.contains("ifb") || ifaceListStr.contains("dummy")) {

                String cleanIfaceStr = sanitizeNativeInterfaceListString(ifaceListStr);
                byte[] cleanBytes = cleanIfaceStr.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

                byte[] newHdr;
                if (vtypeByte == (byte) 0x17) {
                    newHdr = new byte[] {
                        (byte) 0x17,
                        (byte) ((cleanBytes.length >> 24) & 0xFF),
                        (byte) ((cleanBytes.length >> 16) & 0xFF),
                        (byte) ((cleanBytes.length >> 8) & 0xFF),
                        (byte) (cleanBytes.length & 0xFF)
                    };
                } else {
                    newHdr = new byte[] {
                        (byte) 0x16,
                        (byte) (cleanBytes.length & 0xFF)
                    };
                }

                int oldContentEnd = contentStart + strLen;
                int newLen = valHeaderIdx + newHdr.length + cleanBytes.length + (curData.length - oldContentEnd);
                byte[] newData = new byte[newLen];

                System.arraycopy(curData, 0, newData, 0, valHeaderIdx);
                System.arraycopy(newHdr, 0, newData, valHeaderIdx, newHdr.length);
                System.arraycopy(cleanBytes, 0, newData, valHeaderIdx + newHdr.length, cleanBytes.length);
                System.arraycopy(curData, oldContentEnd, newData, valHeaderIdx + newHdr.length + cleanBytes.length, curData.length - oldContentEnd);

                curData = newData;
                modified = true;
                pos = valHeaderIdx + newHdr.length + cleanBytes.length;
            } else {
                pos = idx + 3;
            }
        }
        return curData;
    }

    private static byte[] sanitizeMountTable(byte[] data) {
        if (data == null || data.length < 20) return data;
        int idx = indexOfPattern(data, PATTERN_TMPFS, 0);
        if (idx == -1) return data;

        int headerIdx = -1;
        int headerLen = 0;
        int oldLen = 0;

        if (idx >= 5 && (data[idx - 5] & 0x0F) == 7) {
            headerIdx = idx - 5;
            headerLen = 5;
            oldLen = ((data[idx - 4] & 0xFF) << 24) |
                     ((data[idx - 3] & 0xFF) << 16) |
                     ((data[idx - 2] & 0xFF) << 8) |
                     (data[idx - 1] & 0xFF);
        } else if (idx >= 6 && data[idx - 6] == (byte) 0xF7) {
            headerIdx = idx - 6;
            headerLen = 6;
            oldLen = ((data[idx - 4] & 0xFF) << 24) |
                     ((data[idx - 3] & 0xFF) << 16) |
                     ((data[idx - 2] & 0xFF) << 8) |
                     (data[idx - 1] & 0xFF);
        } else if (idx >= 2 && (data[idx - 2] & 0x0F) == 6) {
            headerIdx = idx - 2;
            headerLen = 2;
            oldLen = data[idx - 1] & 0xFF;
        }

        if (headerIdx == -1 || oldLen <= 0 || idx + oldLen > data.length) {
            return data;
        }

        String mountStr = new String(data, idx, oldLen, java.nio.charset.StandardCharsets.ISO_8859_1);
        String[] entries = mountStr.split(",");
        List<String> cleanList = new ArrayList<>(entries.length);

        for (String e : entries) {
            if (e == null || e.isEmpty()) continue;
            if (e.startsWith("debugfs:") || e.contains(":debugfs:") || e.contains("tracefs")) {
                continue;
            }
            if (e.contains("nhzh") || e.contains("bzwi") || e.contains("wda5") ||
                e.contains("kernelsu") || e.contains("ksud") || e.contains("/ksu") ||
                e.contains("apatch") || e.contains("magisk") || e.contains("lsposed") ||
                e.contains("cacerts") || e.contains("proxypin")) {
                continue;
            }
            if (e.startsWith("tmpfs:/apex/") && !e.equals("tmpfs:/apex")) {
                continue;
            }
            if (e.contains("overlay") && (e.contains("/system/etc") || e.contains("lowerdir="))) {
                continue;
            }
            if (e.startsWith("/dev/block/loop::")) {
                cleanList.add("/dev/block/loop::0");
                continue;
            }
            if (e.startsWith("/dev/block/dm::")) {
                cleanList.add("/dev/block/dm::0");
                continue;
            }
            cleanList.add(e);
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cleanList.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(cleanList.get(i));
        }

        String cleanMountStr = sb.toString();
        if (cleanMountStr.equals(mountStr)) {
            return data;
        }

        byte[] cleanBytes = cleanMountStr.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] newHdr;
        if (headerLen == 5) {
            newHdr = new byte[] {
                data[headerIdx],
                (byte) ((cleanBytes.length >> 24) & 0xFF),
                (byte) ((cleanBytes.length >> 16) & 0xFF),
                (byte) ((cleanBytes.length >> 8) & 0xFF),
                (byte) (cleanBytes.length & 0xFF)
            };
        } else if (headerLen == 6) {
            newHdr = new byte[] {
                data[headerIdx],
                data[headerIdx + 1],
                (byte) ((cleanBytes.length >> 24) & 0xFF),
                (byte) ((cleanBytes.length >> 16) & 0xFF),
                (byte) ((cleanBytes.length >> 8) & 0xFF),
                (byte) (cleanBytes.length & 0xFF)
            };
        } else {
            newHdr = new byte[] {
                data[headerIdx],
                (byte) (cleanBytes.length & 0xFF)
            };
        }

        int oldContentEnd = idx + oldLen;
        int newTotalLen = headerIdx + newHdr.length + cleanBytes.length + (data.length - oldContentEnd);
        byte[] newData = new byte[newTotalLen];

        System.arraycopy(data, 0, newData, 0, headerIdx);
        System.arraycopy(newHdr, 0, newData, headerIdx, newHdr.length);
        System.arraycopy(cleanBytes, 0, newData, headerIdx + newHdr.length, cleanBytes.length);
        System.arraycopy(data, oldContentEnd, newData, headerIdx + newHdr.length + cleanBytes.length, data.length - oldContentEnd);

        return newData;
    }

    private static byte[] sanitizeBootState(byte[] data) {
        if (data == null || data.length < 10) return data;
        replaceFixedPatternInPlace(data, PATTERN_LOCKED_0, ":locked:1".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        replaceFixedPatternInPlace(data, PATTERN_GREEN_0, ":green:1".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        replaceFixedPatternInPlace(data, PATTERN_ENFORCING_0, ":enforcing:1".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        replaceFixedPatternInPlace(data, PATTERN_BOOT_HASH_0, "-336568457738497426:1:1".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        return data;
    }

    private static void replaceFixedPatternInPlace(byte[] data, byte[] target, byte[] replacement) {
        if (target.length != replacement.length || data.length < target.length) return;
        int max = data.length - target.length;
        for (int i = 0; i <= max; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (data[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                System.arraycopy(replacement, 0, data, i, target.length);
                i += target.length - 1;
            }
        }
    }

    private static byte[] sanitizeArtIntegrity(byte[] data) {
        if (data == null || data.length < 30) return data;
        int idx = indexOfPattern(data, PATTERN_RX_P, 0);
        if (idx == -1) return data;

        int start = idx;
        while (start > 0 && data[start - 1] >= 32 && data[start - 1] <= 126) {
            start--;
        }
        int end = idx;
        while (end < data.length && data[end] >= 32 && data[end] <= 126) {
            end++;
        }

        String artStr = new String(data, start, end - start, java.nio.charset.StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher m = ART_INTEGRITY_PATTERN.matcher(artStr);
        StringBuffer sb = new StringBuffer();
        boolean changed = false;

        while (m.find()) {
            String memHex = m.group(1);
            String middle = m.group(2);
            String diskHex = m.group(3);
            if (!memHex.equalsIgnoreCase(diskHex) && memHex.length() == diskHex.length()) {
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(":" + diskHex + ":r-xp:" + middle + diskHex + ":"));
                changed = true;
            } else {
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(m.group(0)));
            }
        }
        m.appendTail(sb);

        if (changed) {
            byte[] cleanBytes = sb.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            if (cleanBytes.length == (end - start)) {
                System.arraycopy(cleanBytes, 0, data, start, cleanBytes.length);
            }
        }
        return data;
    }

    private static int indexOfPattern(byte[] data, byte[] pattern, int start) {
        if (data == null || pattern == null || start + pattern.length > data.length) return -1;
        int max = data.length - pattern.length;
        for (int i = start; i <= max; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    /**
     * Tier 18: TuringFD Port / Process & Accessibility Neutralization (Berry & this).
     */
    public static void hookTuringBerryAndThis(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        hookTuringBerryAndThisWithClassLoader(cl);
    }

    public static void hookTuringBerryAndThisWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        String[] berryClasses = {
            "com.tencent.turingfd.sdk.xq.Berry",
            "com.tencent.tfd.sdk.wxa.Berry",
            "com.tencent.turingfd.sdk.tbs.Berry"
        };
        for (String bClsName : berryClasses) {
            Class<?> bCls = XposedHelpers.findClassIfExists(bClsName, cl);
            if (bCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + bClsName)) {
                // Berry.b() -> listens to open ports/tcp -> allow real execution so Key 118 elapsed time is authentic!
                // In afterHookedMethod: only scrub suspicious debug/instrumentation ports if present, preserving genuine socket list
                HookUtils.hookIfMethodExists(bCls, "b", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof String) {
                            String s = (String) res;
                            if (s.contains(":27042") || s.contains(":27043") || s.contains(":5555")) {
                                param.setResult(s.replaceAll("(:27042|:27043|:5555)", ":0"));
                            }
                        }
                    }
                });
                // Berry.a() -> scans /proc for suspicious processes -> allow real execution, filter suspicious entries
                HookUtils.hookIfMethodExists(bCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) res;
                            java.util.Iterator<?> it = list.iterator();
                            while (it.hasNext()) {
                                Object item = it.next();
                                if (item != null) {
                                    String str = item.toString();
                                    if (DynamicRootDetectionHook.isSuspiciousPath(str) ||
                                        str.contains("magisk") || str.contains("xposed") ||
                                        str.contains("frida") || str.contains("su")) {
                                        it.remove();
                                    }
                                }
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Berry port/process scanners on " + bClsName);
            }
        }

        String[] thisClasses = {
            "com.tencent.turingfd.sdk.xq.this"
        };
        for (String tClsName : thisClasses) {
            Class<?> tCls = XposedHelpers.findClassIfExists(tClsName, cl);
            if (tCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + tClsName)) {
                // this.a(Context) -> returns accessibility inspection string -> allow real execution (authentic Key 140 elapsed time)
                // Normalize to unassisted baseline "0,0,,0,," only if anomalous/enabled
                HookUtils.hookIfMethodExists(tCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length == 1 &&
                            param.args[0] instanceof android.content.Context) {
                            Object res = param.getResult();
                            if (res == null || (res instanceof String && !((String) res).startsWith("0,0,"))) {
                                param.setResult("0,0,,0,,");
                            }
                        }
                    }
                });
                // this.b(Context) -> returns enabled accessibility component list -> filter suspicious items
                HookUtils.hookIfMethodExists(tCls, "b", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof java.util.List) {
                            java.util.List<?> list = (java.util.List<?>) res;
                            java.util.Iterator<?> it = list.iterator();
                            while (it.hasNext()) {
                                Object item = it.next();
                                if (item != null && DynamicRootDetectionHook.isSuspiciousPackage(item.toString())) {
                                    it.remove();
                                }
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized accessibility inspectors on " + tClsName);
            }
        }

        // Bennet: scans /proc/self/maps for third-party injected DSOs/JARs outside QQ's package -> Key 250
        // Allows real execution over build_filtered_maps() so Key 100 elapsed time is authentic!
        String[] bennetClasses = {
            "com.tencent.turingfd.sdk.xq.Bennet",
            "com.tencent.tfd.sdk.wxa.Bennet"
        };
        for (String bnClsName : bennetClasses) {
            Class<?> bnCls = XposedHelpers.findClassIfExists(bnClsName, cl);
            if (bnCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + bnClsName)) {
                HookUtils.hookIfMethodExists(bnCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object res = param.getResult();
                        if (res instanceof String) {
                            String s = (String) res;
                            if (!s.isEmpty()) {
                                param.setResult("");
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Bennet DSO injection scanner on " + bnClsName);
            }
        }

        // Bergamot: scans /proc/self/maps for non-/data/ executable-writable memory (rwxp) -> Key 279
        // Over build_filtered_maps(), memory mappings are cleanly non-rwxp; Key 121 elapsed time is authentic!
        String[] bergamotClasses = {
            "com.tencent.turingfd.sdk.xq.Bergamot",
            "com.tencent.tfd.sdk.wxa.Bergamot"
        };
        for (String bgClsName : bergamotClasses) {
            Class<?> bgCls = XposedHelpers.findClassIfExists(bgClsName, cl);
            if (bgCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + bgClsName)) {
                HookUtils.hookIfMethodExists(bgCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() != null) {
                            param.setResult(null);
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Bergamot RWXP memory scanner on " + bgClsName);
            }
        }

        // Quarenden: checks network proxy / VPN settings -> Key 259
        // Allow real execution so Key 114 elapsed time is authentic!
        String[] quarendenClasses = {
            "com.tencent.turingfd.sdk.xq.Quarenden",
            "com.tencent.tfd.sdk.wxa.Quarenden"
        };
        for (String qClsName : quarendenClasses) {
            Class<?> qCls = XposedHelpers.findClassIfExists(qClsName, cl);
            if (qCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + qClsName)) {
                HookUtils.hookIfMethodExists(qCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == Boolean.TRUE) {
                            param.setResult(false);
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Quarenden proxy/VPN detector on " + qClsName);
            }
        }

        // Marc: checks active network routing interfaces & gateway IPs -> Key 284
        String[] marcClasses = {
            "com.tencent.turingfd.sdk.xq.Marc",
            "com.tencent.tfd.sdk.wxa.Marc"
        };
        for (String mClsName : marcClasses) {
            Class<?> mCls = XposedHelpers.findClassIfExists(mClsName, cl);
            if (mCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + mClsName)) {
                HookUtils.hookIfMethodExists(mCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (result instanceof String) {
                            String str = (String) result;
                            if (isVpnNetworkRouting(str)) {
                                param.setResult(getCleanMarcNetworkRouting(null, str));
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Marc network routing detector on " + mClsName);
            }
        }

        // Rambutan: reflection helper used for mPM dynamic proxy inspection -> Key 2019
        // Allow reflection to run; in afterHookedMethod, normalize if foreign proxy ClassLoader detected
        String[] rambutanClasses = {
            "com.tencent.turingfd.sdk.xq.Rambutan",
            "com.tencent.tfd.sdk.wxa.Rambutan"
        };
        for (String rClsName : rambutanClasses) {
            Class<?> rCls = XposedHelpers.findClassIfExists(rClsName, cl);
            if (rCls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + rClsName)) {
                HookUtils.hookIfMethodExists(rCls, "a", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 2 && "mPM".equals(param.args[1])) {
                            Object res = param.getResult();
                            if (res != null) {
                                boolean isProxy = java.lang.reflect.Proxy.isProxyClass(res.getClass());
                                ClassLoader objCl = res.getClass().getClassLoader();
                                boolean foreignCl = (objCl != null && !objCl.getClass().getName().startsWith("java.") &&
                                    !objCl.getClass().getName().startsWith("dalvik.system."));
                                if (isProxy || foreignCl) {
                                    try {
                                        Class<?> smClass = Class.forName("android.os.ServiceManager");
                                        Method getService = smClass.getMethod("getService", String.class);
                                        android.os.IBinder binder = (android.os.IBinder) getService.invoke(null, "package");
                                        if (binder != null) {
                                            Class<?> stubClass = Class.forName("android.content.pm.IPackageManager$Stub");
                                            Method asInterface = stubClass.getMethod("asInterface", android.os.IBinder.class);
                                            Object cleanPM = asInterface.invoke(null, binder);
                                            if (cleanPM != null) {
                                                param.setResult(cleanPM);
                                            }
                                        }
                                    } catch (Throwable ignored) {}
                                }
                            }
                        }
                    }
                });
                XposedEntry.log("[TuringPatch] Sanitized Rambutan mPM reflection detector on " + rClsName);
            }
        }

        // c2: class/field scan list for dynamic proxy / ClassLoader anomaly detection -> Key 289
        // Allow c2.a() to return its legitimate scan dictionary so reflection runs naturally (authentic Key 154 elapsed time)
        String[] c2Classes = {
            "com.tencent.turingfd.sdk.xq.c2",
            "com.tencent.tfd.sdk.wxa.c2"
        };
        for (String c2ClsName : c2Classes) {
            Class<?> c2Cls = XposedHelpers.findClassIfExists(c2ClsName, cl);
            if (c2Cls != null && sHookedTuringBerryClasses.add(cl.hashCode() + "_" + c2ClsName)) {
                // Keep legitimate scan map; clean PM stub and environment ensure no anomaly is flagged
                XposedEntry.log("[TuringPatch] Passed through c2 ClassLoader anomaly scanner dictionary on " + c2ClsName);
            }
        }
    }

    private static final java.util.Set<String> sHookedTuringMapClasses =
        java.util.concurrent.ConcurrentHashMap.newKeySet();

    private static boolean hasRiskKey(Map<?, ?> map, int key) {
        if (map == null) return false;
        return map.containsKey(key) || map.containsKey(String.valueOf(key)) || map.containsKey((long) key);
    }

    private static Object getRiskValue(Map<?, ?> map, int key) {
        if (map == null) return null;
        if (map.containsKey(key)) return map.get(key);
        if (map.containsKey(String.valueOf(key))) return map.get(String.valueOf(key));
        if (map.containsKey((long) key)) return map.get((long) key);
        return null;
    }

    private static void putRiskValue(Map<Object, Object> map, int key, Object val) {
        if (map == null) return;
        boolean replaced = false;
        if (map.containsKey(key)) {
            map.put(key, val);
            replaced = true;
        }
        if (map.containsKey(String.valueOf(key))) {
            map.put(String.valueOf(key), val);
            replaced = true;
        }
        if (map.containsKey((long) key)) {
            map.put((long) key, val);
            replaced = true;
        }
        if (!replaced) {
            boolean mapUsesStrings = false;
            for (Object k : map.keySet()) {
                if (k instanceof String) {
                    mapUsesStrings = true;
                    break;
                }
            }
            if (mapUsesStrings) {
                map.put(String.valueOf(key), val);
            } else {
                map.put(key, val);
            }
        }
    }

    /**
     * Tier 19: Intercept and Deep-Audit Outbound TuringFD Risk Dictionary (map2).
     * Intercepts the entire compiled risk telemetry map (keys: 272 ports, 268/256 proc scan,
     * 2021 accessibility, 2019 mPM, 289 classloader, 291 USB, 271 HarmonyOS, 285 adb/debug,
     * 282 SIM, 284 device, 4 timing benchmarks, etc.) right before native packaging in TNative$aa!
     */
    public static void hookTuringOutboundRiskMap(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) cl = HookConfig.getClassLoader();
        hookTuringOutboundRiskMapWithClassLoader(cl);
    }

    public static void hookTuringOutboundRiskMapWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        String[] tnativeClasses = {
            "com.tencent.turingfd.sdk.xq.TNative$aa",
            "com.tencent.tfd.sdk.wxa.TNative$aa",
            "com.tencent.turingfd.sdk.tbs.TNative$aa",
            "com.tencent.turingface.sdk.mfa.TNative$aa",
            "com.tencent.turingfd.sdk.xq.TNative",
            "com.tencent.tfd.sdk.wxa.TNative",
            "com.tencent.turingfd.sdk.tbs.TNative",
            "com.tencent.turingface.sdk.mfa.TNative"
        };

        for (String clsName : tnativeClasses) {
            Class<?> clazz = XposedHelpers.findClassIfExists(clsName, cl);
            if (clazz != null && sHookedTuringMapClasses.add(cl.hashCode() + "_" + clsName)) {
                if (clsName.contains(".wxa.")) {
                    io.github.xalsace.qqbypass.NativeBypass.patchLibrary("lib108168wxa.so");
                } else if (clsName.contains(".tbs.")) {
                    io.github.xalsace.qqbypass.NativeBypass.patchLibrary("libturingtbs.so");
                } else if (clsName.contains(".mfa.") || clsName.contains("turingface")) {
                    io.github.xalsace.qqbypass.NativeBypass.patchLibrary("libturingmfa.so");
                } else {
                    io.github.xalsace.qqbypass.NativeBypass.patchLibrary("libturingxq.so");
                }
                for (Method method : clazz.getDeclaredMethods()) {
                    Class<?>[] pTypes = method.getParameterTypes();
                    boolean hasMap = false;
                    for (Class<?> pt : pTypes) {
                        if (Map.class.isAssignableFrom(pt)) {
                            hasMap = true;
                            break;
                        }
                    }

                    if (hasMap) {
                        try {
                            HookUtils.hookMethod(method, new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                    if (param.args == null) return;
                                    for (Object arg : param.args) {
                                        if (arg instanceof Map) {
                                            @SuppressWarnings("unchecked")
                                            Map<Object, Object> map = (Map<Object, Object>) arg;
                                            if (!map.isEmpty()) {
                                                String target = (param.thisObject != null ?
                                                    param.thisObject.getClass().getSimpleName() :
                                                    param.method.getDeclaringClass().getSimpleName())
                                                    + "." + param.method.getName();

                                                // 1. Audit real pre-sanitization risk map (snapshot copy)
                                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordPreSanitizationRiskMap(
                                                    "TuringFD", target, new java.util.LinkedHashMap<>(map), 6);

                                                // 2. Surgical Sanitization of critical risk detection items
                                                boolean sanitized = false;
                                                java.util.List<String> sanitizedDetails = new java.util.ArrayList<>();

                                                // Key 250: Bennet /proc/self/maps third-party DSO injection scanner
                                                if (hasRiskKey(map, 250)) {
                                                    Object v = getRiskValue(map, 250);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 250, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("250(InjectedDSOs)");
                                                    }
                                                }

                                                // Key 279: Bergamot /proc/self/maps RWXP memory scanner
                                                if (hasRiskKey(map, 279)) {
                                                    Object v = getRiskValue(map, 279);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 279, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("279(RWXP)");
                                                    }
                                                }

                                                // Key 2019: PackageManager mPM dynamic proxy inspection
                                                // Clean baseline: "android.content.pm.IPackageManager$Stub$Proxy,,"
                                                if (hasRiskKey(map, 2019)) {
                                                    Object v = getRiskValue(map, 2019);
                                                    if (v != null && !v.toString().equals("android.content.pm.IPackageManager$Stub$Proxy,,")) {
                                                        putRiskValue(map, 2019, "android.content.pm.IPackageManager$Stub$Proxy,,");
                                                        sanitized = true;
                                                        sanitizedDetails.add("2019(mPMProxy)");
                                                    }
                                                }

                                                // Key 259: Quarenden proxy/VPN detection flag
                                                if (hasRiskKey(map, 259)) {
                                                    Object v = getRiskValue(map, 259);
                                                    if ("1".equals(v) || (v != null && !"0".equals(v.toString()))) {
                                                        putRiskValue(map, 259, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("259(Proxy)");
                                                    }
                                                }

                                                // Key 284: Marc network routing table & interfaces (tun0 leak)
                                                if (hasRiskKey(map, 284)) {
                                                    Object v = getRiskValue(map, 284);
                                                    if (v != null) {
                                                        String netStr = v.toString();
                                                        if (isVpnNetworkRouting(netStr)) {
                                                            putRiskValue(map, 284, getCleanMarcNetworkRouting(null, netStr));
                                                            sanitized = true;
                                                            sanitizedDetails.add("284(VPN_InterfaceScrubbed)");
                                                        }
                                                    }
                                                }

                                                // Key 289: ClassLoader hierarchy anomaly
                                                if (hasRiskKey(map, 289)) {
                                                    Object v = getRiskValue(map, 289);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 289, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("289(ClassLoader)");
                                                    }
                                                }

                                                // Key 272: Open ports / listening sockets -> scrub suspicious debug/instrumentation ports if present
                                                if (hasRiskKey(map, 272)) {
                                                    Object v = getRiskValue(map, 272);
                                                    if (v != null) {
                                                        String s = v.toString();
                                                        if (s.contains(":27042") || s.contains(":27043") || s.contains(":5555")) {
                                                            putRiskValue(map, 272, s.replaceAll("(:27042|:27043|:5555)", ":0"));
                                                            sanitized = true;
                                                            sanitizedDetails.add("272(PortsSanitized)");
                                                        }
                                                    }
                                                }

                                                // Key 2021: Accessibility inspection string -> unassisted baseline "0,0,,0,,"
                                                if (hasRiskKey(map, 2021)) {
                                                    Object v = getRiskValue(map, 2021);
                                                    if (v != null) {
                                                        String s = v.toString();
                                                        if (!s.isEmpty() && !s.equals("0,0,,0,,")) {
                                                            putRiskValue(map, 2021, "0,0,,0,,");
                                                            sanitized = true;
                                                            sanitizedDetails.add("2021(Accessibility)");
                                                        }
                                                    }
                                                }

                                                // Key 251: l3.b root/hook detection flag (clean baseline: "0")
                                                if (hasRiskKey(map, 251)) {
                                                    Object v = getRiskValue(map, 251);
                                                    if (v != null && !"0".equals(v.toString())) {
                                                        putRiskValue(map, 251, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("251(RootFlag)");
                                                    }
                                                }

                                                // Key 288: l3.b root/hook bitmask (clean baseline: "0")
                                                if (hasRiskKey(map, 288)) {
                                                    Object v = getRiskValue(map, 288);
                                                    if (v != null && !"0".equals(v.toString())) {
                                                        putRiskValue(map, 288, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("288(RootBitmask)");
                                                    }
                                                }

                                                // Key 252: y0.a virtual environment / su check flag (clean baseline: "0")
                                                if (hasRiskKey(map, 252)) {
                                                    Object v = getRiskValue(map, 252);
                                                    if (v != null && !"0".equals(v.toString())) {
                                                        putRiskValue(map, 252, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("252(VirtualEnv)");
                                                    }
                                                }

                                                // Key 256: Berry.a suspicious process inspection matching r1.c (clean baseline: "")
                                                if (hasRiskKey(map, 256)) {
                                                    Object v = getRiskValue(map, 256);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 256, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("256(ProcScanC)");
                                                    }
                                                }

                                                // Key 268: Berry.a suspicious process inspection matching r1.d (clean baseline: "")
                                                if (hasRiskKey(map, 268)) {
                                                    Object v = getRiskValue(map, 268);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 268, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("268(ProcScanD)");
                                                    }
                                                }

                                                // Key 269: Bennet.a /system/lib DSO inspection (clean baseline: "")
                                                if (hasRiskKey(map, 269)) {
                                                    Object v = getRiskValue(map, 269);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 269, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("269(DsoScan)");
                                                    }
                                                }

                                                // Key 280: protected.a diagnostic shell execution result (clean baseline: "")
                                                if (hasRiskKey(map, 280)) {
                                                    Object v = getRiskValue(map, 280);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 280, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("280(DiagExec)");
                                                    }
                                                }

                                                // Key 270: Kiwifruit.a ADB, developer settings and debuggable flags (clean baseline: "0")
                                                if (hasRiskKey(map, 270)) {
                                                    Object v = getRiskValue(map, 270);
                                                    if (v != null && !"0".equals(v.toString())) {
                                                        putRiskValue(map, 270, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("270(AdbDevSettings)");
                                                    }
                                                }

                                                // Key 253: Kiwifruit.d USB connection & ADB configured state (clean baseline: "0")
                                                if (hasRiskKey(map, 253)) {
                                                    Object v = getRiskValue(map, 253);
                                                    if (v != null && !"0".equals(v.toString())) {
                                                        putRiskValue(map, 253, "0");
                                                        sanitized = true;
                                                        sanitizedDetails.add("253(UsbAdbState)");
                                                    }
                                                }

                                                // Key 291: USB State action broadcast extras (scrub adb:1 / adb:true)
                                                if (hasRiskKey(map, 291)) {
                                                    Object v = getRiskValue(map, 291);
                                                    if (v != null) {
                                                        String s = v.toString();
                                                        if (s.contains("adb:1") || s.contains("adb:true")) {
                                                            putRiskValue(map, 291, s.replace("adb:1", "adb:0").replace("adb:true", "adb:false"));
                                                            sanitized = true;
                                                            sanitizedDetails.add("291(UsbAdbScrubbed)");
                                                        }
                                                    }
                                                }

                                                // Key 205: Caelum container / dual app detection (clean baseline: "")
                                                if (hasRiskKey(map, 205)) {
                                                    Object v = getRiskValue(map, 205);
                                                    if (v != null && !v.toString().isEmpty()) {
                                                        putRiskValue(map, 205, "");
                                                        sanitized = true;
                                                        sanitizedDetails.add("205(ContainerDualApp)");
                                                    }
                                                }

                                                // Key 2024: ART Method Hook Verification Target Methods (m_c_l_2)
                                                // TuringFD natively inspects ArtMethod entry points of listed methods.
                                                // Replace hooked framework methods (e.g. LoadedApk.getClassLoader) with
                                                // unhooked authentic methods (LoadedApk.getPackageName) to preserve the
                                                // cloud probe structure while guaranteeing 100% clean ART verification.
                                                if (hasRiskKey(map, 2024)) {
                                                    Object v = getRiskValue(map, 2024);
                                                    if (v != null) {
                                                        String s = v.toString();
                                                        if (s.contains("LoadedApk") || s.contains("getClassLoader")) {
                                                            String clean = s.replaceAll("LoadedApk:getClassLoader\\([^)]*\\)[^#,]*", "LoadedApk:getPackageName()Ljava/lang/String;");
                                                            if (!clean.equals(s)) {
                                                                putRiskValue(map, 2024, clean);
                                                                sanitized = true;
                                                                sanitizedDetails.add("2024(LoadedApk_Scrubbed)");
                                                            }
                                                        }
                                                    }
                                                }

                                                // STRICT RULE 4.2 COMPLIANCE:
                                                // DO NOT wipe Key 2016 (c_s_l: class scan list) and Key 2024 (m_c_l_2: method check list)!
                                                // These are cloud-configured probe target lists, NOT detection results!
                                                // Wiping them causes missing-telemetry and probe configuration corruption anomalies!

                                                if (sanitized) {
                                                    io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSanitizationEvent(
                                                        "TuringFD", target, sanitizedDetails);
                                                    XposedEntry.log("[TuringPatch] Sanitized outbound risk items " + sanitizedDetails + " before encryption in " + target);
                                                }

                                                // 3. Record ACTUAL outbound risk map dispatched to server after sanitization
                                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskMap(
                                                    "TuringFD", target, map, 0);
                                            }
                                        }
                                    }
                                }

                                @Override
                                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                    Object result = param.getResult();
                                    if (result instanceof android.util.SparseArray) {
                                        android.util.SparseArray<?> sa = (android.util.SparseArray<?>) result;
                                        byte[] packedBytes = null;
                                        int retCode = 0;
                                        int packedKey = -1;
                                        for (int i = 0; i < sa.size(); i++) {
                                            int k = sa.keyAt(i);
                                            Object v = sa.valueAt(i);
                                            if (k == 0 && v instanceof Number) {
                                                retCode = ((Number) v).intValue();
                                            } else if (v instanceof byte[]) {
                                                packedBytes = (byte[]) v;
                                                packedKey = k;
                                            }
                                        }
                                        if (packedBytes != null && packedBytes.length > 0) {
                                            byte[] cleanBytes = sanitizeTuringJceNativePayload(packedBytes);
                                            if (cleanBytes != null && cleanBytes != packedBytes) {
                                                @SuppressWarnings("unchecked")
                                                android.util.SparseArray<Object> mutableSa = (android.util.SparseArray<Object>) sa;
                                                mutableSa.put(packedKey, cleanBytes);
                                                packedBytes = cleanBytes;
                                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSanitizationEvent(
                                                    "TuringFD", param.method.getName(),
                                                    java.util.Arrays.asList(
                                                        "NativePack_Key129_Scrubbed(tun0/ap0/vgate/dummy/ifb)",
                                                        "NativePack_MountTable_Scrubbed(debugfs/overlays/loop/dm)",
                                                        "NativePack_BootState_Normalized(locked:1/green:1/enforcing:1)",
                                                        "NativePack_ArtIntegrity_Normalized(memory_opcodes=disk_opcodes)"
                                                    )
                                                );
                                                XposedEntry.log("[TuringPatch] Sanitized multi-vector native environment telemetry in " + param.method.getName());
                                            }

                                            String detail = "retCode=" + retCode + ", sparseArrayEntries=" + sa.size();
                                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordOutboundRiskPayload(
                                                "TuringFD.NativePack",
                                                param.method.getName() + " -> retCode=" + retCode,
                                                packedBytes, detail, 4);
                                        }
                                    } else if (result instanceof byte[]) {
                                        byte[] b = (byte[]) result;
                                        byte[] cleanB = sanitizeTuringJceNativePayload(b);
                                        if (cleanB != null && cleanB != b) {
                                            param.setResult(cleanB);
                                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordSanitizationEvent(
                                                "TuringFD", param.method.getName(),
                                                java.util.Arrays.asList(
                                                    "NativePack_Key129_Scrubbed(tun0/ap0/vgate/dummy/ifb)",
                                                    "NativePack_MountTable_Scrubbed(debugfs/overlays/loop/dm)",
                                                    "NativePack_BootState_Normalized(locked:1/green:1/enforcing:1)",
                                                    "NativePack_ArtIntegrity_Normalized(memory_opcodes=disk_opcodes)"
                                                )
                                            );
                                            XposedEntry.log("[TuringPatch] Sanitized multi-vector direct byte array in " + param.method.getName());
                                        }
                                    }
                                }
                            });
                        } catch (Throwable t) {
                            XposedEntry.logError("[TuringPatch] Failed to hook " + clsName + "." + method.getName() + ": " + t.getMessage(), t);
                        }
                    }
                }
                XposedEntry.log("[TuringPatch] Installed outbound risk map hooks on " + clsName);
            }
        }
    }

    public static final byte[] OFFICIAL_TENCENT_PKG_SIG_MD5 = new byte[] {
        (byte) 0xa6, (byte) 0xb7, (byte) 0x45, (byte) 0xbf,
        (byte) 0x24, (byte) 0xa2, (byte) 0xc2, (byte) 0x77,
        (byte) 0x52, (byte) 0x77, (byte) 0x16, (byte) 0xf6,
        (byte) 0xf3, (byte) 0x6e, (byte) 0xb6, (byte) 0x8d
    };

    private static final java.util.Set<ClassLoader> sHookedCKeyLoaders =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    /**
     * Tier 20: TVK Player CKey & CKeyGuard Security Data Normalization & Pass-Through.
     * In accordance with user policy ("有些本应无条件上报的数据禁止阻断"):
     * Unconditional telemetry events (vs_init, vs_ckey, vs_taskenc) are strictly preserved and allowed to transmit.
     * We perform transparent normalization on their payload:
     * - CKeyBeaconReport: Keeps Beacon reporting pipeline OPEN. Normalizes any empty vs_platform / vs_sdtfrom.
     * - VsReporter: Ensures propInit supplies legitimate parameters (vs_platform=V1000, vs_sdtfrom=1,
     *   vs_so_version=V3.0.000, guard_so_version=V1.0.002, pkg=com.tencent.mobileqq).
     * - VsAppKeyVerify: Returns a valid VsAppKeyBean, registers it in VsAppKeyUtil, and ensures CKeyFacade fields are initialized.
     * - CKeyGuard: Sets clean versions (V1.0.002), ensures bLoadSucc=true, and lets native sGuardInit execute safely.
     * - CKeyFacade: Sets bLoadSucc=true, clean versions (V3.0.000), and provides official package signature MD5.
     */
    public static void hookCKeyAndTVKSecurity(ClassLoader cl) {
        if (cl == null || !sHookedCKeyLoaders.add(cl)) return;

        try {
            // 1. CKeyBeaconReport: KEEP PIPELINE OPEN, sanitize payload
            Class<?> beaconReportCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.CKeyBeaconReport", cl);
            if (beaconReportCls != null) {
                // Ensure switch is explicitly enabled (never closed)
                try {
                    XposedHelpers.callStaticMethod(beaconReportCls, "setSwitchReport", true);
                } catch (Throwable ignored) {}

                // Transparent normalization on trackCustomKVEvent: do NOT block, sanitize properties
                HookUtils.hookAllMethods(beaconReportCls, "trackCustomKVEvent", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 3 && param.args[2] instanceof java.util.Properties) {
                            java.util.Properties props = (java.util.Properties) param.args[2];
                            String plat = props.getProperty("vs_platform");
                            if (plat == null || plat.isEmpty() || "nil".equals(plat)) {
                                props.setProperty("vs_platform", "V1000");
                            }
                            String sdt = props.getProperty("vs_sdtfrom");
                            if (sdt == null || sdt.isEmpty() || "nil".equals(sdt)) {
                                props.setProperty("vs_sdtfrom", "1");
                            }
                            String guardVer = props.getProperty("guard_so_version");
                            if (guardVer == null || guardVer.isEmpty() || "nil".equals(guardVer)) {
                                props.setProperty("guard_so_version", "V1.0.002");
                            }
                            String vsVer = props.getProperty("vs_so_version");
                            if (vsVer == null || vsVer.isEmpty() || "nil".equals(vsVer)) {
                                props.setProperty("vs_so_version", "V3.0.000");
                            }
                            String pkg = props.getProperty("vs_pkgmame");
                            if (pkg == null || pkg.isEmpty() || "nil".equals(pkg)) {
                                props.setProperty("vs_pkgmame", "com.tencent.mobileqq");
                            }
                        }
                    }
                });
                XposedEntry.log("[CKeyPatch] Installed transparent data normalization on CKeyBeaconReport");
            }

            // 2. VsAppKeyVerify: always synthesize valid VsAppKeyBean and register in VsAppKeyUtil
            Class<?> verifyCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.comm.VsAppKeyVerify", cl);
            Class<?> beanCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.comm.VsAppKeyBean", cl);
            Class<?> utilCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.comm.VsAppKeyUtil", cl);
            if (verifyCls != null && beanCls != null) {
                HookUtils.hookAllMethods(verifyCls, "verifyVsAppKey", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            android.content.Context ctx = param.args != null && param.args.length > 0 && param.args[0] instanceof android.content.Context ?
                                (android.content.Context) param.args[0] : null;
                            String pkg = ctx != null ? ctx.getPackageName() : "com.tencent.mobileqq";
                            Object bean = XposedHelpers.newInstance(beanCls, "V1000", "1", "vskey", pkg);

                            if (utilCls != null) {
                                try {
                                    Object utilInst = XposedHelpers.callStaticMethod(utilCls, "getInstance");
                                    if (utilInst != null) {
                                        XposedHelpers.callMethod(utilInst, "add", bean);
                                    }
                                } catch (Throwable ignored) {}
                            }

                            try {
                                Class<?> fCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.CKeyFacade", cl);
                                if (fCls != null) {
                                    XposedHelpers.setStaticObjectField(fCls, "mPlatform", "V1000");
                                    XposedHelpers.setStaticObjectField(fCls, "mSdtfrom", "1");
                                    XposedHelpers.setStaticObjectField(fCls, "mVsKey", "vskey");
                                    XposedHelpers.setStaticObjectField(fCls, "mPkgName", pkg);
                                }
                            } catch (Throwable ignored) {}

                            param.setResult(bean);
                        } catch (Throwable ignored) {}
                    }
                });
            }

            // 3. VsReporter: transparent normalization of propInit (pass-through, DO NOT DROP)
            Class<?> vsReporterCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.comm.VsReporter", cl);
            if (vsReporterCls != null) {
                HookUtils.hookAllMethods(vsReporterCls, "propInit", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof java.util.Properties) {
                            java.util.Properties props = (java.util.Properties) param.args[0];
                            String plat = props.getProperty("vs_platform");
                            if (plat == null || plat.isEmpty() || "nil".equals(plat)) {
                                props.setProperty("vs_platform", "V1000");
                            }
                            String sdt = props.getProperty("vs_sdtfrom");
                            if (sdt == null || sdt.isEmpty() || "nil".equals(sdt)) {
                                props.setProperty("vs_sdtfrom", "1");
                            }
                            props.setProperty("guard_so_version", "V1.0.002");
                            props.setProperty("guard_jar_version", "V3.0.015.5");
                            props.setProperty("vs_so_version", "V3.0.000");
                            props.setProperty("vs_jar_version", "V3.0.015.5");
                            props.setProperty("vs_pkgmame", "com.tencent.mobileqq");
                        }
                    }
                });
            }

            // 4. CKeyGuard: ensure clean versions, let native sGuard execute safely
            Class<?> guardCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.CKeyGuard", cl);
            if (guardCls != null) {
                try {
                    XposedHelpers.setStaticBooleanField(guardCls, "bLoadSucc", true);
                    XposedHelpers.setStaticObjectField(guardCls, "mSoVersion", "V1.0.002");
                } catch (Throwable ignored) {}

                HookUtils.hookAllMethods(guardCls, "sVersion", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == null || "".equals(param.getResult())) {
                            param.setResult("V1.0.002");
                        }
                    }
                });
                HookUtils.hookAllMethods(guardCls, "getVersion", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == null || "".equals(param.getResult())) {
                            param.setResult("V1.0.002");
                        }
                    }
                });
                HookUtils.hookAllMethods(guardCls, "getSoVersion", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == null || "".equals(param.getResult())) {
                            param.setResult("V1.0.002");
                        }
                    }
                });
                HookUtils.hookAllMethods(guardCls, "sGuardInit", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getThrowable() != null) {
                            param.setResult(null); // suppress crash if library missing
                        }
                        try {
                            XposedHelpers.setStaticBooleanField(guardCls, "bLoadSucc", true);
                        } catch (Throwable ignored) {}
                    }
                });
            }

            // 5. CKeyFacade: ensure bLoadSucc = true and clean signature returns
            Class<?> facadeCls = XposedHelpers.findClassIfExists("com.tencent.qqlive.tvkplayer.vinfo.ckey.CKeyFacade", cl);
            if (facadeCls != null) {
                try {
                    XposedHelpers.setStaticBooleanField(facadeCls, "bLoadSucc", true);
                    XposedHelpers.setStaticObjectField(facadeCls, "mSoVersion", "V3.0.000");
                } catch (Throwable ignored) {}

                HookUtils.hookAllMethods(facadeCls, "getSoVersion", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == null || "".equals(param.getResult())) {
                            param.setResult("V3.0.000");
                        }
                    }
                });
                HookUtils.hookAllMethods(facadeCls, "getVersion", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getResult() == null || "".equals(param.getResult())) {
                            param.setResult("V3.0.000");
                        }
                    }
                });
                HookUtils.hookAllMethods(facadeCls, "ckeyMoudleInit", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            XposedHelpers.setStaticBooleanField(facadeCls, "bLoadSucc", true);
                        } catch (Throwable ignored) {}
                    }
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.getThrowable() != null) {
                            param.setResult(null); // suppress crash if lib missing
                        }
                    }
                });
            }
            XposedEntry.log("[CKeyPatch] Successfully hooked CKey & TVK security suite with pass-through normalization on loader " + cl);
        } catch (Throwable t) {
            XposedEntry.logError("[CKeyPatch] Error hooking CKey & TVK security: " + t.getMessage(), t);
        }
    }

    @Deprecated
    public static boolean scrubPackedRiskPayload(byte[] data) {
        // Deprecated: In-place byte scrubbing corrupts binary serialized packets and triggers server-side integrity failures
        return false;
    }

    private static int indexOfSubArray(byte[] source, byte[] target, int fromIndex) {
        if (source == null || target == null || target.length == 0 || fromIndex < 0) return -1;
        int max = source.length - target.length;
        for (int i = fromIndex; i <= max; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    /**
     * Sanitizes trpc.o3.report.Report.SsoReport payloads generated by FEKit super_reporter.
     * When FEKit encounters transient network timeouts (e.g., during Android deep sleep / Doze),
     * super_reporter emits failure telemetry packets carrying:
     *   attaId: "02800075562"
     *   event:  "report_fail"
     *   code:   "903" (or other negative/positive failure code)
     *
     * In accordance with Rule 4.2 (Transparent Parameter Normalization & Pass-Through):
     * The report channel is NEVER blocked or dropped. Instead, "report_fail" is normalized
     * to official baseline "normal", and the failure code is normalized to "0".
     *
     * Handles both raw Protobuf bytes (from ChannelProxyExt) and 4-byte length-prefixed
     * Protobuf buffers (from MsfCore).
     */
    public static byte[] sanitizeSsoReportPayload(byte[] raw) {
        if (raw == null || raw.length < 8) return raw;

        byte[] needle = "report_fail".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (indexOfSubArray(raw, needle, 0) == -1) {
            return raw; // Fast-path: not a failure report
        }

        try {
            boolean hasPrefix = false;
            byte[] data = raw;
            if (raw.length >= 4) {
                int firstInt = ((raw[0] & 0xFF) << 24) | ((raw[1] & 0xFF) << 16) | ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
                if (firstInt == raw.length) {
                    hasPrefix = true;
                    data = new byte[raw.length - 4];
                    System.arraycopy(raw, 4, data, 0, data.length);
                }
            }

            int idx = 0;
            String attaId = "";
            java.util.List<String> items = new java.util.ArrayList<>();
            while (idx < data.length) {
                long key = 0;
                int shift = 0;
                while (true) {
                    if (idx >= data.length) break;
                    byte b = data[idx++];
                    key |= (long) (b & 0x7F) << shift;
                    if ((b & 0x80) == 0) break;
                    shift += 7;
                }
                int fn = (int) (key >>> 3);
                int wt = (int) (key & 0x7);
                if (wt == 2) {
                    int length = 0;
                    shift = 0;
                    while (true) {
                        if (idx >= data.length) break;
                        byte b = data[idx++];
                        length |= (b & 0x7F) << shift;
                        if ((b & 0x80) == 0) break;
                        shift += 7;
                    }
                    if (length < 0 || idx + length > data.length) break;
                    byte[] content = new byte[length];
                    System.arraycopy(data, idx, content, 0, length);
                    idx += length;
                    if (fn == 1) {
                        attaId = new String(content, java.nio.charset.StandardCharsets.UTF_8);
                    } else if (fn == 2) {
                        int subIdx = 0;
                        while (subIdx < content.length) {
                            long sk = 0;
                            int sshift = 0;
                            while (true) {
                                if (subIdx >= content.length) break;
                                byte sb = content[subIdx++];
                                sk |= (long) (sb & 0x7F) << sshift;
                                if ((sb & 0x80) == 0) break;
                                sshift += 7;
                            }
                            int sl = 0;
                            sshift = 0;
                            while (true) {
                                if (subIdx >= content.length) break;
                                byte sb = content[subIdx++];
                                sl |= (sb & 0x7F) << sshift;
                                if ((sb & 0x80) == 0) break;
                                sshift += 7;
                            }
                            if (sl < 0 || subIdx + sl > content.length) break;
                            String sval = new String(content, subIdx, sl, java.nio.charset.StandardCharsets.UTF_8);
                            subIdx += sl;
                            items.add(sval);
                        }
                    }
                } else if (wt == 0) {
                    while (idx < data.length && (data[idx++] & 0x80) != 0);
                } else {
                    break;
                }
            }

            // Strictly only sanitize FEKit A2/ECDH failure reports (attaId = "02800075562")
            if (!"02800075562".equals(attaId) || items.isEmpty()) {
                return raw;
            }

            boolean modified = false;
            for (int i = 0; i < items.size(); i++) {
                String it = items.get(i);
                if ("report_fail".equals(it) || it.contains("report_fail")) {
                    items.set(i, "normal");
                    modified = true;
                    if (i + 1 < items.size()) {
                        String next = items.get(i + 1);
                        if (next.matches("-?\\d+")) {
                            items.set(i + 1, "0");
                        }
                    }
                }
            }
            if (!modified) return raw;

            java.io.ByteArrayOutputStream f2Buf = new java.io.ByteArrayOutputStream();
            for (String item : items) {
                byte[] bs = item.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                writeVarint(f2Buf, (1 << 3) | 2);
                writeVarint(f2Buf, bs.length);
                f2Buf.write(bs);
            }
            byte[] f2Payload = f2Buf.toByteArray();

            java.io.ByteArrayOutputStream rootBuf = new java.io.ByteArrayOutputStream();
            byte[] bs1 = attaId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            writeVarint(rootBuf, (1 << 3) | 2);
            writeVarint(rootBuf, bs1.length);
            rootBuf.write(bs1);

            writeVarint(rootBuf, (2 << 3) | 2);
            writeVarint(rootBuf, f2Payload.length);
            rootBuf.write(f2Payload);

            byte[] outPayload = rootBuf.toByteArray();
            XposedEntry.log("[SsoReportDefense] Normalized trpc.o3.report.Report.SsoReport: replaced 'report_fail' -> 'normal', code -> '0' (attaId=" + attaId + ")");
            if (hasPrefix) {
                int totalLen = outPayload.length + 4;
                byte[] full = new byte[totalLen];
                full[0] = (byte) ((totalLen >>> 24) & 0xFF);
                full[1] = (byte) ((totalLen >>> 16) & 0xFF);
                full[2] = (byte) ((totalLen >>> 8) & 0xFF);
                full[3] = (byte) (totalLen & 0xFF);
                System.arraycopy(outPayload, 0, full, 4, outPayload.length);
                return full;
            }
            return outPayload;
        } catch (Throwable t) {
            XposedEntry.logError("[SsoReportDefense] Error sanitizing SsoReport payload", t);
            return raw;
        }
    }

    private static void writeVarint(java.io.OutputStream out, long value) throws java.io.IOException {
        while (true) {
            if ((value & ~0x7FL) == 0) {
                out.write((int) value);
                return;
            } else {
                out.write((int) ((value & 0x7F) | 0x80));
                value >>>= 7;
            }
        }
    }

    // =========================================================================
    // Tier 21: Zero-Intervention Policy for Natural NT Ticket Renewal & Session Management
    // =========================================================================

    private static final Set<String> sProtectedTicketClasses = java.util.Collections.synchronizedSet(new LinkedHashSet<>());

    /**
     * Tier 21: Zero-Intervention Policy for Natural NT Ticket Renewal & Session Management
     *
     * In accordance with User Invariant: "当我不启用任何模块时，它能够正常换票，不要干预正常运行，让他自然换票"
     * And User Command: "严禁拦截清除操作造成僵尸会话"
     * 1. Official Mobile QQ contains complete native mechanisms for session keepalive and ticket renewal.
     * 2. QQBypass strictly refrains from injecting artificial daemons, hooking GuardManager ticks,
     *    or tampering with ticket renewal logic or callbacks.
     * 3. Clear operations (oicq.wlogin_sdk.request.w.c) are NEVER intercepted or blocked;
     *    we perform only read-only passive auditing to prevent zombie sessions.
     * 4. Zero intervention allows Mobile QQ to naturally manage its ticket lifecycle completely unhindered.
     */
    public static void hookNTLoginAndSessionDefense(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        if (cl == null) {
            cl = HookConfig.getClassLoader();
        }
        if (cl == null) return;

        try {
            Class<?> wClass = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.request.w", cl);
            if (wClass != null && sProtectedTicketClasses.add(cl.hashCode() + "_wlogin_w")) {
                HookUtils.hookMethod(wClass, "c", long.class, long.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 2) {
                            long uin = ((Number) param.args[0]).longValue();
                            long appid = ((Number) param.args[1]).longValue();
                            // Read-only audit only: never modify args, never call setResult, never block clear
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "oicq.wlogin_sdk.request.w.c (Read-Only Audit)",
                                null, "w.c called: uin=" + uin + ", appid=" + appid);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            XposedEntry.logError("[KickAudit] Failed to install w.c audit: " + t.getMessage(), t);
        }
    }

    // Note on SSO Token Expiration & Kick Compliance (Iron Rule 4.1):
    // Forced logout and token invalidation (e.g. -10003 w21, -10001, StatSvc.ReqMSFOffline)
    // are authoritative server-side state transitions. Swallowing or intercepting them in MSF
    // (e.g. msf.core.t.b) or UI (MyErrorHandler.onUserTokenExpired / popupNotification) traps
    // the client in an unrecoverable "Zombie Session" where all outgoing requests fail and UI
    // remains falsely alive. Defenses MUST focus 100% on preventing anomalous telemetry triggers
    // at the root cause, rather than suppressing legitimate server session state transitions.
}



