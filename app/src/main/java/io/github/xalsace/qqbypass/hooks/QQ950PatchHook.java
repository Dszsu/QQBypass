package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

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
        try {
            Class<?> fClass = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.f", HookConfig.getClassLoader());
            if (fClass != null) {
                Object fb = XposedHelpers.callStaticMethod(fClass, "b");
                if (fb != null) {
                    String cached = (String) XposedHelpers.callMethod(fb, "d", "DeviceToken-TuringCache-V001", "");
                    if (cached != null && cached.length() >= 16) {
                        sLastKnownOpenIdTicket = cached;
                        return cached;
                    }
                }
            }
        } catch (Throwable ignored) {}
        return "";
    }

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_QQ950_PATCH) return;

        XposedEntry.log("Initializing QQ 9.3.70 detection & kick patch");

        // Tier 1: void-return, crash-safe backstops
        hookMsfTelemetry(lpparam);
        hookMsfCheckWTSig(lpparam);
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

        // Tier 9: NT Kick Diagnostics (Passive Logging Only, Zero Client-side Suppression)
        hookKickDiagnostics(lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader());

        // Tier 10: Message Sync & Loading State Stabilization (prevents prolonged "Receiving..." stall)
        hookMessageSyncAndLoadingState(lpparam);

        // Tier 11: Real Device Emulator Detection Adaptation (Safe boolean guards without device identity spoofing)
        hookEmulatorDetectionForRealDevice(lpparam);
    }

    // ==================== Tier 1: void-return, crash-safe ====================
    // Note: hookKickBackstop previously swallowed kick notifications at MSF and UI levels.
    // However, forced logout is an authoritative server-side state. Swallowing kick events
    // traps the client in a "Zombie Session" (outbox packets rejected, inbox pushes halted,
    // and turning off module immediately exposes w21). Defenses must focus on eliminating
    // detection triggers rather than suppressing legitimate session state transitions.


    /**
     * MSF telemetry: all void, pure reporting.
     */
    private static void hookMsfTelemetry(XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.mobileqq.msf.core.MsfCore";
        String[] reportMethods = {
            "doReportOnInitComplete", "reportMsfCoreInit",
            "tryReportJobAlive", "tryReportLoadCfgTempFile",
            "tryReportMSFAlive", "tryReportSoLoadUseTxlib"
        };
        for (String m : reportMethods) {
            hookSafe(cls, m, lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });
        }
    }

    /**
     * Defend checkWTSig in com.tencent.mobileqq.msf.core.auth.k:
     * When checkWTSig runs (k.h(ToServiceMsg)), in NT login mode it may trigger
     * k.a(ToServiceMsg, boolean) which dispatches CODE_NO_LOGIN (2001) kick.
     * We surgically hook k.a(ToServiceMsg, boolean) to prevent CODE_NO_LOGIN,
     * without swallowing k.h itself, ensuring message pipelines remain active.
     */
    private static void hookMsfCheckWTSig(XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.mobileqq.msf.core.auth.k";
        hookSafe(cls, "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length == 2 && p.args[0] != null && p.args[1] instanceof Boolean) {
                    Object req = p.args[0];
                    if ("com.tencent.qphone.base.remote.ToServiceMsg".equals(req.getClass().getName())) {
                        p.setResult(null);
                        XposedEntry.log("[MSFPatch] Defended against checkWTSig CODE_NO_LOGIN kick in k.a");
                    }
                }
            }
        });
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
     * ChannelManager checkMethod & ChannelReport telemetry.
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

        // Suppress ChannelManagerImpl telemetry reports
        hookSafe("com.tencent.mobileqq.channel.ChannelManagerImpl", "onChannelReadyReport", lpparam,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });

        // Suppress ChannelReport methods
        final String crCls = "com.tencent.mobileqq.channel.ChannelReport";
        String[] reportMethods = {
            "reportInitTime", "reportTZ", "reportLoadFixedSo",
            "reportGoogleAttestation", "reportStep"
        };
        for (String rm : reportMethods) {
            hookSafe(crCls, rm, lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null);
                }
            });
        }

        // Suppress eventReport (0df00071646 SsoEventReport)
        hookSafe(crCls, "eventReport", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[ChannelPatch] Neutralized ChannelReport.eventReport");
            }
        });

        // Neutralize commonReport and batchCommonReport for sensitive telemetry attaIds
        XC_MethodHook attaFilterHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                    String attaId = (String) p.args[0];
                    if ("0df00071646".equals(attaId) || "00e00075618".equals(attaId) ||
                        "02f00075617".equals(attaId) || "0b500076578".equals(attaId)) {
                        p.setResult(null);
                        XposedEntry.log("[ChannelPatch] Suppressed ChannelReport for attaId: " + attaId);
                    }
                }
            }
        };
        hookSafe(crCls, "commonReport", lpparam, attaFilterHook);
        hookSafe(crCls, "batchCommonReport", lpparam, attaFilterHook);
    }

    /**
     * QQ 9.3.70 APK signature and integrity checks.
     * Hooks:
     * - ApkSignatureSchemeV2Verifier.g(String): returns true (verifies V2 signature)
     * - ApkExternalInfoTool (com.tencent.securitysdk.utils.a.f(File)): getSecurityCodeV1
     */
    private static void hookSignatureAndIntegrity(XC_LoadPackage.LoadPackageParam lpparam) {
        // ApkSignatureSchemeV2Verifier.g(String apkPath)
        final String v2Cls = "com.tencent.securitysdk.utils.ApkSignatureSchemeV2Verifier";
        hookSafe(v2Cls, "g", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
                XposedEntry.log("[SignaturePatch] Neutralized ApkSignatureSchemeV2Verifier.g");
            }
        });

        // ApkExternalInfoTool: getSecurityCodeV1(File)
        final String extCls = "com.tencent.securitysdk.utils.a";
        hookSafe(extCls, "f", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() == null) {
                    p.setResult("qq_security_verified");
                    XposedEntry.log("[SignaturePatch] Fallback ApkExternalInfoTool security code");
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
        // 1. TenPay ScreenSecurityDetector
        final String ssdCls = "com.tenpay.security.ScreenSecurityDetector";
        hookSafe(ssdCls, "isAtRisk", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[ScreenSecurity] Neutralized ScreenSecurityDetector.isAtRisk -> false");
            }
        });
        hookSafe(ssdCls, "isScreenRecording", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
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

        // 2. TenPay & CameraSDK & LightDevice Root Checks
        hookSafe("com.tenpay.charge.v2.util.ChargeV2Utils", "isDeviceRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe("com.tencent.camerasdk.avreport.DeviceInfo", "isDeviceRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe("org.light.device.LightDeviceUtils", "isRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });

        // 3. GathererGA UserInfoImpl.isRooted
        final String userInfoCls = "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl";
        hookSafe(userInfoCls, "isRooted", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.thisObject == null) return;
                ClassLoader cl = p.thisObject.getClass().getClassLoader();
                Class<?> resCls = XposedHelpers.findClassIfExists("com.tencent.gathererga.core.internal.provider.c", cl);
                if (resCls != null) {
                    try {
                        Object fakeRes = XposedHelpers.newInstance(resCls, 0L, Boolean.FALSE);
                        p.setResult(fakeRes);
                        XposedEntry.log("[RootPatch] Sanitized UserInfoImpl.isRooted -> false");
                        return;
                    } catch (Throwable ignored) { }
                }
                Class<?> iface = XposedHelpers.findClassIfExists("com.tencent.gathererga.core.f", cl);
                if (iface != null) {
                    Object proxy = Proxy.newProxyInstance(cl, new Class<?>[]{iface}, new InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                            String mName = method.getName();
                            if ("getErrorCode".equals(mName) || "a".equals(mName)) return 0L;
                            if ("getResult".equals(mName) || "b".equals(mName)) return Boolean.FALSE;
                            return null;
                        }
                    });
                    p.setResult(proxy);
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[DtcPatch] Suppressed Dtc.isAbnormalConfig -> false");
            }
        });
        hookSafe(dtcCls, "isDebugVersion", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(dtcCls, "checkAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledStatus", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("[]");
            }
        });
        hookSafe(dtcCls, "getAccessibilityServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("[]");
            }
        });

        // Neutralize com.tencent.mobileqq.fe.utils.a (Obfuscated XOR 0x55 ClassLoader & dexElements scanner)
        final String feUtilsA = "com.tencent.mobileqq.fe.utils.a";
        XC_MethodHook falseHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        };
        hookSafe(feUtilsA, "g", lpparam, falseHook);
        hookSafe(feUtilsA, "a", lpparam, falseHook);
        hookSafe(feUtilsA, "b", lpparam, falseHook);
        hookSafe(feUtilsA, "f", lpparam, falseHook);

        // Neutralize com.tencent.mobileqq.dt.app.h (Suspicious CA Certificate detector)
        final String dtHCls = "com.tencent.mobileqq.dt.app.h";
        hookSafe(dtHCls, "b", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(new java.util.ArrayList<>());
            }
        });
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
            "com.tencent.turingfd.sdk.xq.TuringRiskService"
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
                                    Field fa = wild.getClass().getDeclaredField("a");
                                    fa.setAccessible(true);
                                    Object aVal = fa.get(wild);
                                    if (aVal instanceof Number) {
                                        long err = ((Number) aVal).longValue();
                                        if (err != 0L) {
                                            if (fa.getType() == int.class) {
                                                fa.setInt(wild, 0);
                                            } else {
                                                fa.setLong(wild, 0L);
                                            }
                                            XposedEntry.log("[TuringPatch] Sanitized Wild.a errorCode: " + err + " -> 0");
                                        }
                                    }
                                } catch (Throwable t) {
                                    XposedEntry.log("[TuringPatch] Error accessing Wild.a: " + t.getMessage());
                                }
                                try {
                                    Field fb = wild.getClass().getDeclaredField("b");
                                    fb.setAccessible(true);
                                    String dt = (String) fb.get(wild);
                                    if (dt != null && !dt.isEmpty()) {
                                        sLastKnownDeviceToken = dt;
                                        XposedEntry.log("[TuringPatch] Preserved authentic Wild.b deviceToken");
                                    } else {
                                        String tok = getOrGenerateDeviceToken();
                                        if (!tok.isEmpty()) {
                                            fb.set(wild, tok);
                                            XposedEntry.log("[TuringPatch] Injected cached deviceToken into Wild.b");
                                        }
                                    }
                                } catch (Throwable ignored) {}
                            }
                        } catch (Throwable t) {
                            try {
                                long err = (Long) XposedHelpers.callMethod(result, "getErrorCode");
                                if (err != 0L) {
                                    XposedHelpers.setLongField(result, "errorCode", 0L);
                                }
                            } catch (Throwable ignored) {}
                        }
                    } else {
                        Object proxy = createSafeRiskDetectRespProxy();
                        if (proxy != null) {
                            p.setResult(proxy);
                            XposedEntry.log("[TuringPatch] Fallback null reqRiskDetectV2 with safe proxy @ " + cls);
                        }
                    }
                }
            });
        }

        // Direct method hooks on o2 implementations to guarantee 0L errorCode and non-empty deviceToken
        String[] o2Classes = {
            "com.tencent.turingfd.sdk.xq.o2",
            "com.tencent.tfd.sdk.wxa.o2"
        };
        for (String o2Cls : o2Classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(o2Cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            HookUtils.hookAllMethods(clazz, "getErrorCode", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0L);
                }
            });
            HookUtils.hookAllMethods(clazz, "getDeviceToken", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String && !((String) res).isEmpty()) {
                        sLastKnownDeviceToken = (String) res;
                    } else {
                        String tok = getOrGenerateDeviceToken();
                        if (!tok.isEmpty()) {
                            p.setResult(tok);
                        }
                    }
                }
            });
        }
    }

    private static Object createSafeRiskDetectRespProxy() {
        ClassLoader cl = HookConfig.getClassLoader();
        Class<?> iface = XposedHelpers.findClassIfExists("com.tencent.turingfd.sdk.xq.RiskDetectResp", cl);
        if (iface == null) {
            iface = XposedHelpers.findClassIfExists("com.tencent.tfd.sdk.wxa.RiskDetectResp", cl);
        }
        if (iface == null) return null;

        try {
            return Proxy.newProxyInstance(cl, new Class<?>[]{iface}, new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    String name = method.getName();
                    if ("getErrorCode".equals(name)) return 0L;
                    if ("getDeviceToken".equals(name)) return getOrGenerateDeviceToken();
                    if ("isDowngrade".equals(name)) return false;
                    if ("getStagePackTimeMillis".equals(name) || "getStageReqTimeMillis".equals(name)) return 0L;

                    Class<?> ret = method.getReturnType();
                    if (ret == boolean.class) return false;
                    if (ret == int.class) return 0;
                    if (ret == long.class) return 0L;
                    if (ret == String.class) return "";
                    return null;
                }
            });
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * TuringIDService.getTuringDID / getTuringDIDCached : ITuringDID.
     * Allow real Turing ID generation to run under Native layer protection so genuine openIdTicket is generated.
     * On result: sanitize errorCode to 0, ensure timestamp is valid for 24h, and preserve authentic openIdTicket.
     * Fallback to safe proxy only if result is null to avoid NPE.
     */
    private static void hookTuringDID() {
        hookTuringDIDWithClassLoader(HookConfig.getClassLoader());
    }

    public static void hookTuringDIDWithClassLoader(ClassLoader cl) {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK || cl == null) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringIDService",
            "com.tencent.turingfd.sdk.xq.TuringIDService"
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
                                    // int c is errorCode
                                    int err = XposedHelpers.getIntField(t1, "c");
                                    if (err != 0) {
                                        XposedHelpers.setIntField(t1, "c", 0);
                                        XposedEntry.log("[TuringPatch] Sanitized t1.c errorCode: " + err + " -> 0");
                                    }
                                    // long b is expiredTimestamp; ensure never expired
                                    long exp = XposedHelpers.getLongField(t1, "b");
                                    if (exp <= System.currentTimeMillis()) {
                                        XposedHelpers.setLongField(t1, "b", System.currentTimeMillis() + 86400000L);
                                        XposedEntry.log("[TuringPatch] Refreshed expired timestamp in t1.b -> +24h");
                                    }
                                    // String a is openIdTicket
                                    String ticket = (String) XposedHelpers.getObjectField(t1, "a");
                                    if (ticket != null && !ticket.isEmpty()) {
                                        sLastKnownOpenIdTicket = ticket;
                                        XposedEntry.log("[TuringPatch] Preserved authentic t1.a openIdTicket");
                                    } else {
                                        String tok = getOrGenerateOpenIdTicket();
                                        if (!tok.isEmpty()) {
                                            XposedHelpers.setObjectField(t1, "a", tok);
                                            XposedEntry.log("[TuringPatch] Injected cached openIdTicket into t1.a");
                                        }
                                    }
                                }
                            } catch (Throwable t) {
                                try {
                                    int err = (Integer) XposedHelpers.callMethod(result, "getErrorCode");
                                    if (err != 0) {
                                        XposedHelpers.setIntField(result, "errorCode", 0);
                                    }
                                } catch (Throwable ignored) {}
                            }
                        } else {
                            Object proxy = createSafeTuringDIDProxy();
                            if (proxy != null) {
                                p.setResult(proxy);
                            }
                        }
                    }
                });
            }
        }

        // Direct method hooks on h2 implementations
        String[] h2Classes = {
            "com.tencent.turingfd.sdk.xq.h2",
            "com.tencent.tfd.sdk.wxa.h2"
        };
        for (String h2Cls : h2Classes) {
            Class<?> clazz = XposedHelpers.findClassIfExists(h2Cls, cl);
            if (clazz == null || !sHookedTuringClasses.add(clazz)) continue;
            HookUtils.hookAllMethods(clazz, "getErrorCode", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0);
                }
            });
            HookUtils.hookAllMethods(clazz, "getExpiredTimestamp", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof Number && ((Number) res).longValue() <= System.currentTimeMillis()) {
                        p.setResult(System.currentTimeMillis() + 86400000L);
                    }
                }
            });
            HookUtils.hookAllMethods(clazz, "getOpenIdTicket", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    Object res = p.getResult();
                    if (res instanceof String && !((String) res).isEmpty()) {
                        sLastKnownOpenIdTicket = (String) res;
                    } else {
                        String tok = getOrGenerateOpenIdTicket();
                        if (!tok.isEmpty()) {
                            p.setResult(tok);
                        }
                    }
                }
            });
        }
    }

    private static Object createSafeTuringDIDProxy() {
        ClassLoader cl = HookConfig.getClassLoader();
        Class<?> iface = XposedHelpers.findClassIfExists("com.tencent.turingfd.sdk.xq.ITuringDID", cl);
        if (iface == null) {
            iface = XposedHelpers.findClassIfExists("com.tencent.tfd.sdk.wxa.ITuringDID", cl);
        }
        if (iface == null) return null;

        try {
            return Proxy.newProxyInstance(cl, new Class<?>[]{iface}, new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    String name = method.getName();
                    if ("getErrorCode".equals(name)) return 0;
                    if ("getOpenIdTicket".equals(name)) return getOrGenerateOpenIdTicket();
                    if ("getAIDCode".equals(name) || "getAIDTicket".equals(name) || "getTAIDTicket".equals(name)) return getOrGenerateOpenIdTicket();
                    if ("getExpiredTimestamp".equals(name)) return System.currentTimeMillis() + 86400000L;

                    Class<?> ret = method.getReturnType();
                    if (ret == boolean.class) return false;
                    if (ret == int.class) return 0;
                    if (ret == long.class) return 0L;
                    if (ret == String.class) return "";
                    return null;
                }
            });
        } catch (Throwable t) {
            return null;
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
                XposedBridge.hookMethod(method, new XC_MethodHook() {
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

    private static final java.util.Set<Class<?>> sHookedKickClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static final java.util.Set<Class<?>> sHookedFeUtilsAClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    public static void hookLateStage(ClassLoader cl) {
        if (cl == null) return;
        try {
            resolvePendingSafeHooks(cl);
            hookFaceRecognitionAndMFAWithClassLoader(cl);
            hookTroopSecurityTipsBannerCrashWithClassLoader(cl);
            hookKickDiagnostics(cl);
            hookTuringRiskDetectWithClassLoader(cl);
            hookTuringDIDWithClassLoader(cl);
            hookO3SecurityAndTelemetryWithClassLoader(cl);
            hookFeUtilsAWithClassLoader(cl);
            hookMessageSyncAndLoadingStateWithClassLoader(cl);
        } catch (Throwable t) {
            XposedEntry.log("[LateStage] hookLateStage error: " + t.getMessage());
        }
    }

    public static void hookFeUtilsAWithClassLoader(ClassLoader cl) {
        if (cl == null) return;
        try {
            Class<?> feUtilsA = XposedHelpers.findClassIfExists("com.tencent.mobileqq.fe.utils.a", cl);
            if (feUtilsA != null && sHookedFeUtilsAClasses.add(feUtilsA)) {
                Method[] methods = feUtilsA.getDeclaredMethods();
                for (Method m : methods) {
                    Class<?> ret = m.getReturnType();
                    if (ret == boolean.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult(false);
                            }
                        });
                    } else if (ret == String.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult("");
                            }
                        });
                    } else if (ret == int.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                param.setResult(0);
                            }
                        });
                    }
                }
                XposedEntry.log("[FEKitCensor] Successfully neutralized com.tencent.mobileqq.fe.utils.a via LateStage");
            }
        } catch (Throwable t) {
            XposedEntry.log("[FEKitCensor] Error hooking fe.utils.a in LateStage: " + t.getMessage());
        }
    }


    public static void hookKickDiagnostics(ClassLoader cl) {
        if (cl == null) return;
        try {
            // 1. NTKickProcessor: Switchable kick interception & diagnostic logging
            Class<?> ntKickProcessorCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.kick.NTKickProcessor", cl);
            if (ntKickProcessorCls != null && sHookedKickClasses.add(ntKickProcessorCls)) {
                Method[] methods = ntKickProcessorCls.getDeclaredMethods();
                for (Method m : methods) {
                    if (Modifier.isStatic(m.getModifiers()) || m.getName().equals("a") || m.getName().equals("b")) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                String kickInfoSummary = null;
                                if (param.args != null) {
                                    for (Object arg : param.args) {
                                        if (arg != null && arg.getClass().getName().contains("KickedInfo")) {
                                            try {
                                                kickInfoSummary = "kickedType=" + XposedHelpers.getObjectField(arg, "kickedType") +
                                                    ", securityKickedType=" + XposedHelpers.getObjectField(arg, "securityKickedType") +
                                                    ", sameDevice=" + XposedHelpers.getObjectField(arg, "sameDevice") +
                                                    ", appId/instanceId=" + XposedHelpers.getObjectField(arg, "appId") + "/" + XposedHelpers.getObjectField(arg, "instanceId") +
                                                    ", tipsTitle=" + XposedHelpers.getObjectField(arg, "tipsTitle") +
                                                    ", tipsDesc=" + XposedHelpers.getObjectField(arg, "tipsDesc");
                                            } catch (Throwable ignored) {}
                                            break;
                                        }
                                    }
                                }
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    "NTKickProcessor." + param.method.getName(), null,
                                    kickInfoSummary != null ? kickInfoSummary : (param.args != null ? java.util.Arrays.toString(param.args) : "null"));
                                if (HookConfig.isKickInterceptEnabled()) {
                                    XposedEntry.log("[KickShield] Intercepted NTKickProcessor." + param.method.getName());
                                    param.setResult(null);
                                    return;
                                }
                                StringBuilder sb = new StringBuilder();
                                sb.append("[KickDiagnostic] NTKickProcessor.").append(param.method.getName()).append(" invoked");
                                if (kickInfoSummary != null) {
                                    sb.append(" (").append(kickInfoSummary).append(")");
                                }
                                sb.append(" with args: ");
                                if (param.args != null) {
                                    for (Object arg : param.args) {
                                        if (arg == null) {
                                            sb.append("null, ");
                                            continue;
                                        }
                                        sb.append(arg.getClass().getSimpleName()).append("{");
                                        try {
                                            Field[] fields = arg.getClass().getDeclaredFields();
                                            for (Field f : fields) {
                                                f.setAccessible(true);
                                                sb.append(f.getName()).append("=").append(f.get(arg)).append(", ");
                                            }
                                        } catch (Throwable ignored) {
                                            sb.append(arg.toString());
                                        }
                                        sb.append("}, ");
                                    }
                                }
                                XposedEntry.log(sb.toString());
                            }
                        });
                    }
                }
                XposedEntry.log("[KickShield] Hooked NTKickProcessor methods (switchable)");
            }

            // 2. KickApiImpl: Switchable kick suppression
            Class<?> kickApiImplCls = XposedHelpers.findClassIfExists("com.tencent.qqnt.kernel.api.impl.KickApiImpl", cl);
            if (kickApiImplCls != null && sHookedKickClasses.add(kickApiImplCls)) {
                XC_MethodHook kickApiHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "KickApiImpl." + param.method.getName(), null, param.args != null ? java.util.Arrays.toString(param.args) : "null");
                        if (HookConfig.isKickInterceptEnabled()) {
                            XposedEntry.log("[KickShield] Suppressed KickApiImpl." + param.method.getName());
                            param.setResult(null);
                        } else {
                            XposedEntry.log("[KickDiagnostic] KickApiImpl." + param.method.getName() + " called! args=" + java.util.Arrays.toString(param.args));
                        }
                    }
                };
                HookUtils.hookAllMethods(kickApiImplCls, "kick", kickApiHook);
                HookUtils.hookAllMethods(kickApiImplCls, "onKickedOffLine", kickApiHook);
                HookUtils.hookAllMethods(kickApiImplCls, "onKicked", kickApiHook);
                HookUtils.hookAllMethods(kickApiImplCls, "shouldIgnoreNotifyMsfStatusChanged", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        // CRITICAL: Must return false! Returning true prevents QQAppInterface.onMessageConnect
                        // from notifying IKernelService.setOnMsfStatusChanged(KCONNECTED), stalling message sync
                        // and permanently stranding the main conversation list in a 'Loading...' state.
                        p.setResult(false);
                    }
                });
                HookUtils.hookAllMethods(kickApiImplCls, "getBeInterceptor", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(false);
                    }
                });
                XposedEntry.log("[KickShield] Hooked KickApiImpl methods (connection status protected)");
            }

            // 3. MainService$MyErrorHandler: Switchable kick event & popup suppression
            Class<?> myErrorHandlerCls = XposedHelpers.findClassIfExists("mqq.app.MainService$MyErrorHandler", cl);
            if (myErrorHandlerCls != null && sHookedKickClasses.add(myErrorHandlerCls)) {
                HookUtils.hookAllMethods(myErrorHandlerCls, "onUserTokenExpired", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Object fromServiceMsg = param.args != null && param.args.length > 1 ? param.args[1] : (param.args != null && param.args.length > 0 ? param.args[0] : null);
                        String uin = fromServiceMsg != null ? (String) XposedHelpers.callMethod(fromServiceMsg, "getUin") : "";
                        String cmd = fromServiceMsg != null ? (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd") : "";
                        Object ssoErr = fromServiceMsg != null ? XposedHelpers.callMethod(fromServiceMsg, "getAttribute", "attr_sso_error_code", 0) : 0;
                        String failMsg = fromServiceMsg != null ? (String) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailMsg") : "";

                        // Deep Kick Decoding Audit
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "MyErrorHandler.onUserTokenExpired", fromServiceMsg, "ssoErr=" + ssoErr + ", failMsg=" + failMsg);

                        if (HookConfig.isKickInterceptEnabled()) {
                            XposedEntry.log("[KickShield] Suppressed onUserTokenExpired! uin=" + uin + ", cmd=" + cmd);
                            param.setResult(null);
                        } else {
                            XposedEntry.log("[KickDiagnostic] onUserTokenExpired invoked! uin=" + uin + ", cmd=" + cmd + ", ssoErr=" + ssoErr + ", msg=" + failMsg);
                        }
                    }
                });

                String[] kickEventMethods = {"onKicked", "onKickedAndClearToken", "onGrayError", "onServerSuspended", "onNoTestEnvPermission", "onInvalidSign", "onRecvServerTip", "onInterceptKicked", "onKickedInternal", "onCloneError"};
                for (String km : kickEventMethods) {
                    HookUtils.hookAllMethods(myErrorHandlerCls, km, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object fromServiceMsg = param.args != null && param.args.length > 1 ? param.args[1] : (param.args != null && param.args.length > 0 ? param.args[0] : null);
                            String uin = fromServiceMsg != null ? (String) XposedHelpers.callMethod(fromServiceMsg, "getUin") : "";
                            String cmd = fromServiceMsg != null ? (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd") : "";

                            // Deep Kick Decoding Audit
                            io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                "MyErrorHandler." + param.method.getName(), fromServiceMsg, "cmd=" + cmd + ", uin=" + uin);

                            if (HookConfig.isKickInterceptEnabled()) {
                                XposedEntry.log("[KickShield] Suppressed MyErrorHandler." + param.method.getName() + "! uin=" + uin);
                                param.setResult(null);
                            } else {
                                XposedEntry.log("[KickDiagnostic] MyErrorHandler." + param.method.getName() + " called! uin=" + uin + ", cmd=" + cmd);
                            }
                        }
                    });
                }

                XC_MethodHook popupHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String action = param.args != null && param.args.length > 0 && param.args[0] instanceof String ? (String) param.args[0] : "";
                        String uin = param.args != null && param.args.length > 1 && param.args[1] instanceof String ? (String) param.args[1] : "";
                        Object reason = null;
                        if (param.args != null) {
                            for (Object arg : param.args) {
                                if (arg != null && arg.getClass().getName().contains("LogoutReason")) {
                                    reason = arg;
                                    break;
                                }
                            }
                        }

                        // Deep Kick Decoding Audit
                        io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                            "MyErrorHandler.popupNotification", null, "action=" + action + ", uin=" + uin + ", reason=" + reason);

                        if (HookConfig.isKickInterceptEnabled()) {
                            XposedEntry.log("[KickShield] Suppressed popupNotification: action=" + action + ", uin=" + uin);
                            param.setResult(null);
                        } else {
                            XposedEntry.log("[KickDiagnostic] popupNotification called: action=" + action + ", uin=" + uin + ", reason=" + reason);
                        }
                    }
                };
                HookUtils.hookAllMethods(myErrorHandlerCls, "popupNotification", popupHook);
                HookUtils.hookAllMethods(myErrorHandlerCls, "popupNotificationEx", popupHook);
                XposedEntry.log("[KickShield] Hooked mqq.app.MainService$MyErrorHandler methods (switchable)");
            }

            // 4. com.tencent.mobileqq.msf.sdk.g & com.tencent.mobileqq.msf.sdk.h: Switchable kick & token expired consumption
            String[] msfDispatcherClasses = {"com.tencent.mobileqq.msf.sdk.g", "com.tencent.mobileqq.msf.sdk.h"};
            for (final String msfClsName : msfDispatcherClasses) {
                Class<?> msfCls = XposedHelpers.findClassIfExists(msfClsName, cl);
                if (msfCls != null && sHookedKickClasses.add(msfCls)) {
                    HookUtils.hookAllMethods(msfCls, "e", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            if (param.args == null || param.args.length < 2 || param.args[1] == null) return;
                            Object fromServiceMsg = param.args[1];
                            int failCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode");
                            String uin = (String) XposedHelpers.callMethod(fromServiceMsg, "getUin");
                            String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");

                            boolean isKickFailCode = (failCode == 2001 ||
                                                      failCode == 2011 ||
                                                      failCode == 2012 ||
                                                      failCode == 2013 ||
                                                      failCode == 2014 ||
                                                      failCode == 2008 ||
                                                      failCode == 2009 ||
                                                      failCode == 2903 || failCode == 3003);

                            boolean isKickCmd = "StatSvc.ReqMSFOffline".equals(cmd) ||
                                                "StatSvc.ReqForceOffline".equals(cmd) ||
                                                "MessageSvc.PushForceOffline".equals(cmd);

                            if (isKickFailCode || isKickCmd) {
                                io.github.xalsace.qqbypass.utils.ReportAuditManager.recordKickEvent(
                                    msfClsName + ".e", fromServiceMsg, "failCode=" + failCode + ", cmd=" + cmd + ", uin=" + uin);

                                if (HookConfig.isKickInterceptEnabled()) {
                                    XposedEntry.log("[KickShield] " + msfClsName + ".e consumed kick packet: failCode=" + failCode + ", cmd=" + cmd + ", uin=" + uin);
                                    param.setResult(true);
                                } else {
                                    XposedEntry.log("[KickDiagnostic] " + msfClsName + ".e kick signal received: failCode=" + failCode + ", cmd=" + cmd + ", uin=" + uin);
                                }
                            }
                        }
                    });
                    XposedEntry.log("[KickShield] Hooked " + msfClsName + ".e (switchable)");
                }
            }

            // 5. com.tencent.mobileqq.msf.sdk.MsfSdkUtils: Prevent account token wipe during kick when enabled
            Class<?> msfSdkUtilsCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.sdk.MsfSdkUtils", cl);
            if (msfSdkUtilsCls != null && sHookedKickClasses.add(msfSdkUtilsCls)) {
                XC_MethodHook accountWipeHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (!HookConfig.isKickInterceptEnabled()) return;
                        if (param.args != null && param.args.length >= 2 && param.args[1] instanceof Boolean) {
                            boolean isLogined = (Boolean) param.args[1];
                            if (!isLogined) {
                                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                                boolean fromKick = false;
                                for (StackTraceElement ste : stack) {
                                    String cn = ste.getClassName();
                                    String mn = ste.getMethodName();
                                    if (cn.contains("MyErrorHandler") || cn.contains("Kick") || mn.contains("Kicked") || mn.contains("kicked") || mn.contains("Offline") || cn.contains("msf.sdk") || mn.contains("onUserTokenExpired") || mn.contains("TokenExpired")) {
                                        fromKick = true;
                                        break;
                                    }
                                }
                                if (fromKick) {
                                    XposedEntry.log("[KickShield] Protected user token against wipe in " + param.method.getName() + "(uin=" + param.args[0] + ", isLogined=false)");
                                    param.setResult(null);
                                }
                            }
                        }
                    }
                };
                HookUtils.hookAllMethods(msfSdkUtilsCls, "updateSimpleAccount", accountWipeHook);
                HookUtils.hookAllMethods(msfSdkUtilsCls, "updateSimpleAccountNotCreate", accountWipeHook);
                XposedEntry.log("[KickShield] Hooked MsfSdkUtils.updateSimpleAccount & updateSimpleAccountNotCreate for token protection (switchable)");
            }
        } catch (Throwable t) {
            XposedEntry.log("[KickShield] Failed to hook kick shield/diagnostics: " + t.getMessage());
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

            XposedEntry.log("[FacePatch] OTVRM uninitialized (g=" + g + ", b=" + (b != null) + "), repairing state...");
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

        // 1. TuringFaceDefender: init, signData, activeSign, getDeviceInfo, setPreviewDisplay
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

            HookUtils.hookAllMethods(tfdClass, "getDeviceInfo", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() == null) {
                        param.setResult(new org.json.JSONObject());
                        XposedEntry.log("[FacePatch] Sanitized null TuringFaceDefender.getDeviceInfo -> safe empty JSON");
                    }
                }
            });

            HookUtils.hookAllMethods(tfdClass, "signData", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object result = param.getResult();
                    String safeSign = generateSafeTuringSignMsg();
                    if (result != null) {
                        try {
                            long code = XposedHelpers.getLongField(result, "code");
                            if (code != 0) {
                                XposedHelpers.setLongField(result, "code", 0L);
                                XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData code: " + code + " -> 0");
                            }
                        } catch (Throwable t) {
                            try {
                                int codeInt = XposedHelpers.getIntField(result, "code");
                                if (codeInt != 0) {
                                    XposedHelpers.setIntField(result, "code", 0);
                                    XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData code: " + codeInt + " -> 0");
                                }
                            } catch (Throwable ignored) {}
                        }
                        try {
                            String signMsg = (String) XposedHelpers.getObjectField(result, "signMsg");
                            if (signMsg == null || signMsg.isEmpty()) {
                                XposedHelpers.setObjectField(result, "signMsg", safeSign);
                                XposedEntry.log("[FacePatch] Sanitized TuringFaceDefender.signData signMsg: null -> valid safe token");
                            } else {
                                XposedEntry.log("[FacePatch] Preserved genuine TuringFaceDefender.signData signMsg (len=" + signMsg.length() + ")");
                            }
                        } catch (Throwable t) {
                            try {
                                XposedHelpers.setObjectField(result, "signMsg", safeSign);
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
            XposedEntry.log("[FacePatch] Hooked TuringFaceDefender for face recognition safety");
        }

        // 1.1 OTVRM: direct defense in depth for constructors, setPreviewDisplay and start methods
        final String otvrmCls = "com.tencent.turingcam.OTVRM";
        Class<?> otvrmClass = XposedHelpers.findClassIfExists(otvrmCls, cl);
        if (otvrmClass != null && !sHookedFaceClasses.contains(otvrmClass)) {
            sHookedFaceClasses.add(otvrmClass);
            HookUtils.hookAllConstructors(otvrmClass, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.thisObject != null) {
                        ensureOtvrmInitialized(param.thisObject, cl, null);
                    }
                }
            });
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
            XposedEntry.log("[FacePatch] Hooked OTVRM constructors & a methods with universal null-safe guard");
        }

        // 2. TuringSdkImp: b(Context) hardware init & a() status / a(String, String) sign / a(View, CameraHolder, String) start
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
                        if (m.getReturnType() == String.class && (param.args == null || param.args.length == 0)) {
                            param.setResult(""); // Only String a() -> return error string or ""
                        } else if (param.args != null && param.args.length == 2) {
                            if (param.args[0] == null) param.args[0] = "";
                            if (param.args[1] == null) param.args[1] = "";
                        } else if (m.getReturnType() == int.class && param.args != null && param.args.length == 3) {
                            // a(View, CameraHolder, String) defender start
                            try {
                                android.content.Context ctx = null;
                                if (param.args[0] instanceof android.view.View) {
                                    ctx = ((android.view.View) param.args[0]).getContext();
                                }
                                Class<?> bi3eTClass = XposedHelpers.findClassIfExists("com.tencent.turingcam.OTVRM$Bi3eT", cl);
                                if (bi3eTClass != null) {
                                    Object otvrm = XposedHelpers.getStaticObjectField(bi3eTClass, "a");
                                    ensureOtvrmInitialized(otvrm, cl, ctx);
                                }
                            } catch (Throwable t) {
                                XposedEntry.log("[FacePatch] Error pre-initializing OTVRM before TuringSdkImp.a: " + t.getMessage());
                            }
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
            XposedEntry.log("[FacePatch] Hooked TuringSdkImp for face hardware status, sign, and defender start");
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
                                        XposedHelpers.setObjectField(fInstance, "g", impCls.newInstance());
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

        // 3. TuringSdkImp$a: onException, onFinish, onFinishFrameCheck
        final String callbackCls = "com.tencent.could.huiyansdk.turingmodule.TuringSdkImp$a";
        Class<?> cbClass = XposedHelpers.findClassIfExists(callbackCls, cl);
        if (cbClass != null && !sHookedFaceClasses.contains(cbClass)) {
            sHookedFaceClasses.add(cbClass);
            HookUtils.hookAllMethods(cbClass, "onException", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(null); // void, suppress exception
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
            HookUtils.hookAllMethods(cbClass, "onFinish", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number && ((Number) param.args[0]).longValue() != 0) {
                            param.args[0] = 0L;
                        }
                        if (param.args[1] == null) {
                            param.args[1] = new byte[32];
                        }
                        XposedEntry.log("[FacePatch] Sanitized TuringSdkImp$a.onFinish args -> 0L");
                    }
                }
            });
            HookUtils.hookAllMethods(cbClass, "onFinishFrameCheck", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number && ((Number) param.args[0]).longValue() != 0) {
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

        // 4. Turing helper: com.tencent.could.huiyansdk.turing.d.a(long, byte[])
        final String dCls = "com.tencent.could.huiyansdk.turing.d";
        Class<?> dClass = XposedHelpers.findClassIfExists(dCls, cl);
        if (dClass != null && !sHookedFaceClasses.contains(dClass)) {
            sHookedFaceClasses.add(dClass);
            HookUtils.hookAllMethods(dClass, "a", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        if (param.args[0] instanceof Number) {
                            long code = ((Number) param.args[0]).longValue();
                            if (code != 0) {
                                param.args[0] = 0L;
                                XposedEntry.log("[FacePatch] Sanitized HuiYan Turing retCode: " + code + " -> 0");
                            }
                        }
                        if (param.args[1] == null) {
                            param.args[1] = new byte[32];
                            XposedEntry.log("[FacePatch] Provided fallback non-null Turing face token buffer");
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked HuiYan turing.d result consumer");
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
            });
            HookUtils.hookAllMethods(cacheClass, "isNeedFrameCheck", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
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
                            param.setResult(0); // public static int a() -> return 0 (initialized and healthy)
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
                        // ONLY hook int a(TuringFaceBuilder) -> return 0
                        // NEVER touch static JD1Ej a() or byte[] a(String)
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
                                XposedHelpers.setObjectField(safeSkEpO, "b", "");
                                param.setResult(safeSkEpO);
                                XposedEntry.log("[FacePatch] Constructed safe SkEpO for null JD1Ej.b");
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
                        if (event.contains("Error") || event.contains("Fail") || event.contains("Risk") || event.contains("Turing")) {
                            param.setResult(null);
                            XposedEntry.log("[FacePatch] Suppressed HuiYan buried point event: " + event);
                        }
                    }
                }
            });
            HookUtils.hookAllMethods(huiyanSdkClass, "doOnFail", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
                        String msg = String.valueOf(param.args[1]);
                        int code = param.args[0] instanceof Number ? ((Number) param.args[0]).intValue() : 0;
                        if (msg.contains("400103") || msg.contains("Turing") || msg.contains("Env") || msg.contains("环境") || code == 214 || code == 216 || code == 224 || code == 285) {
                            param.setResult(null);
                            XposedEntry.log("[FacePatch] Intercepted HuiYanSdkImp.doOnFail environment error: code=" + code + ", msg=" + msg);
                        }
                    }
                }
            });
            XposedEntry.log("[FacePatch] Hooked HuiYanSdkImp.sendBuriedPointInfo & doOnFail");
        }

        // 9. CommonUtils: sendErrorAndExitAuth
        final String commonUtilsCls = "com.tencent.could.huiyansdk.utils.CommonUtils";
        Class<?> commonUtilsClass = XposedHelpers.findClassIfExists(commonUtilsCls, cl);
        if (commonUtilsClass != null && !sHookedFaceClasses.contains(commonUtilsClass)) {
            sHookedFaceClasses.add(commonUtilsClass);
            HookUtils.hookAllMethods(commonUtilsClass, "sendErrorAndExitAuth", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length >= 2) {
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
                            param.setResult(320.0f);
                            XposedEntry.log("[FacePatch] SensorManagerWorker.getLux fallback: " + lux + " -> 320.0f");
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
                                f.setFloat(param.thisObject, 320.0f);
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
                                param.args[0] = 320.0f;
                                XposedEntry.log("[FacePatch] " + sdcName + " ctor lux sanitized: " + lux + " -> 320.0f");
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
                                        XposedHelpers.setObjectField(ad, "lux", 320.0f);
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
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object r = param.getResult();
                                if (r instanceof Float) {
                                    float v = (Float) r;
                                    if (v < 0.0f || v > 20000.0f) {
                                        param.setResult(320.0f);
                                    }
                                }
                            }
                        });
                    }
                }
            }
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
            // Normalize O3Report.d(String, String, String) - sign_report (attaId = "0df00071646")
            HookUtils.hookAllMethods(o3ReportClazz, "d", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] != null) {
                        p.args[0] = "a6b745bf24a2c277527716f6f36eb68d";
                    }
                    XposedEntry.log("[O3Patch] Normalized O3Report.d (sign_report official MD5)");
                }
            });

            // Normalize O3Report.b(String, List, String) - env_detect (attaId = "00e00075618")
            HookUtils.hookAllMethods(o3ReportClazz, "b", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                        java.util.List list = (java.util.List) p.args[1];
                        for (int i = 0; i < list.size(); i++) {
                            list.set(i, "0");
                        }
                    }
                    XposedEntry.log("[O3Patch] Normalized O3Report.b (env_detect clean values)");
                }
            });

            // Normalize O3Report.c(String, List) - fakeLocationReport / nearLocationReport
            HookUtils.hookAllMethods(o3ReportClazz, "c", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof java.util.List) {
                        java.util.List list = (java.util.List) p.args[1];
                        if (!list.isEmpty()) {
                            list.set(0, "0");
                        }
                    }
                    XposedEntry.log("[O3Patch] Normalized O3Report.c (fakeReason=0)");
                }
            });

            // Allow O3Report.a(String, ArrayList, ProtoUtils.TroopProtocolObserver) to deliver to server
        }

        // 2. Hook com.tencent.qqprotect.qsec.a (Device profile collector)
        Class<?> qsecAClazz = XposedHelpers.findClassIfExists("com.tencent.qqprotect.qsec.a", cl);
        if (qsecAClazz != null && sHookedO3Classes.add(qsecAClazz)) {
            HookUtils.hookAllMethods(qsecAClazz, "e", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof String) {
                        String raw = (String) p.getResult();
                        try {
                            org.json.JSONObject json = new org.json.JSONObject(raw);
                            json.put("10", "none");
                            json.put("30", 0);
                            json.put("31", "[]");
                            json.put("32", "[]");
                            json.put("14", "CK_N");
                            p.setResult(json.toString());
                            XposedEntry.log("[O3Patch] Sanitized qqprotect.qsec.a.e device profile JSON");
                        } catch (Throwable ignored) { }
                    }
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "n", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("none");
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "f", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("[]");
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "g", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult("[]");
                }
            });
            HookUtils.hookAllMethods(qsecAClazz, "o", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.getResult() instanceof Number && ((Number) p.getResult()).longValue() <= 0L) {
                        p.setResult(1727000000000L);
                    }
                }
            });
        }

        // 3. Hook O3BusinessHandler (P2, Q2, R2, S2)
        Class<?> o3HandlerClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.web.O3BusinessHandler", cl);
        if (o3HandlerClazz != null && sHookedO3Classes.add(o3HandlerClazz)) {
            XC_MethodHook o3HandlerHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[0] instanceof String) {
                        String event = (String) p.args[0];
                        String params = p.args[1] != null ? p.args[1].toString() : "";
                        if ("recError".equals(event)) {
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Dropped O3BusinessHandler.recError (prevented server lock)");
                            return;
                        }
                        if (params.contains("GetSocialLockStatus") || ("sendRequest".equals(event) && params.contains("SocialLock"))) {
                            if (p.args.length >= 3 && p.args[2] != null) {
                                try {
                                    XposedHelpers.callMethod(p.args[2], "a", 0, "{\"is_locked\":false,\"rsp_code\":0}".getBytes("UTF-8"));
                                } catch (Throwable ignored) {}
                            }
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Fulfilled GetSocialLockStatus with safe is_locked=false");
                            return;
                        }
                        if (params.contains("display_report")) {
                            try {
                                org.json.JSONObject jobj = new org.json.JSONObject(params);
                                org.json.JSONObject inner = new org.json.JSONObject();
                                inner.put("data", "0,0,0,0");
                                jobj.put("data", inner);
                                p.args[1] = jobj.toString();
                            } catch (Throwable ignored) {}
                            XposedEntry.log("[O3Patch] Normalized display_report payload (0,0,0,0) and allowed delivery");
                            return;
                        }
                        if (params.contains("FullSocialLockPunish") || params.contains("socialError")) {
                            if (p.args.length >= 3 && p.args[2] != null) {
                                try {
                                    XposedHelpers.callMethod(p.args[2], "a", 0, new byte[0]);
                                } catch (Throwable ignored) {}
                            }
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Suppressed social punishment: " + event);
                            return;
                        }
                    }
                }
            };
            HookUtils.hookAllMethods(o3HandlerClazz, "P2", o3HandlerHook);
            HookUtils.hookAllMethods(o3HandlerClazz, "Q2", o3HandlerHook);

            HookUtils.hookAllMethods(o3HandlerClazz, "R2", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                        String cmd = (String) p.args[0];
                        if (cmd.contains("SocialLock") || cmd.contains("full_social_lock_punish")) {
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Suppressed O3BusinessHandler.R2: " + cmd);
                        }
                    }
                }
            });

            HookUtils.hookAllMethods(o3HandlerClazz, "S2", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                        String cmd = (String) p.args[0];
                        if (cmd.contains("SocialLock") || cmd.contains("full_social_lock_punish")) {
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Suppressed O3BusinessHandler.S2: " + cmd);
                        }
                    }
                }
            });
        }

        // 4. Hook com.tencent.mobileqq.dt.model.d & VirtualClickDetection & DTAPIImpl
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

        Class<?> dtapiClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.api.impl.DTAPIImpl", cl);
        if (dtapiClazz != null && sHookedO3Classes.add(dtapiClazz)) {
            HookUtils.hookAllMethods(dtapiClazz, "onSecDispatchToAppEvent", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 1 && p.args[0] instanceof String) {
                        String event = (String) p.args[0];
                        if ("socialError".equals(event) || "mainProcessCall".equals(event)) {
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Suppressed DTAPIImpl.onSecDispatchToAppEvent: " + event);
                        }
                    }
                }
            });
        }

        // 5. Hook com.tencent.mobileqq.dt.api.impl.QSecChannelImpl
        Class<?> qsecChannelClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.dt.api.impl.QSecChannelImpl", cl);
        if (qsecChannelClazz != null && sHookedO3Classes.add(qsecChannelClazz)) {
            HookUtils.hookAllMethods(qsecChannelClazz, "reportEnable", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(true);
                }
            });
            HookUtils.hookAllMethods(qsecChannelClazz, "sendRequest", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args != null && p.args.length >= 2 && p.args[1] instanceof String) {
                        String cmd = (String) p.args[1];
                        if (cmd.contains("SocialLock") || cmd.contains("GetSocialLockStatus")) {
                            if (p.args.length >= 5 && p.args[4] != null) {
                                try {
                                    XposedHelpers.callMethod(p.args[4], "onResult", 0, "{\"is_locked\":false,\"rsp_code\":0}".getBytes("UTF-8"));
                                } catch (Throwable ignored) {}
                            }
                            p.setResult(null);
                            XposedEntry.log("[O3Patch] Intercepted QSecChannelImpl.sendRequest (" + cmd + ")");
                        }
                    }
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
            HookUtils.hookAllMethods(ganliangClazz, "checkDeviceRisk", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0);
                }
            });
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
            "com.tencent.map.geolocation.sapp.TencentLocation",
            "com.tencent.map.geolocation.internal.TencentExtraKeys",
            "com.tencent.map.geolocation.sapp.internal.TencentExtraKeys"
        };
        for (String cls : tencentLocClasses) {
            hookSafe(cls, "getFakeReason", lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0); // 0 = genuine, zero anomaly
                }
            });
            hookSafe(cls, "isMockGps", lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(0);
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

        // Framework Location: isFromMockProvider & isMock
        HookUtils.hookAllMethods("android.location.Location", "isFromMockProvider", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        HookUtils.hookAllMethods("android.location.Location", "isMock", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });

        // 2. Physical Sensor Detection Source: qqprotect.qsec.b, c, d
        // We do NOT fabricate static sensor values like "{x=0.231, y=9.765, z=0.412}" or 150.0f.
        // Static sensor readings over time with zero jitter are an immediate red flag for Tencent risk engines.
        // On physical devices, genuine sensor listeners update dynamically; uninitialized state naturally returns "-1"
        // or "-1.0" matching Tencent's official baseline logic.

        // 3. Screen / Display & Remote Control Detection Source: Display & Ganliang
        HookUtils.hookAllMethods("android.view.Display", "getOwnerPackageName", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
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

        // 4. SourceDir LastModified Detection Source
        final String qsecACls = "com.tencent.qqprotect.qsec.a";
        hookSafe(qsecACls, "o", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                if (p.getResult() instanceof Number && ((Number) p.getResult()).longValue() <= 0L) {
                    p.setResult(1727000000000L);
                }
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
                    java.util.List list = (java.util.List) res;
                    java.util.List filtered = new java.util.ArrayList();
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
                    java.util.List list = (java.util.List) res;
                    java.util.List filtered = new java.util.ArrayList();
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
        hookSafe(dtcCls, "getAccessibilityServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("[]");
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledServiceList", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("[]");
            }
        });
        hookSafe(dtcCls, "getAccessibilityEnabledStatus", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
            }
        });
        hookSafe(dtcCls, "checkRiskPermission", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
            }
        });
        hookSafe(dtcCls, "checkAppInstalled", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
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
        hookSafe(crashDefendMgrCls, "hasCrashedAtStartup", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(crashDefendMgrCls, "d", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });
        hookSafe(crashDefendMgrCls, "b", lpparam, new XC_MethodHook() {
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
        XposedEntry.log("[Tier6] Initializing txlib, txPttlib & MQP integrity protection");

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

        final String msfCoreCls = "com.tencent.mobileqq.msf.core.MsfCore";
        hookSafe(msfCoreCls, "tryReportSoLoadUseTxlib", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[TxLibPatch] Suppressed MsfCore.tryReportSoLoadUseTxlib");
            }
        });

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
                XposedEntry.log("[MQPPatch] Neutralized MQPSecUtil.antitrace");
            }
        });

        hookSafe(mqpSecUtilCls, "do_report", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MQPSecUtil.do_report");
            }
        });

        final String intChkStrikeCls = "com.tencent.msfmqpsdkbridge.MSFIntChkStrike";
        hookSafe(intChkStrikeCls, "exec", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(null);
                XposedEntry.log("[MQPPatch] Suppressed MSFIntChkStrike.exec (prevented strike popup/logout)");
            }
        });

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
                p.setResult("A6B745BF24A2C277527716F6F36EB68D");
                XposedEntry.log("[SelfVerifyPatch] SecUtil.getSignatureHash -> spoofed official MD5 A6B745BF24A2C277527716F6F36EB68D");
            }
        });

        // SafeCheckUtilApiImpl: getFileMD5
        final String safeCheckCls = "com.tencent.qqprotect.sfcfg.api.impl.SafeCheckUtilApiImpl";
        hookSafe(safeCheckCls, "getFileMD5", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
                XposedEntry.log("[SelfVerifyPatch] SafeCheckUtilApiImpl.getFileMD5 -> forced 0 (clean APK MD5)");
            }
        });

        // Yuanbao launcher signature MD5 check
        final String ybLauncherCls = "com.tencent.mobileqq.ad.yuanbao.launch.c";
        hookSafe(ybLauncherCls, "c", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult("A6B745BF24A2C277527716F6F36EB68D");
                XposedEntry.log("[SelfVerifyPatch] YuanbaoOpenSdkLauncher.c -> spoofed official MD5");
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
                                ((java.util.Map) p.args[i]).put("param_FailCode", "0");
                                break;
                            }
                        }
                        XposedEntry.log("[PttPatch] Sanitized actPttSoUpdate telemetry to success (0)");
                    } else if ("msf_core_EvtMsfLoadSoError".equals(tag) || "msf_core_EvtLoadUseTxlib".equals(tag)) {
                        p.setResult(null);
                        XposedEntry.log("[TxLibPatch] Suppressed SO load telemetry: " + tag);
                    }
                }
            }
        });
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
        XposedEntry.log("[Tier7] Initializing RFix & Hotfix failure sanitization and telemetry drop");

        // 1. RFix Quality Reporter: Drop failure reports in com.tencent.rfix.lib.reporter.e
        XC_MethodHook dropFailureReportHook = new XC_MethodHook() {
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

                    if (!eventSuccess || (eventCode != null && eventCode.contains("FAIL")) ||
                        "-8".equals(eventCodeExt) || "LOAD_RESULT_PATCH_LOADER_FAIL".equals(eventCode)) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped RFix failure telemetry report: eventCode=" + eventCode + ", codeExt=" + eventCodeExt);
                    }
                } catch (Throwable t) {
                    XposedEntry.log("[RFixPatch] Error filtering RFix reporter: " + t.getMessage());
                }
            }
        };
        hookSafe("com.tencent.rfix.lib.reporter.e", "d", lpparam, dropFailureReportHook);
        hookSafe("com.tencent.rfix.lib.reporter.e", "e", lpparam, dropFailureReportHook);

        // Drop caller methods in e: a, b
        hookSafe("com.tencent.rfix.lib.reporter.e", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(null);
                            XposedEntry.log("[RFixPatch] Dropped com.tencent.rfix.lib.reporter.e.a failure report");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });
        hookSafe("com.tencent.rfix.lib.reporter.e", "b", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 1 && p.args[1] != null) {
                    try {
                        boolean isSuccess = (Boolean) XposedHelpers.callMethod(p.args[1], "isLoaderSuccess");
                        if (!isSuccess) {
                            p.setResult(true);
                            XposedEntry.log("[RFixPatch] Dropped com.tencent.rfix.lib.reporter.e.b failure report");
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        // 2. RFix ATTASwitch: Force disable RFix ATTA/WeData network reporting
        hookSafe("com.tencent.rfix.lib.atta.RFixATTASwitch", "a", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
            }
        });

        // 3. RFix ATTA Database & Upload Helper (com.tencent.rfix.lib.atta.e)
        hookSafe("com.tencent.rfix.lib.atta.e", "d", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object eventCode = map.get("event_code");
                    Object eventSuccess = map.get("event_success");
                    Object attaid = map.get("attaid");
                    if ("0ac00056535".equals(attaid) && ("0".equals(eventSuccess) || (eventCode != null && eventCode.toString().contains("FAIL")))) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped ATTA poison failure record from atta.e.d");
                    }
                }
            }
        });

        // 4. WeData Reporter (com.tencent.rfix.lib.wedata.base.d)
        hookSafe("com.tencent.rfix.lib.wedata.base.d", "c", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                if (p.args != null && p.args.length > 0 && p.args[0] instanceof java.util.Map) {
                    java.util.Map map = (java.util.Map) p.args[0];
                    Object eventCode = map.get("event_code");
                    Object eventSuccess = map.get("event_success");
                    if ("0".equals(eventSuccess) || (eventCode != null && eventCode.toString().contains("FAIL"))) {
                        p.setResult(true);
                        XposedEntry.log("[RFixPatch] Dropped WeData failure report in wedata.base.d.c");
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
                    if (cls != null && (cls.contains("xposed") || cls.contains("lsposed") ||
                                       cls.contains("canyie") || cls.contains("sandhook") ||
                                       cls.contains("epic") || cls.contains("pine") ||
                                       cls.contains("yahfa") || cls.contains("qqbypass") ||
                                       cls.contains("native-bypass") || cls.contains("bytehook"))) {
                        p.setResult(false);
                        XposedEntry.log("[QSecPatch] Blocked detectMethod: " + cls + "->" + mtd);
                    }
                }
            }
        });

        hookSafe(qsecCls, "getFeKitAttach", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                byte[] res = (byte[]) p.getResult();
                if (res == null || res.length == 0) {
                    p.setResult(new byte[]{0});
                }
            }
        });

        // Hardware Keystore / Keymaster Attestation BootStatus Normalization
        final String parserCls = "com.tencent.mobileqq.qsec.qsecurity.utils.SimpleAttestationParser";
        hookSafe(parserCls, "getBootStatus", lpparam, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {
                Object bs = p.getResult();
                if (bs == null) return;
                try {
                    XposedHelpers.setIntField(bs, "verifiedBootState", 0);
                } catch (Throwable ignored) {}
                try {
                    XposedHelpers.setIntField(bs, "isDeviceLocked", 1);
                } catch (Throwable ignored) {}
                try {
                    XposedHelpers.setIntField(bs, "attestationSecurityLevel", 1);
                } catch (Throwable ignored) {}
                try {
                    XposedHelpers.setIntField(bs, "keymasterSecurityLevel", 1);
                } catch (Throwable ignored) {}
                XposedEntry.log("[QSecPatch] Normalized SimpleAttestationParser.BootStatus: verifiedBootState=0, isDeviceLocked=1");
            }
        });

        // Socket detection neutralization
        hookSafe("com.tencent.mobileqq.qsec.qsecurity.utils.SocketStatus", "checkSocket", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
            }
        });

        // Certification status check
        hookSafe("com.tencent.mobileqq.qsec.qsecurity.utils.CertificationStatus", "BL", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(0);
            }
        });

        // Main process check
        hookSafe("com.tencent.mobileqq.qsec.qsecurity.utils.ProcessCheck", "isMainProcess", lpparam, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(true);
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
            hookSafe(cn, "isX86Emulator", lpparam, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(false);
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
            protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                p.setResult(false);
                XposedEntry.log("[EmulatorPatch] RFWDeviceUtil.isX86Emulator forced false");
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

    // ============ Tier 10: Message Sync & Loading State Stabilization ============

    private static final java.util.Set<Class<?>> sHookedSyncClasses =
        java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    private static void hookMessageSyncAndLoadingState(XC_LoadPackage.LoadPackageParam lpparam) {
        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        hookMessageSyncAndLoadingStateWithClassLoader(cl);
    }

    public static void hookMessageSyncAndLoadingStateWithClassLoader(ClassLoader cl) {
        if (cl == null) return;

        // 1. LoadingStateManager (com.tencent.mobileqq.managers.d)
        // When state changes to 1 (connecting) or 2 (syncing), schedule auto-dismiss if sync stalls
        Class<?> dClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.managers.d", cl);
        if (dClazz != null && sHookedSyncClasses.add(dClazz)) {
            HookUtils.hookAllMethods(dClazz, "c", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof Number) {
                        int state = ((Number) param.args[0]).intValue();
                        if (state == 1 || state == 2) {
                            final Object manager = param.thisObject;
                            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                                try {
                                    int cur = (int) XposedHelpers.callMethod(manager, "f");
                                    if (cur == 1 || cur == 2) {
                                        XposedHelpers.callMethod(manager, "c", 3, "autoDismissSyncStall");
                                        XposedEntry.log("[SyncPatch] Auto-cleared prolonged loading state: " + cur + " -> 3");
                                    }
                                } catch (Throwable ignored) {}
                            }, 2500L);
                        }
                    }
                }
            });
            XposedEntry.log("[SyncPatch] Hooked LoadingStateManager.c with 2.5s auto-dismiss safeguard");
        }

        // 2. Conversation loading state handler: clamp 180s delay down to 2.5s
        Class<?> convClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.activity.home.Conversation", cl);
        if (convClazz != null && sHookedSyncClasses.add(convClazz)) {
            HookUtils.hookAllMethods(convClazz, "changeConversationLoadingState", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    try {
                        Object handler = XposedHelpers.getObjectField(param.thisObject, "mLoadingStateHandler");
                        if (handler instanceof android.os.Handler) {
                            android.os.Handler h = (android.os.Handler) handler;
                            if (h.hasMessages(3)) {
                                h.removeMessages(3);
                                h.sendEmptyMessageDelayed(3, 2500L);
                            }
                            if (h.hasMessages(4)) {
                                h.removeMessages(4);
                                h.sendEmptyMessageDelayed(4, 2500L);
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            });
            XposedEntry.log("[SyncPatch] Hooked Conversation.changeConversationLoadingState to clamp 180s timeout");
        }

        // 3. QQAppInterface.setLoadingState: prevent reconnect from sticking in loading state
        Class<?> appClazz = XposedHelpers.findClassIfExists("com.tencent.mobileqq.app.QQAppInterface", cl);
        if (appClazz != null && sHookedSyncClasses.add(appClazz)) {
            HookUtils.hookAllMethods(appClazz, "setLoadingState", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                        try {
                            Class<?> dCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.managers.d", cl);
                            if (dCls != null) {
                                Object dInst = XposedHelpers.callStaticMethod(dCls, "e");
                                if (dInst != null) {
                                    int cur = (int) XposedHelpers.callMethod(dInst, "f");
                                    if (cur == 1 || cur == 2) {
                                        XposedHelpers.callMethod(dInst, "c", 3, "reconnectDismiss");
                                        XposedEntry.log("[SyncPatch] Cleared reconnect loadingState -> 3");
                                    }
                                }
                            }
                        } catch (Throwable ignored) {}
                    }, 2000L);
                }
            });
            XposedEntry.log("[SyncPatch] Hooked QQAppInterface.setLoadingState for instant reconnect recovery");
        }
    }
}


