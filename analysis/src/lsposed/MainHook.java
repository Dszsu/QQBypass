package com.qqclean.bypass;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * QQ 自检测 / 完整性校验全返回值清理  v2
 *
 * v1 只覆盖了 11 个根/调试检测点。v2 依据两轮静态分析 + 外部参考文档补全：
 *   - SecUtil 三件套（0Day 重打包 / 签名原始字节 / 签名 MD5）
 *   - SafeCheckUtilApiImpl.getFileMD5（APK 内条目校验）
 *   - PackageUtil 六个方法的「按槽位精准置换」（不是全抹零）
 *   - fe.utils.a —— XOR 0x55 混淆的 ClassLoader/DEX 扫描器
 *   - Dtc 环境画像 + dt.app.h 证书探针
 *
 * 设计铁律：
 *   1. 每个 hook 独立 try/catch，符号缺失只记 [SKIP]，绝不影响其他项。
 *   2. 不改类结构、不删类、不动 native。
 *   3. 批量接口按索引槽位替换，避免「全零响应」这种更明显的异常特征。
 */
public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "QQClean";
    private static final String PKG = "com.tencent.mobileqq";

    /** QQ 官方签名证书的 MD5（腾讯沿用十余年的通配签名，本样本实测一致） */
    private static final String OFFICIAL_SIGN_MD5 = "A6B745BF24A2C277527716F6F36EB68D";

    private static volatile boolean sweepArmed = false;

    /** su / 后门路径关键词（合并了 QQ 各处检测表并集） */
    private static final Set<String> SU_TOKENS = new HashSet<>(Arrays.asList(
            "/su", "su/bin", "/sbin/su", "xbin/su", "/bin/su", "failsafe/su",
            "/data/local/su", "/system/sd/xbin/su", "Superuser.apk",
            "cufsdosck", "cufsmgr", "cufaevdd", "conbb",
            "magisk", "kernelsu", "ksu", "apatch", "sukisu", "ksunext",
            "kingroot", "oneclickroot", "daemonsu", "permmgrd", "360sguard",
            "busybox", "bdsu", "sutemp", "shuamesu"
    ));

    /** 需要伪装成「未安装」的框架包（合并文档补充项） */
    private static final Set<String> HIDDEN_PACKAGES = new HashSet<>(Arrays.asList(
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed",
            "com.saurik.substrate",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "io.va.exposed",
            "top.canyie.dreamland.manager",
            "re.frida.server",
            "com.topjohnwu.magisk",
            "moe.shizuku.privileged.api",
            "com.termux",
            "io.github.vvb2060.magisk",
            "moe.ono",
            "com.tsng.hidemyapplist"
    ));

    private final Set<String> done = new HashSet<>();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) {
        if (!PKG.equals(lpp.packageName)) {
            return;
        }
        log("注入 QQ v" + getVersionName(lpp) + "  process=" + lpp.processName);

        installClassOnlyHooks(lpp.classLoader);
        installApplicationHook(lpp.classLoader);

        // 模拟器检测中和
        EmulatorHook.install(lpp.classLoader);

        // 人脸核身（优图活体）环境数据中和：lux 等
        try {
            FaceEnvHook.install(lpp.classLoader);
        } catch (Throwable t) {
            log("FaceEnvHook 失败: " + t);
        }

        // 踢线诊断：默认只记录不抑制，见 KickDiag 顶部说明
        KickDiag.install(lpp.classLoader);
    }

    /** 不需要 Context 的 hook，尽早装上 */
    private void installClassOnlyHooks(ClassLoader cl) {
        hookSuFileExist(cl);
        hookLightIsRooted(cl);
        hookGatherergaRooted(cl);
        hookTenpayRooted(cl);
        hookPackageUtil(cl);          // v2：六个方法全覆盖
        hookPackageManagerInstalled(cl);
        hookFeUtilsA(cl);             // v2：XOR 混淆扫描器
        hookQSecDetectMethod(cl);
        hookQSecCheckSocket(cl);
        hookQSecCertification(cl);
        hookAttestationParser(cl);
        hookSecUtil(cl);              // v2：签名三件套
        hookSafeCheckFileMd5(cl);     // v2：APK 条目 MD5
        hookDtCaList(cl);             // v2：证书探针
        log("类级 hook 装完，生效 " + done.size() + " 项");
    }

    private void installApplicationHook(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod(
                    "android.app.Application", cl,
                    "attach", Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            hookDebugInfo(cl);
                            hookQSecMasterProcess(cl);
                            hookDtcRiskPermission(cl);
                            log("Context 级 hook 装完，累计 " + done.size() + " 项");
                            armSweeper(cl);
                        }
                    });
        } catch (Throwable t) {
            log("attach hook 失败: " + t);
            armSweeper(cl);
        }
    }

    // ==========================================================
    //  ① 根检测
    // ==========================================================

    private void hookSuFileExist(ClassLoader cl) {
        hook("wlogin.util.isFileExist", () -> {
            XposedHelpers.findAndHookMethod(
                    "oicq.wlogin_sdk.tools.util", cl,
                    "isFileExist", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            String path = (String) p.args[0];
                            if (path != null && isSuPath(path)) {
                                p.setResult(false);
                                log("→ isFileExist(\"" + path + "\") = false");
                            }
                        }
                    });
        });
    }

    private void hookLightIsRooted(ClassLoader cl) {
        hook("LightDeviceUtils.isRooted", () -> {
            XposedHelpers.findAndHookMethod(
                    "org.light.device.LightDeviceUtils", cl,
                    "isRooted",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                            setStaticField(cl, "org.light.device.LightDeviceUtils",
                                    "isRooted", Boolean.FALSE);
                        }
                    });
        });
    }

    private void hookGatherergaRooted(ClassLoader cl) {
        hook("Gathererga.isRooted", () -> {
            Class<?> impl = XposedHelpers.findClass(
                    "com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", cl);
            Class<?> wrapper = XposedHelpers.findClass(
                    "com.tencent.gathererga.core.internal.provider.c", cl);
            XposedBridge.hookAllMethods(impl, "isRooted", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (p.getResult() == null) {
                        return;
                    }
                    try {
                        p.setResult(XposedHelpers.newInstance(wrapper, 0L, Boolean.FALSE));
                        log("→ Gathererga.isRooted = FALSE");
                    } catch (Throwable t) {
                        log("  Gathererga 包装失败: " + t);
                    }
                }
            });
        });
    }

    private void hookTenpayRooted(ClassLoader cl) {
        hook("Tenpay.isDeviceRooted", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tenpay.charge.v2.util.ChargeV2Utils", cl,
                    "isDeviceRooted",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                        }
                    });
        });
    }

    // ==========================================================
    //  ② PackageUtil —— 六个方法，按槽位精准置换
    // ==========================================================

    private void hookPackageUtil(ClassLoader cl) {
        final String CN = "com.tencent.mobileqq.utils.PackageUtil";

        // 单包：敏感命中才改，否则保持原样
        hook("PackageUtil.isAppInstalled", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "isAppInstalled",
                    Context.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            String pkg = (String) p.args[1];
                            if (isSuspiciousPackage(pkg)) {
                                p.setResult(false);
                                log("→ isAppInstalled(" + pkg + ") = false");
                            }
                        }
                    });
        });

        hook("PackageUtil.checkAppInstalled", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "checkAppInstalled",
                    Context.class, String.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            String pkg = (String) p.args[1];
                            if (isSuspiciousPackage(pkg)) {
                                p.setResult("0");
                                log("→ checkAppInstalled(" + pkg + ") = \"0\"");
                            }
                        }
                    });
        });

        // 批量三兄弟：解析 | 分隔，只替换敏感包对应的槽位
        for (final String meth : new String[]{
                "checkAppInstalledBatch", "isAppInstalledBatch", "getAppsVerionCodeBatch"}) {
            hook("PackageUtil." + meth, () -> {
                XposedHelpers.findAndHookMethod(CN, cl, meth,
                        Context.class, String.class, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) {
                                String req = (String) p.args[1];
                                Object res = p.getResult();
                                if (req == null || !(res instanceof String)) {
                                    return;
                                }
                                String reqs = (String) res;
                                String[] parts = req.split("\\|", -1);
                                String[] outs = reqs.split("\\|", -1);
                                if (parts.length != outs.length) {
                                    return;   // 结构对不上就不动，避免制造异常
                                }
                                boolean changed = false;
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < parts.length; i++) {
                                    String v = outs[i];
                                    if (isSuspiciousPackage(parts[i])) {
                                        v = "0";
                                        changed = true;
                                    }
                                    if (i > 0) {
                                        sb.append('|');
                                    }
                                    sb.append(v);
                                }
                                if (changed) {
                                    p.setResult(sb.toString());
                                    log("→ " + meth + " 槽位替换完成");
                                }
                            }
                        });
            });
        }

        hook("PackageUtil.verifyInstalledApp", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "verifyInstalledApp",
                    Context.class, String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            String pkg = (String) p.args[1];
                            if (isSuspiciousPackage(pkg)) {
                                p.setResult(false);
                            }
                        }
                    });
        });
    }

    /** PackageManager 层面兜底 */
    private void hookPackageManagerInstalled(ClassLoader cl) {
        hook("PackageManager.getPackageInfo", () -> {
            XposedHelpers.findAndHookMethod(
                    "android.app.ApplicationPackageManager", cl,
                    "getPackageInfo", String.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            String pkg = (String) p.args[0];
                            if (isSuspiciousPackage(pkg)) {
                                p.setThrowable(new android.content.pm.PackageManager
                                        .NameNotFoundException(pkg));
                            }
                        }
                    });
        });
    }

    // ==========================================================
    //  ③ SecUtil —— 签名三件套 + 0Day 重打包
    // ==========================================================

    private void hookSecUtil(ClassLoader cl) {
        final String CN = "com.tencent.mobileqq.utils.SecUtil";

        hook("SecUtil.check0DayRepack", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "check0DayRepack",
                    Context.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                            log("→ SecUtil.check0DayRepack = false");
                        }
                    });
        });

        // getSignatureHash(byte[]) 可能被调用多次，直接给官方 MD5
        hook("SecUtil.getSignatureHash", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "getSignatureHash",
                    byte[].class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(OFFICIAL_SIGN_MD5);
                        }
                    });
        });

        // getSign(Context) 返回签名证书原始字节。不伪造证书（伪造反而可能被比对），
        // 只保证它不返回 null / 空数组，让下游的 MD5 计算走正常路径。
        hook("SecUtil.getSign", () -> {
            XposedHelpers.findAndHookMethod(CN, cl, "getSign",
                    Context.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object r = p.getResult();
                            if (r instanceof byte[] && ((byte[]) r).length > 0) {
                                return;   // 原包未被改动时本来就正常
                            }
                            log("→ SecUtil.getSign 返回空，标记（需真机确认）");
                        }
                    });
        });
    }

    /** SafeCheckUtilApiImpl.getFileMD5(apkPath, entryName, byte[]) —— 条目级校验 */
    private void hookSafeCheckFileMd5(ClassLoader cl) {
        hook("SafeCheckUtilApiImpl.getFileMD5", () -> {
            Class<?> c = XposedHelpers.findClass(
                    "com.tencent.qqprotect.sfcfg.api.impl.SafeCheckUtilApiImpl", cl);
            XposedBridge.hookAllMethods(c, "getFileMD5", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    Object r = p.getResult();
                    // 原方法返回 String 或 int；按类型给「成功」默认值
                    if (r instanceof Integer) {
                        p.setResult(0);
                    } else if (r instanceof String) {
                        p.setResult(OFFICIAL_SIGN_MD5);
                    }
                    log("→ getFileMD5 已归一");
                }
            });
        });
    }

    // ==========================================================
    //  ④ fe.utils.a —— XOR 0x55 混淆的 ClassLoader / DEX 扫描器
    // ==========================================================

    /**
     * 该类方法名被混淆为 a/b/c/d/e/f/g，语义靠参数签名区分：
     *   a(Context, ClassLoader) -> boolean   父级 ClassLoader 黑名单检测
     *   b(Context, ClassLoader) -> boolean   DexElement 路径检测
     *   g(Context)              -> boolean   总入口 = a || b
     *   c/d/e/f                 -> 辅助（字符串解密 / 条件判断）
     *
     * 出于「宁可少动」的考虑，这里只中和判定类方法（返回 boolean 的），
     * 不解密类（c）以免影响其他调用方。
     */
    private void hookFeUtilsA(ClassLoader cl) {
        hook("fe.utils.a", () -> {
            Class<?> c = XposedHelpers.findClass("com.tencent.mobileqq.fe.utils.a", cl);
            int n = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() != boolean.class) {
                    continue;
                }
                Class<?>[] pt = m.getParameterTypes();
                boolean target = (pt.length == 1 && pt[0] == Context.class)
                        || (pt.length == 2 && pt[0] == Context.class
                            && pt[1] == ClassLoader.class);
                if (!target) {
                    continue;
                }
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(false);
                    }
                });
                n++;
            }
            if (n > 0) {
                log("→ fe.utils.a 已中和 " + n + " 个判定方法");
            } else {
                log("  fe.utils.a 未匹配到判定方法（签名可能变了）");
            }
        });
    }

    // ==========================================================
    //  ⑤ Dtc 环境画像
    // ==========================================================

    private void hookDtcRiskPermission(ClassLoader cl) {
        hook("Dtc.checkRiskPermission", () -> {
            Class<?> c = XposedHelpers.findClass("com.tencent.mobileqq.dt.app.Dtc", cl);
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals("checkRiskPermission")) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        if (p.getResult() instanceof Integer) {
                            p.setResult(0);
                        }
                    }
                });
            }
            log("→ Dtc.checkRiskPermission = 0");
        });

        // isAbnormalConfig 是 fe.utils.a 的上层调用者，直接压成 false 最稳
        hook("Dtc.isAbnormalConfig", () -> {
            XposedHelpers.findAndHookMethod("com.tencent.mobileqq.dt.app.Dtc", cl,
                    "isAbnormalConfig", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                        }
                    });
        });
    }

    /** dt.app.h —— 受信任凭证扫描，返回 List 的方法全部置空 */
    private void hookDtCaList(ClassLoader cl) {
        hook("dt.app.h 证书探针", () -> {
            Class<?> c = XposedHelpers.findClass("com.tencent.mobileqq.dt.app.h", cl);
            int n = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() != List.class) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(new ArrayList<>());
                    }
                });
                n++;
            }
            if (n > 0) {
                log("→ dt.app.h 已清空 " + n + " 个证书列表探针");
            }
        });
    }

    // ==========================================================
    //  ⑥ 调试 / 遥测
    // ==========================================================

    private void hookDebugInfo(ClassLoader cl) {
        hook("CameraSdk.getDebugInfo", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.camerasdk.avreport.DeviceInfo", cl,
                    "getDebugInfo", Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object r = p.getResult();
                            if (!(r instanceof String)) {
                                return;
                            }
                            String out = ((String) r)
                                    .replaceAll("(?m)^ro\\.debuggable\\|.*$", "ro.debuggable|0")
                                    .replaceAll("(?m)^ro\\.secure\\|.*$", "ro.secure|1")
                                    .replaceAll("(?m)^tracer_pid\\|.*$", "tracer_pid|0");
                            p.setResult(out);
                        }
                    });
        });
        hook("CameraSdk.staticFields", () -> {
            setStaticField(cl, "com.tencent.camerasdk.avreport.DeviceInfo", "roDebuggable", "0");
            setStaticField(cl, "com.tencent.camerasdk.avreport.DeviceInfo", "roSecure", "1");
        });
    }

    // ==========================================================
    //  ⑦ QSec
    // ==========================================================

    private void hookQSecDetectMethod(ClassLoader cl) {
        hook("QSec.detectMethod", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.mobileqq.qsec.qsecurity.QSec", cl,
                    "detectMethod", String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                        }
                    });
        });
    }

    private void hookQSecCheckSocket(ClassLoader cl) {
        hook("QSec.checkSocket", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.mobileqq.qsec.qsecurity.utils.SocketStatus", cl,
                    "checkSocket", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(1);
                        }
                    });
        });
    }

    private void hookQSecMasterProcess(ClassLoader cl) {
        hook("QSec.isMainProcess", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.mobileqq.qsec.qsecurity.utils.ProcessCheck", cl,
                    "isMainProcess", Context.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(true);
                        }
                    });
        });
    }

    private void hookQSecCertification(ClassLoader cl) {
        hook("QSec.CertificationStatus.BL", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.mobileqq.qsec.qsecurity.utils.CertificationStatus", cl,
                    "BL", byte[].class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(null);
                        }
                    });
        });
    }

    private void hookAttestationParser(ClassLoader cl) {
        hook("QSec.getBootStatus", () -> {
            XposedHelpers.findAndHookMethod(
                    "com.tencent.mobileqq.qsec.qsecurity.utils.SimpleAttestationParser", cl,
                    "getBootStatus", java.security.cert.X509Certificate.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object bs = p.getResult();
                            if (bs == null) {
                                return;
                            }
                            setInstanceField(bs, "verifiedBootState", 0);
                            setInstanceField(bs, "isDeviceLocked", 1);
                            setInstanceField(bs, "attestationSecurityLevel", 1);
                            setInstanceField(bs, "keymasterSecurityLevel", 1);
                        }
                    });
        });
    }

    // ==========================================================
    //  ⑧ 静态字段清扫
    // ==========================================================

    private void armSweeper(ClassLoader cl) {
        if (sweepArmed) {
            return;
        }
        sweepArmed = true;
        Thread t = new Thread(() -> {
            long end = System.currentTimeMillis() + 120_000L;
            while (System.currentTimeMillis() < end) {
                sweepStatics(cl);
                try {
                    Thread.sleep(3000L);
                } catch (InterruptedException e) {
                    return;
                }
            }
            log("清扫线程退出（启动期已过）");
        }, "QQClean-Sweeper");
        t.setDaemon(true);
        t.start();
    }

    private void sweepStatics(ClassLoader cl) {
        setStaticField(cl, "oicq.wlogin_sdk.request.w", "Y", 0);
        setStaticField(cl, "org.light.device.LightDeviceUtils", "isRooted", Boolean.FALSE);
        setStaticField(cl, "com.tencent.camerasdk.avreport.DeviceInfo", "roDebuggable", "0");
        setStaticField(cl, "com.tencent.camerasdk.avreport.DeviceInfo", "roSecure", "1");
    }

    // ==========================================================
    //  工具
    // ==========================================================

    private static boolean isSuPath(String path) {
        String p = path.toLowerCase();
        for (String t : SU_TOKENS) {
            if (p.contains(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSuspiciousPackage(String pkg) {
        if (pkg == null) {
            return false;
        }
        String p = pkg.toLowerCase();
        if (HIDDEN_PACKAGES.contains(p)) {
            return true;
        }
        String[] kw = {"xposed", "lsposed", "substrate", "cydia", "magisk",
                "kernelsu", "sukisu", "ksunext", "apatch", "shizuku",
                "frida", "sandhook", "edxp", "dreamland"};
        for (String k : kw) {
            if (p.contains(k)) {
                return true;
            }
        }
        return false;
    }

    private void setStaticField(ClassLoader cl, String cls, String name, Object val) {
        try {
            XposedHelpers.setStaticObjectField(
                    XposedHelpers.findClass(cls, cl), name, val);
        } catch (Throwable ignored) {
        }
    }

    private void setInstanceField(Object obj, String name, Object val) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(obj, val);
        } catch (Throwable ignored) {
        }
    }

    private void hook(String name, Runnable r) {
        try {
            r.run();
            done.add(name);
        } catch (Throwable t) {
            log("[SKIP] " + name + " —— " + t.getClass().getSimpleName()
                    + ": " + t.getMessage());
        }
    }

    private static String getVersionName(XC_LoadPackage.LoadPackageParam lpp) {
        try {
            Object ai = lpp.appInfo;
            if (ai == null) {
                return "?";
            }
            // appInfo 是 android.content.pm.ApplicationInfo
            try {
                Field f = ai.getClass().getField("versionName");
                Object v = f.get(ai);
                if (v != null) {
                    return v.toString();
                }
            } catch (Throwable ignored) {
            }
            // 兜底：直接问 PackageManager
            try {
                Object ctx = XposedHelpers.callStaticMethod(
                        XposedHelpers.findClass("android.app.ActivityThread", lpp.classLoader),
                        "currentApplication");
                if (ctx == null) {
                    ctx = XposedHelpers.callStaticMethod(
                            XposedHelpers.findClass("android.app.AppGlobals", lpp.classLoader),
                            "getInitialApplication");
                }
                if (ctx instanceof Context) {
                    return ((Context) ctx).getPackageManager()
                            .getPackageInfo(lpp.packageName, 0).versionName;
                }
            } catch (Throwable ignored) {
            }
            return "?";
        } catch (Throwable t) {
            return "?";
        }
    }

    private static void log(String s) {
        Log.i(TAG, s);
        XposedBridge.log(TAG + ": " + s);
    }
}
