package com.qqclean.bypass;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * QQ 模拟器检测中和。
 *
 * ===================== 设计原则（关键）=====================
 *
 * 参考项目 QB 在 v1.0.23 踩过一个坑：它为了"藏住"图灵 SDK，
 * 直接把 TuringRiskService.reqRiskDetectV2 / TuringIDService.getTuringDID
 * 的返回值换成硬编码空对象，getDeviceToken() 返回 ""。
 *
 * 结果：登录直接 w21「身份验证失败」。
 *
 * 原因：deviceToken / openIdTicket 是 MSF 与 WTLogin 协议包必须携带的凭证，
 * 服务端会校验。把它置空 = 自断凭证链。
 *
 * 所以本类 **绝不碰 Turing 的任何 token / ticket / 签名**。
 * 做法是反过来：让 Turing 自己采集到"这是一台真机"，它自然会生成合法 token。
 *
 * ===================== 检测点（9.3.65 实测）=====================
 *
 * 1. RFWDeviceUtil.isX86Emulator()
 *      判据只有两条：Build.MODEL 含 "Android SDK built for x86"
 *                    || getCpuAbiName() 含 "x86"
 * 2. RFWDeviceUtil.getCpuAbiName()
 * 3. com.tencent.mobileqq.minigame.utils.CPUUtil.sIsX86Emulator   (static boolean)
 * 4. com.tencent.qqmini.sdk.launcher.utils.CPUUtil.sIsX86Emulator (static boolean)
 * 5. DeviceInfoMonitor.getModel()          ← RFWDeviceUtil 的数据来源
 * 6. SystemProperties.get("ro.kernel.qemu" / "ro.hardware" / "ro.product.*")
 * 7. Gathererga HardwareInfoProvider.getModel/getBrand/getManufacturer/getDevice/getBoard
 * 8. com.tencent.mobileqq.qqpet.setting.i  设备黑白名单
 */
public class EmulatorHook {

    private static final String TAG = "QQClean";

    /** 已在中和时记录过，避免日志刷屏 */
    private static volatile boolean logged = false;

    // ==========================================================
    //  目标设备画像 —— 改成你想伪装的机型
    // ==========================================================

    static final String D_MODEL        = "23127PN0CC";
    static final String D_BRAND        = "Xiaomi";
    static final String D_MANUFACTURER = "Xiaomi";
    static final String D_DEVICE       = "fuxi";
    static final String D_PRODUCT      = "fuxi";
    static final String D_BOARD        = "kalama";
    static final String D_HARDWARE     = "qcom";
    static final String D_HOST         = "builder";
    static final String D_FINGERPRINT  =
            "Xiaomi/fuxi/fuxi:14/UKQ1.231003.002/V816.0.5.0.UNBCNXM:user/release-keys";
    static final String D_ABI          = "arm64-v8a";

    /** 需要伪造成「真机」的系统属性 */
    private static final String[][] PROP_MAP = {
            {"ro.product.model",       D_MODEL},
            {"ro.product.brand",       D_BRAND},
            {"ro.product.manufacturer", D_MANUFACTURER},
            {"ro.product.device",      D_DEVICE},
            {"ro.product.name",        D_PRODUCT},
            {"ro.product.board",       D_BOARD},
            {"ro.hardware",            D_HARDWARE},
            {"ro.boot.hardware",       D_HARDWARE},
            {"ro.kernel.qemu",         "0"},
            {"ro.boot.qemu",           "0"},
            {"ro.secure",              "1"},
            {"ro.debuggable",          "0"},
            {"ro.build.tags",          "release-keys"},
            {"ro.boot.verifiedbootstate", "green"},
            {"ro.boot.flash.locked",   "1"},
    };

    private static final Set<String> ABI_KEYS = new HashSet<>(Arrays.asList(
            "ro.product.cpu.abi", "ro.product.cpu.abilist",
            "ro.product.cpu.abilist32", "ro.product.cpu.abilist64"));

    public static void install(final ClassLoader cl) {
        // 1. 先尝试直接改 Build.* 静态字段（覆盖直接读 Build 的代码）
        patchBuildFields();

        // 2. 再 hook 所有读取通道（覆盖走中间层的代码）
        hookDeviceInfoMonitor(cl);
        hookRfwDeviceUtil(cl);
        hookCpuUtil(cl);
        hookSystemProperties(cl);
        hookGathererga(cl);

        log("模拟器检测中和已安装  目标机型=" + D_BRAND + "/" + D_MODEL);
    }

    // ==========================================================
    //  1. 直接改写 android.os.Build 静态字段
    // ==========================================================

    /**
     * Build.* 在 ART 上是 public static final。反射改值时需要先把
     * final 修饰去掉，否则 Android 9+ 抛 IllegalAccessException。
     * 这里逐个尝试，失败不抛（还有第 2 步的 hook 兜底）。
     */
    private static void patchBuildFields() {
        String[][] map = {
                {"MODEL", D_MODEL},
                {"BRAND", D_BRAND},
                {"MANUFACTURER", D_MANUFACTURER},
                {"DEVICE", D_DEVICE},
                {"PRODUCT", D_PRODUCT},
                {"BOARD", D_BOARD},
                {"HARDWARE", D_HARDWARE},
                {"HOST", D_HOST},
                {"FINGERPRINT", D_FINGERPRINT},
                {"TAGS", "release-keys"},
                {"TYPE", "user"},
                {"ID", "UKQ1.231003.002"},
                {"DISPLAY", "UKQ1.231003.002"},
        };
        int ok = 0;
        for (String[] kv : map) {
            if (setStaticFinal(Build.class, kv[0], kv[1])) {
                ok++;
            }
        }
        // CPU_ABI 系列（可能还有 CPU_ABI2 / SUPPORTED_ABIS）
        setStaticFinal(Build.class, "CPU_ABI", D_ABI);
        setStaticFinal(Build.class, "CPU_ABI2", "");
        try {
            Field f = Build.class.getDeclaredField("SUPPORTED_ABIS");
            f.setAccessible(true);
            removeFinal(f);
            f.set(null, new String[]{D_ABI, "arm64-v8a"});
            ok++;
        } catch (Throwable ignored) {
        }
        log("Build 字段改写 " + ok + "/" + map.length + " 项");
    }

    private static boolean setStaticFinal(Class<?> cls, String name, Object val) {
        try {
            Field f = cls.getDeclaredField(name);
            f.setAccessible(true);
            removeFinal(f);
            f.set(null, val);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 去掉 final 修饰符（Android 上需要反射改 Field.accessFlags） */
    private static void removeFinal(Field f) {
        try {
            Field af = Field.class.getDeclaredField("accessFlags");
            af.setAccessible(true);
            int flags = af.getInt(f);
            af.setInt(f, flags & ~Modifier.FINAL);
        } catch (Throwable ignored) {
            // Android 9+ 可能禁止，靠上层的 set 兜底
            try {
                f.setAccessible(true);
            } catch (Throwable ignored2) {
            }
        }
    }

    // ==========================================================
    //  2. DeviceInfoMonitor.getModel()
    // ==========================================================

    private static void hookDeviceInfoMonitor(final ClassLoader cl) {
        try {
            final Class<?> c = XposedHelpers.findClass(
                    "com.tencent.qmethod.pandoraex.monitor.DeviceInfoMonitor", cl);
            for (final Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals("getModel")) {
                    continue;
                }
                if (m.getReturnType() != String.class) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(D_MODEL);
                        once("→ DeviceInfoMonitor.getModel = " + D_MODEL);
                    }
                });
            }
        } catch (Throwable t) {
            log("[SKIP] DeviceInfoMonitor —— " + t);
        }
    }

    // ==========================================================
    //  3. RFWDeviceUtil
    // ==========================================================

    private static void hookRfwDeviceUtil(final ClassLoader cl) {
        final String CN = "com.tencent.biz.richframework.util.RFWDeviceUtil";
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);
            for (final Method m : c.getDeclaredMethods()) {
                String n = m.getName();
                if (n.equals("isX86Emulator") && m.getReturnType() == boolean.class) {
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(false);
                            once("→ RFWDeviceUtil.isX86Emulator = false");
                        }
                    });
                } else if (n.equals("getCpuAbiName") && m.getReturnType() == String.class) {
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            p.setResult(D_ABI);
                        }
                    });
                }
            }
            log("  ✓ RFWDeviceUtil 已处理");
        } catch (Throwable t) {
            log("[SKIP] RFWDeviceUtil —— " + t);
        }
    }

    // ==========================================================
    //  4. CPUUtil.sIsX86Emulator（两个包，静态布尔）
    // ==========================================================

    private static void hookCpuUtil(final ClassLoader cl) {
        String[] classes = {
                "com.tencent.mobileqq.minigame.utils.CPUUtil",
                "com.tencent.qqmini.sdk.launcher.utils.CPUUtil",
        };
        for (final String CN : classes) {
            try {
                final Class<?> c = XposedHelpers.findClass(CN, cl);
                // CPUUtil 没有 getter，只有 <clinit> 会 sput sIsX86Emulator。
                // 这里 hook 它的 <clinit>（静态初始化完成后压回），不 hook 构造器。
                try {
                    XposedBridge.hookAllConstructors(c, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            setStatic(c, "sIsX86Emulator", false);
                        }
                    });
                } catch (Throwable ignored) {
                    // 某些版本没有实例构造器
                }
                for (final Method m : c.getDeclaredMethods()) {
                    if (m.getReturnType() == boolean.class) {
                        m.setAccessible(true);
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) {
                                p.setResult(false);
                            }
                        });
                    }
                }
                setStatic(c, "sIsX86Emulator", false);
                log("  ✓ " + CN + " 已处理");
            } catch (Throwable t) {
                log("[SKIP] " + CN + " —— " + t);
            }
        }
    }

    private static void setStatic(Class<?> c, String name, Object val) {
        try {
            XposedHelpers.setStaticObjectField(c, name, val);
        } catch (Throwable ignored) {
        }
    }

    // ==========================================================
    //  5. SystemProperties（定向替换，不是全拦）
    // ==========================================================

    /**
     * 只替换 PROP_MAP 里列出的键。
     * 不做「全部返回空」——那样会破坏 QQ 正常的系统属性读取（厂商判断、ABI 判断等）。
     */
    private static void hookSystemProperties(final ClassLoader cl) {
        final String[] classes = {
                "android.os.SystemProperties",
                "com.tencent.qmethod.pandoraex.core.SystemProperties",
        };
        for (final String CN : classes) {
            try {
                final Class<?> c = XposedHelpers.findClass(CN, cl);
                for (final Method m : c.getDeclaredMethods()) {
                    String n = m.getName();
                    if (!(n.equals("get") || n.equals("getString")
                            || n.equals("getInt") || n.equals("getBoolean")
                            || n.equals("getLong"))) {
                        continue;
                    }
                    Class<?>[] pt = m.getParameterTypes();
                    if (pt.length < 1 || pt[0] != String.class) {
                        continue;
                    }
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            String key = (String) p.args[0];
                            if (key == null) {
                                return;
                            }
                            Object repl = lookup(key, m.getReturnType());
                            if (repl != null) {
                                p.setResult(repl);
                            }
                        }
                    });
                }
                log("  ✓ " + CN + " 已定向替换");
            } catch (Throwable t) {
                // android.os.SystemProperties 是 @hide，正常情况能反射到
                log("  [SKIP] " + CN + " —— " + t.getClass().getSimpleName());
            }
        }
    }

    /** 按返回类型给出替换值 */
    private static Object lookup(String key, Class<?> ret) {
        if (ABI_KEYS.contains(key)) {
            return ret == String.class ? D_ABI : null;
        }
        for (String[] kv : PROP_MAP) {
            if (!kv[0].equals(key)) {
                continue;
            }
            String v = kv[1];
            if (ret == String.class) {
                return v;
            }
            try {
                if (ret == int.class || ret == Integer.class) {
                    return Integer.parseInt(v);
                }
                if (ret == long.class || ret == Long.class) {
                    return Long.parseLong(v);
                }
                if (ret == boolean.class || ret == Boolean.class) {
                    return "1".equals(v) || "true".equalsIgnoreCase(v);
                }
            } catch (NumberFormatException e) {
                return ret == int.class ? 0 : null;
            }
        }
        return null;
    }

    // ==========================================================
    //  6. Gathererga 硬件信息
    // ==========================================================

    /**
     * Gathererga 是腾讯统一的设备指纹 SDK，HardwareInfoProvider 是接口，
     * 实现在 Impl 类里。这里 hook 接口的所有实现类的同名方法。
     */
    private static void hookGathererga(final ClassLoader cl) {
        final String[] impls = {
                "com.tencent.gathererga.core.internal.provider.impl.c",
                "com.tencent.gathererga.core.internal.provider.impl.DeviceInfoImpl",
        };
        final String[][] map = {
                {"getModel", D_MODEL},
                {"getBrand", D_BRAND},
                {"getManufacturer", D_MANUFACTURER},
                {"getDevice", D_DEVICE},
                {"getBoard", D_BOARD},
        };
        int n = 0;
        for (final String CN : impls) {
            try {
                final Class<?> c = XposedHelpers.findClass(CN, cl);
                for (final Method m : c.getDeclaredMethods()) {
                    String mn = m.getName();
                    for (String[] kv : map) {
                        if (!kv[0].equals(mn)) {
                            continue;
                        }
                        m.setAccessible(true);
                        final String val = kv[1];
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam p) {
                                Object r = p.getResult();
                                if (r == null) {
                                    return;
                                }
                                // provider.c 包装对象，需要把里面的值换掉
                                try {
                                    Field fv = r.getClass().getDeclaredField("c");
                                    fv.setAccessible(true);
                                    fv.set(r, val);
                                } catch (Throwable ignored) {
                                }
                            }
                        });
                        n++;
                    }
                }
            } catch (Throwable t) {
                log("  [SKIP] " + CN + " —— " + t.getClass().getSimpleName());
            }
        }
        if (n > 0) {
            log("  ✓ Gathererga " + n + " 个方法已处理");
        }
    }

    // ==========================================================

    private static void once(String s) {
        if (!logged) {
            logged = true;
            log(s);
        }
    }

    private static void log(String s) {
        Log.i(TAG, s);
        XposedBridge.log(TAG + ": " + s);
    }
}
