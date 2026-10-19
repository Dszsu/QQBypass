package com.qqclean.bypass;

import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 人脸核身（优图活体）环境数据中和。
 *
 * ============================ 问题来源 ============================
 *
 * 抓包日志里这个 JSON 是决定性证据：
 *
 *   "select_data": {
 *     "android_data": {
 *       "build_model":  "23127PN0CC",   ← Build 改写生效了
 *       "build_brand":  "Xiaomi",
 *       ...
 *       "lux": -10000                    ← 破绽
 *     },
 *     "sensor_data": []                  ← 这是 SDK 设计，真机也常见
 *   }
 *
 * lux = -10000 是优图 SDK 的「读不到光感」哨兵值。
 * 真机室内通常在 100~1000 之间。
 *
 * 根因不是 Java 层读不到，而是这台模拟器的光感传感器
 * **声明存在但从不产生事件**（adb dumpsys sensorservice 实测：
 * 只有加速度计有 last events，光感 0 次）。
 *
 * 所以只能在数据写入 JSON 之前改。
 *
 * ============================ 改哪里 ============================
 *
 * 优图这两套类各有一个 lux 写入点：
 *
 *   com.tencent.youtu.ytagreflectlivecheck.requester.LiveStyleRequester$SeleceData
 *       ctor(F)                    → 参数就是 lux
 *   com.tencent.youtu.sdkkitframework.liveness.YtLivenessNetProtoHelper
 *       $LiveStyleRequester$SeleceData
 *       ctor(F I String String String)  → 第一参数是 lux
 *
 * 以及对应的 LiveStyleAndroidData.lux 字段。
 *
 * ============================ 注意 ============================
 *
 * lux 只影响「环境画像」，不影响活体算法判定。
 * 活体不过（errorcode 1007）是摄像头画面本身的问题，
 * 改 lux 解决不了。这个类的定位是：把环境画像做干净，
 * 让服务端不要因为「设备可疑」而拒绝，把问题收敛到纯活体环节。
 */
public class FaceEnvHook {

    private static final String TAG = "QQClean";

    /** 目标光感值（真机室内常见范围） */
    private static final float FAKE_LUX = 320.0f;

    /** 目标色温 / RGB，留空则不改 */
    private static volatile boolean logged = false;

    public static void install(ClassLoader cl) {
        int n = 0;
        // 核心：直接改光感数据源
        n += hookSensorWorker(cl);
        n += hookSelectData(cl,
                "com.tencent.youtu.ytagreflectlivecheck.requester.LiveStyleRequester$SeleceData");
        n += hookSelectData(cl,
                "com.tencent.youtu.sdkkitframework.liveness."
                + "YtLivenessNetProtoHelper$LiveStyleRequester$SeleceData");
        n += hookAndroidData(cl,
                "com.tencent.youtu.ytagreflectlivecheck.requester."
                + "LiveStyleRequester$LiveStyleAndroidData");
        n += hookAndroidData(cl,
                "com.tencent.youtu.sdkkitframework.liveness."
                + "YtLivenessNetProtoHelper$LiveStyleRequester$LiveStyleAndroidData");
        log("人脸核身环境中和：lux → " + FAKE_LUX + "（生效 " + n + " 处）");
    }

    /**
     * com.tencent.youtu.ytagreflectlivecheck.worker.SensorManagerWorker
     *
     *   getLux()  : listener != null ? listener.lux : -1.0f
     *   start()   : 拿不到光感就返回 1，且 listener 保持 null
     *
     * 这台模拟器光感声明存在但从不产生事件，getDefaultSensor 拿不到，
     * listener 为 null → getLux() 返回 -1.0f → 服务端收到 -10000。
     *
     * 这里双保险：start() 保证返回 0（成功），getLux() 直接给正常值。
     */
    private static int hookSensorWorker(ClassLoader cl) {
        final String CN = "com.tencent.youtu.ytagreflectlivecheck.worker.SensorManagerWorker";
        int n = 0;
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);

            for (final Method m : c.getDeclaredMethods()) {
                if (m.getName().equals("getLux")) {
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object r = p.getResult();
                            // 只在「无效值」时替换，别盖掉真实读数
                            if (r instanceof Float) {
                                float v = (Float) r;
                                if (v < 0f || v > 20000f) {
                                    p.setResult(FAKE_LUX);
                                    once("→ getLux() 原值 " + v + " → " + FAKE_LUX);
                                }
                            }
                        }
                    });
                    n++;
                } else if (m.getName().equals("start")) {
                    m.setAccessible(true);
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            Object r = p.getResult();
                            if (r instanceof Integer && ((Integer) r) != 0) {
                                // 1 = 系统无光感，2 = 已启动；统一报「成功」
                                p.setResult(0);
                                once("→ SensorManagerWorker.start() 返回值 "
                                        + r + " → 0（成功）");
                            }
                        }
                    });
                    n++;
                }
            }
            // 同时把 listener 的 lux 字段兜住
            n += hookLuxField(cl,
                    "com.tencent.youtu.ytagreflectlivecheck.worker."
                    + "SensorManagerWorker$LightSensorListener");
        } catch (Throwable t) {
            log("  [SKIP] SensorManagerWorker —— " + t);
        }
        return n;
    }

    /** LightSensorListener.lux 是 private float，构造后压成正常值 */
    private static int hookLuxField(ClassLoader cl, final String CN) {
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);
            for (final java.lang.reflect.Constructor<?> ct : c.getDeclaredConstructors()) {
                ct.setAccessible(true);
                XposedBridge.hookMethod(ct, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Field f = c.getDeclaredField("lux");
                            f.setAccessible(true);
                            f.setFloat(p.thisObject, FAKE_LUX);
                        } catch (Throwable ignored) {
                        }
                    }
                });
                return 1;
            }
        } catch (Throwable ignored) {
        }
        return 0;
    }

    /** hook SeleceData 的构造器：把第一个 float 参数换掉 */
    private static int hookSelectData(ClassLoader cl, final String CN) {
        int n = 0;
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);
            for (final java.lang.reflect.Constructor<?> m : c.getDeclaredConstructors()) {
                Class<?>[] pt = m.getParameterTypes();
                if (pt.length < 1 || pt[0] != float.class) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        p.args[0] = FAKE_LUX;
                        once("→ " + simple(CN) + " ctor lux = " + FAKE_LUX);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        // 构造完成后兜底：把 android_data.lux 和 sensor_data 再压一次
                        try {
                            Object self = p.thisObject;
                            Object ad = XposedHelpers.getObjectField(self, "android_data");
                            if (ad != null) {
                                XposedHelpers.setObjectField(ad, "lux", FAKE_LUX);
                            }
                        } catch (Throwable ignored) {
                        }
                        try {
                            Object self = p.thisObject;
                            Object sd = XposedHelpers.getObjectField(self, "sensor_data");
                            if (sd == null) {
                                // 空数组对真机也常见，但给个占位更自然
                                XposedHelpers.setObjectField(self, "sensor_data",
                                        new ArrayList<>());
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                });
                n++;
            }
        } catch (Throwable t) {
            // 类不存在是正常的（不同版本包结构不同）
        }
        return n;
    }

    /** hook LiveStyleAndroidData：字段级兜底 */
    private static int hookAndroidData(ClassLoader cl, final String CN) {
        int n = 0;
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);
            // hook 所有返回 float 且无参的方法（getter 风格）
            for (final Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() != float.class || m.getParameterTypes().length != 0) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        p.setResult(FAKE_LUX);
                    }
                });
                n++;
            }
            // 同时在构造后设字段
            for (final java.lang.reflect.Constructor<?> m : c.getDeclaredConstructors()) {
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        try {
                            Field f = c.getDeclaredField("lux");
                            f.setAccessible(true);
                            f.setFloat(p.thisObject, FAKE_LUX);
                        } catch (Throwable ignored) {
                        }
                    }
                });
                n++;
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    private static String simple(String cn) {
        int i = cn.lastIndexOf('.');
        return i < 0 ? cn : cn.substring(i + 1);
    }

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
