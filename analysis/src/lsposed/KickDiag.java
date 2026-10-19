package com.qqclean.bypass;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 踢线（Kick）链路诊断 + 可选抑制。
 *
 * ============================ 重要前提 ============================
 *
 * 这个类默认 **只诊断、不抑制**。原因不是偷懒，是踩过的坑：
 *
 *   拦截踢线 = 僵尸会话。
 *
 * 服务端一旦判定会话失效，会在服务端注销 D2/SKey/Ticket 并关闭下行管道。
 * 此时客户端把 onKicked / onKickedAndClearToken 吞掉、把 UI 伪装成"在线"，
 * 结果是：发消息服务端全量拒收、收消息服务端永不推送、也无法退出去重新登录。
 * 网络层表现是"在线"，实际收发全废。更糟的是——一旦关掉模块重启，
 * 积压的失效状态瞬间爆发，直接弹 w21「身份验证失败」。
 *
 * 参考项目 QB 在 v1.0.23 和 v1.0.37 两次把自己的防踢逻辑整段删掉，
 * 理由写的和上面一模一样（The Zombie Client Fallacy）。
 *
 * ============================ 正确做法 ============================
 *
 *   "安全防御必须且只能在源头消除风控检测特征，
 *    绝不能在末端拦截 Kick 掩耳盗铃。"
 *
 * 也就是说：不想被踢，就把触发踢的检测点消掉 —— 那部分在 MainHook 里
 * （根检测、签名校验、ClassLoader 扫描、DEX 痕迹、包检测…）。
 * 本类的作用是把它变成可观测的：
 *
 *   1. 被抓到踢线时，精确记录 kickedType / securityKickedType / failCode /
 *      cmd / reason，写进 logcat。
 *   2. 用这些信息反查是哪一类检测触发的，回到 MainHook 补对应的 hook。
 *
 * ============================ 抑制开关 ============================
 *
 * 如果确实要坚持拦截（例如只是想让弹窗别打断游戏），把 SUPPRESS 改成 true。
 * 但请清楚代价：会话会进入僵尸状态，收发的消息会静默丢失。
 * 这不是"更强的保护"，是把一个显式故障变成隐式故障。
 */
public class KickDiag {

    private static final String TAG = "QQClean";

    /** 诊断模式：只记录，不改任何返回值 */
    private static final boolean SUPPRESS = false;

    /** 有值的 kickedType 才值得报警 */
    private static boolean sawAny = false;

    public static void install(final ClassLoader cl) {
        diagNtKick(cl);
        diagKickApi(cl);
        diagMyErrorHandler(cl);
        log("踢线诊断已挂载（抑制模式=" + SUPPRESS + "）");
    }

    // ==========================================================
    //  1. NT 内核踢线入口
    //     NTKickProcessor.a(AppRuntime, KickedInfo)
    //     NTKickProcessor.b(AppRuntime, KickedInfo, LogoutReason)  ← private
    // ==========================================================

    private static void diagNtKick(final ClassLoader cl) {
        try {
            final Class<?> c = XposedHelpers.findClass(
                    "com.tencent.mobileqq.kick.NTKickProcessor", cl);

            for (final Method m : c.getDeclaredMethods()) {
                if (!(m.getParameterTypes().length >= 2)) {
                    continue;
                }
                boolean isEntry = m.getName().equals("a") || m.getName().equals("b");
                if (!isEntry) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        report("NTKickProcessor." + m.getName(), p.args, null);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        if (SUPPRESS) {
                            // 只在明确要抑制时才介入
                            p.setResult(null);
                        }
                    }
                });
            }
            log("  ✓ NTKickProcessor 已挂载");
        } catch (Throwable t) {
            log("  [SKIP] NTKickProcessor —— " + t);
        }
    }

    // ==========================================================
    //  2. KickApi 层
    //     KickApiImpl.kick(KickedInfo)
    // ==========================================================

    private static void diagKickApi(final ClassLoader cl) {
        try {
            final Class<?> c = XposedHelpers.findClass(
                    "com.tencent.qqnt.kernel.api.impl.KickApiImpl", cl);
            XposedBridge.hookAllMethods(c, "kick", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    report("KickApiImpl.kick", p.args, null);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    if (SUPPRESS) {
                        p.setResult(null);
                    }
                }
            });
            log("  ✓ KickApiImpl.kick 已挂载");
        } catch (Throwable t) {
            log("  [SKIP] KickApiImpl —— " + t);
        }
    }

    // ==========================================================
    //  3. MSF failCode 层
    //     MainService$MyErrorHandler.onKicked / onKickedAndClearToken
    //     onUserTokenExpired / onKickedInternal / popupNotification
    // ==========================================================

    private static void diagMyErrorHandler(final ClassLoader cl) {
        final String CN = "mqq.app.MainService$MyErrorHandler";
        final String[] targets = {
                "onKicked", "onKickedAndClearToken", "onUserTokenExpired",
                "onKickedInternal", "onGrayError", "onServerSuspended"
        };
        try {
            final Class<?> c = XposedHelpers.findClass(CN, cl);
            int n = 0;
            for (final Method m : c.getDeclaredMethods()) {
                boolean hit = false;
                for (String t : targets) {
                    if (t.equals(m.getName())) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    continue;
                }
                m.setAccessible(true);
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) {
                        report(CN + "." + m.getName(), p.args, null);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam p) {
                        if (SUPPRESS) {
                            p.setResult(null);
                        }
                    }
                });
                n++;
            }
            log("  ✓ MyErrorHandler " + n + " 个入口已挂载");
        } catch (Throwable t) {
            log("  [SKIP] MyErrorHandler —— " + t);
        }
    }

    // ==========================================================
    //  上报
    // ==========================================================

    /**
     * 从参数里挖出 KickedInfo / FromServiceMsg，把能拿到的信号全打出来。
     * 这些字段就是"为什么被踢"的唯一证据。
     */
    private static void report(String where, Object[] args, Throwable t) {
        sawAny = true;
        StringBuilder sb = new StringBuilder();
        sb.append("[KICK] ").append(where);

        if (args != null) {
            for (Object a : args) {
                if (a == null) {
                    continue;
                }
                String cn = a.getClass().getName();
                if (cn.endsWith("KickedInfo")) {
                    sb.append("\n        kickedType        = ").append(f(a, "kickedType"));
                    sb.append("\n        securityKickedType= ").append(f(a, "securityKickedType"));
                    sb.append("\n        sameDevice        = ").append(f(a, "sameDevice"));
                    sb.append("\n        appId / instanceId= ")
                      .append(f(a, "appId")).append(" / ").append(f(a, "instanceId"));
                    sb.append("\n        tipsTitle         = ").append(f(a, "tipsTitle"));
                    sb.append("\n        tipsDesc          = ").append(f(a, "tipsDesc"));
                } else if (cn.endsWith("FromServiceMsg")) {
                    sb.append("\n        cmd               = ").append(f(a, "getServiceCmd"));
                    sb.append("\n        ssoErr            = ").append(f(a, "getBusinessFailCode"));
                    sb.append("\n        errMsg            = ").append(f(a, "getBusinessFailMsg"));
                    sb.append("\n        uin               = ").append(f(a, "getUin"));
                } else if (cn.endsWith("ToServiceMsg")) {
                    sb.append("\n        to.cmd            = ").append(f(a, "getServiceCmd"));
                    sb.append("\n        to.uin            = ").append(f(a, "getUin"));
                } else if (cn.endsWith("Boolean")) {
                    sb.append("\n        flag              = ").append(a);
                } else if (cn.endsWith("LogoutReason")) {
                    sb.append("\n        logoutReason      = ").append(a);
                }
            }
        }
        if (t != null) {
            sb.append("\n        throwable         = ").append(t);
        }
        log(sb.toString());
    }

    /** 先试 getter，再试字段，都失败返回 "?" */
    private static Object f(Object obj, String name) {
        if (obj == null) {
            return "?";
        }
        try {
            Method m = obj.getClass().getMethod(name);
            m.setAccessible(true);
            Object v = m.invoke(obj);
            if (v != null) {
                return v;
            }
        } catch (Throwable ignored) {
        }
        try {
            Field fd = obj.getClass().getField(name);
            fd.setAccessible(true);
            Object v = fd.get(obj);
            return v == null ? "null" : v;
        } catch (Throwable ignored) {
        }
        try {
            Field fd = obj.getClass().getDeclaredField(name);
            fd.setAccessible(true);
            Object v = fd.get(obj);
            return v == null ? "null" : v;
        } catch (Throwable ignored) {
        }
        return "?";
    }

    private static void log(String s) {
        Log.i(TAG, s);
        XposedBridge.log(TAG + ": " + s);
    }
}
