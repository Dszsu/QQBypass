package io.github.xalsace.qqbypass.hooks;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;
import io.github.xalsace.qqbypass.utils.ReportAuditManager;

/**
 * 拦截下线受管 Hook (Hardened Kick Interception Hook)
 *
 * 条件编译受管类：仅在 CompileHookConfig.ENABLE_KICK_INTERCEPT 为 true 时编译打包并生效。
 * 若设置为 false，该类在打包时将被 R8 完全剥离剔除，绝不计入 Hook 统计总数。
 *
 * 全链路下线拦截与 Token 保护矩阵：
 * 1. MSF 核心下线推送信令拦截 (com.tencent.mobileqq.msf.core.t.a / t.b):
 *    - 阻断 StatSvc.ReqMSFOffline / StatSvc.ReqForceOffline / MessageSvc.PushForceOffline;
 *    - 阻止 MSF 反注册推送管理器 (pushManager.d) 与发送 _msf_kickedAndCleanTokenResp 信令。
 * 2. 跨平台信令发送与本地 Token 清理阻断 (com.tencent.mobileqq.msf.core.service.crossplatform.c$a.run):
 *    - 阻断 _msf_kickedAndCleanTokenResp 执行，杜绝 setAccountNoLogin 与 wt_all_sig_clear(1002)。
 * 3. WTLogin 凭据擦除保护 (oicq.wlogin_sdk.request.WtloginHelper.ClearUserLoginData):
 *    - 下线上下文中阻断 ClearUserLoginData，保全 A2/D2/ST 等核心会话密钥。
 *    - 抑制 reportClearSig(1001/1002) 异常上报。
 * 4. MSF 账号中心状态锁 (com.tencent.mobileqq.msf.core.auth.b.p / b.e):
 *    - 阻止将账号标记为未登录 (setAccountNoLogin) 或重置主账号为 0。
 * 5. WTLogin 票据刷新重试保活 (com.tencent.mobileqq.msf.core.auth.q.a / util.shouldKick):
 *    - 将 OnGetStWithoutPasswd2 失败码转换为 -1000 (超时重试)，util.shouldKick 强制返回 false。
 * 6. IPC 推送响应消费 (com.tencent.mobileqq.msf.sdk.g.e / h.e):
 *    - 吞噬 failCode=2012 / 2001 / 2011 / 2013 / 2014 等下线错误分发，返回 true (consumed)。
 * 7. 主进程错误处理与下线弹窗销毁 (mqq.app.MainService$MyErrorHandler):
 *    - 阻断 onKickedAndClearToken / onInterceptKicked / onKickedInternal / onUserTokenExpired;
 *    - 阻断 popupNotification(mqq.intent.action.ACCOUNT_KICKED) 弹窗。
 * 8. NT 内核与接口阻断 (com.tencent.mobileqq.kick.NTKickProcessor / KickApiImpl):
 *    - 阻断 NT 内核下线广播，维持 shouldIgnoreNotifyMsfStatusChanged -> false 确保消息通道畅通。
 * 9. SDK 账号状态防护 (com.tencent.mobileqq.msf.sdk.MsfSdkUtils):
 *    - 阻断下线调用栈触发 updateSimpleAccount(isLogined=false)。
 */
public class KickInterceptHook {

    private static final Set<Class<?>> sHookedClasses =
        ConcurrentHashMap.newKeySet();

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_KICK_INTERCEPT) return;

        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;

        hookAllKickDefensePoints(cl);
    }

    public static void hookLateStage(ClassLoader cl) {
        if (!CompileHookConfig.ENABLE_KICK_INTERCEPT) return;
        if (cl == null) return;

        hookAllKickDefensePoints(cl);
    }

    private static void hookAllKickDefensePoints(ClassLoader cl) {
        hookMSFCoreKick(cl);
        hookClientAndUIKick(cl);
    }

    /**
     * 1. MSF 进程核心下线推送信令、Token 擦除与跨进程信令拦截
     */
    private static void hookMSFCoreKick(ClassLoader cl) {
        try {
            // (1) MSF core.t: CMD_OFFLINEPUSH (StatSvc.ReqMSFOffline) 阻断入口
            Class<?> msfTCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.t", cl);
            if (msfTCls != null && sHookedClasses.add(msfTCls)) {
                // b(int failCode) -> 返回 false，阻止判定为 TokenExpired
                HookUtils.hookAllMethods(msfTCls, "b", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });

                // a(FromServiceMsg, ToServiceMsg) 与 a(ToServiceMsg, FromServiceMsg)
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
                        if (fromMsg == null && p.args[0] != null && p.args[0].getClass().getName().contains("FromServiceMsg")) {
                            fromMsg = p.args[0];
                        }
                        if (fromMsg != null) {
                            try {
                                String cmd = (String) XposedHelpers.callMethod(fromMsg, "getServiceCmd");
                                int failCode = 0;
                                try {
                                    failCode = ((Number) XposedHelpers.callMethod(fromMsg, "getBusinessFailCode")).intValue();
                                } catch (Throwable ignored) {}

                                boolean isKickCmd = "StatSvc.ReqMSFOffline".equals(cmd) ||
                                                    "StatSvc.ReqForceOffline".equals(cmd) ||
                                                    "MessageSvc.PushForceOffline".equals(cmd);
                                boolean isKickFail = (failCode == 1000 || failCode == 2012 || failCode == -10103 || failCode == -10104 || failCode == 2001);

                                if (isKickCmd || isKickFail) {
                                    ReportAuditManager.recordKickEvent("MSF.core.t.a", fromMsg, "offline push intercepted cmd=" + cmd + ", failCode=" + failCode);
                                    XposedEntry.log("[KickShield] Intercepted MSF core.t.a offline push: cmd=" + cmd + ", failCode=" + failCode);
                                    if (p.method instanceof Method) {
                                        Class<?> ret = ((Method) p.method).getReturnType();
                                        if (ret == boolean.class) {
                                            p.setResult(true);
                                        } else if (ret == void.class) {
                                            p.setResult(null);
                                        }
                                    } else {
                                        p.setResult(true);
                                    }
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
                });
            }

            // (2) crossplatform.c$a: _msf_kickedAndCleanTokenResp 拦截
            Class<?> crossplatformCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.service.crossplatform.c$a", cl);
            if (crossplatformCls != null && sHookedClasses.add(crossplatformCls)) {
                HookUtils.hookAllMethods(crossplatformCls, "run", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            Field f = null;
                            try {
                                f = param.thisObject.getClass().getDeclaredField("a");
                            } catch (Throwable t2) {
                                Field[] fields = param.thisObject.getClass().getDeclaredFields();
                                for (Field fd : fields) {
                                    if (fd.getType().getName().contains("ToServiceMsg")) {
                                        f = fd;
                                        break;
                                    }
                                }
                            }
                            if (f != null) {
                                f.setAccessible(true);
                                Object toServiceMsg = f.get(param.thisObject);
                                if (toServiceMsg != null) {
                                    Object cmd = XposedHelpers.callMethod(toServiceMsg, "getMsfCommand");
                                    String serviceCmd = null;
                                    try {
                                        serviceCmd = (String) XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                                    } catch (Throwable ignored) {}

                                    boolean isKickedResp = (cmd != null && cmd.toString().contains("_msf_kickedAndCleanTokenResp")) ||
                                                           "StatSvc.RspMSFForceOffline".equals(serviceCmd) ||
                                                           "StatSvc.ReqMSFOffline".equals(serviceCmd);

                                    if (isKickedResp) {
                                        ReportAuditManager.recordKickEvent("crossplatform.c$a.run", null, "_msf_kickedAndCleanTokenResp intercepted");
                                        XposedEntry.log("[KickShield] Intercepted crossplatform.c$a _msf_kickedAndCleanTokenResp (suppressed token wipe & kick dispatch)");
                                        param.setResult(null);
                                    }
                                }
                            }
                        } catch (Throwable t) {
                            XposedEntry.log("[KickShield] Error in crossplatform.c$a hook: " + t.getMessage());
                        }
                    }
                });
            }

            // (3) AccountCenter.p(setAccountNoLogin) & e(setMainAccount)
            Class<?> authB = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.auth.b", cl);
            if (authB != null && sHookedClasses.add(authB)) {
                HookUtils.hookAllMethods(authB, "p", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String uin = param.args != null && param.args.length > 0 ? String.valueOf(param.args[0]) : "";
                        XposedEntry.log("[KickShield] Blocked AccountCenter.p(setAccountNoLogin) for uin=" + uin);
                        param.setResult(null);
                    }
                });

                HookUtils.hookAllMethods(authB, "e", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 2) {
                            String targetUin = String.valueOf(param.args[0]);
                            String src = String.valueOf(param.args[1]);
                            if (("0".equals(targetUin) || "10000".equals(targetUin)) &&
                                (src.contains("setNoLogin") || src.contains("onKicked") || src.contains("kick"))) {
                                XposedEntry.log("[KickShield] Blocked AccountCenter.e(setMainAccount->0) src=" + src);
                                param.setResult(null);
                            }
                        }
                    }
                });
            }

            // (4) WTLogin WtloginHelper.ClearUserLoginData & reportClearSig
            Class<?> wtHelperCls = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.request.WtloginHelper", cl);
            if (wtHelperCls != null && sHookedClasses.add(wtHelperCls)) {
                HookUtils.hookAllMethods(wtHelperCls, "ClearUserLoginData", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        XposedEntry.log("[KickShield] Shielded WtloginHelper.ClearUserLoginData (preserved session keys)");
                        p.setResult(Boolean.TRUE);
                    }
                });

                HookUtils.hookAllMethods(wtHelperCls, "reportClearSig", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        if (p.args != null && p.args.length > 1 && p.args[1] instanceof Integer) {
                            int clearFrom = (Integer) p.args[1];
                            if (clearFrom == 1002 || clearFrom == 1001) {
                                XposedEntry.log("[KickShield] Suppressed WtloginHelper.reportClearSig (clearFrom=" + clearFrom + ")");
                                p.setResult(null);
                            }
                        }
                    }
                });
            }

            // (5) WTLogin OnGetStWithoutPasswd2 ticket refresh
            Class<?> authQ = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.auth.q", cl);
            if (authQ != null && sHookedClasses.add(authQ)) {
                HookUtils.hookAllMethods(authQ, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 9 && param.args[8] instanceof Integer) {
                            int ret = (Integer) param.args[8];
                            if (ret != 0 && ret != -1000) {
                                XposedEntry.log("[KickShield] Neutralized OnGetStWithoutPasswd2 failure ret=" + ret + " -> -1000 (timeout retry)");
                                param.args[8] = -1000;
                            }
                        }
                    }
                });
            }

            // (6) oicq.wlogin_sdk.tools.util.shouldKick -> false
            Class<?> util = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.tools.util", cl);
            if (util != null && sHookedClasses.add(util)) {
                HookUtils.hookAllMethods(util, "shouldKick", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });
            }

            // (7) MsfSdkUtils: Prevent user token wipe during kick
            Class<?> msfSdkUtilsCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.sdk.MsfSdkUtils", cl);
            if (msfSdkUtilsCls != null && sHookedClasses.add(msfSdkUtilsCls)) {
                XC_MethodHook accountWipeHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 2 && param.args[1] instanceof Boolean) {
                            boolean isLogined = (Boolean) param.args[1];
                            if (!isLogined) {
                                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                                boolean fromKick = false;
                                for (StackTraceElement ste : stack) {
                                    String cn = ste.getClassName();
                                    String mn = ste.getMethodName();
                                    if (cn.contains("MyErrorHandler") || cn.contains("Kick") || mn.contains("Kicked") ||
                                        mn.contains("kicked") || mn.contains("Offline") || cn.contains("msf.sdk") ||
                                        mn.contains("onUserTokenExpired") || mn.contains("TokenExpired")) {
                                        fromKick = true;
                                        break;
                                    }
                                }
                                if (fromKick) {
                                    XposedEntry.log("[KickShield] Protected user token against wipe in " + param.method.getName());
                                    param.setResult(null);
                                }
                            }
                        }
                    }
                };
                HookUtils.hookAllMethods(msfSdkUtilsCls, "updateSimpleAccount", accountWipeHook);
                HookUtils.hookAllMethods(msfSdkUtilsCls, "updateSimpleAccountNotCreate", accountWipeHook);
            }

        } catch (Throwable t) {
            XposedEntry.logError("Failed to hook MSFCoreKick: " + t.getMessage(), t);
        }
    }

    /**
     * 2. 主进程与 UI 错误分发、弹窗及 NT 内核下线拦截
     */
    private static void hookClientAndUIKick(ClassLoader cl) {
        try {
            // (1) com.tencent.mobileqq.msf.sdk.g & h: 消费下线与 tokenExpired 推送
            String[] msfDispatcherClasses = {"com.tencent.mobileqq.msf.sdk.g", "com.tencent.mobileqq.msf.sdk.h"};
            for (final String msfClsName : msfDispatcherClasses) {
                Class<?> msfCls = XposedHelpers.findClassIfExists(msfClsName, cl);
                if (msfCls != null && sHookedClasses.add(msfCls)) {
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
                                ReportAuditManager.recordKickEvent(
                                    msfClsName + ".e", fromServiceMsg, "consumed failCode=" + failCode + ", cmd=" + cmd + ", uin=" + uin);
                                XposedEntry.log("[KickShield] " + msfClsName + ".e consumed kick packet: failCode=" + failCode + ", cmd=" + cmd);
                                param.setResult(true);
                            }
                        }
                    });
                }
            }

            // (2) mqq.app.MainService$MyErrorHandler: 阻断所有下线回调与 ACCOUNT_KICKED 弹窗
            Class<?> myErrorHandlerCls = XposedHelpers.findClassIfExists("mqq.app.MainService$MyErrorHandler", cl);
            if (myErrorHandlerCls != null && sHookedClasses.add(myErrorHandlerCls)) {
                HookUtils.hookAllMethods(myErrorHandlerCls, "onUserTokenExpired", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Object fromServiceMsg = param.args != null && param.args.length > 1 ? param.args[1] : (param.args != null && param.args.length > 0 ? param.args[0] : null);
                        ReportAuditManager.recordKickEvent("MyErrorHandler.onUserTokenExpired", fromServiceMsg, "suppressed");
                        XposedEntry.log("[KickShield] Suppressed MyErrorHandler.onUserTokenExpired!");
                        param.setResult(null);
                    }
                });

                String[] kickEventMethods = {
                    "onKicked", "onKickedAndClearToken", "onGrayError", "onServerSuspended",
                    "onNoTestEnvPermission", "onInvalidSign", "onRecvServerTip",
                    "onInterceptKicked", "onKickedInternal", "onCloneError"
                };
                for (String km : kickEventMethods) {
                    hookIfMethodExists(myErrorHandlerCls, km, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            Object fromServiceMsg = param.args != null && param.args.length > 1 ? param.args[1] : (param.args != null && param.args.length > 0 ? param.args[0] : null);
                            ReportAuditManager.recordKickEvent("MyErrorHandler." + param.method.getName(), fromServiceMsg, "suppressed");
                            XposedEntry.log("[KickShield] Suppressed MyErrorHandler." + param.method.getName() + "!");
                            param.setResult(null);
                        }
                    });
                }

                XC_MethodHook popupHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String action = param.args != null && param.args.length > 0 && param.args[0] instanceof String ? (String) param.args[0] : "";
                        ReportAuditManager.recordKickEvent("MyErrorHandler.popupNotification", null, "action=" + action + " suppressed");
                        XposedEntry.log("[KickShield] Suppressed popupNotification: action=" + action);
                        param.setResult(null);
                    }
                };
                hookIfMethodExists(myErrorHandlerCls, "popupNotification", popupHook);
                hookIfMethodExists(myErrorHandlerCls, "popupNotificationEx", popupHook);
            }

            // (3) NTKickProcessor: 阻断 NT 架构下线处理器
            Class<?> ntKickProcessorCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.kick.NTKickProcessor", cl);
            if (ntKickProcessorCls != null && sHookedClasses.add(ntKickProcessorCls)) {
                Method[] methods = ntKickProcessorCls.getDeclaredMethods();
                for (Method m : methods) {
                    if (Modifier.isStatic(m.getModifiers()) || m.getName().equals("a") || m.getName().equals("b")) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                ReportAuditManager.recordKickEvent("NTKickProcessor." + param.method.getName(), null, "suppressed");
                                XposedEntry.log("[KickShield] Intercepted NTKickProcessor." + param.method.getName());
                                param.setResult(null);
                            }
                        });
                    }
                }
            }

            // (4) KickApiImpl: 阻断 NT Kick API 并维持消息连接状态
            Class<?> kickApiImplCls = XposedHelpers.findClassIfExists("com.tencent.qqnt.kernel.api.impl.KickApiImpl", cl);
            if (kickApiImplCls != null && sHookedClasses.add(kickApiImplCls)) {
                XC_MethodHook kickApiHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        ReportAuditManager.recordKickEvent("KickApiImpl." + param.method.getName(), null, "suppressed");
                        XposedEntry.log("[KickShield] Suppressed KickApiImpl." + param.method.getName());
                        param.setResult(null);
                    }
                };
                hookIfMethodExists(kickApiImplCls, "kick", kickApiHook);
                hookIfMethodExists(kickApiImplCls, "onKickedOffLine", kickApiHook);
                hookIfMethodExists(kickApiImplCls, "onKicked", kickApiHook);
                hookIfMethodExists(kickApiImplCls, "shouldIgnoreNotifyMsfStatusChanged", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        // 强制返回 false，确保 QQAppInterface 持续向 NT 内核同步 KCONNECTED 在线状态，防止消息拉取停滞
                        p.setResult(false);
                    }
                });
                hookIfMethodExists(kickApiImplCls, "getBeInterceptor", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(false);
                    }
                });
            }

        } catch (Throwable t) {
            XposedEntry.logError("Failed to hook ClientAndUIKick: " + t.getMessage(), t);
        }
    }

    private static void hookIfMethodExists(Class<?> clazz, String methodName, XC_MethodHook callback) {
        HookUtils.hookIfMethodExists(clazz, methodName, callback);
    }
}
