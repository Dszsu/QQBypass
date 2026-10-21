package io.github.xalsace.qqbypass.hooks;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * 拦截下线受管 Hook (Kick Interception Hook)
 *
 * 条件编译受管类：仅在 CompileHookConfig.ENABLE_KICK_INTERCEPT 为 true 时编译打包并生效。
 * 若设置为 false，该类在打包时将被 R8 完全剥离剔除，绝不计入 Hook 统计总数。
 */
public class KickInterceptHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_KICK_INTERCEPT) return;

        ClassLoader cl = lpparam != null && lpparam.classLoader != null ? lpparam.classLoader : HookConfig.getClassLoader();
        if (cl == null) return;

        hookMSFCoreKick(cl);
        hookNTKickProcessor(cl);
    }

    private static void hookMSFCoreKick(ClassLoader cl) {
        try {
            // 1. AccountCenter.p(setAccountNoLogin)
            Class<?> authB = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.auth.b", cl);
            if (authB != null) {
                HookUtils.hookAllMethods(authB, "p", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String uin = param.args != null && param.args.length > 0 ? String.valueOf(param.args[0]) : "";
                        XposedEntry.log("[KickIntercept] Blocked AccountCenter.p(setAccountNoLogin) for uin=" + uin);
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
                                XposedEntry.log("[KickIntercept] Blocked AccountCenter.e(setMainAccount->0) src=" + src);
                                param.setResult(null);
                            }
                        }
                    }
                });
            }

            // 2. WTLogin OnGetStWithoutPasswd2 ticket refresh
            Class<?> authQ = XposedHelpers.findClassIfExists("com.tencent.mobileqq.msf.core.auth.q", cl);
            if (authQ != null) {
                HookUtils.hookAllMethods(authQ, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args != null && param.args.length >= 9 && param.args[8] instanceof Integer) {
                            int ret = (Integer) param.args[8];
                            if (ret != 0 && ret != -1000) {
                                XposedEntry.log("[KickIntercept] Neutralized OnGetStWithoutPasswd2 failure ret=" + ret + " -> -1000 (timeout retry)");
                                param.args[8] = -1000;
                            }
                        }
                    }
                });
            }

            // 3. oicq.wlogin_sdk.tools.util.shouldKick -> false
            Class<?> util = XposedHelpers.findClassIfExists("oicq.wlogin_sdk.tools.util", cl);
            if (util != null) {
                HookUtils.hookAllMethods(util, "shouldKick", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(false);
                    }
                });
            }
        } catch (Throwable t) {
            XposedEntry.logError("Failed to hook MSFCoreKick: " + t.getMessage(), t);
        }
    }

    private static void hookNTKickProcessor(ClassLoader cl) {
        try {
            Class<?> ntKickProcessorCls = XposedHelpers.findClassIfExists("com.tencent.mobileqq.kick.NTKickProcessor", cl);
            if (ntKickProcessorCls != null) {
                Method[] methods = ntKickProcessorCls.getDeclaredMethods();
                for (Method m : methods) {
                    if (Modifier.isStatic(m.getModifiers()) || m.getName().equals("a") || m.getName().equals("b")) {
                        HookUtils.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                XposedEntry.log("[KickIntercept] Intercepted NTKickProcessor." + param.method.getName());
                                param.setResult(null);
                            }
                        });
                    }
                }
            }
        } catch (Throwable t) {
            XposedEntry.logError("Failed to hook NTKickProcessor: " + t.getMessage(), t);
        }
    }
}
