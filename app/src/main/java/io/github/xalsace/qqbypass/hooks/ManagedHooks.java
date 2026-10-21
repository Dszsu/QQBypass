package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.config.CompileHookConfig;

/**
 * 受管理的 Hook 统一调度管理类 (Managed Hooks Manager)
 *
 * 专门集中管理 3 个受管理的编译期条件编译特性：
 * 1. 拦截下线 (CompileHookConfig.ENABLE_KICK_INTERCEPT)
 * 2. 设备修改 (CompileHookConfig.ENABLE_DEVICE_SPOOF，带对应设备参数)
 * 3. 模拟器伪装 (CompileHookConfig.ENABLE_EMULATOR_SPOOF)
 *
 * 采用条件编译特性（JLS §14.21）：
 * 当上述某项开关在 CompileHookConfig 中为 false 时，Javac 会在编译期直接剔除死代码分支，
 * R8 在打包时将对应 Hook 类完全剥离（不打包进 APK），运行时也绝不计入 Hook 统计总数。
 */
public final class ManagedHooks {

    private ManagedHooks() {}

    /**
     * 安装所有已启用的受管特性 Hook
     */
    public static void installManagedHooks(XC_LoadPackage.LoadPackageParam lpparam) {
        // 1. 拦截下线
        if (CompileHookConfig.ENABLE_KICK_INTERCEPT) {
            KickInterceptHook.hook(lpparam);
        }

        // 2. 设备修改 (带对应设备参数)
        if (CompileHookConfig.ENABLE_DEVICE_SPOOF) {
            DeviceInfoHook.hook(lpparam);
        }

        // 3. 模拟器伪装
        if (CompileHookConfig.ENABLE_EMULATOR_SPOOF) {
            EmulatorCamouflageHook.hook(lpparam);
        }
    }

    /**
     * 次级 Dex 或热补丁动态加载时补充挂载受管特性 Hook
     */
    public static void hookLateStage(ClassLoader cl) {
        if (CompileHookConfig.ENABLE_KICK_INTERCEPT) {
            KickInterceptHook.hookLateStage(cl);
        }
    }
}
