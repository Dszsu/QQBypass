package io.github.xalsace.qqbypass.hooks;

import java.io.File;
import java.lang.reflect.Member;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.detector.DexMethodData;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * 模拟器伪装受管 Hook (Emulator Camouflage Hook)
 *
 * 条件编译受管类：仅在 CompileHookConfig.ENABLE_EMULATOR_SPOOF 为 true 时编译打包并生效。
 * 抹除 qemu / goldfish / ranchu / vbox 等模拟器虚拟化环境特征，将其伪装为真实真机。
 * 若设置为 false，该类在打包时将被 R8 完全剥离剔除，绝不计入 Hook 统计总数。
 */
public class EmulatorCamouflageHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!CompileHookConfig.ENABLE_EMULATOR_SPOOF) return;

        try {
            hookEmulatorProperties();
            hookEmulatorFiles();
            hookDynamicEmulatorCheckers(lpparam);
        } catch (Throwable t) {
            XposedEntry.logError("Failed to initialize EmulatorCamouflageHook: " + t.getMessage(), t);
        }
    }

    private static void hookEmulatorProperties() {
        HookUtils.hookAllMethods("android.os.SystemProperties", "get",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.kernel.qemu".equals(key)) {
                            param.setResult("0");
                        } else if ("ro.hardware".equals(key)) {
                            String res = (String) param.getResult();
                            if (res != null && (res.contains("goldfish") || res.contains("ranchu") || res.contains("vbox"))) {
                                param.setResult("qcom");
                            }
                        } else if ("ro.product.board".equals(key)) {
                            String res = (String) param.getResult();
                            if (res != null && (res.contains("goldfish") || res.contains("vbox"))) {
                                param.setResult("taro");
                            }
                        } else if ("ro.bootloader".equals(key)) {
                            String res = (String) param.getResult();
                            if (res != null && (res.contains("unknown") || res.contains("vbox"))) {
                                param.setResult("c1-00000");
                            }
                        } else if ("ro.arch".equals(key)) {
                            param.setResult("arm64");
                        }
                    }
                }
            });
    }

    private static void hookEmulatorFiles() {
        XC_MethodHook fileHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.thisObject instanceof File) {
                    String path = ((File) param.thisObject).getAbsolutePath();
                    if (isEmulatorPath(path)) {
                        param.setResult(false);
                    }
                }
            }
        };

        HookUtils.hookMethod(File.class, "exists", fileHook);
        HookUtils.hookMethod(File.class, "isFile", fileHook);
    }

    private static boolean isEmulatorPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("qemu_pipe")
            || lower.contains("qemud")
            || lower.contains("goldfish")
            || lower.contains("qemu-props")
            || lower.contains("vboxguest")
            || lower.contains("vboxuser")
            || lower.contains("libc_malloc_debug_qemu.so");
    }

    private static void hookDynamicEmulatorCheckers(XC_LoadPackage.LoadPackageParam lpparam) {
        new Thread(() -> {
            try {
                if (!DexKitDetector.awaitReady(30000)) return;
                List<DexMethodData> emulatorCheckers = DexKitDetector.findEmulatorCheckers();
                for (DexMethodData methodData : emulatorCheckers) {
                    try {
                        Member method = methodData.getMethodInstance(lpparam.classLoader);
                        HookUtils.hookMethod(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                Object result = param.getResult();
                                if (result instanceof Boolean && (Boolean) result) {
                                    param.setResult(false);
                                } else if (result instanceof Integer && (Integer) result != 0) {
                                    param.setResult(0);
                                }
                            }
                        });
                    } catch (Throwable t) {
                        XposedEntry.logError("Failed to hook dynamic emulator checker: " + t.getMessage(), t);
                    }
                }
            } catch (Throwable t) {
                XposedEntry.logError("Error in hookDynamicEmulatorCheckers: " + t.getMessage(), t);
            }
        }).start();
    }
}
