package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.detector.DexMethodData;

import java.lang.reflect.Member;
import java.util.List;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.detector.DexKitDetector;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * DexKit-based Runtime Monitor Bypass
 * Dynamically locates and hooks obfuscated runtime command detection methods
 */
public class DynamicRuntimeMonitorHook {

    private static final String[] MONITORED_COMMANDS = {
        "ip", "pm", "getprop", "sh", "/system/bin/sh",
        "ps", "cat", "mount", "which", "su"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_RUNTIME_BYPASS) return;

        // Universal hook: ProcessBuilder.start() - catches all command execution
        hookProcessBuilder();

        // Dynamic hooks: DexKit-discovered Runtime.exec callers
        // Run in background thread; wait for the shared scan instead of a fixed
        // sleep (the old sleep(5000) raced the scan and read an empty cache).
        new Thread(() -> {
            try {
                if (!DexKitDetector.awaitReady(30000)) {
                    XposedEntry.log("DynamicRuntime: DexKit not available, skipping dynamic hooks");
                    return;
                }
                hookRuntimeExecCallers(lpparam);

            } catch (Throwable e) {
                XposedEntry.log("Dynamic runtime hook setup failed: " + e.getMessage());
            }
        }).start();
    }

    private static void hookProcessBuilder() {
        // ProcessBuilder.start() is the UNIVERSAL choke point for command execution
        HookUtils.hookMethod(ProcessBuilder.class, "start",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                    java.util.List<String> command = pb.command();
                    if (command == null || command.isEmpty()) return;

                    String joined = joinCommand(command);

                    if (joined.contains("logcat")) {
                        pb.command("/system/bin/sh", "-c", "exit 0");
                        XposedEntry.log("Suppressed ProcessBuilder logcat capture: " + joined);
                        return;
                    }

                    if (isSensitiveProbe(joined)) {
                        pb.command("/system/bin/sh", "-c", "echo 'Package not found'; exit 1");
                        XposedEntry.log("Neutralized ProcessBuilder sensitive probe: " + joined);
                        return;
                    }

                    if (isRootProbe(joined)) {
                        // Rewrite to harmless no-op: return non-zero code AND standard shell 'not found' message
                        pb.command("/system/bin/sh", "-c", "echo 'sh: type: su: not found'; exit 127");
                        XposedEntry.log("Neutralized ProcessBuilder root probe: " + joined);
                    } else if (isMonitoredCommand(joined)) {
                        XposedEntry.log("ProcessBuilder command intercepted: " + joined);
                    }
                }
            });
    }

    private static void hookRuntimeExecCallers(XC_LoadPackage.LoadPackageParam lpparam) {
        List<DexMethodData> execCallers = DexKitDetector.findRuntimeExecCallers();
        if (execCallers.isEmpty()) {
            XposedEntry.log("DynamicRuntime: No Runtime.exec callers found by DexKit");
            return;
        }

        for (DexMethodData methodData : execCallers) {
            try {
                String className = methodData.getClassName();
                String methodName = methodData.getMethodName();

                // Resolve the exact method (correct overload) from the full DEX descriptor
                Member method;
                try {
                    method = methodData.getMethodInstance(lpparam.classLoader);
                } catch (Throwable t) {
                    continue;
                }

                HookUtils.hookMethod(method, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logCommandArgs("Runtime.exec caller: " + className, param.args);
                    }
                });

            } catch (Exception e) {
                XposedEntry.log("Failed to hook Runtime.exec caller: " + e.getMessage());
            }
        }
    }

    private static void logCommandArgs(String tag, Object[] args) {
        if (args == null) return;
        for (Object arg : args) {
            if (arg == null) continue;
            String s;
            if (arg instanceof String[]) {
                s = java.util.Arrays.toString((String[]) arg);
            } else {
                s = arg.toString();
            }
            if (isMonitoredCommand(s)) {
                XposedEntry.log(tag + " observed monitored command: " + s);
            }
        }
    }

    private static String joinCommand(java.util.List<String> command) {
        StringBuilder sb = new StringBuilder();
        for (String part : command) {
            if (part == null) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(part);
        }
        return sb.toString();
    }

    private static boolean isSensitiveProbe(String joined) {
        if (joined == null) return false;
        String s = joined.toLowerCase();
        return s.contains("bin.mt") || s.contains("io.github.qauxv") || s.contains("org.lsposed")
                || s.contains("top.nkbe.npatch") || s.contains("bytebuddy") || s.contains("singleneuron")
                || s.contains("xalsace") || s.contains("qqbypass") || s.contains("libqauxv");
    }

    private static boolean isRootProbe(String joined) {
        if (joined == null) return false;
        String s = joined.toLowerCase();

        if (s.contains("magisk") || s.contains("supersu") || s.contains("superuser")
                || s.contains("busybox") || s.contains("kernelsu") || s.contains("ksud") || s.contains("/ksu")
                || s.contains("libapatch") || s.contains("/apatch") || s.contains("apatchd") || s.contains("shamiko")
                || s.contains("which su") || s.contains("type su") || s.contains("command -v su")
                || s.contains("/system/bin/su") || s.contains("/system/xbin/su")
                || s.contains("/sbin/su") || s.contains("/su/bin")
                || s.contains("/data/local/su")) {
            return true;
        }

        for (String tok : s.split("\\s+")) {
            if (tok.equals("su") || tok.equals("ksud") || tok.equals("magisk")) return true;
        }
        return false;
    }

    private static boolean isMonitoredCommand(String command) {
        if (command == null) return false;
        for (String monitored : MONITORED_COMMANDS) {
            if (command.contains(monitored)) {
                return true;
            }
        }
        return false;
    }
}
