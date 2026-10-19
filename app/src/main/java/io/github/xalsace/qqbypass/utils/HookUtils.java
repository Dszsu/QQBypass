package io.github.xalsace.qqbypass.utils;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import io.github.xalsace.qqbypass.config.HookConfig;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Utility class for common Xposed hook operations
 */
public class HookUtils {

    private static final String TAG = "QQEnhancedBypass";

    /**
     * Safe hook with error handling
     */
    public static void hookMethod(String className, String methodName, Object... parameterTypesAndCallback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null) {
                hookMethod(clazz, methodName, parameterTypesAndCallback);
            }
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook: " + className + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook method with class object
     */
    public static void hookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        if (clazz == null || clazz.isInterface()) return;
        try {
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
            log("Hooked: " + clazz.getName() + "." + methodName);
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook: " + clazz.getName() + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook all methods with specific name
     */
    public static void hookAllMethods(String className, String methodName, XC_MethodHook callback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null) {
                hookAllMethods(clazz, methodName, callback);
            }
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook all methods: " + className + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook all methods with specific name on Class object
     */
    public static void hookAllMethods(Class<?> clazz, String methodName, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface()) return;
        try {
            int hooked = 0;
            for (Method method : clazz.getDeclaredMethods()) {
                if (method.getName().equals(methodName)) {
                    if (Modifier.isAbstract(method.getModifiers())) {
                        continue;
                    }
                    try {
                        XposedBridge.hookMethod(method, callback);
                        hooked++;
                    } catch (Throwable t) {
                        if (HookConfig.VERBOSE_LOGGING) {
                            log("Failed to hook method: " + clazz.getName() + "." + methodName + " - " + t.getMessage());
                        }
                    }
                }
            }
            if (hooked > 0) {
                log("Hooked " + hooked + " method(s): " + clazz.getName() + "." + methodName);
            }
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook all methods: " + clazz.getName() + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook constructor
     */
    public static void hookConstructor(String className, Object... parameterTypesAndCallback) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
            XposedHelpers.findAndHookConstructor(clazz, parameterTypesAndCallback);
            log("Hooked constructor: " + className);
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook constructor: " + className + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook all constructors of class
     */
    public static void hookAllConstructors(String className, XC_MethodHook callback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null && !clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                hookAllConstructors(clazz, callback);
            }
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook all constructors: " + className + " - " + t.getMessage());
            }
        }
    }

    public static void hookAllConstructors(Class<?> clazz, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface() || Modifier.isAbstract(clazz.getModifiers())) return;
        try {
            XposedBridge.hookAllConstructors(clazz, callback);
            log("Hooked all constructors: " + clazz.getName());
        } catch (Throwable t) {
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook all constructors: " + clazz.getName() + " - " + t.getMessage());
            }
        }
    }

    /**
     * Check if class exists
     */
    public static boolean classExists(String className) {
        try {
            XposedHelpers.findClass(className, HookConfig.getClassLoader());
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Safely find class with fallback to HookConfig classloader
     */
    public static Class<?> findClass(String className, ClassLoader cl) {
        try {
            return XposedHelpers.findClassIfExists(className, cl != null ? cl : HookConfig.getClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    public static Class<?> findClass(String className) {
        return findClass(className, null);
    }

    public static void log(String message) {
        if (HookConfig.VERBOSE_LOGGING) {
            io.github.xalsace.qqbypass.XposedEntry.log(message);
        }
    }
}
