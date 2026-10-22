package io.github.xalsace.qqbypass.utils;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import io.github.xalsace.qqbypass.config.HookConfig;

import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Utility class for common Xposed hook operations with unified tracking.
 */
public class HookUtils {

    /**
     * Hook a Member (Method or Constructor) directly with tracking
     */
    public static void hookMethod(Member member, XC_MethodHook callback) {
        if (member == null) return;
        String name = member.getDeclaringClass().getName() + "." + member.getName();
        try {
            XposedBridge.hookMethod(member, callback);
            HookTracker.recordJavaSuccess(name);
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
        }
    }

    /**
     * Safe hook with class name and error handling
     */
    public static void hookMethod(String className, String methodName, Object... parameterTypesAndCallback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null) {
                hookMethod(clazz, methodName, parameterTypesAndCallback);
            } else {
                HookTracker.recordJavaFailure(className + "." + methodName, new ClassNotFoundException("Class not found: " + className));
            }
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(className + "." + methodName, t);
        }
    }

    /**
     * Hook method with class object
     */
    public static void hookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        if (clazz == null || clazz.isInterface()) return;
        String name = clazz.getName() + "." + methodName;
        try {
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
            HookTracker.recordJavaSuccess(name);
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
        }
    }

    /**
     * Hook all methods with specific name by class name
     */
    public static void hookAllMethods(String className, String methodName, XC_MethodHook callback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null) {
                hookAllMethods(clazz, methodName, callback);
            } else {
                HookTracker.recordJavaFailure(className + "." + methodName, new ClassNotFoundException("Class not found: " + className));
            }
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(className + "." + methodName, t);
        }
    }

    /**
     * Hook all methods with specific name on Class object
     */
    public static void hookAllMethods(Class<?> clazz, String methodName, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface()) return;
        String name = clazz.getName() + "." + methodName;
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
                        HookTracker.recordJavaFailure(name + "()", t);
                    }
                }
            }
            if (hooked > 0) {
                HookTracker.recordJavaSuccess(name);
            } else {
                HookTracker.recordJavaFailure(name, new NoSuchMethodException("Method not found: " + methodName));
            }
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
        }
    }

    /**
     * Hook all overloads of method if it exists on class (silent if not found, 0 failures recorded)
     */
    public static void hookAllMethodsIfExists(Class<?> clazz, String methodName, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface()) return;
        String name = clazz.getName() + "." + methodName;
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
                        HookTracker.recordJavaFailure(name + "()", t);
                    }
                }
            }
            if (hooked > 0) {
                HookTracker.recordJavaSuccess(name);
            }
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
        }
    }

    /**
     * Hook constructor by class name
     */
    public static void hookConstructor(String className, Object... parameterTypesAndCallback) {
        String name = className + ".<init>";
        try {
            Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
            XposedHelpers.findAndHookConstructor(clazz, parameterTypesAndCallback);
            HookTracker.recordJavaSuccess(name);
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
        }
    }

    /**
     * Hook all constructors of class by class name
     */
    public static void hookAllConstructors(String className, XC_MethodHook callback) {
        try {
            Class<?> clazz = XposedHelpers.findClassIfExists(className, HookConfig.getClassLoader());
            if (clazz != null && !clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                hookAllConstructors(clazz, callback);
            } else {
                HookTracker.recordJavaFailure(className + ".<init>", new ClassNotFoundException("Class not found: " + className));
            }
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(className + ".<init>", t);
        }
    }

    /**
     * Hook all constructors of class by Class object
     */
    public static void hookAllConstructors(Class<?> clazz, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface() || Modifier.isAbstract(clazz.getModifiers())) return;
        String name = clazz.getName() + ".<init>";
        try {
            XposedBridge.hookAllConstructors(clazz, callback);
            HookTracker.recordJavaSuccess(name);
        } catch (Throwable t) {
            HookTracker.recordJavaFailure(name, t);
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

    /**
     * Hook method only if it exists in clazz (or its non-abstract declared methods).
     * Does NOT record failure if the method does not exist on this specific version/class.
     * Returns true if at least one method was hooked.
     */
    public static boolean hookIfMethodExists(Class<?> clazz, String methodName, XC_MethodHook callback) {
        if (clazz == null || clazz.isInterface() || methodName == null) return false;
        boolean hasMethod = false;
        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getName().equals(methodName) && !Modifier.isAbstract(method.getModifiers())) {
                hasMethod = true;
                break;
            }
        }
        if (hasMethod) {
            hookAllMethods(clazz, methodName, callback);
            return true;
        }
        return false;
    }

    public static boolean hookIfMethodExists(String className, String methodName, ClassLoader cl, XC_MethodHook callback) {
        Class<?> clazz = findClass(className, cl);
        if (clazz != null) {
            return hookIfMethodExists(clazz, methodName, callback);
        }
        return false;
    }

    /**
     * Hook candidate methods across multiple version variants.
     * Hooks all matching candidate methods that actually exist.
     * Returns the count of hooked candidate method names.
     */
    public static int hookCandidateMethods(Class<?> clazz, String[] candidateMethodNames, XC_MethodHook callback) {
        if (clazz == null || candidateMethodNames == null) return 0;
        int count = 0;
        for (String methodName : candidateMethodNames) {
            if (hookIfMethodExists(clazz, methodName, callback)) {
                count++;
            }
        }
        return count;
    }

    public static int hookCandidateMethods(String className, String[] candidateMethodNames, ClassLoader cl, XC_MethodHook callback) {
        Class<?> clazz = findClass(className, cl);
        if (clazz != null) {
            return hookCandidateMethods(clazz, candidateMethodNames, callback);
        }
        return 0;
    }

    public static void log(String message) {
        // 静默：不再输出细粒度的普通过程日志
    }
}
