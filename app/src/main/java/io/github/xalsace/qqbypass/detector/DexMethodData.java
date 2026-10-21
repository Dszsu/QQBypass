package io.github.xalsace.qqbypass.detector;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Lightweight, serializable representation of a detected method.
 * Allows caching detected method signatures to disk and restoring them without DexKit.
 */
public class DexMethodData implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String className;
    private final String methodName;
    private final ArrayList<String> paramTypeNames;
    private final String returnTypeName;
    private final String descriptor;

    private transient Method cachedMethodInstance;

    public DexMethodData(String className, String methodName, List<String> paramTypeNames, String returnTypeName, String descriptor) {
        this.className = className;
        this.methodName = methodName;
        this.paramTypeNames = paramTypeNames != null ? new ArrayList<>(paramTypeNames) : new ArrayList<String>();
        this.returnTypeName = returnTypeName != null ? returnTypeName : "";
        this.descriptor = descriptor != null ? descriptor : "";
    }

    public static DexMethodData from(org.luckypray.dexkit.result.MethodData md) {
        if (md == null) return null;
        List<String> params = md.getParamTypeNames();
        return new DexMethodData(
            md.getClassName(),
            md.getMethodName(),
            params,
            md.getReturnTypeName(),
            md.getDescriptor()
        );
    }

    public String getClassName() {
        return className;
    }

    public String getMethodName() {
        return methodName;
    }

    public List<String> getParamTypeNames() {
        return paramTypeNames;
    }

    public String getReturnTypeName() {
        return returnTypeName;
    }

    public String getDescriptor() {
        return descriptor;
    }

    /**
     * Resolves the actual reflection Method instance from the target ClassLoader.
     * Caches the resolved Method so subsequent calls do not repeat reflection lookups.
     */
    public Member getMethodInstance(ClassLoader classLoader) throws NoSuchMethodException {
        if (cachedMethodInstance != null) {
            return cachedMethodInstance;
        }
        if (classLoader == null) {
            throw new NoSuchMethodException("ClassLoader is null for " + className + "." + methodName);
        }

        try {
            Class<?> clazz = classLoader.loadClass(className);
            Class<?>[] paramClasses;
            if (paramTypeNames != null && !paramTypeNames.isEmpty()) {
                paramClasses = new Class<?>[paramTypeNames.size()];
                for (int i = 0; i < paramTypeNames.size(); i++) {
                    paramClasses[i] = resolveClass(paramTypeNames.get(i), classLoader);
                }
            } else {
                paramClasses = new Class<?>[0];
            }

            Method found = null;
            try {
                found = clazz.getDeclaredMethod(methodName, paramClasses);
            } catch (NoSuchMethodException e) {
                // Fallback: search declared methods in clazz matching name and param count
                for (Method m : clazz.getDeclaredMethods()) {
                    if (m.getName().equals(methodName)) {
                        if (paramClasses.length == 0 && m.getParameterTypes().length == 0) {
                            found = m;
                            break;
                        }
                        if (m.getParameterTypes().length == paramClasses.length) {
                            found = m;
                            break;
                        }
                    }
                }
            }

            if (found == null) {
                // Fallback: search superclasses
                Class<?> current = clazz.getSuperclass();
                while (current != null && current != Object.class && found == null) {
                    for (Method m : current.getDeclaredMethods()) {
                        if (m.getName().equals(methodName) && m.getParameterTypes().length == paramClasses.length) {
                            found = m;
                            break;
                        }
                    }
                    current = current.getSuperclass();
                }
            }

            if (found == null) {
                throw new NoSuchMethodException(className + "." + methodName);
            }

            found.setAccessible(true);
            cachedMethodInstance = found;
            return found;
        } catch (ClassNotFoundException e) {
            NoSuchMethodException nsme = new NoSuchMethodException("Class not found: " + className);
            nsme.initCause(e);
            throw nsme;
        }
    }

    public static Class<?> resolveClass(String typeName, ClassLoader classLoader) throws ClassNotFoundException {
        if (typeName == null || typeName.isEmpty()) return Object.class;
        switch (typeName) {
            case "boolean":
            case "Z": return boolean.class;
            case "byte":
            case "B": return byte.class;
            case "char":
            case "C": return char.class;
            case "short":
            case "S": return short.class;
            case "int":
            case "I": return int.class;
            case "long":
            case "J": return long.class;
            case "float":
            case "F": return float.class;
            case "double":
            case "D": return double.class;
            case "void":
            case "V": return void.class;
        }
        if (typeName.endsWith("[]")) {
            String component = typeName.substring(0, typeName.length() - 2);
            Class<?> compClass = resolveClass(component, classLoader);
            return java.lang.reflect.Array.newInstance(compClass, 0).getClass();
        }
        if (typeName.startsWith("[")) {
            return Class.forName(typeName.replace('/', '.'), false, classLoader);
        }
        if (typeName.startsWith("L") && typeName.endsWith(";")) {
            String clean = typeName.substring(1, typeName.length() - 1).replace('/', '.');
            return classLoader.loadClass(clean);
        }
        return classLoader.loadClass(typeName);
    }

    public JSONObject toJson() throws JSONException {
        JSONObject obj = new JSONObject();
        obj.put("class", className);
        obj.put("method", methodName);
        obj.put("return", returnTypeName);
        obj.put("desc", descriptor);
        JSONArray params = new JSONArray();
        for (String p : paramTypeNames) {
            params.put(p);
        }
        obj.put("params", params);
        return obj;
    }

    public static DexMethodData fromJson(JSONObject obj) throws JSONException {
        String className = obj.getString("class");
        String methodName = obj.getString("method");
        String returnTypeName = obj.optString("return", "");
        String descriptor = obj.optString("desc", "");
        List<String> paramTypeNames = new ArrayList<>();
        JSONArray params = obj.optJSONArray("params");
        if (params != null) {
            for (int i = 0; i < params.length(); i++) {
                paramTypeNames.add(params.getString(i));
            }
        }
        return new DexMethodData(className, methodName, paramTypeNames, returnTypeName, descriptor);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DexMethodData that = (DexMethodData) o;
        if (descriptor != null && !descriptor.isEmpty() && that.descriptor != null && !that.descriptor.isEmpty()) {
            return descriptor.equals(that.descriptor);
        }
        return className.equals(that.className) && methodName.equals(that.methodName) && paramTypeNames.equals(that.paramTypeNames);
    }

    @Override
    public int hashCode() {
        if (descriptor != null && !descriptor.isEmpty()) {
            return descriptor.hashCode();
        }
        return (className + "." + methodName).hashCode();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < paramTypeNames.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(paramTypeNames.get(i));
        }
        return className + "." + methodName + "(" + sb.toString() + "):" + returnTypeName;
    }
}
