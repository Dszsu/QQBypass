# ========================================================
# Xposed 模块入口与核心类保留规则
# ========================================================

# 1. 保留 Xposed 模块入口类（由 Xposed/LSPosed 框架动态反射加载）
-keep class io.github.xalsace.qqbypass.XposedEntry {
    public *;
    <init>(...);
}

# 2. 保留核心支持类（配置、探测器、工具类及版本适配）
-keep class io.github.xalsace.qqbypass.config.** { *; }
-keep class io.github.xalsace.qqbypass.detector.** { *; }
-keep class io.github.xalsace.qqbypass.utils.** { *; }
-keep class io.github.xalsace.qqbypass.version.** { *; }
-keep class io.github.xalsace.qqbypass.NativeBypass { *; }

# 3. Hook 与防御类：使用 allowshrinking 规则支持条件编译裁剪
# 当受管 Hook（拦截下线、设备修改、模拟器伪装）在 CompileHookConfig 中为 false 时，
# 对应死代码未被引用，R8 在打包时将该 Hook 类完全从 APK 中裁剪剔除（不被打包进去）
-keep,allowshrinking class io.github.xalsace.qqbypass.hooks.** { *; }
-keep,allowshrinking class io.github.xalsace.qqbypass.defense.** { *; }

# 3. 保留 Native 方法及其声明类（防止 JNI 方法签名不一致）
-keepclasseswithmembernames class * {
    native <methods>;
}

# 4. 保留 ByteHook 相关类
-keep class com.bytedance.android.bytehook.** { *; }
-dontwarn com.bytedance.android.bytehook.**

# 5. 保留 DexKit 相关类及原生方法
-keep class org.luckypray.dexkit.** { *; }
-keepclasseswithmembers,includedescriptorclasses class org.luckypray.dexkit.** {
    native <methods>;
    long token;
}
-dontwarn org.luckypray.dexkit.**

# 6. 保留 Kotlin 相关类及抑制警告
-dontwarn kotlin.**
-keep class kotlin.** { *; }

# 7. Xposed API（由运行时的 Xposed/LSPosed 宿主环境提供，仅编译期依赖）
-dontwarn de.robv.android.xposed.**

# 8. 保留反射相关注解与调试信息
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,SourceFile,LineNumberTable

# 9. 保留 FlatBuffers 相关类（DexKit 序列化依赖）
-keep class com.google.flatbuffers.** { *; }
-dontwarn com.google.flatbuffers.**

