package io.github.xalsace.qqbypass.config;

/**
 * 编译期 Hook 条件编译配置 (Compile-Time Conditional Hook Configuration)
 *
 * 仅保留 3 个受管理的编译期条件编译开关：
 * 1. 拦截下线 (ENABLE_KICK_INTERCEPT)
 * 2. 设备修改 (ENABLE_DEVICE_SPOOF，附带设备参数)
 * 3. 模拟器伪装 (ENABLE_EMULATOR_SPOOF)
 *
 * 采用 public static final 编译期常量实现条件编译（JLS §14.21）：
 * 设置为 false 时，Javac 与 R8 编译器在构建时直接将死代码完全裁剪剔除，
 * 对应 Hook 类不被打包进最终 Release APK，且绝不计入运行时 Hook 统计总数中。
 */
public final class CompileHookConfig {

    private CompileHookConfig() {}

    // =========================================================================
    // 1. 拦截下线 (Kick Interception)
    // =========================================================================
    /**
     * 是否开启强制下线拦截。
     * 【默认关闭 (false)】：强制下线属于服务端权威会话状态。若客户端私自拦截或吞噬 kick 信令，
     * 将导致“僵尸会话”（发不出也收不到消息，持续暴露异常特征导致封号）。
     * 设置为 false 时，下线拦截逻辑完全被条件编译剔除，不打包进 APK，不计入 Hook 总数。
     */
    public static final boolean ENABLE_KICK_INTERCEPT = false;


    // =========================================================================
    // 2. 设备修改 (Device Modification / Spoofing，附带对应设备参数)
    // =========================================================================
    /**
     * 是否开启设备参数修改/伪造。
     * 【默认关闭 (false)】：保持真机参数，避免跨系统源反差。
     * 设置为 false 时，相关设备伪造 Hook 类完全不被打包进 APK，不计入 Hook 总数。
     * 设置为 true 时，使用下方配置的设备参数进行全局伪装。
     */
    public static final boolean ENABLE_DEVICE_SPOOF = false;

    // 对应设备修改参数配置 (当 ENABLE_DEVICE_SPOOF 为 true 时生效)
    public static final String FAKE_BRAND = "Xiaomi";
    public static final String FAKE_MANUFACTURER = "Xiaomi";
    public static final String FAKE_MODEL = "23127PN0CC";
    public static final String FAKE_PRODUCT = "shennong";
    public static final String FAKE_DEVICE = "shennong";
    public static final String FAKE_BOARD = "shennong";
    public static final String FAKE_HARDWARE = "qcom";
    public static final String FAKE_FINGERPRINT = "Xiaomi/shennong/shennong:14/UKQ1.230804.001/V816.0.24.1.28.DEV:user/release-keys";
    public static final String FAKE_IMEI = "867543051234567";
    public static final String FAKE_ANDROID_ID = "3a8f9b2c1d4e5f60";
    public static final String FAKE_SERIAL = "c2a3b4d5";
    public static final String FAKE_MAC = "02:00:00:00:00:00";


    // =========================================================================
    // 3. 模拟器伪装 (Emulator Camouflage / Spoofing)
    // =========================================================================
    /**
     * 是否开启模拟器特征伪装（将模拟器环境伪装为真实真机）。
     * 【默认关闭 (false)】：在真机运行时关闭，相关模拟器专属伪装 Hook 完全不被打包进 APK，不计入 Hook 总数。
     * 在模拟器环境下可置为 true，自动擦除 qemu / goldfish / ranchu 虚拟化痕迹。
     */
    public static final boolean ENABLE_EMULATOR_SPOOF = false;
}
