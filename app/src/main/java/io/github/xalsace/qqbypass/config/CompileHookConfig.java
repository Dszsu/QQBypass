package io.github.xalsace.qqbypass.config;

/**
 * 编译期 Hook 条件编译配置 (Compile-Time Conditional Hook Configuration)
 *
 * 保留 6 个受管理的编译期条件编译开关：
 * 1. 拦截下线 (ENABLE_KICK_INTERCEPT，默认关闭且严禁开启)
 * 2. 设备修改 (ENABLE_DEVICE_SPOOF，附带设备参数)
 * 3. 模拟器伪装 (ENABLE_EMULATOR_SPOOF)
 * 4. 记录 QQ 上报 (ENABLE_RECORD_QQ_REPORT，默认开启)
 * 5. QAuxiliary 文件处理报错兼容 (ENABLE_QAUXILIARY_FILE_COMPAT)
 * 6. 完整输出到 LSPosed 日志 (ENABLE_VERBOSE_LSPOSED_LOG，默认关闭)
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
     * 【默认关闭 (false)，且严禁开启】：
     * 严禁私自开启或默认开启此功能！
     * 下线信令（如 StatSvc.ReqMSFOffline / ReqForceOffline / failCode: 2012）属于腾讯服务端权威会话状态变更。
     * 客户端吞噬、拦截下线信令只会制造“僵尸会话（Zombie Session）”。服务端已作废会话票据与鉴权，
     * 客户端单方面不退出将导致后续数据包全部鉴权拒绝、异常重试风暴，极速引爆腾讯风控系统导致账号被封禁（w21/冻结）。
     * 防风控与反检测必须做在“前端检测规避”（如环境/签名/检测点对抗），绝对严禁通过“客户端吞噬下线信令”的方式进行掩耳盗铃。
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


    // =========================================================================
    // 4. 记录 QQ 上报 (Record QQ Telemetry / Reporting Audit)
    // =========================================================================
    /**
     * 是否开启记录 QQ 内部各类数据上报、SSO 信令与网络审计日志。
     * 【默认开启 (true)】：将 QQ 发起的各类数据上报、SSO 信令、Beacon 与统计埋点异步审计记录到：
     * - 每 30 分钟独立日志切片（如 report_audit_yyyyMMdd_HHmm.log、security_environment_audit_yyyyMMdd_HHmm.log）
     * - 每小时执行一次自动删除巡检，仅保留最近 8 个日志文件（覆盖最近 4 小时），轻量高效。
     * 设置为 false 时，上报审计与日志记录功能被条件编译完全关闭，避免多余的磁盘 I/O 开销与 Hook 挂载。
     */
    public static final boolean ENABLE_RECORD_QQ_REPORT = true;


    // =========================================================================
    // 5. QAuxiliary 文件处理报错兼容 (QAuxiliary / QAuxv File Error Compat)
    // =========================================================================
    /**
     * 是否开启 QAuxiliary (QAuxv) 文件传输与 APK 发送 NPE 崩溃兼容补丁。
     * 【默认开启 (true)】：为同时使用 QAuxiliary 的用户提供兼容，防止其在 QQ NT 新版发送 APK/群文件时
     * 因找不到 Item 字段抛出 NPE 崩溃。
     * 设置为 false 时，该兼容 Hook 完全被条件编译剔除，不打包进最终 APK，不计入运行时 Hook 统计总数。
     * 设置为 true 时，挂载该兼容补丁并安全处理 BaseApk 异常与 APK 文件名规范化。
     */
    public static final boolean ENABLE_QAUXILIARY_FILE_COMPAT = true;


    // =========================================================================
    // 6. 完整输出到 LSPosed 日志 (Verbose LSPosed Logging)
    // =========================================================================
    /**
     * 是否完整输出所有遥测审计日志到 LSPosed 系统日志。
     * 【默认关闭 (false)】：
     * 为关时，LSPosed 日志仅输出 Hook 安装汇总情况和真实严重报错，常规遥测、信令与环境审计日志
     * 仅异步写入磁盘外部存储缓存目录，避免高频 Binder 调用导致 LSPosed 缓冲区溢出；
     * 为开时才完整将所有遥测审计日志输出到 LSPosed 日志。
     */
    public static final boolean ENABLE_VERBOSE_LSPOSED_LOG = false;
}
