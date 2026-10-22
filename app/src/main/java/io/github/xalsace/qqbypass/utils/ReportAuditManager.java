package io.github.xalsace.qqbypass.utils;

import android.os.Process;
import android.util.Log;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import io.github.xalsace.qqbypass.config.CompileHookConfig;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance, non-blocking telemetry & security environment audit manager.
 *
 * Responsibilities:
 * 1. Asynchronously captures and writes outgoing telemetry / report events to disk:
 *    - All traffic:
 *        * /data/user/0/com.tencent.mobileqq/files/report_audit.log
 *        * /storage/emulated/0/Android/data/com.tencent.mobileqq/files/report_audit.log
 *        * /storage/emulated/0/0_TM/report_audit.log (when writable)
 *    - Pure Security & Environment Telemetry (Filtered, Noise-Free):
 *        * /data/user/0/com.tencent.mobileqq/files/security_environment_audit.log
 *        * /storage/emulated/0/Android/data/com.tencent.mobileqq/files/security_environment_audit.log
 *        * /storage/emulated/0/0_TM/security_environment_audit.log (when writable)
 * 2. Deep decoding of Kick / ForceOffline events:
 *    - Decodes RequestMSFForceOffline / RequestPushForceOffline WUP & JCE structures
 *    - Analyzes bSigKick, strTitle, strInfo, strTips, failCode, failMsg
 *    - Flushes synchronously to disk immediately upon kick reception (READ-ONLY, no swallowing)
 * 3. Sanitizes Bugly & CrashReport exception reports to prevent Xposed frames from leaking
 * 4. Audits ProtoBuf security scan packets (safecheckPB, SecVerifyApk, ClientInfoA/B, MobileQQDetect)
 * 5. Audits native probes, package queries, file checks, and security strikes
 */
public class ReportAuditManager {

    private static final String TAG = "QQReportAudit";
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB rolling limit

    // Base directories for report audit logs
    private static final File PRIMARY_DIR = new File("/data/user/0/com.tencent.mobileqq/files");
    private static final File SECONDARY_DIR = new File("/storage/emulated/0/Android/data/com.tencent.mobileqq/files");
    private static final File TERTIARY_DIR = new File("/storage/emulated/0/0_TM");

    public static final String PREFIX_ALL = "report_audit_";
    public static final String PREFIX_SEC = "security_environment_audit_";

    public static final int MAX_RETAINED_FILES = 8; // Retain latest 8 files (8 * 30min = 4 hours)
    public static final long CLEANUP_INTERVAL_MS = 60 * 60 * 1000L; // Check every 1 hour

    private static final AtomicBoolean sCleanerStarted = new AtomicBoolean(false);
    private static ScheduledExecutorService sCleanupScheduler = null;

    public static class AuditEntry {
        public final String text;
        public final boolean isSecurity;
        public final boolean syncFlush;

        public AuditEntry(String text, boolean isSecurity, boolean syncFlush) {
            this.text = text;
            this.isSecurity = isSecurity;
            this.syncFlush = syncFlush;
        }
    }

    private static final BlockingQueue<AuditEntry> sLogQueue = new LinkedBlockingQueue<>(4096);
    private static final AtomicBoolean sWorkerStarted = new AtomicBoolean(false);
    private static final ThreadLocal<SimpleDateFormat> sDateFormat = ThreadLocal.withInitial(
        () -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    );

    private static String sProcessName = "unknown";

    static {
        ensureWorkerStarted();
        ensureCleanerStarted();
    }

    public static void setProcessName(String processName) {
        if (processName != null && !processName.isEmpty()) {
            sProcessName = processName;
        }
    }

    public static String getProcessName() {
        return sProcessName;
    }

    public static String get30MinTimeTag(long timestamp) {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(timestamp);
        int minute = cal.get(Calendar.MINUTE);
        int bucketMinute = (minute / 30) * 30; // 0 or 30
        return String.format(Locale.US, "%04d%02d%02d_%02d%02d",
                cal.get(Calendar.YEAR),
                cal.get(Calendar.MONTH) + 1,
                cal.get(Calendar.DAY_OF_MONTH),
                cal.get(Calendar.HOUR_OF_DAY),
                bucketMinute);
    }

    private static void ensureCleanerStarted() {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            return;
        }
        if (sCleanerStarted.compareAndSet(false, true)) {
            sCleanupScheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "QQReportAuditCleaner");
                    t.setDaemon(true);
                    t.setPriority(Thread.MIN_PRIORITY);
                    return t;
                }
            });
            // Initial delay 0, repeat every 1 hour indefinitely: keeps latest 8 files (30 min each = 4 hours)
            sCleanupScheduler.scheduleWithFixedDelay(new Runnable() {
                @Override
                public void run() {
                    try {
                        cleanExpiredLogsInternal();
                    } catch (Throwable t) {
                        Log.e(TAG, "Cleaner periodic run error: " + t.getMessage());
                    }
                }
            }, 0, 1, TimeUnit.HOURS);
        }
    }

    private static void ensureWorkerStarted() {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            return;
        }
        if (sWorkerStarted.compareAndSet(false, true)) {
            Thread workerThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    // Initial cleanup of expired logs at startup
                    cleanExpiredLogsInternal();
                    long lastCleanupTime = System.currentTimeMillis();

                    while (true) {
                        try {
                            AuditEntry entry = sLogQueue.poll(5000, TimeUnit.MILLISECONDS);
                            if (entry != null) {
                                writeEntryInternal(entry);
                            }
                            long now = System.currentTimeMillis();
                            if (now - lastCleanupTime > CLEANUP_INTERVAL_MS) {
                                lastCleanupTime = now;
                                cleanExpiredLogsInternal();
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }, "QQReportAuditWriter");
            workerThread.setDaemon(true);
            workerThread.setPriority(Thread.MIN_PRIORITY);
            workerThread.start();
        }
    }

    private static synchronized void writeEntryInternal(AuditEntry entry) {
        if (entry == null || entry.text == null || entry.text.isEmpty()) return;

        long now = System.currentTimeMillis();
        String timeTag = get30MinTimeTag(now);

        String allFileName = PREFIX_ALL + timeTag + ".log";
        String secFileName = PREFIX_SEC + timeTag + ".log";

        // 1. Write to All-Events files (30-minute bucket)
        writeToSingleFile(new File(PRIMARY_DIR, allFileName), entry.text);
        writeToOptionalFile(new File(SECONDARY_DIR, allFileName), entry.text);
        writeToOptionalFile(new File(TERTIARY_DIR, allFileName), entry.text);

        // 2. If it's a security/environment event, route to dedicated noise-free security log (30-minute bucket)
        if (entry.isSecurity) {
            writeToSingleFile(new File(PRIMARY_DIR, secFileName), entry.text);
            writeToOptionalFile(new File(SECONDARY_DIR, secFileName), entry.text);
            writeToOptionalFile(new File(TERTIARY_DIR, secFileName), entry.text);
        }
    }

    private static void writeToOptionalFile(File targetFile, String entry) {
        try {
            File parent = targetFile.getParentFile();
            if (parent != null && (parent.exists() || parent.mkdirs()) && parent.canWrite()) {
                writeToSingleFile(targetFile, entry);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void writeToSingleFile(File targetFile, String entry) {
        try {
            File parent = targetFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            // Rolling file check (10MB)
            if (targetFile.exists() && targetFile.length() > MAX_FILE_SIZE) {
                File backupFile = new File(targetFile.getAbsolutePath() + ".1");
                if (backupFile.exists()) {
                    backupFile.delete();
                }
                targetFile.renameTo(backupFile);
            }

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(targetFile, true))) {
                writer.write(entry);
                writer.newLine();
                writer.flush();
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Manually triggers cleanup of log files.
     */
    public static void cleanExpiredLogs() {
        cleanExpiredLogsInternal();
    }

    /**
     * Deletion executed once every hour:
     * Retains strictly the most recent 8 log files (each covering 30 minutes, total 4 hours),
     * and deletes all older files across internal, external, and tertiary directories.
     */
    private static synchronized void cleanExpiredLogsInternal() {
        try {
            File[] searchDirs = new File[] {
                PRIMARY_DIR,
                SECONDARY_DIR,
                TERTIARY_DIR
            };

            for (File dir : searchDirs) {
                if (dir == null || !dir.exists() || !dir.isDirectory()) continue;

                // 1. Retain only the 8 most recent report_audit_*.log files
                cleanDirectoryByPrefix(dir, PREFIX_ALL, MAX_RETAINED_FILES);

                // 2. Retain only the 8 most recent security_environment_audit_*.log files
                cleanDirectoryByPrefix(dir, PREFIX_SEC, MAX_RETAINED_FILES);

                // 3. Clean legacy non-bucketed audit files and old temporary/prune files
                cleanLegacyFiles(dir);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in cleanExpiredLogsInternal: " + t.getMessage());
        }
    }

    private static void cleanDirectoryByPrefix(File dir, final String prefix, int maxKeep) {
        File[] files = dir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File d, String name) {
                return name.startsWith(prefix) && name.endsWith(".log");
            }
        });
        if (files == null || files.length <= maxKeep) return;

        // Sort descending: newest files first.
        // File names format: prefix_YYYYMMDD_HHmm.log
        // Lexicographical sorting order strictly equals chronological order!
        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File f1, File f2) {
                return f2.getName().compareTo(f1.getName());
            }
        });

        // Retain index 0 .. maxKeep - 1, delete all older files (index >= maxKeep)
        for (int i = maxKeep; i < files.length; i++) {
            try {
                File stale = files[i];
                boolean deleted = stale.delete();
                Log.i(TAG, "[LogCleanup] Deleted stale log file (> " + maxKeep + " recent kept): "
                        + stale.getName() + " (success=" + deleted + ")");
            } catch (Throwable ignored) {
            }
        }
    }

    private static void cleanLegacyFiles(File dir) {
        try {
            File[] files = dir.listFiles();
            if (files == null) return;
            for (File f : files) {
                if (f == null || !f.isFile()) continue;
                String name = f.getName();
                // If it's a legacy un-bucketed log or temporary prune file
                if (name.equals("report_audit.log") || name.equals("security_environment_audit.log")
                        || name.contains(".prune.tmp") || name.endsWith(".bak") || name.contains(".log.1")) {
                    f.delete();
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static String getCurrentTimestamp() {
        return sDateFormat.get().format(new Date());
    }

    private static String getCallerSummary(int maxFrames) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        if (stack == null || stack.length == 0) return "unknown";

        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (StackTraceElement ste : stack) {
            String cn = ste.getClassName();
            if (cn.contains("ReportAuditManager") ||
                cn.contains("HookUtils") ||
                cn.contains("Xposed") ||
                cn.contains("de.robv") ||
                cn.contains("org.lsposed") ||
                cn.contains("java.lang.reflect") ||
                cn.contains("android.app.ActivityThread") ||
                cn.contains("com.android.internal.os")) {
                continue;
            }

            if (count > 0) sb.append(" -> ");
            sb.append(ste.getClassName()).append(".").append(ste.getMethodName())
              .append("(").append(ste.getFileName()).append(":").append(ste.getLineNumber()).append(")");
            count++;
            if (count >= maxFrames) break;
        }
        return sb.length() > 0 ? sb.toString() : "root";
    }

    public static boolean isBusinessOrUiEvent(String eventCode) {
        if (eventCode == null) return false;
        String c = eventCode.toLowerCase(Locale.ROOT);
        return c.startsWith("qq_") || c.startsWith("dt_") || c.startsWith("ev_") ||
               c.startsWith("em_") || c.startsWith("msg_") || c.startsWith("new_msg_") ||
               c.startsWith("cost_tracer") || c.startsWith("apm_") ||
               c.startsWith("markdown_") || c.startsWith("vip") || c.startsWith("fav") ||
               c.startsWith("relation_") || c.startsWith("gm_") || c.startsWith("notification_") ||
               c.equals("qqin") || c.equals("qqout") || c.startsWith("rqd_tfm");
    }

    /**
     * Intelligent Classifier: Distinguishes critical security & environment detection telemetry
     * from high-frequency UI interaction noise (dt_clck, qq_imp, dt_pgin, etc.).
     */
    public static boolean isSecurityOrEnvironmentEvent(String channel, String eventOrCmd, Map<String, ?> params, String extraDetail) {
        if (channel != null && channel.equals("BeaconReport")) {
            if (isBusinessOrUiEvent(eventOrCmd) && (extraDetail == null || !extraDetail.contains("sanitized"))) {
                return false;
            }
        }

        if (channel != null) {
            String cLower = channel.toLowerCase(Locale.ROOT);
            if (cLower.contains("kick") ||
                cLower.contains("native") ||
                cLower.contains("probe") ||
                cLower.contains("security") ||
                cLower.contains("strike") ||
                cLower.contains("protobuf") ||
                cLower.contains("exception") ||
                cLower.contains("dtc") ||
                cLower.contains("turing") ||
                cLower.contains("channelmanager") ||
                cLower.contains("channelproxy") ||
                cLower.contains("outbound") ||
                cLower.contains("fekit") ||
                cLower.contains("wlogin") ||
                cLower.contains("safecenter") ||
                cLower.contains("risk")) {
                return true;
            }
        }

        if (extraDetail != null) {
            String edLower = extraDetail.toLowerCase(Locale.ROOT);
            if (edLower.contains("sanitized") ||
                edLower.contains("blocked") ||
                edLower.contains("suppressed") ||
                edLower.contains("kick") ||
                edLower.contains("strike") ||
                edLower.contains("failcode") ||
                edLower.contains("intercepted") ||
                edLower.contains("risk") ||
                edLower.contains("outbound") ||
                edLower.contains("payload")) {
                return true;
            }
        }

        if (eventOrCmd != null) {
            String eLower = eventOrCmd.toLowerCase(Locale.ROOT);
            if (eLower.contains("actlogin") ||
                eLower.contains("token") ||
                eLower.contains("ticket") ||
                eLower.contains("wtlogin") ||
                eLower.contains("offline") ||
                eLower.contains("kick") ||
                eLower.contains("sig_clear") ||
                eLower.contains("wt_all_sig_clear") ||
                eLower.contains("clearsig") ||
                eLower.contains("clearlogin") ||
                eLower.contains("forceoffline") ||
                eLower.contains("sec_") ||
                eLower.contains("security") ||
                eLower.contains("detect") ||
                eLower.contains("root") ||
                eLower.contains("risk") ||
                eLower.contains("xposed") ||
                eLower.contains("magisk") ||
                eLower.contains("turing") ||
                eLower.contains("device_report") ||
                eLower.contains("qimei") ||
                eLower.contains("oaid") ||
                eLower.contains("antitrace") ||
                eLower.contains("verify") ||
                eLower.contains("check") ||
                eLower.contains("safecheck") ||
                eLower.contains("patch") ||
                eLower.contains("intchk") ||
                eLower.contains("oidbsvc.0xd79") ||
                eLower.contains("0ac00056535") ||
                eLower.contains("0df00071646") ||
                eLower.contains("trpc.login.") ||
                eLower.contains("trpc.o3.") ||
                eLower.contains("trpc.qq_security.") ||
                eLower.contains("trpc.qsec.") ||
                eLower.contains("trpc.device.") ||
                eLower.contains("trpc.safe.") ||
                eLower.contains("trpc.atta.") ||
                eLower.contains("seccheck.") ||
                eLower.contains("devlockauth.") ||
                eLower.contains("qqprotect.") ||
                eLower.contains("load_result_patch_loader_fail") ||
                eLower.contains("safecenter") ||
                eLower.contains("clientinfo") ||
                eLower.contains("secverifyapk") ||
                eLower.contains("mobileqqdetect")) {
                return true;
            }
        }

        if (params != null && !params.isEmpty()) {
            for (Map.Entry<String, ?> entry : params.entrySet()) {
                String k = entry.getKey();
                if (k == null) continue;
                String kLower = k.toLowerCase(Locale.ROOT);
                if (kLower.contains("root") ||
                    kLower.contains("risk") ||
                    kLower.contains("jailbreak") ||
                    kLower.contains("xposed") ||
                    kLower.contains("magisk") ||
                    kLower.contains("detect") ||
                    kLower.contains("fake") ||
                    kLower.contains("tamper") ||
                    kLower.contains("strike") ||
                    kLower.contains("check") ||
                    kLower.contains("sec_") ||
                    kLower.equals("sig") ||
                    kLower.contains("sig_") ||
                    kLower.contains("_sig") ||
                    kLower.contains("clearfrom") ||
                    kLower.contains("clear_from") ||
                    kLower.contains("clearsig") ||
                    kLower.contains("qimei") ||
                    kLower.contains("sysprop") ||
                    kLower.contains("token") ||
                    kLower.contains("probe") ||
                    kLower.contains("turing")) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * General telemetry / network report audit logger.
     */
    public static void recordReport(String channel, String eventOrCmd, Map<String, ?> params, String extraDetail, int stackDepth) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            return;
        }
        try {
            boolean isSecurity = isSecurityOrEnvironmentEvent(channel, eventOrCmd, params, extraDetail);
            if (eventOrCmd != null && (eventOrCmd.contains("sig_clear") || eventOrCmd.contains("wt_all_sig_clear") || eventOrCmd.contains("clearFrom"))) {
                stackDepth = Math.max(stackDepth, 15);
                isSecurity = true;
            } else if (params != null && (params.containsKey("clearFrom") || params.containsKey("clear_from"))) {
                stackDepth = Math.max(stackDepth, 15);
                isSecurity = true;
            }
            String time = getCurrentTimestamp();
            int pid = Process.myPid();
            int tid = Process.myTid();
            String threadName = Thread.currentThread().getName();

            StringBuilder sb = new StringBuilder(256);
            sb.append("[").append(time).append("]")
              .append("[").append(sProcessName).append(" pid:").append(pid).append(" tid:").append(tid).append(" (").append(threadName).append(")]")
              .append("[").append(channel).append("] ")
              .append(eventOrCmd != null ? eventOrCmd : "");

            if (extraDetail != null && !extraDetail.isEmpty()) {
                sb.append(" | ").append(extraDetail);
            }

            if (params != null && !params.isEmpty()) {
                sb.append("\n    Params: ").append(params.toString());
            }

            if (isSecurity && stackDepth > 0) {
                sb.append("\n    Caller: ").append(getCallerSummary(stackDepth));
            }

            String fullLog = sb.toString();
            sLogQueue.offer(new AuditEntry(fullLog, isSecurity, false));

            if (isSecurity) {
                Log.w(TAG, "[ENV_AUDIT] " + fullLog);
                XposedBridge.log("[EnvAudit] " + fullLog);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in recordReport: " + t.getMessage());
        }
    }

    /**
     * Specific audit for BeaconReport with parameter sanitization details.
     */
    public static void recordBeacon(String eventCode, boolean isSuccess, Map<String, String> params, String appKey, List<String> sanitizedDetails) {
        StringBuilder detail = new StringBuilder();
        detail.append("success=").append(isSuccess);
        if (appKey != null) {
            detail.append(", appKey=").append(appKey);
        }
        if (sanitizedDetails != null && !sanitizedDetails.isEmpty()) {
            detail.append(" | [SECURITY_SANITIZED: ");
            for (int i = 0; i < sanitizedDetails.size(); i++) {
                if (i > 0) detail.append(", ");
                detail.append(sanitizedDetails.get(i));
            }
            detail.append("]");
        }
        recordReport("BeaconReport", eventCode, params, detail.toString(), 4);
    }

    public static void recordBeacon(String eventCode, boolean isSuccess, Map<String, String> params, String appKey) {
        recordBeacon(eventCode, isSuccess, params, appKey, null);
    }

    /**
     * Specific audit for Security / Environment Probes (File checks, package queries, commands).
     */
    public static void recordProbe(String probeType, String target, String action) {
        String detail = "target=\"" + target + "\" | action=" + action;
        recordReport("Probe", probeType, null, detail, 3);
    }

    /**
     * Specific audit for ProtoBuf security scan packets (safecheckPB, SecVerifyApk, ClientInfoA/B, MobileQQDetect).
     */
    public static void recordProtoBufSecurity(String packetName, Object packetObj, String actionSummary) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) return;
        try {
            String time = getCurrentTimestamp();
            int pid = Process.myPid();
            int tid = Process.myTid();

            StringBuilder sb = new StringBuilder(512);
            sb.append("[").append(time).append("]")
              .append("[").append(sProcessName).append(" pid:").append(pid).append(" tid:").append(tid).append("]")
              .append("[ProtoBufSecurity] ").append(packetName).append(" | ").append(actionSummary);

            if (packetObj != null) {
                sb.append("\n    Dump: ");
                dumpObjectFields(packetObj, sb);
            }
            sb.append("\n    Caller: ").append(getCallerSummary(4));

            String fullLog = sb.toString();
            sLogQueue.offer(new AuditEntry(fullLog, true, false));
            Log.w(TAG, "[ENV_AUDIT] " + fullLog);
            XposedBridge.log("[EnvAudit] " + fullLog);
        } catch (Throwable t) {
            Log.e(TAG, "Error in recordProtoBufSecurity: " + t.getMessage());
        }
    }

    /**
     * Specific audit for Security Strike & AntiTrace triggers.
     */
    public static void recordSecurityStrike(String strikeType, String detail) {
        recordReport("SecurityStrike", strikeType, null, detail, 4);
    }

    /**
     * Specific audit for StatisticCollector.
     */
    public static void recordStatisticCollector(String uin, String tagName, boolean success, long duration, long size, Map<String, String> params, String reserved) {
        String detail = "uin=" + uin + ", success=" + success + ", duration=" + duration + "ms, size=" + size + (reserved != null ? ", res=" + reserved : "");
        recordReport("StatisticCollector", tagName, params, detail, 0);
    }

    /**
     * Specific audit for ReportController.
     */
    public static void recordReportController(String tag, String subTag, String opType, String opName, int result, String r2, String r3, String r4, String r5) {
        String detail = "subTag=" + subTag + ", opType=" + opType + ", opName=" + opName + ", res=" + result + ", r2=" + r2 + ", r3=" + r3 + ", r4=" + r4 + ", r5=" + r5;
        recordReport("ReportController", tag, null, detail, 0);
    }

    /**
     * Comprehensive Turing / Device Risk Check Key Definitions.
     * Maps internal numeric / string keys to precise security diagnostic descriptions.
     */
    public static String getTuringKeyDescription(String key) {
        if (key == null) return "Unknown Key";
        switch (key) {
            case "1": return "SDK Version / Type";
            case "4": return "Crux Execution Timing Benchmarks";
            case "205": return "Caelum Hardware Specs";
            case "207": return "T1 Client Information";
            case "210": return "Timing Profiler (C/T/LT Timestamps)";
            case "240": return "N1 Network / Device Fingerprint";
            case "250": return "Core Device Architecture ID";
            case "251": return "Dual App / Multi-User Flag (Binary)";
            case "252": return "Virtual Environment / Container Check";
            case "253": return "Device Hardware Spec D (Kiwifruit.d)";
            case "254": return "Device Hardware Spec B (Kiwifruit.b)";
            case "255": return "Device Spec Public (Screen/DPI)";
            case "256": return "Proc Scanner Detailed Process Name";
            case "257": return "E-Tag Environment Info";
            case "259": return "ZA Environment Integrity Flag";
            case "264": return "CPU Info & Native Architecture (Auriga)";
            case "266": return "Persistent Device Storage Cache 901";
            case "267": return "Sensor & Motion Hardware Scan";
            case "268": return "Proc Scanner Suspicious Process List";
            case "269": return "A7 Sensor Hardware Flag";
            case "270": return "OS Flavor & HarmonyOS Detection (Kiwifruit.a)";
            case "272": return "Open Ports Scanner (/proc/net/tcp)";
            case "273": return "Tough Hardware Integrity Key";
            case "274": return "IMEI Telephony Fingerprint";
            case "275": return "Android ID Device Identifier";
            case "276": return "IMSI Subscriber Identifier";
            case "279": return "Mounts & Virtual Filesystem Scan";
            case "280": return "SELinux & Root Detection State";
            case "281": return "Device Uptime & Boot Offset";
            case "282": return "SIM Card Status (Kiwifruit.c)";
            case "283": return "B Info Hardware String";
            case "284": return "Device Model & Brand Fingerprint";
            case "285": return "ADB / USB Debugging Status";
            case "286": return "System Timezone ID";
            case "287": return "Telephony SIM Operator Code";
            case "288": return "Multi-User / Dual App User ID Value";
            case "289": return "ClassLoader Hierarchy & Dynamic Hook Scan";
            case "290": return "Audio Mode Status";
            case "291": return "USB Configuration State (adb/mtp)";
            case "292": return "Android 15 API Compatibility Check";
            case "293": return "Android 14 API Compatibility Check";
            case "297": return "A11 System Properties Flag";
            case "303": return "Persistent Device Cache Tag 703";
            case "308": return "Marc Sensor State Flag";
            case "309": return "Peanut Device Fingerprint";
            case "402": return "Turing SDK Client ID";
            case "406": return "Core Device Hash Signature";
            case "2001": return "E2 Package Context Integrity Hash";
            case "2005": return "UIN State Flag";
            case "2013": return "Context Signature & APK Cert Verification";
            case "2016": return "System Properties & Prop Scan";
            case "2017": return "A2 Prop Fingerprint";
            case "2018": return "Process UID (Process.myUid())";
            case "2019": return "PackageManager & Installed Apps Scan (mPM)";
            case "2021": return "Accessibility Services & TalkBack List";
            case "2022": return "A10 Prop Fingerprint";
            case "2024": return "A13 System Flag";
            case "2029": return "String Signature Flag";
            default: return "Risk Item " + key;
        }
    }

    /**
     * Standard 16-bytes per line hex dump with byte offsets and printable ASCII sidebar.
     */
    public static String formatHexDump(byte[] data, int maxLen) {
        if (data == null || data.length == 0) return "    (empty payload)\n";
        int len = Math.min(data.length, maxLen);
        StringBuilder sb = new StringBuilder(len * 5);
        for (int i = 0; i < len; i += 16) {
            sb.append(String.format(Locale.US, "    %08x: ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < len) {
                    sb.append(String.format(Locale.US, "%02x ", data[i + j]));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(" ");
            }
            sb.append(" |");
            for (int j = 0; j < 16 && (i + j) < len; j++) {
                byte b = data[i + j];
                if (b >= 32 && b <= 126) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }
            sb.append("|\n");
        }
        if (data.length > maxLen) {
            sb.append("    ... (truncated, total ").append(data.length).append(" bytes)\n");
        }
        return sb.toString();
    }

    /**
     * Extracts printable strings with exact byte offsets.
     */
    public static List<String> extractPrintableStringsWithOffsets(byte[] data, int minLen, int maxCount) {
        List<String> list = new ArrayList<>();
        if (data == null || data.length == 0) return list;

        int start = -1;
        for (int i = 0; i < data.length && list.size() < maxCount; i++) {
            byte b = data[i];
            boolean isPrintable = (b >= 32 && b <= 126);
            if (isPrintable) {
                if (start == -1) start = i;
            } else {
                if (start != -1) {
                    int len = i - start;
                    if (len >= minLen) {
                        try {
                            String s = new String(data, start, len, "UTF-8").trim();
                            if (s.length() >= minLen) {
                                list.add(String.format(Locale.US, "[0x%04x] \"%s\"", start, s));
                            }
                        } catch (Throwable ignored) {}
                    }
                    start = -1;
                }
            }
        }
        if (start != -1 && (data.length - start) >= minLen && list.size() < maxCount) {
            try {
                String s = new String(data, start, data.length - start, "UTF-8").trim();
                if (s.length() >= minLen) {
                    list.add(String.format(Locale.US, "[0x%04x] \"%s\"", start, s));
                }
            } catch (Throwable ignored) {}
        }
        return list;
    }

    /**
     * Extracts JSON block if embedded in printable strings.
     */
    public static String tryExtractJson(List<String> printableWithOffsets) {
        if (printableWithOffsets == null) return null;
        for (String item : printableWithOffsets) {
            int quoteIdx = item.indexOf('"');
            if (quoteIdx != -1 && item.endsWith("\"")) {
                String content = item.substring(quoteIdx + 1, item.length() - 1);
                if (content.startsWith("{") && content.endsWith("}") && content.length() > 5) {
                    return content;
                }
            }
        }
        return null;
    }

    /**
     * Dedicated High-Visibility Outbound Risk Payload Auditor.
     * Prominently audits all environment telemetry, device fingerprints, and security payloads
     * dispatched by QQ to Tencent servers (ChannelManager, MsfCore SSO, TuringFD, Dtc, Beacon).
     */
    public static void recordOutboundRiskPayload(String channel, String cmd, byte[] payload, String extraInfo, int stackDepth) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) return;
        try {
            String time = getCurrentTimestamp();
            int pid = Process.myPid();
            int tid = Process.myTid();
            String threadName = Thread.currentThread().getName();

            int payloadLen = payload != null ? payload.length : 0;
            StringBuilder sb = new StringBuilder(1024);
            sb.append("\n==================== [OUTBOUND RISK TELEMETRY SENT TO SERVER] ====================\n")
              .append("Time: ").append(time).append("\n")
              .append("Process: ").append(sProcessName).append(" (pid:").append(pid).append(", tid:").append(tid).append(", thread:").append(threadName).append(")\n")
              .append("Channel: ").append(channel).append("\n")
              .append("Target Command / Event: ").append(cmd != null ? cmd : "unknown").append("\n")
              .append("Payload Size: ").append(payloadLen).append(" bytes\n");

            if (extraInfo != null && !extraInfo.isEmpty()) {
                sb.append("Extra Information: ").append(extraInfo).append("\n");
            }

            if (payload != null && payloadLen > 0) {
                List<String> printable = extractPrintableStringsWithOffsets(payload, 3, 50);
                if (!printable.isEmpty()) {
                    sb.append("Extracted Printable Strings (").append(printable.size()).append(" entries):\n");
                    for (String str : printable) {
                        sb.append("    ").append(str).append("\n");
                    }
                }

                String jsonStr = tryExtractJson(printable);
                if (jsonStr != null) {
                    sb.append("Decoded JSON Data:\n    ").append(jsonStr).append("\n");
                }

                sb.append("Hex Dump Preview (up to 256 bytes):\n");
                sb.append(formatHexDump(payload, 256));
            }

            if (stackDepth > 0) {
                sb.append("Caller Stack Trace:\n");
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                if (stack != null) {
                    int count = 0;
                    for (StackTraceElement ste : stack) {
                        String cn = ste.getClassName();
                        if (cn.contains("ReportAuditManager") || cn.contains("java.lang.Thread")) continue;
                        sb.append("    at ").append(ste.toString()).append("\n");
                        count++;
                        if (count >= stackDepth) break;
                    }
                }
            }
            sb.append("==================================================================================\n");

            String fullLog = sb.toString();
            sLogQueue.offer(new AuditEntry(fullLog, true, false));
            Log.w(TAG, fullLog);
            XposedBridge.log(fullLog);
        } catch (Throwable t) {
            Log.e(TAG, "Error in recordOutboundRiskPayload: " + t.getMessage());
        }
    }

    /**
     * Dedicated High-Visibility Outbound Turing / Device Risk Dictionary Auditor.
     * Formats and logs the complete key-value inspection map compiled by TuringFD / QSec
     * before native packaging and transmission to Tencent risk servers.
     */
    public static void recordOutboundRiskMap(String channel, String operation, Map<?, ?> riskMap, int stackDepth) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) return;
        try {
            String time = getCurrentTimestamp();
            int pid = Process.myPid();
            int tid = Process.myTid();
            String threadName = Thread.currentThread().getName();

            StringBuilder sb = new StringBuilder(1024);
            sb.append("\n==================== [OUTBOUND RISK TELEMETRY SENT TO SERVER] ====================\n")
              .append("Time: ").append(time).append("\n")
              .append("Process: ").append(sProcessName).append(" (pid:").append(pid).append(", tid:").append(tid).append(", thread:").append(threadName).append(")\n")
              .append("Channel: ").append(channel).append("\n")
              .append("Target Operation: ").append(operation).append("\n");

            if (riskMap != null) {
                sb.append("Payload Dictionary: ").append(riskMap.size()).append(" risk-control inspection items\n")
                  .append("----------------------------------------------------------------------------------\n");
                for (Map.Entry<?, ?> entry : riskMap.entrySet()) {
                    String k = String.valueOf(entry.getKey());
                    Object v = entry.getValue();
                    String desc = getTuringKeyDescription(k);
                    sb.append(String.format(Locale.US, "  [Key %-5s] [%-42s] = ", k, desc));
                    if (v == null) {
                        sb.append("null\n");
                    } else if (v instanceof String) {
                        String s = (String) v;
                        if (s.length() > 300) {
                            sb.append("\"").append(s.substring(0, 300)).append("...\" (len=").append(s.length()).append(")\n");
                        } else {
                            sb.append("\"").append(s).append("\"\n");
                        }
                    } else {
                        sb.append(v.toString()).append("\n");
                    }
                }
            } else {
                sb.append("Payload Dictionary: null\n");
            }

            if (stackDepth > 0) {
                sb.append("Caller Stack Trace:\n");
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                if (stack != null) {
                    int count = 0;
                    for (StackTraceElement ste : stack) {
                        String cn = ste.getClassName();
                        if (cn.contains("ReportAuditManager") || cn.contains("java.lang.Thread")) continue;
                        sb.append("    at ").append(ste.toString()).append("\n");
                        count++;
                        if (count >= stackDepth) break;
                    }
                }
            }
            sb.append("==================================================================================\n");

            String fullLog = sb.toString();
            sLogQueue.offer(new AuditEntry(fullLog, true, false));
            Log.w(TAG, fullLog);
            XposedBridge.log(fullLog);
        } catch (Throwable t) {
            Log.e(TAG, "Error in recordOutboundRiskMap: " + t.getMessage());
        }
    }

    /**
     * Specific audit for ChannelManager / SSO.
     */
    public static void recordChannelManager(String cmd, long callbackId, int dataLen, byte[] data) {
        if (data != null && data.length > 0) {
            recordOutboundRiskPayload("ChannelManager", cmd, data, "callbackId=" + callbackId + ", dataLen=" + dataLen, 6);
        } else {
            String detail = "callbackId=" + callbackId + ", dataLen=" + dataLen;
            recordReport("ChannelManager", cmd, null, detail, 4);
        }
    }

    public static void recordChannelManager(String cmd, long callbackId, int dataLen) {
        recordChannelManager(cmd, callbackId, dataLen, null);
    }

    /**
     * Specific audit for MsfCore SSO.
     */
    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp, Map<?, ?> attributes, byte[] wupBuf) {
        int bufLen = wupBuf != null ? wupBuf.length : 0;
        boolean isSecurity = isSecurityOrEnvironmentEvent("MsfCore", cmd, null, null);
        if (isSecurity && wupBuf != null && bufLen > 0) {
            StringBuilder extra = new StringBuilder();
            extra.append("uin=").append(uin).append(", seq=").append(ssoSeq).append(", needResp=").append(needResp);
            if (attributes != null && !attributes.isEmpty()) {
                extra.append(", attrs=").append(attributes.toString());
            }
            recordOutboundRiskPayload("MsfCore", cmd, wupBuf, extra.toString(), 6);
        } else {
            StringBuilder detail = new StringBuilder();
            detail.append("uin=").append(uin).append(", seq=").append(ssoSeq).append(", needResp=").append(needResp).append(", len=").append(bufLen);
            if (attributes != null && !attributes.isEmpty()) {
                detail.append(", attrs={");
                boolean first = true;
                for (Map.Entry<?, ?> entry : attributes.entrySet()) {
                    String k = String.valueOf(entry.getKey());
                    if (k.contains("security") || k.contains("retry") || k.contains("cmd") || k.contains("seq") || k.contains("token")) {
                        if (!first) detail.append(", ");
                        first = false;
                        detail.append(k).append("=").append(entry.getValue());
                    }
                }
                detail.append("}");
            }
            recordReport("MsfCore", cmd, null, detail.toString(), isSecurity ? 4 : 0);
        }
    }

    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp, Map<?, ?> attributes, int bufLen) {
        recordMsfSso(cmd, uin, ssoSeq, needResp, attributes, (byte[]) null);
    }

    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp) {
        recordMsfSso(cmd, uin, ssoSeq, needResp, null, (byte[]) null);
    }

    /**
     * Checks if a Throwable contains sensitive Xposed / Root / Hook framework frames.
     * If sensitive, returns true indicating the crash report MUST be suppressed to protect against server-side risk bans.
     */
    public static boolean isSensitiveException(Throwable t) {
        if (t == null) return false;
        Throwable current = t;
        int depth = 0;
        while (current != null && depth < 10) {
            String msg = current.getMessage();
            if (msg != null && containsSensitiveKeyword(msg)) {
                return true;
            }
            StackTraceElement[] stack = current.getStackTrace();
            if (stack != null) {
                for (StackTraceElement ste : stack) {
                    if (containsSensitiveKeyword(ste.getClassName()) || containsSensitiveKeyword(ste.getMethodName())) {
                        return true;
                    }
                }
            }
            current = current.getCause();
            depth++;
        }
        return false;
    }

    private static boolean containsSensitiveKeyword(String text) {
        if (text == null) return false;
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("xposed") ||
               lower.contains("lsposed") ||
               lower.contains("edxposed") ||
               lower.contains("qqbypass") ||
               lower.contains("xalsace") ||
               lower.contains("sandhook") ||
               lower.contains("libepic") || lower.contains("me.ele.epic") ||
               lower.contains("libpine") || lower.contains("top.canyie.pine") ||
               lower.contains("dexkit") ||
               lower.contains("bytehook") ||
               lower.contains("frida") ||
               lower.contains("magisk") ||
               lower.contains("kernelsu") || lower.contains("ksud") ||
               lower.contains("libapatch") || lower.contains("me.bmax.apatch") || lower.contains("apatchd") ||
               lower.contains("substrate") ||
               lower.contains("cydia");
    }

    /**
     * Audits and sanitizes CrashReport / Bugly exceptions.
     * Returns TRUE if the exception was suppressed due to containing sensitive hook frames.
     */
    public static boolean recordAndSanitizeException(String reporterType, Throwable t, String message) {
        boolean sensitive = isSensitiveException(t) || containsSensitiveKeyword(message);
        String time = getCurrentTimestamp();
        int pid = Process.myPid();
        int tid = Process.myTid();

        StringBuilder sb = new StringBuilder(512);
        sb.append("[").append(time).append("]")
          .append("[").append(sProcessName).append(" pid:").append(pid).append(" tid:").append(tid).append("]")
          .append("[").append(reporterType).append("] ");

        if (sensitive) {
            sb.append(">>> SUPPRESSED SENSITIVE EXCEPTION (Prevented Risk Ban) <<<\n");
        } else {
            sb.append("Allowed Normal Crash/Exception Report\n");
        }

        if (message != null && !message.isEmpty()) {
            sb.append("    Message: ").append(message).append("\n");
        }

        if (t != null) {
            sb.append("    Exception: ").append(t.getClass().getName()).append(": ").append(t.getMessage()).append("\n");
            StackTraceElement[] stack = t.getStackTrace();
            if (stack != null) {
                int count = 0;
                for (StackTraceElement ste : stack) {
                    sb.append("        at ").append(ste.toString()).append("\n");
                    count++;
                    if (count >= 10) break;
                }
            }
        }

        String fullLog = sb.toString();
        if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            sLogQueue.offer(new AuditEntry(fullLog, true, false));
        }
        Log.w(TAG, fullLog);
        XposedBridge.log("[ReportAudit] " + fullLog);

        return sensitive;
    }

    /**
     * Deep Kick & ForceOffline Event Decoder.
     * Strictly READ-ONLY observational diagnosis:
     * Extracts:
     * - UIN, Cmd, FailCode, FailMsg, ResultCode
     * - Attributes Map (both request and response)
     * - Decodes RequestMSFForceOffline / RequestPushForceOffline fields (strTitle, strInfo, bSigKick)
     * - Printable text strings in raw WUP buffer
     * - Full 20-frame caller stack trace
     * Synchronously flushed to disk immediately!
     */
    public static void recordKickEvent(String sourceMethod, Object fromServiceMsg, Object extraInfo) {
        recordKickEvent(sourceMethod, fromServiceMsg, null, extraInfo);
    }

    public static void recordKickEvent(String sourceMethod, Object msg1, Object msg2, Object extraInfo) {
        try {
            String time = getCurrentTimestamp();
            int pid = Process.myPid();
            int tid = Process.myTid();
            String threadName = Thread.currentThread().getName();

            StringBuilder sb = new StringBuilder(1024);
            sb.append("\n==================== [KICK / OFFLINE EVENT DETECTED] ====================\n")
              .append("Time: ").append(time).append("\n")
              .append("Process: ").append(sProcessName).append(" (pid:").append(pid).append(", tid:").append(tid).append(", thread:").append(threadName).append(")\n")
              .append("Source: ").append(sourceMethod).append("\n");

            if (extraInfo != null) {
                sb.append("ExtraInfo: ").append(extraInfo.toString()).append("\n");
            }

            // Distinguish FromServiceMsg and ToServiceMsg dynamically regardless of argument order
            Object fromServiceMsg = null;
            Object toServiceMsg = null;
            for (Object candidate : new Object[]{msg1, msg2}) {
                if (candidate != null) {
                    String cls = candidate.getClass().getName();
                    if (cls.contains("FromServiceMsg")) {
                        fromServiceMsg = candidate;
                    } else if (cls.contains("ToServiceMsg")) {
                        toServiceMsg = candidate;
                    }
                }
            }

            // 1. If ToServiceMsg present, log originating request command, seq, msfCommand, and attributes
            if (toServiceMsg != null) {
                try {
                    String reqCmd = (String) XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                    Object msfCmd = XposedHelpers.callMethod(toServiceMsg, "getMsfCommand");
                    int reqSeq = ((Number) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq")).intValue();
                    int appId = ((Number) XposedHelpers.callMethod(toServiceMsg, "getAppId")).intValue();
                    sb.append("[Originating Request ToServiceMsg]\n")
                      .append("    RequestCommand: ").append(reqCmd).append("\n")
                      .append("    MsfCommand: ").append(msfCmd).append("\n")
                      .append("    RequestSsoSeq: ").append(reqSeq).append("\n")
                      .append("    AppId: ").append(appId).append("\n");

                    Map<?, ?> attrs = (Map<?, ?>) XposedHelpers.callMethod(toServiceMsg, "getAttributes");
                    if (attrs != null && !attrs.isEmpty()) {
                        sb.append("    RequestAttributes (").append(attrs.size()).append(" entries):\n");
                        for (Map.Entry<?, ?> entry : attrs.entrySet()) {
                            Object k = entry.getKey();
                            Object v = entry.getValue();
                            sb.append("        [").append(k).append("] = ");
                            if (v != null) {
                                sb.append(v.getClass().getSimpleName()).append(": ");
                                dumpObjectFields(v, sb);
                            } else {
                                sb.append("null");
                            }
                            sb.append("\n");
                        }
                    }
                } catch (Throwable t) {
                    sb.append("Error inspecting ToServiceMsg: ").append(t.getMessage()).append("\n");
                }
            }

            // 2. If FromServiceMsg present, log failCode, failMsg, resultCode, attributes, and WUP
            if (fromServiceMsg != null) {
                try {
                    String uin = (String) XposedHelpers.callMethod(fromServiceMsg, "getUin");
                    String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");
                    int failCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode");
                    String failMsg = (String) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailMsg");
                    int resCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getResultCode");

                    sb.append("[Response FromServiceMsg]\n")
                      .append("    UIN: ").append(uin).append("\n")
                      .append("    ResponseCommand: ").append(cmd).append("\n")
                      .append("    BusinessFailCode: ").append(failCode).append("\n")
                      .append("    BusinessFailMsg: ").append(failMsg).append("\n")
                      .append("    ResultCode: ").append(resCode).append("\n");

                    // 1. Dump attributes
                    Map<?, ?> attrs = (Map<?, ?>) XposedHelpers.callMethod(fromServiceMsg, "getAttributes");
                    if (attrs != null && !attrs.isEmpty()) {
                        sb.append("    ResponseAttributes (").append(attrs.size()).append(" entries):\n");
                        for (Map.Entry<?, ?> entry : attrs.entrySet()) {
                            Object k = entry.getKey();
                            Object v = entry.getValue();
                            sb.append("        [").append(k).append("] = ");
                            if (v != null) {
                                sb.append(v.getClass().getSimpleName()).append(": ");
                                dumpObjectFields(v, sb);
                            } else {
                                sb.append("null");
                            }
                            sb.append("\n");
                        }
                    }

                    // 2. Decode WUP buffer
                    byte[] wupBuf = (byte[]) XposedHelpers.callMethod(fromServiceMsg, "getWupBuffer");
                    if (wupBuf != null && wupBuf.length > 0) {
                        sb.append("    WupBuffer Length: ").append(wupBuf.length).append(" bytes\n");
                        List<String> printableStrings = extractPrintableStrings(wupBuf, 3);
                        if (!printableStrings.isEmpty()) {
                            sb.append("    WupBuffer Extracted Strings:\n");
                            for (String str : printableStrings) {
                                sb.append("        \"").append(str).append("\"\n");
                            }
                        }
                    }
                } catch (Throwable t) {
                    sb.append("Error inspecting FromServiceMsg: ").append(t.getMessage()).append("\n");
                }
            } else if (toServiceMsg == null && msg1 != null) {
                // If neither msg1 nor msg2 was FromServiceMsg / ToServiceMsg, dump msg1 generic fields
                try {
                    sb.append("RawMessageDump: ");
                    dumpObjectFields(msg1, sb);
                    sb.append("\n");
                } catch (Throwable ignored) {}
            }

            // 3. Dump Stack Trace (20 frames)
            sb.append("Caller Stack Trace:\n");
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            if (stack != null) {
                int frameCount = 0;
                for (StackTraceElement ste : stack) {
                    String cn = ste.getClassName();
                    if (cn.contains("ReportAuditManager") || cn.contains("java.lang.Thread")) continue;
                    sb.append("    at ").append(ste.toString()).append("\n");
                    frameCount++;
                    if (frameCount >= 20) break;
                }
            }

            sb.append("=========================================================================\n");

            String fullLog = sb.toString();

            // Synchronously flush to disk immediately
            if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                writeEntryInternal(new AuditEntry(fullLog, true, true));
            }

            // Also output to Logcat and LSPosed
            Log.e(TAG, fullLog);
            XposedBridge.log(fullLog);

        } catch (Throwable t) {
            Log.e(TAG, "Failed to record kick event: " + t.getMessage());
        }
    }

    private static void dumpObjectFields(Object obj, StringBuilder sb) {
        if (obj == null) return;
        Class<?> cls = obj.getClass();
        if (cls.isPrimitive() || obj instanceof String || obj instanceof Number || obj instanceof Boolean) {
            sb.append(obj.toString());
            return;
        }

        sb.append("{");
        try {
            Field[] fields = cls.getDeclaredFields();
            boolean first = true;
            for (Field f : fields) {
                f.setAccessible(true);
                if (!first) sb.append(", ");
                first = false;
                Object val = f.get(obj);
                sb.append(f.getName()).append("=");
                if (val instanceof byte[]) {
                    sb.append("byte[").append(((byte[]) val).length).append("]");
                } else {
                    sb.append(val);
                }
            }
        } catch (Throwable t) {
            sb.append("dumpErr:").append(t.getMessage());
        }
        sb.append("}");
    }

    public static List<String> extractPrintableStrings(byte[] data, int minLen) {
        List<String> list = new ArrayList<>();
        if (data == null || data.length == 0) return list;

        int start = -1;
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            boolean isPrintable = (b >= 32 && b <= 126) || (b < 0);
            if (isPrintable) {
                if (start == -1) start = i;
            } else {
                if (start != -1) {
                    int len = i - start;
                    if (len >= minLen) {
                        try {
                            String s = new String(data, start, len, "UTF-8").trim();
                            if (s.length() >= minLen) {
                                list.add(s);
                            }
                        } catch (Throwable ignored) {}
                    }
                    start = -1;
                }
            }
        }
        if (start != -1 && (data.length - start) >= minLen) {
            try {
                String s = new String(data, start, data.length - start, "UTF-8").trim();
                if (s.length() >= minLen) {
                    list.add(s);
                }
            } catch (Throwable ignored) {}
        }
        return list;
    }
}
