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
    private static final SimpleDateFormat sDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

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
        synchronized (sDateFormat) {
            return sDateFormat.format(new Date());
        }
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

    /**
     * Intelligent Classifier: Distinguishes critical security & environment detection telemetry
     * from high-frequency UI interaction noise (dt_clck, qq_imp, dt_pgin, etc.).
     */
    public static boolean isSecurityOrEnvironmentEvent(String channel, String eventOrCmd, Map<String, ?> params, String extraDetail) {
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
                cLower.contains("turing")) {
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
                edLower.contains("intercepted")) {
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
                eLower.contains("sec_") ||
                eLower.contains("security") ||
                eLower.contains("detect") ||
                eLower.contains("root") ||
                eLower.contains("risk") ||
                eLower.contains("xposed") ||
                eLower.contains("magisk") ||
                eLower.contains("turing") ||
                eLower.contains("device") ||
                eLower.contains("qimei") ||
                eLower.contains("oaid") ||
                eLower.contains("guid") ||
                eLower.contains("antitrace") ||
                eLower.contains("verify") ||
                eLower.contains("check") ||
                eLower.contains("safecheck") ||
                eLower.contains("patch") ||
                eLower.contains("intchk") ||
                eLower.contains("oidbsvc.0xd79") ||
                eLower.contains("0ac00056535")) {
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
                    kLower.contains("sig")) {
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

            if (stackDepth > 0) {
                sb.append("\n    Caller: ").append(getCallerSummary(stackDepth));
            }

            String fullLog = sb.toString();
            sLogQueue.offer(new AuditEntry(fullLog, isSecurity, false));

            if (isSecurity) {
                Log.w(TAG, "[ENV_AUDIT] " + fullLog);
                XposedBridge.log("[EnvAudit] " + fullLog);
            } else {
                Log.i(TAG, fullLog);
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
        recordReport("StatisticCollector", tagName, params, detail, 4);
    }

    /**
     * Specific audit for ReportController.
     */
    public static void recordReportController(String tag, String subTag, String opType, String opName, int result, String r2, String r3, String r4, String r5) {
        String detail = "subTag=" + subTag + ", opType=" + opType + ", opName=" + opName + ", res=" + result + ", r2=" + r2 + ", r3=" + r3 + ", r4=" + r4 + ", r5=" + r5;
        recordReport("ReportController", tag, null, detail, 3);
    }

    /**
     * Specific audit for ChannelManager / SSO.
     */
    public static void recordChannelManager(String cmd, long callbackId, int dataLen, byte[] data) {
        StringBuilder detail = new StringBuilder();
        detail.append("callbackId=").append(callbackId).append(", dataLen=").append(dataLen);
        if (data != null && data.length > 0) {
            List<String> printable = extractPrintableStrings(data, 3);
            if (!printable.isEmpty()) {
                detail.append(", strings=[");
                for (int i = 0; i < Math.min(printable.size(), 6); i++) {
                    if (i > 0) detail.append(", ");
                    detail.append("\"").append(printable.get(i)).append("\"");
                }
                detail.append("]");
            }
        }
        recordReport("ChannelManager", cmd, null, detail.toString(), 4);
    }

    public static void recordChannelManager(String cmd, long callbackId, int dataLen) {
        recordChannelManager(cmd, callbackId, dataLen, null);
    }

    /**
     * Specific audit for MsfCore SSO.
     */
    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp, Map<?, ?> attributes, int bufLen) {
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
        recordReport("MsfCore", cmd, null, detail.toString(), 3);
    }

    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp) {
        recordMsfSso(cmd, uin, ssoSeq, needResp, null, 0);
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
               lower.contains("epic") ||
               lower.contains("pine") ||
               lower.contains("dexkit") ||
               lower.contains("bytehook") ||
               lower.contains("frida") ||
               lower.contains("magisk") ||
               lower.contains("kernelsu") ||
               lower.contains("apatch") ||
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
     * - Attributes Map
     * - Decodes RequestMSFForceOffline / RequestPushForceOffline fields (strTitle, strInfo, bSigKick)
     * - Printable text strings in raw WUP buffer
     * - Full 15-frame caller stack trace
     * Synchronously flushed to disk immediately!
     */
    public static void recordKickEvent(String sourceMethod, Object fromServiceMsg, Object extraInfo) {
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

            if (fromServiceMsg != null) {
                try {
                    String uin = (String) XposedHelpers.callMethod(fromServiceMsg, "getUin");
                    String cmd = (String) XposedHelpers.callMethod(fromServiceMsg, "getServiceCmd");
                    int failCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailCode");
                    String failMsg = (String) XposedHelpers.callMethod(fromServiceMsg, "getBusinessFailMsg");
                    int resCode = (Integer) XposedHelpers.callMethod(fromServiceMsg, "getResultCode");

                    sb.append("UIN: ").append(uin).append("\n")
                      .append("Command: ").append(cmd).append("\n")
                      .append("BusinessFailCode: ").append(failCode).append("\n")
                      .append("BusinessFailMsg: ").append(failMsg).append("\n")
                      .append("ResultCode: ").append(resCode).append("\n");

                    // 1. Dump attributes
                    Map<?, ?> attrs = (Map<?, ?>) XposedHelpers.callMethod(fromServiceMsg, "getAttributes");
                    if (attrs != null && !attrs.isEmpty()) {
                        sb.append("Attributes (").append(attrs.size()).append(" entries):\n");
                        for (Map.Entry<?, ?> entry : attrs.entrySet()) {
                            Object k = entry.getKey();
                            Object v = entry.getValue();
                            sb.append("    [").append(k).append("] = ");
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
                        sb.append("WupBuffer Length: ").append(wupBuf.length).append(" bytes\n");
                        List<String> printableStrings = extractPrintableStrings(wupBuf, 3);
                        if (!printableStrings.isEmpty()) {
                            sb.append("WupBuffer Extracted Strings:\n");
                            for (String str : printableStrings) {
                                sb.append("    \"").append(str).append("\"\n");
                            }
                        }
                    }
                } catch (Throwable t) {
                    sb.append("Error inspecting FromServiceMsg: ").append(t.getMessage()).append("\n");
                }
            }

            // 3. Dump Stack Trace (15 frames)
            sb.append("Caller Stack Trace:\n");
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            if (stack != null) {
                int frameCount = 0;
                for (StackTraceElement ste : stack) {
                    String cn = ste.getClassName();
                    if (cn.contains("ReportAuditManager") || cn.contains("java.lang.Thread")) continue;
                    sb.append("    at ").append(ste.toString()).append("\n");
                    frameCount++;
                    if (frameCount >= 15) break;
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
