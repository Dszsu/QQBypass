package io.github.xalsace.qqbypass.utils;

import android.os.Process;
import android.util.Log;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import io.github.xalsace.qqbypass.config.CompileHookConfig;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance, non-blocking telemetry & kick event audit manager.
 *
 * Responsibilities:
 * 1. Asynchronously captures and writes outgoing telemetry / report events to disk:
 *    - Primary storage: /data/user/0/com.tencent.mobileqq/files/report_audit.log (always writable)
 *    - Secondary storage: /storage/emulated/0/0_TM/report_audit.log (when available)
 * 2. Provides deep decoding of Kick / ForceOffline events:
 *    - Decodes RequestMSFForceOffline / RequestPushForceOffline WUP & JCE structures
 *    - Analyzes bSigKick (security kick detection), strTitle, strInfo, strTips
 *    - Flushes synchronously to disk immediately upon kick reception
 * 3. Sanitizes Bugly & CrashReport exception reports to prevent Xposed frames from leaking
 */
public class ReportAuditManager {

    private static final String TAG = "QQReportAudit";
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB rolling limit

    private static final File PRIMARY_FILE = new File("/data/user/0/com.tencent.mobileqq/files/report_audit.log");
    private static final File SECONDARY_FILE = new File("/storage/emulated/0/0_TM/report_audit.log");

    private static final BlockingQueue<String> sLogQueue = new LinkedBlockingQueue<>(4096);
    private static final AtomicBoolean sWorkerStarted = new AtomicBoolean(false);
    private static final SimpleDateFormat sDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);

    private static String sProcessName = "unknown";

    static {
        ensureWorkerStarted();
    }

    public static void setProcessName(String processName) {
        if (processName != null && !processName.isEmpty()) {
            sProcessName = processName;
        }
    }

    public static String getProcessName() {
        return sProcessName;
    }

    private static void ensureWorkerStarted() {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            return;
        }
        if (sWorkerStarted.compareAndSet(false, true)) {
            Thread workerThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        try {
                            String logEntry = sLogQueue.take();
                            writeToFileInternal(logEntry);
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

    private static synchronized void writeToFileInternal(String entry) {
        if (entry == null || entry.isEmpty()) return;

        // 1. Write to Primary File
        writeToSingleFile(PRIMARY_FILE, entry);

        // 2. Write to Secondary File if directory exists
        try {
            File parent = SECONDARY_FILE.getParentFile();
            if (parent != null && parent.exists() && parent.canWrite()) {
                writeToSingleFile(SECONDARY_FILE, entry);
            }
        } catch (Throwable ignored) {}
    }

    private static void writeToSingleFile(File targetFile, String entry) {
        try {
            File parent = targetFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            // Rolling file check
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
     * General telemetry / network report audit logger.
     */
    public static void recordReport(String channel, String eventOrCmd, Map<String, ?> params, String extraDetail, int stackDepth) {
        if (!CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
            return;
        }
        try {
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
            sLogQueue.offer(fullLog);

            // Also send to Logcat and LSPosed
            Log.i(TAG, fullLog);
            XposedBridge.log("[ReportAudit] " + fullLog);
        } catch (Throwable t) {
            Log.e(TAG, "Error in recordReport: " + t.getMessage());
        }
    }

    /**
     * Specific audit for BeaconReport.
     */
    public static void recordBeacon(String eventCode, boolean isSuccess, Map<String, String> params, String appKey) {
        String detail = "success=" + isSuccess + (appKey != null ? ", appKey=" + appKey : "");
        recordReport("BeaconReport", eventCode, params, detail, 4);
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
    public static void recordChannelManager(String cmd, long callbackId, int dataLen) {
        String detail = "callbackId=" + callbackId + ", dataLen=" + dataLen;
        recordReport("ChannelManager", cmd, null, detail, 4);
    }

    /**
     * Specific audit for MsfCore SSO.
     */
    public static void recordMsfSso(String cmd, String uin, int ssoSeq, boolean needResp) {
        String detail = "uin=" + uin + ", seq=" + ssoSeq + ", needResp=" + needResp;
        recordReport("MsfCore", cmd, null, detail, 3);
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
            sLogQueue.offer(fullLog);
        }
        Log.w(TAG, fullLog);
        XposedBridge.log("[ReportAudit] " + fullLog);

        return sensitive;
    }

    /**
     * Deep Kick & ForceOffline Event Decoder.
     * Extracts:
     * - UIN, Cmd, FailCode, FailMsg
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
            sb.append("\n==================== [KICK EVENT DETECTED] ====================\n")
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

            sb.append("==============================================================\n");

            String fullLog = sb.toString();

            // Synchronously flush to disk if report recording is enabled
            if (CompileHookConfig.ENABLE_RECORD_QQ_REPORT) {
                writeToFileInternal(fullLog);
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

    private static List<String> extractPrintableStrings(byte[] data, int minLen) {
        List<String> list = new ArrayList<>();
        if (data == null || data.length == 0) return list;

        int start = -1;
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            // Printable ASCII range (32..126) or UTF-8 multi-byte sequence (b < 0)
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
