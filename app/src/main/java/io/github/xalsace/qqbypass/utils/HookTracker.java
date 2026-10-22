package io.github.xalsace.qqbypass.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.XposedBridge;
import io.github.xalsace.qqbypass.NativeBypass;

/**
 * 集中管理并汇总 Hook 加载与安装统计指标。
 * 遵循设计准则：
 * 1. 模块加载/Hook 成功时不输出繁琐过程日志；
 * 2. 一旦 Hook 或加载 Hook 失败，立即输出失败日志；
 * 3. 最终汇总输出且仅输出一条总统计日志。
 */
public class HookTracker {
    private static final String TAG = "QQBypass";

    private static final AtomicInteger sJavaTotal = new AtomicInteger(0);
    private static final AtomicInteger sJavaSuccess = new AtomicInteger(0);
    private static final AtomicInteger sJavaFailed = new AtomicInteger(0);
    private static final List<String> sJavaFailedHooks = Collections.synchronizedList(new ArrayList<>());
    private static final AtomicBoolean sSummaryPrinted = new AtomicBoolean(false);

    public static void recordJavaSuccess(String hookName) {
        sJavaTotal.incrementAndGet();
        sJavaSuccess.incrementAndGet();
        // 成功时静默，不输出过程日志
    }

    public static void recordJavaFailure(String hookName, Throwable t) {
        sJavaTotal.incrementAndGet();
        sJavaFailed.incrementAndGet();
        String name = (hookName != null && !hookName.isEmpty()) ? hookName : "unknown";
        sJavaFailedHooks.add(name);

        // Hook 失败必须立即输出错误级别日志 (Log.e)
        String errorMsg = (t != null) ? (t.getClass().getSimpleName() + ": " + t.getMessage()) : "unknown error";
        String logMsg = "[" + TAG + "] [ERROR] Java Hook 失败: " + name + " (" + errorMsg + ")";
        android.util.Log.e(TAG, logMsg, t);
        XposedBridge.log(logMsg);
        if (t != null) {
            XposedBridge.log(t);
        }
    }

    public static int getJavaTotal() {
        return sJavaTotal.get();
    }

    public static int getJavaSuccess() {
        return sJavaSuccess.get();
    }

    public static int getJavaFailed() {
        return sJavaFailed.get();
    }

    public static List<String> getJavaFailedHooks() {
        return new ArrayList<>(sJavaFailedHooks);
    }

    /**
     * 输出最终汇总统计日志：
     * 总共多少 hook，几个 native hook，几个 java hook，各自有多少个成功，哪几个失败（如果有）。
     */
    public static void printSummaryReport(String processName) {
        if (!sSummaryPrinted.compareAndSet(false, true)) {
            return;
        }

        int jTotal = sJavaTotal.get();
        int jSuccess = sJavaSuccess.get();
        int jFailed = sJavaFailed.get();
        List<String> jFailedList = getJavaFailedHooks();

        int nTotal = 0;
        int nSuccess = 0;
        int nFailed = 0;
        String nFailedStr = "";

        if (NativeBypass.isLibraryLoaded()) {
            try {
                nTotal = NativeBypass.getNativeHookTotal();
                nSuccess = NativeBypass.getNativeHookSuccess();
                nFailed = NativeBypass.getNativeHookFailed();
                nFailedStr = NativeBypass.getNativeFailedHooks();
            } catch (Throwable ignored) {}
        }

        int grandTotal = jTotal + nTotal;

        StringBuilder sb = new StringBuilder();
        sb.append("[").append(TAG).append("] ");
        if (processName != null && !processName.isEmpty()) {
            sb.append("[").append(processName).append("] ");
        }
        sb.append("Hook 汇总统计: 总计 ").append(grandTotal).append(" 个 Hook ")
          .append("(Java: ").append(jTotal).append(", Native: ").append(nTotal).append(")")
          .append(" | Java 成功: ").append(jSuccess).append(", 失败: ").append(jFailed);

        if (jFailed > 0 && !jFailedList.isEmpty()) {
            sb.append(" 失败列表: ").append(jFailedList.toString());
        }

        sb.append(" | Native 成功: ").append(nSuccess).append(", 失败: ").append(nFailed);
        if (nFailed > 0 && nFailedStr != null && !nFailedStr.isEmpty()) {
            sb.append(" 失败列表: [").append(nFailedStr).append("]");
        }

        String summary = sb.toString();
        XposedBridge.log(summary);
        if (jFailed > 0 || nFailed > 0) {
            android.util.Log.e(TAG, summary);
        } else {
            android.util.Log.i(TAG, summary);
        }
    }
}
