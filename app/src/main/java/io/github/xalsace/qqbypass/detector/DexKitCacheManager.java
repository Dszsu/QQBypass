package io.github.xalsace.qqbypass.detector;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.config.CompileHookConfig;
import io.github.xalsace.qqbypass.config.HookConfig;

/**
 * Manages persistent disk caching for DexKit detection results.
 * When the target application and module versions remain unchanged,
 * cached method signatures are loaded directly from disk in < 5ms,
 * completely avoiding DexKit initialization and multi-DEX parsing.
 */
public class DexKitCacheManager {
    private static final String TAG = "DexKitCache";
    private static final String CACHE_FILE_NAME = ".msf_nt_token_meta.dat";
    private static final String LEGACY_CACHE_FILE_NAME = "qqbypass_dexkit_cache.json";

    public static File getCacheFile(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || lpparam.appInfo == null) return null;
        String dataDir = lpparam.appInfo.dataDir;
        if (dataDir == null) return null;

        // Clean up legacy cache files if present
        try {
            File old1 = new File(new File(dataDir, "files"), LEGACY_CACHE_FILE_NAME);
            if (old1.exists()) old1.delete();
            File old2 = new File(new File(dataDir, "cache"), LEGACY_CACHE_FILE_NAME);
            if (old2.exists()) old2.delete();
        } catch (Throwable ignored) {}

        File filesDir = new File(dataDir, "files");
        if (!filesDir.exists()) {
            filesDir.mkdirs();
        }
        if (filesDir.exists() && filesDir.canWrite()) {
            return new File(filesDir, CACHE_FILE_NAME);
        }

        File cacheDir = new File(dataDir, "cache");
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }
        return new File(cacheDir, CACHE_FILE_NAME);
    }

    public static Map<String, List<DexMethodData>> loadCache(XC_LoadPackage.LoadPackageParam lpparam) {
        return loadFromDisk(lpparam);
    }

    private static Map<String, List<DexMethodData>> loadFromDisk(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            File cacheFile = getCacheFile(lpparam);
            if (cacheFile == null || !cacheFile.exists() || cacheFile.length() == 0) {
                logInfo("[" + TAG + "] No disk cache found at: " + (cacheFile != null ? cacheFile.getAbsolutePath() : "null"));
                return null;
            }

            String apkPath = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;
            if (apkPath == null) return null;
            File apkFile = new File(apkPath);
            if (!apkFile.exists()) return null;

            long currentApkModified = apkFile.lastModified();
            long currentApkLength = apkFile.length();

            // Read cache content
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(cacheFile), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());

            // 1. Validate schema version (compatible across module revisions)
            int schemaVersion = root.optInt("schemaVersion", 0);
            if (schemaVersion != HookConfig.CACHE_SCHEMA_VERSION) {
                logInfo("[" + TAG + "] Cache schema version mismatch: cached=" + schemaVersion + ", current=" + HookConfig.CACHE_SCHEMA_VERSION);
                return null;
            }

            // 2. Validate target APK identity (timestamp + size)
            long cachedApkModified = root.optLong("apkLastModified", 0L);
            long cachedApkLength = root.optLong("apkLength", 0L);

            if (cachedApkModified != 0 && currentApkModified != 0 && (cachedApkModified != currentApkModified || cachedApkLength != currentApkLength)) {
                logInfo("[" + TAG + "] Cache invalidated: Target APK updated (time: " + cachedApkModified + " -> " + currentApkModified + ", size: " + cachedApkLength + " -> " + currentApkLength + ")");
                return null;
            }

            // 3. Parse methods map
            JSONObject methodsObj = root.optJSONObject("methods");
            if (methodsObj == null) {
                logInfo("[" + TAG + "] Cache invalid: missing 'methods' object");
                return null;
            }

            Map<String, List<DexMethodData>> resultMap = parseMethodsMap(methodsObj);
            logInfo("[" + TAG + "] Disk Cache HIT! Loaded " + resultMap.size() + " categories from disk cache: " + cacheFile.getAbsolutePath());
            return resultMap;

        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] Error reading disk cache: " + t.getMessage());
            return null;
        }
    }

    private static Map<String, List<DexMethodData>> parseMethodsMap(JSONObject methodsObj) {
        Map<String, List<DexMethodData>> resultMap = new HashMap<>();
        Iterator<String> keys = methodsObj.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            JSONArray arr = methodsObj.optJSONArray(key);
            List<DexMethodData> list = new ArrayList<>();
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject mObj = arr.optJSONObject(i);
                    if (mObj != null) {
                        try {
                            list.add(DexMethodData.fromJson(mObj));
                        } catch (Exception ignored) { }
                    }
                }
            }
            resultMap.put(key, list);
        }
        return resultMap;
    }

    public static boolean saveCache(XC_LoadPackage.LoadPackageParam lpparam, Map<String, List<DexMethodData>> methodMap) {
        if (methodMap == null || methodMap.isEmpty()) return false;
        try {
            File cacheFile = getCacheFile(lpparam);
            if (cacheFile == null) return false;

            String apkPath = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;
            if (apkPath == null) return false;
            File apkFile = new File(apkPath);
            if (!apkFile.exists()) return false;

            JSONObject root = new JSONObject();
            root.put("schemaVersion", HookConfig.CACHE_SCHEMA_VERSION);
            root.put("moduleVersionCode", HookConfig.MODULE_VERSION_CODE);
            root.put("moduleVersionName", HookConfig.MODULE_VERSION_NAME);
            root.put("appPackageName", lpparam.packageName);
            root.put("apkPath", apkPath);
            root.put("apkLastModified", apkFile.lastModified());
            root.put("apkLength", apkFile.length());
            root.put("createdAt", System.currentTimeMillis());

            JSONObject methodsObj = new JSONObject();
            int totalCount = 0;
            for (Map.Entry<String, List<DexMethodData>> entry : methodMap.entrySet()) {
                JSONArray arr = new JSONArray();
                for (DexMethodData md : entry.getValue()) {
                    arr.put(md.toJson());
                    totalCount++;
                }
                methodsObj.put(entry.getKey(), arr);
            }
            root.put("methods", methodsObj);

            // Atomic write: write to .tmp file then rename
            File tempFile = new File(cacheFile.getParentFile(), cacheFile.getName() + ".tmp");
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(root.toString(2).getBytes(StandardCharsets.UTF_8));
                fos.flush();
            }

            if (tempFile.renameTo(cacheFile)) {
                cacheFile.setReadable(true, false);
                logInfo("[" + TAG + "] Saved " + totalCount + " methods to disk cache successfully: " + cacheFile.getAbsolutePath());
                return true;
            } else {
                // If rename fails across filesystems or Android security profiles, fallback to direct write
                try (FileOutputStream fos = new FileOutputStream(cacheFile)) {
                    fos.write(root.toString(2).getBytes(StandardCharsets.UTF_8));
                    fos.flush();
                }
                tempFile.delete();
                cacheFile.setReadable(true, false);
                logInfo("[" + TAG + "] Saved " + totalCount + " methods to disk cache (direct write): " + cacheFile.getAbsolutePath());
                return true;
            }
        } catch (Throwable t) {
            XposedBridge.log("[" + TAG + "] Failed to save disk cache: " + t.getMessage());
            return false;
        }
    }

    private static void logInfo(String message) {
        if (CompileHookConfig.ENABLE_VERBOSE_LSPOSED_LOG) {
            XposedBridge.log(message);
        }
    }
}
