package io.github.xalsace.qqbypass.version;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.XmlResourceParser;
import android.os.Build;

import java.io.File;
import java.lang.reflect.Method;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import io.github.xalsace.qqbypass.config.CompileHookConfig;

/**
 * Manages host version detection and coordinates with VersionProfileRegistry
 * to supply the active version-specific metadata.
 */
public class HostVersionManager {
    private static final String TAG = "HostVersionMgr";

    private static volatile HostVersion sHostVersion = null;
    private static volatile IVersionProfile sCurrentProfile = null;
    private static final Object sLock = new Object();

    public static HostVersion getHostVersion() {
        return sHostVersion;
    }

    public static IVersionProfile getCurrentProfile() {
        if (sCurrentProfile == null) {
            synchronized (sLock) {
                if (sCurrentProfile == null) {
                    sCurrentProfile = new QQ9375Profile();
                }
            }
        }
        return sCurrentProfile;
    }

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        if (sHostVersion != null) return;
        synchronized (sLock) {
            if (sHostVersion != null) return;

            int versionCode = 0;
            String versionName = null;
            String apkPath = lpparam.appInfo != null ? lpparam.appInfo.sourceDir : null;

            // Strategy 1: ActivityThread IPackageManager Binder query
            try {
                Class<?> atCls = Class.forName("android.app.ActivityThread");
                Object at = atCls.getMethod("currentActivityThread").invoke(null);
                if (at != null) {
                    Object ipm = atCls.getMethod("getPackageManager").invoke(at);
                    if (ipm != null) {
                        int userId = 0;
                        try {
                            userId = (int) Class.forName("android.os.UserHandle").getMethod("myUserId").invoke(null);
                        } catch (Throwable ignored) {}

                        PackageInfo pi = null;
                        try {
                            Method m = ipm.getClass().getMethod("getPackageInfo", String.class, long.class, int.class);
                            pi = (PackageInfo) m.invoke(ipm, lpparam.packageName, 0L, userId);
                        } catch (NoSuchMethodException ignored) {
                            try {
                                Method m = ipm.getClass().getMethod("getPackageInfo", String.class, int.class, int.class);
                                pi = (PackageInfo) m.invoke(ipm, lpparam.packageName, 0, userId);
                            } catch (Throwable ignored2) {}
                        }
                        if (pi != null) {
                            versionCode = (int) (Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : getLegacyVersionCode(pi));
                            versionName = pi.versionName;
                            logInfo("[" + TAG + "] Detected via IPackageManager: " + versionName + " (" + versionCode + ")");
                        }
                    }
                }
            } catch (Throwable t) {
                logInfo("[" + TAG + "] IPackageManager detection failed: " + t.getMessage());
            }

            // Strategy 2: Context PackageManager query if available
            if (versionCode == 0 || versionName == null) {
                try {
                    Context ctx = (Context) Class.forName("android.app.ActivityThread")
                        .getMethod("currentApplication").invoke(null);
                    if (ctx != null) {
                        PackageManager pm = ctx.getPackageManager();
                        PackageInfo pi = pm.getPackageInfo(lpparam.packageName, 0);
                        if (pi != null) {
                            versionCode = (int) (Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : getLegacyVersionCode(pi));
                            versionName = pi.versionName;
                            logInfo("[" + TAG + "] Detected via Context PackageManager: " + versionName + " (" + versionCode + ")");
                        }
                    }
                } catch (Throwable ignored) {}
            }

            // Strategy 3: Fast AssetManager AndroidManifest.xml parser from host APK
            if ((versionCode == 0 || versionName == null) && apkPath != null && new File(apkPath).exists()) {
                try {
                    AssetManager am = AssetManager.class.getDeclaredConstructor().newInstance();
                    Method addAssetPath = AssetManager.class.getMethod("addAssetPath", String.class);
                    addAssetPath.invoke(am, apkPath);
                    XmlResourceParser parser = am.openXmlResourceParser("AndroidManifest.xml");
                    int eventType = parser.getEventType();
                    while (eventType != XmlResourceParser.END_DOCUMENT) {
                        if (eventType == XmlResourceParser.START_TAG && "manifest".equals(parser.getName())) {
                            versionCode = parser.getAttributeIntValue("http://schemas.android.com/apk/res/android", "versionCode", 0);
                            versionName = parser.getAttributeValue("http://schemas.android.com/apk/res/android", "versionName");
                            break;
                        }
                        eventType = parser.next();
                    }
                    parser.close();
                    if (versionCode != 0 || versionName != null) {
                        logInfo("[" + TAG + "] Detected via AssetManager Manifest: " + versionName + " (" + versionCode + ")");
                    }
                } catch (Throwable t) {
                    logInfo("[" + TAG + "] AssetManager manifest detection failed: " + t.getMessage());
                }
            }

            // Strategy 4: Fallback baseline (9.3.75)
            if (versionCode == 0 && versionName == null) {
                versionCode = QQ9375Profile.VERSION_CODE;
                versionName = QQ9375Profile.VERSION_NAME;
                logInfo("[" + TAG + "] Using baseline fallback: " + versionName + " (" + versionCode + ")");
            }

            sHostVersion = HostVersion.parse(versionCode, versionName);
            sCurrentProfile = VersionProfileRegistry.resolve(sHostVersion, apkPath);
            logInfo("[" + TAG + "] Active Version Profile: " + sCurrentProfile.getClass().getSimpleName()
                + " for QQ " + sHostVersion.getVersionName() + " (VC: " + sHostVersion.getVersionCode()
                + ", Official MD5: " + sCurrentProfile.getOfficialApkMd5Upper() + ")");
        }
    }

    private static void logInfo(String message) {
        if (CompileHookConfig.ENABLE_VERBOSE_LSPOSED_LOG) {
            XposedBridge.log(message);
        }
    }

    @SuppressWarnings("deprecation")
    private static int getLegacyVersionCode(PackageInfo pi) {
        return pi.versionCode;
    }
}
