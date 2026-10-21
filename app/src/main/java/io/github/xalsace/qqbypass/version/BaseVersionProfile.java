package io.github.xalsace.qqbypass.version;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Base abstract profile implementing standard metadata operations.
 */
public abstract class BaseVersionProfile implements IVersionProfile {

    protected final String versionName;
    protected final int versionCode;
    protected final String officialApkMd5;
    protected final String officialSignatureHash;
    protected final String fallbackPushHandlerClass;
    protected final String fallbackRepackHelperClass;
    protected final String fallbackTuringBridgeClass;

    public BaseVersionProfile(String versionName,
                              int versionCode,
                              String officialApkMd5,
                              String officialSignatureHash,
                              String fallbackPushHandlerClass,
                              String fallbackRepackHelperClass,
                              String fallbackTuringBridgeClass) {
        this.versionName = versionName;
        this.versionCode = versionCode;
        this.officialApkMd5 = officialApkMd5 != null ? officialApkMd5.trim() : "";
        this.officialSignatureHash = officialSignatureHash != null ? officialSignatureHash.trim() : "a6b745bf24a2c277527716f6f36eb68d";
        this.fallbackPushHandlerClass = fallbackPushHandlerClass;
        this.fallbackRepackHelperClass = fallbackRepackHelperClass;
        this.fallbackTuringBridgeClass = fallbackTuringBridgeClass;
    }

    @Override
    public String getVersionName() {
        return versionName;
    }

    @Override
    public int getVersionCode() {
        return versionCode;
    }

    @Override
    public String getOfficialApkMd5Upper() {
        return officialApkMd5.toUpperCase(java.util.Locale.US);
    }

    @Override
    public String getOfficialApkMd5Lower() {
        return officialApkMd5.toLowerCase(java.util.Locale.US);
    }

    @Override
    public String getOfficialSignatureHash() {
        return officialSignatureHash.toLowerCase(java.util.Locale.US);
    }

    @Override
    public String getOfficialSignatureHashUpper() {
        return officialSignatureHash.toUpperCase(java.util.Locale.US);
    }

    @Override
    public String getFallbackPushHandlerClass() {
        return fallbackPushHandlerClass;
    }

    @Override
    public String getFallbackRepackHelperClass() {
        return fallbackRepackHelperClass;
    }

    @Override
    public String getFallbackTuringBridgeClass() {
        return fallbackTuringBridgeClass;
    }

    @Override
    public void applyVersionSpecificHooks(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {
        // Default empty implementation, overridden by subclasses if needed
    }
}
