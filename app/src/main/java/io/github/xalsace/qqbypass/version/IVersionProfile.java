package io.github.xalsace.qqbypass.version;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Interface defining version-specific metadata and hook logic that cannot
 * be resolved purely dynamically via DexKit (e.g. official APK MD5, signature hashes,
 * and static fallbacks for Android 15+ / cache misses).
 */
public interface IVersionProfile {

    /** Expected version name (e.g., "9.3.75") */
    String getVersionName();

    /** Expected version code (e.g., 16580) */
    int getVersionCode();

    /** Official APK MD5 in uppercase (e.g., "1EB75AC01BD16FE8A06672F4BAF1D10C") */
    String getOfficialApkMd5Upper();

    /** Official APK MD5 in lowercase (e.g., "1eb75ac01bd16fe8a06672f4baf1d10c") */
    String getOfficialApkMd5Lower();

    /** Official certificate signature hash (e.g., "a6b745bf24a2c277527716f6f36eb68d") */
    String getOfficialSignatureHash();

    /** Official certificate signature hash in uppercase (e.g., "A6B745BF24A2C277527716F6F36EB68D") */
    String getOfficialSignatureHashUpper();

    /** Fallback SafeCenter push handler class name when DexKit is unavailable */
    String getFallbackPushHandlerClass();

    /** Fallback Repack detection helper class name when DexKit is unavailable */
    String getFallbackRepackHelperClass();

    /** Fallback Turing bridge class name when DexKit is unavailable */
    String getFallbackTuringBridgeClass();

    /** Apply any custom hooks exclusive to this QQ version */
    void applyVersionSpecificHooks(XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl);
}
