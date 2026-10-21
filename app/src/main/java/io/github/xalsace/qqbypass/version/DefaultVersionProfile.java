package io.github.xalsace.qqbypass.version;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

/**
 * Fallback profile for unlisted or future QQ versions.
 * Attempts to dynamically calculate the host APK's genuine MD5,
 * or gracefully defaults to the latest known release baseline (9.3.75).
 */
public class DefaultVersionProfile extends BaseVersionProfile {

    public DefaultVersionProfile(HostVersion hostVersion, String apkPath) {
        super(
            hostVersion != null ? hostVersion.getVersionName() : "unknown",
            hostVersion != null ? hostVersion.getVersionCode() : 0,
            resolveDynamicMd5(apkPath),
            "a6b745bf24a2c277527716f6f36eb68d",
            "com.tencent.mobileqq.app.di",
            "com.tencent.ctsz.m",
            "com.tencent.mobileqq.turingfd.i"
        );
    }

    private static String resolveDynamicMd5(String apkPath) {
        if (apkPath != null) {
            File f = new File(apkPath);
            if (f.exists() && f.canRead()) {
                try (FileInputStream fis = new FileInputStream(f)) {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] buffer = new byte[65536];
                    int len;
                    while ((len = fis.read(buffer)) > 0) {
                        md.update(buffer, 0, len);
                    }
                    byte[] digest = md.digest();
                    StringBuilder sb = new StringBuilder();
                    for (byte b : digest) {
                        sb.append(String.format("%02x", b & 0xff));
                    }
                    return sb.toString();
                } catch (Throwable ignored) {}
            }
        }
        // Fallback to latest stable release
        return QQ9375Profile.OFFICIAL_MD5;
    }
}
