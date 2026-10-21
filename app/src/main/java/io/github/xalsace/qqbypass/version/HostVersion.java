package io.github.xalsace.qqbypass.version;

import java.io.Serializable;

/**
 * Represents the detected host QQ version.
 */
public class HostVersion implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int versionCode;
    private final String versionName;
    private final int major;
    private final int minor;
    private final int patch;
    private final int build;

    public HostVersion(int versionCode, String versionName, int major, int minor, int patch, int build) {
        this.versionCode = versionCode;
        this.versionName = versionName != null ? versionName.trim() : "";
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.build = build;
    }

    public static HostVersion parse(int versionCode, String versionName) {
        int maj = 0, min = 0, pat = 0, bld = 0;
        if (versionName != null && !versionName.isEmpty()) {
            try {
                // Remove non-numeric prefixes/suffixes if any
                String clean = versionName.replaceAll("[^0-9.]", " ");
                String[] parts = clean.trim().split("\\.");
                if (parts.length > 0 && !parts[0].isEmpty()) maj = Integer.parseInt(parts[0]);
                if (parts.length > 1 && !parts[1].isEmpty()) min = Integer.parseInt(parts[1]);
                if (parts.length > 2 && !parts[2].isEmpty()) pat = Integer.parseInt(parts[2]);
                if (parts.length > 3 && !parts[3].isEmpty()) bld = Integer.parseInt(parts[3]);
            } catch (Throwable ignored) {}
        }
        return new HostVersion(versionCode, versionName, maj, min, pat, bld);
    }

    public int getVersionCode() {
        return versionCode;
    }

    public String getVersionName() {
        return versionName;
    }

    public int getMajor() {
        return major;
    }

    public int getMinor() {
        return minor;
    }

    public int getPatch() {
        return patch;
    }

    public int getBuild() {
        return build;
    }

    public boolean isVersion(String prefix) {
        return versionName != null && versionName.startsWith(prefix);
    }

    public boolean isAtLeast(int targetMajor, int targetMinor, int targetPatch) {
        if (this.major > targetMajor) return true;
        if (this.major < targetMajor) return false;
        if (this.minor > targetMinor) return true;
        if (this.minor < targetMinor) return false;
        return this.patch >= targetPatch;
    }

    @Override
    public String toString() {
        return versionName + " (" + versionCode + ")";
    }
}
