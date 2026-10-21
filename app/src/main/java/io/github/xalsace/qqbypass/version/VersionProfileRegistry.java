package io.github.xalsace.qqbypass.version;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry mapping host versions to their corresponding IVersionProfile.
 */
public class VersionProfileRegistry {

    private static final Map<Integer, IVersionProfile> sCodeProfiles = new ConcurrentHashMap<>();
    private static final Map<String, IVersionProfile> sNameProfiles = new ConcurrentHashMap<>();

    static {
        register(new QQ9375Profile());
        register(new QQ9370Profile());
        register(new QQ9350Profile());
    }

    public static void register(IVersionProfile profile) {
        if (profile != null) {
            sCodeProfiles.put(profile.getVersionCode(), profile);
            sNameProfiles.put(profile.getVersionName(), profile);
        }
    }

    public static IVersionProfile resolve(HostVersion version, String apkPath) {
        if (version != null) {
            // 1. Exact match by versionCode
            IVersionProfile byCode = sCodeProfiles.get(version.getVersionCode());
            if (byCode != null) {
                return byCode;
            }

            // 2. Exact or prefix match by versionName
            String name = version.getVersionName();
            if (name != null) {
                IVersionProfile byName = sNameProfiles.get(name);
                if (byName != null) {
                    return byName;
                }
                for (Map.Entry<String, IVersionProfile> entry : sNameProfiles.entrySet()) {
                    if (name.startsWith(entry.getKey())) {
                        return entry.getValue();
                    }
                }
            }

            // 3. Range heuristic: if version is >= 9.3.75, use 9.3.75; if >= 9.3.70, use 9.3.70
            if (version.isAtLeast(9, 3, 75)) {
                return sNameProfiles.get(QQ9375Profile.VERSION_NAME);
            } else if (version.isAtLeast(9, 3, 70)) {
                return sNameProfiles.get(QQ9370Profile.VERSION_NAME);
            } else if (version.isAtLeast(9, 3, 50)) {
                return sNameProfiles.get(QQ9350Profile.VERSION_NAME);
            }
        }

        return new DefaultVersionProfile(version, apkPath);
    }
}
