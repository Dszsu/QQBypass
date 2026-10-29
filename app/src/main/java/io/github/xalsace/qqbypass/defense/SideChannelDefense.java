package io.github.xalsace.qqbypass.defense;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.net.TrafficStats;
import android.net.wifi.WifiInfo;
import android.os.BatteryManager;
import android.os.SystemClock;
import android.view.MotionEvent;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Side-Channel Defense & Dynamic Physics Simulation:
 *
 * Replaces static constants, empty responses, and blind interceptions with
 * continuous, realistic, physics-consistent randomized normal values.
 *
 * Mitigates client-side side-channel attacks and statistical anomaly models:
 * 1. Ambient Light & Reflective Liveness Sensor Jitter (Brownian/sinusoidal drift)
 * 2. Accelerometer Handheld Micro-Tremors (Gaussian noise around gravity vector)
 * 3. Gyroscope Micro-Angular Drift (zero-mean tremor)
 * 4. Battery State & Power Supply Side-Channel (BatteryManager & broadcast synthesis)
 * 5. Timing & Computation Benchmark Side-Channel (QSec.bench11hex & bench22hex)
 * 6. Touch Pressure & Fingertip Contact Area Side-Channel (MotionEvent pressure/size)
 * 7. RF / WiFi Signal RSSI & Traffic Jitter (WifiInfo & TrafficStats)
 */
public class SideChannelDefense {

    // ==========================================================
    // 1. Dynamic Physics-Consistent Environmental Data
    // ==========================================================

    /**
     * Realistic indoor ambient lux with continuous multi-frequency sinusoidal drift
     * and Gaussian micro-fluctuations (normal range: 285.0f - 355.0f lux).
     * Eliminates detection of static constants like 320.0f or uninitialized -10000.
     */
    public static float getDynamicLux() {
        long now = SystemClock.elapsedRealtime();
        double drift = Math.sin(now / 14000.0) * 16.0 + Math.cos(now / 3800.0) * 7.5;
        double noise = (ThreadLocalRandom.current().nextDouble() - 0.5) * 4.0;
        float lux = (float) (320.0 + drift + noise);
        return Math.max(150.0f, Math.min(550.0f, lux));
    }

    /**
     * Handheld micro-tremors for 3-axis accelerometer (m/s²).
     * Total magnitude: |g| ≈ 9.80665 m/s² with natural ±0.035 m/s² tremor.
     */
    public static float[] getDynamicAccelerometer() {
        long now = SystemClock.elapsedRealtime();
        double t = now / 1000.0;
        float jx = (float) (Math.sin(t * 8.2) * 0.025 + (ThreadLocalRandom.current().nextDouble() - 0.5) * 0.03);
        float jy = (float) (Math.cos(t * 7.5) * 0.035 + (ThreadLocalRandom.current().nextDouble() - 0.5) * 0.04);
        float jz = (float) (Math.sin(t * 9.1) * 0.025 + (ThreadLocalRandom.current().nextDouble() - 0.5) * 0.03);
        return new float[]{ 0.22f + jx, 9.78f + jy, 0.45f + jz };
    }

    public static String getDynamicAccelerometerString() {
        float[] v = getDynamicAccelerometer();
        return String.format(Locale.US, "{x=%.3f, y=%.3f, z=%.3f}", v[0], v[1], v[2]);
    }

    /**
     * Handheld micro-angular velocity for 3-axis gyroscope (rad/s).
     * Zero-mean physiological tremor: ±(0.001 - 0.005) rad/s.
     */
    public static float[] getDynamicGyroscope() {
        float gx = (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.005);
        float gy = (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.005);
        float gz = (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.004);
        return new float[]{ gx, gy, gz };
    }

    public static String getDynamicGyroscopeString() {
        float[] v = getDynamicGyroscope();
        return String.format(Locale.US, "{x=%.3f, y=%.3f, z=%.3f}", v[0], v[1], v[2]);
    }

    /**
     * Geomagnetic field vector (~42.5 μT).
     */
    public static float[] getDynamicMagnetometer() {
        float mx = 18.2f + (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.4);
        float my = -8.5f + (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.3);
        float mz = 37.8f + (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.5);
        return new float[]{ mx, my, mz };
    }

    // ==========================================================
    // 2. Dynamic Battery & Power Supply State
    // ==========================================================

    /**
     * Realistic battery percentage draining slowly over time.
     */
    public static int getBatteryLevel() {
        long now = SystemClock.elapsedRealtime();
        int drop = (int) ((now / 60000L) / 16L); // 1% per 16 minutes
        int level = 78 - (drop % 35);
        return Math.max(18, Math.min(100, level));
    }

    /**
     * Battery temperature in tenths of a degree Celsius (e.g. 308 = 30.8°C).
     */
    public static int getBatteryTemperature() {
        long now = SystemClock.elapsedRealtime();
        int osc = (int) (Math.sin(now / 25000.0) * 8);
        return 308 + osc + ThreadLocalRandom.current().nextInt(3);
    }

    /**
     * Battery voltage in mV (e.g. 4020 mV).
     */
    public static int getBatteryVoltage() {
        int lvl = getBatteryLevel();
        return 3870 + (lvl * 3) + ThreadLocalRandom.current().nextInt(12);
    }

    /**
     * Battery discharging current in microamps (e.g. -380000 uA).
     */
    public static int getBatteryCurrentNow() {
        return -360000 - ThreadLocalRandom.current().nextInt(80000);
    }

    // ==========================================================
    // 3. Timing & Latency Benchmark Scoring
    // ==========================================================

    /**
     * Realistic benchmark hex string for QSec.bench11hex and bench22hex.
     * Mimics ARMv8-A CPU cycle timing (~8500 - 11000 cycles).
     */
    public static String getBenchmarkHex(long timestamp, int mode) {
        long base = (mode == 11) ? 0x21a0L : 0x24e0L;
        long jitter = (timestamp & 0x1ffL) ^ 0xa5L;
        long score = base + jitter;
        return String.format(Locale.US, "%016x", score);
    }

    // ==========================================================
    // 4. Touch Pressure & Area Jitter
    // ==========================================================

    public static float getDynamicPressure() {
        return 0.65f + (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.16);
    }

    public static float getDynamicTouchSize() {
        return 0.18f + (float) ((ThreadLocalRandom.current().nextDouble() - 0.5) * 0.05);
    }

    // ==========================================================
    // 5. Connectivity & Bandwidth State
    // ==========================================================

    public static int getDynamicRssi() {
        long now = SystemClock.elapsedRealtime();
        int drift = (int) (Math.sin(now / 9000.0) * 4);
        return -58 + drift + ThreadLocalRandom.current().nextInt(3);
    }

    public static long getDynamicTotalRxBytes() {
        long now = SystemClock.elapsedRealtime();
        return 52428800L + (now * 85L);
    }

    public static long getDynamicTotalTxBytes() {
        long now = SystemClock.elapsedRealtime();
        return 18874368L + (now * 25L);
    }

    // ==========================================================
    // 6. Hook Installation & Integration
    // ==========================================================

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        // Strictly guard against spoofing side-channel data on real hardware.
        // Faking link speed (866 Mbps), RSSI, battery, or motion sensors on a genuine device
        // creates immediate statistical discrepancies with Beacon / MSF telemetry (e.g. cellular data).
        if (!HookConfig.ENABLE_DEVICE_SPOOF) {
            return;
        }

        // 1. Hook BatteryManager query via Intent.ACTION_BATTERY_CHANGED
        hookBatteryReceiver();

        // 2. Hook BatteryManager.getIntProperty
        hookBatteryProperty();

        // 3. QSec bench11hex / bench22hex are native cryptographic functions in libfekit.so
        // and MUST NOT be intercepted to avoid corrupting session token HMAC signatures!

        // 4. Hook MotionEvent touch pressure & size
        hookMotionEvent();

        // 5. Hook WifiInfo RSSI & link speed
        hookWifiInfo();

        // 6. Hook TrafficStats bytes counters
        hookTrafficStats();

        // 7. QSec physical sensor polling:
        // Do NOT hook com.tencent.qqprotect.qsec.b/c/d methods!
        // Faking dynamic sensor strings and modifying ArtMethod entry points of QSec companion classes
        // causes server sign flag rejection (attr_key_security_sign_flag: 2) during sleep/wake transitions.
        // Let physical sensors run naturally.
    }

    private static void hookBatteryReceiver() {
        HookUtils.hookAllMethods("android.content.ContextWrapper", "registerReceiver", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args != null && param.args.length > 1 && param.args[1] instanceof IntentFilter) {
                    IntentFilter filter = (IntentFilter) param.args[1];
                    if (filter.hasAction(Intent.ACTION_BATTERY_CHANGED)) {
                        Intent intent = (Intent) param.getResult();
                        if (intent == null) {
                            intent = new Intent(Intent.ACTION_BATTERY_CHANGED);
                            param.setResult(intent);
                            sanitizeBatteryIntent(intent);
                        } else if (HookConfig.ENABLE_DEVICE_SPOOF) {
                            sanitizeBatteryIntent(intent);
                        } else {
                            // Real device mode: PRESERVE genuine battery info!
                            // Only provide fallback if intent is missing valid battery level
                            int curLevel = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                            if (curLevel <= 0) {
                                intent.putExtra(BatteryManager.EXTRA_LEVEL, getBatteryLevel());
                                intent.putExtra(BatteryManager.EXTRA_SCALE, 100);
                            }
                            int curTemp = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
                            if (curTemp <= 0) {
                                intent.putExtra(BatteryManager.EXTRA_TEMPERATURE, getBatteryTemperature());
                            }
                            int curVolt = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
                            if (curVolt <= 0) {
                                intent.putExtra(BatteryManager.EXTRA_VOLTAGE, getBatteryVoltage());
                            }
                        }
                    }
                }
            }
        });
    }

    public static void sanitizeBatteryIntent(Intent intent) {
        if (intent == null) return;
        intent.putExtra(BatteryManager.EXTRA_LEVEL, getBatteryLevel());
        intent.putExtra(BatteryManager.EXTRA_SCALE, 100);
        intent.putExtra(BatteryManager.EXTRA_TEMPERATURE, getBatteryTemperature());
        intent.putExtra(BatteryManager.EXTRA_VOLTAGE, getBatteryVoltage());
        intent.putExtra(BatteryManager.EXTRA_STATUS, BatteryManager.BATTERY_STATUS_DISCHARGING);
        intent.putExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_GOOD);
        intent.putExtra(BatteryManager.EXTRA_PLUGGED, 0);
        intent.putExtra(BatteryManager.EXTRA_PRESENT, true);
        intent.putExtra(BatteryManager.EXTRA_TECHNOLOGY, "Li-poly");
    }

    private static void hookBatteryProperty() {
        HookUtils.hookAllMethods("android.os.BatteryManager", "getIntProperty", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (HookConfig.ENABLE_DEVICE_SPOOF) {
                    if (param.args != null && param.args.length > 0 && param.args[0] instanceof Number) {
                        int prop = ((Number) param.args[0]).intValue();
                        switch (prop) {
                            case BatteryManager.BATTERY_PROPERTY_CAPACITY:
                                param.setResult(getBatteryLevel());
                                break;
                            case BatteryManager.BATTERY_PROPERTY_CURRENT_NOW:
                                param.setResult(getBatteryCurrentNow());
                                break;
                            case BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER:
                                param.setResult(getBatteryLevel() * 45000);
                                break;
                            case BatteryManager.BATTERY_PROPERTY_STATUS:
                                param.setResult(BatteryManager.BATTERY_STATUS_DISCHARGING);
                                break;
                        }
                    }
                } else {
                    // Real device mode: PRESERVE genuine battery hardware property!
                    // Only fallback if system returns invalid <= 0 (e.g. missing battery service in emulator/container)
                    Object res = param.getResult();
                    if (res instanceof Integer && ((Integer) res) <= 0) {
                        if (param.args != null && param.args.length > 0 && param.args[0] instanceof Number) {
                            int prop = ((Number) param.args[0]).intValue();
                            if (prop == BatteryManager.BATTERY_PROPERTY_CAPACITY) {
                                param.setResult(getBatteryLevel());
                            } else if (prop == BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) {
                                param.setResult(getBatteryCurrentNow());
                            }
                        }
                    }
                }
            }
        });
    }


    private static void hookMotionEvent() {
        HookUtils.hookAllMethods("android.view.MotionEvent", "getPressure", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object res = param.getResult();
                if (res instanceof Float) {
                    float p = (Float) res;
                    // If flat 1.0f or 0.0f (indicative of synthetic bot/adb event), inject natural touch pressure
                    if (p <= 0.01f || Math.abs(p - 1.0f) < 0.001f) {
                        param.setResult(getDynamicPressure());
                    }
                }
            }
        });

        HookUtils.hookAllMethods("android.view.MotionEvent", "getSize", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object res = param.getResult();
                if (res instanceof Float) {
                    float s = (Float) res;
                    if (s <= 0.01f || Math.abs(s - 1.0f) < 0.001f) {
                        param.setResult(getDynamicTouchSize());
                    }
                }
            }
        });
    }

    private static void hookWifiInfo() {
        HookUtils.hookAllMethods("android.net.wifi.WifiInfo", "getRssi", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                // If not connected to Wi-Fi, preserve Android's genuine disconnected RSSI (-127)
                if (param.thisObject instanceof android.net.wifi.WifiInfo) {
                    android.net.wifi.WifiInfo info = (android.net.wifi.WifiInfo) param.thisObject;
                    String ssid = info.getSSID();
                    if (ssid == null || ssid.isEmpty() || "<unknown ssid>".equals(ssid) || "0x".equals(ssid)) {
                        return;
                    }
                }
                Object res = param.getResult();
                if (res instanceof Integer) {
                    int r = (Integer) res;
                    // If connected to Wi-Fi but RSSI is 0 or invalid, supply realistic dynamic RSSI
                    if (r == 0 || r <= -127 || r > -10) {
                        param.setResult(getDynamicRssi());
                    }
                }
            }
        });

        HookUtils.hookAllMethods("android.net.wifi.WifiInfo", "getLinkSpeed", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                // If not connected to Wi-Fi, preserve Android's genuine disconnected sentinel (-1)
                if (param.thisObject instanceof android.net.wifi.WifiInfo) {
                    android.net.wifi.WifiInfo info = (android.net.wifi.WifiInfo) param.thisObject;
                    String ssid = info.getSSID();
                    if (ssid == null || ssid.isEmpty() || "<unknown ssid>".equals(ssid) || "0x".equals(ssid)) {
                        return;
                    }
                }
                Object res = param.getResult();
                if (res instanceof Integer && ((Integer) res) <= 0) {
                    param.setResult(866); // 866 Mbps standard 5GHz AC link speed when connected
                }
            }
        });
    }

    private static void hookTrafficStats() {
        HookUtils.hookAllMethods("android.net.TrafficStats", "getTotalRxBytes", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object res = param.getResult();
                if (res instanceof Long && ((Long) res) <= 0L) {
                    param.setResult(getDynamicTotalRxBytes());
                }
            }
        });

        HookUtils.hookAllMethods("android.net.TrafficStats", "getTotalTxBytes", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object res = param.getResult();
                if (res instanceof Long && ((Long) res) <= 0L) {
                    param.setResult(getDynamicTotalTxBytes());
                }
            }
        });
    }
}
