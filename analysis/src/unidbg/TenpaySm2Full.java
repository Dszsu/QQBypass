package local.retools;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.File;

/**
 * SM2 全链路验证：密钥对 → 签名 → 验签 → 加密 → 解密 → ECDH
 *
 * 关键点：
 *   1. 每次调用前把 [base+0xbecc8] 置 0（前置标志）
 *   2. sm2GenKeyPair 返回 byte[][]{pri(32), pub(64 或 65)}
 */
public class TenpaySm2Full {

    private final AndroidEmulator emulator;
    private final Module module;
    private final VM vm;
    private final DvmClass clazz;
    private final long fixAddr;

    public TenpaySm2Full(String so) {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory m = emulator.getMemory();
        m.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        clazz = vm.resolveClass("com/tenpay/qqsc/FitScUtil");
        DalvikModule dm = vm.loadLibrary(new File(so), true);
        module = dm.getModule();
        try { dm.callJNI_OnLoad(emulator); } catch (Throwable ignored) { }
        fixAddr = module.base + 0xbecc8;
    }

    void fix() {
        UnidbgPointer.pointer(emulator, fixAddr).setInt(0, 0);
    }

    private DvmObject<?> obj(String n, Object... a) {
        fix();
        return clazz.callStaticJniMethodObject(emulator, n, a);
    }

    private byte[] bytes(String n, Object... a) {
        DvmObject<?> r = obj(n, a);
        return (r instanceof ByteArray) ? ((ByteArray) r).getValue() : null;
    }

    private int i(String n, Object... a) {
        return clazz.callStaticJniMethodInt(emulator, n, a);
    }

    /** 提取 Object[] 里的每个元素为 byte[] */
    private byte[][] keyPair() {
        DvmObject<?> r = obj("sm2GenKeyPair");
        if (r == null) return null;
        Object v = r.getValue();
        if (!(v instanceof Object[])) return null;
        Object[] arr = (Object[]) v;
        byte[][] out = new byte[arr.length][];
        for (int k = 0; k < arr.length; k++) {
            Object o = arr[k];
            if (o instanceof ByteArray) {
                out[k] = ((ByteArray) o).getValue();
            } else if (o instanceof DvmObject) {
                Object iv = ((DvmObject<?>) o).getValue();
                if (iv instanceof byte[]) out[k] = (byte[]) iv;
            }
        }
        return out;
    }

    static String hex(byte[] b) {
        if (b == null) return "null";
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    public static void main(String[] a) throws Exception {
        String so = "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\ext_libtsmqqsc.so";
        TenpaySm2Full c = new TenpaySm2Full(so);

        System.out.println("=== 1. SM2 密钥对 ===");
        byte[][] kp = c.keyPair();
        if (kp == null || kp.length < 2 || kp[0] == null || kp[1] == null) {
            System.out.println("  失败");
            c.emulator.close();
            return;
        }
        byte[] pri = kp[0], pub = kp[1];
        System.out.println("  私钥 (" + pri.length + "B) = " + hex(pri));
        System.out.println("  公钥 (" + pub.length + "B) = " + hex(pub));
        System.out.println("  lastError = " + c.i("getLastError"));

        byte[] data = "hello tenpay sm2".getBytes();

        System.out.println();
        System.out.println("=== 2. SM2 签名 ===");
        byte[] sig = c.bytes("sm2Sign", new ByteArray(c.vm, pri),
                new ByteArray(c.vm, data));
        System.out.println("  签名 (" + (sig == null ? 0 : sig.length) + "B) = " + hex(sig));
        System.out.println("  lastError = " + c.i("getLastError"));

        if (sig != null) {
            System.out.println();
            System.out.println("=== 3. SM2 验签 ===");
            int ok = c.i("sm2Verify",
                    new ByteArray(c.vm, pub),
                    new ByteArray(c.vm, data),
                    new ByteArray(c.vm, sig));
            System.out.println("  原始数据 verify = " + ok
                    + (ok != 0 ? "  ✔" : "  ✘"));

            byte[] bad = data.clone();
            bad[0] ^= 0xFF;
            int ok2 = c.i("sm2Verify",
                    new ByteArray(c.vm, pub),
                    new ByteArray(c.vm, bad),
                    new ByteArray(c.vm, sig));
            System.out.println("  篡改数据 verify = " + ok2
                    + (ok2 == 0 ? "  ✔（正确拒绝）" : "  ✘（应当拒绝）"));
        }

        System.out.println();
        System.out.println("=== 4. SM2 加密 / 解密 ===");
        byte[] ct = c.bytes("sm2Encrypt", new ByteArray(c.vm, pub),
                new ByteArray(c.vm, data));
        System.out.println("  密文 (" + (ct == null ? 0 : ct.length) + "B) = " + hex(ct));
        System.out.println("  lastError = " + c.i("getLastError"));
        if (ct != null) {
            byte[] pt = c.bytes("sm2Decrypt", new ByteArray(c.vm, pri),
                    new ByteArray(c.vm, ct));
            String s = pt == null ? "null" : new String(pt, "UTF-8");
            System.out.println("  解密 = " + s);
            System.out.println("  往返 " + (pt != null
                    && java.util.Arrays.equals(pt, data) ? "✔" : "✘"));
        }

        System.out.println();
        System.out.println("=== 5. ECDH 共享密钥 ===");
        byte[][] kp2 = c.keyPair();
        if (kp2 != null && kp2[1] != null) {
            byte[] k1 = c.bytes("sm2CalcSharedKey",
                    new ByteArray(c.vm, pri), new ByteArray(c.vm, kp2[1]));
            byte[] k2 = c.bytes("sm2CalcSharedKey",
                    new ByteArray(c.vm, kp2[0]), new ByteArray(c.vm, pub));
            System.out.println("  A(pri)+B(pub) = " + hex(k1));
            System.out.println("  B(pri)+A(pub) = " + hex(k2));
            System.out.println("  一致 " + (k1 != null && k2 != null
                    && java.util.Arrays.equals(k1, k2) ? "✔" : "✘"));
            System.out.println("  lastError = " + c.i("getLastError"));
        }

        c.emulator.close();
    }
}
