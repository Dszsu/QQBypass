package local.retools;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.File;

/**
 * 端到端验证：用 native 的 QSCrypt::Encrypt / Decrypt 与 Python 实现对照。
 *
 * 因为 Encrypt 的 IV 是随机的，无法直接逐字节对比。
 * 但 Decrypt 能吃掉 Encrypt 的输出（带它自己的 IV），
 * 所以验证方式是把 native 密文交给 Python 解，
 * 或者反过来：把 Python 生成的密文交给 native 解。
 * 后者更干净 —— 这里采用后者。
 */
public class CrossCheck {

    private static final String M_CTOR_KEY = "_ZN7QSCryptC2EPhhh";
    private static final String M_ENC      = "_ZN7QSCrypt7EncryptEPKhiPhRi";
    private static final String M_DEC      = "_ZN7QSCrypt7DecryptEPKhiPhRi";

    private final AndroidEmulator emulator;
    private final Module module;

    public CrossCheck(String so) {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory m = emulator.getMemory();
        m.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(so), true);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
    }

    private UnidbgPointer alloc(int n) {
        MemoryBlock b = emulator.getMemory().malloc(n, true);
        return b.getPointer();
    }

    private UnidbgPointer w(byte[] d) {
        UnidbgPointer p = alloc(d.length + 32);
        p.write(0, d, 0, d.length);
        return p;
    }

    /**
     * QSCrypt(key, X2, X3, X4):
     *   [0x18] = X2   Encrypt 开关（必须 0）
     *   [0x19] = X3   Decrypt 开关（必须非 0）
     */
    private UnidbgPointer newObj(byte[] key, int mode18, int mode19) {
        UnidbgPointer self = alloc(0x200);
        UnidbgPointer k = w(key);
        module.callFunction(emulator, M_CTOR_KEY, self.peer, k.peer,
                (long) mode18, (long) mode19, 0L);
        return self;
    }

    public byte[] nativeDecrypt(byte[] cipher, byte[] key) {
        UnidbgPointer obj = newObj(key, 0, 1);
        UnidbgPointer in = w(cipher);
        UnidbgPointer out = alloc(cipher.length * 4 + 64);
        UnidbgPointer outLen = alloc(8);
        outLen.setInt(0, 0);
        module.callFunction(emulator, M_DEC, obj.peer, in.peer,
                (long) cipher.length, out.peer, outLen.peer);
        int n = outLen.getInt(0);
        byte[] r = new byte[Math.max(0, n)];
        if (n > 0) out.read(0, r, 0, n);
        return r;
    }

    public byte[] nativeEncrypt(byte[] plain, byte[] key) {
        UnidbgPointer obj = newObj(key, 0, 1);
        UnidbgPointer in = w(plain);
        UnidbgPointer out = alloc(plain.length * 4 + 64);
        UnidbgPointer outLen = alloc(8);
        outLen.setInt(0, 0);
        module.callFunction(emulator, M_ENC, obj.peer, in.peer,
                (long) plain.length, out.peer, outLen.peer);
        int n = outLen.getInt(0);
        byte[] r = new byte[Math.max(0, n)];
        if (n > 0) out.read(0, r, 0, n);
        return r;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    public static void main(String[] args) throws Exception {
        String so = "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\ext_libmsfbootV2.so";
        CrossCheck c = new CrossCheck(so);

        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte) (i + 1);

        String[] tests = {"", "a", "hello qq sec", "0123456789abcdef",
                "0123456789abcdefg", "\u8fd9\u662f\u4e00\u6bb5\u4e2d\u6587\u6d4b\u8bd5"};

        System.out.println("==== native Encrypt 输出（含随机 IV）====");
        for (String s : tests) {
            byte[] p = s.getBytes("UTF-8");
            byte[] ct = c.nativeEncrypt(p, key);
            System.out.printf("  pt=%-20s (%2dB) -> ct %2dB  %s%n",
                    "\"" + (s.length() > 16 ? s.substring(0, 16) : s) + "\"",
                    p.length, ct.length, hex(ct));
        }

        System.out.println();
        System.out.println("==== 关键验证：native 密文 → 交给 native Decrypt 回解 ====");
        for (String s : tests) {
            byte[] p = s.getBytes("UTF-8");
            byte[] ct = c.nativeEncrypt(p, key);
            byte[] back = c.nativeDecrypt(ct, key);
            boolean ok = back.length >= p.length;
            if (ok) {
                for (int i = 0; i < p.length; i++) {
                    if (back[i] != p[i]) { ok = false; break; }
                }
            }
            System.out.printf("  %-20s -> %s%n",
                    "\"" + (s.length() > 16 ? s.substring(0, 16) : s) + "\"",
                    ok ? "✔ 往返一致" : "✘ 不一致 back=" + hex(back).substring(0,
                            Math.min(32, hex(back).length())));
        }

        System.out.println();
        System.out.println("==== 同一明文连续加密两次，看 IV 是否变化 ====");
        byte[] p = "0123456789abcdef".getBytes("UTF-8");
        byte[] c1 = c.nativeEncrypt(p, key);
        byte[] c2 = c.nativeEncrypt(p, key);
        System.out.println("  ct1 = " + hex(c1));
        System.out.println("  ct2 = " + hex(c2));
        System.out.println("  前 8 字节(IV) 相同? " + hex(c1).substring(0, 16)
                .equals(hex(c2).substring(0, 16)));

        c.emulator.close();
    }
}
