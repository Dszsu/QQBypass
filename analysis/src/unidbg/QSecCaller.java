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
import java.util.ArrayList;
import java.util.List;

/**
 * QQ libmsfbootV2.so QSCrypt 黑盒调用器 v2。
 *
 * v1 的两个 bug（已由 ARM64 trace 定位）：
 *   1. FindEncryptSize 是成员函数 —— 首参 X0 必须是 this，
 *      trace 显示它执行 ldrb w8, [x0, #0x18]，X0=0x1 时必然崩。
 *   2. Decrypt 对同一对象复用无输出 —— 加解密共享对象内部状态，
 *      必须每次用新构造的实例。
 *
 * 另：QSCrypt 构造函数是 (uchar* key, uchar, uchar, uchar)，后三个是
 * 密钥长度 / 算法 / 标志位；v1 传了 0,0,0 等于没给密钥。
 */
public class QSecCaller {

    private static final String M_TEA_DEC  = "_ZN7QSCrypt13TeaDecryptECBEPKhS1_Ph";
    private static final String M_TEA_ENC  = "_ZN7QSCrypt13TeaEncryptECBEPKhS1_Ph";
    private static final String M_CTOR_KEY = "_ZN7QSCryptC2EPhhh";
    private static final String M_CTOR     = "_ZN7QSCryptC2Ev";
    private static final String M_ENC      = "_ZN7QSCrypt7EncryptEPKhiPhRi";
    private static final String M_DEC      = "_ZN7QSCrypt7DecryptEPKhiPhRi";
    private static final String M_SIZE     = "_ZN7QSCrypt15FindEncryptSizeEi";
    private static final String M_MD5      = "_ZN7QSCrypt7Md5HashEPhPKhi";
    private static final String M_SETKEY   = "_ZN7QSCrypt6SetKeyEPhi";
    private static final String M_SETARITH = "_ZN7QSCrypt8SetArithEhh";

    private final AndroidEmulator emulator;
    private final Module module;

    public QSecCaller(String soPath) {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(soPath), true);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
        System.out.printf("加载 OK  基址=0x%x  大小=0x%x%n", module.base, module.size);
    }

    // ---------- 内存 ----------
    private UnidbgPointer alloc(int size) {
        MemoryBlock b = emulator.getMemory().malloc(size, true);
        return b.getPointer();
    }

    private UnidbgPointer w(byte[] d) {
        UnidbgPointer p = alloc(d.length + 32);
        p.write(0, d, 0, d.length);
        return p;
    }

    private byte[] r(UnidbgPointer p, int len) {
        byte[] b = new byte[len];
        p.read(0, b, 0, len);
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    private static byte[] unhex(String s) {
        byte[] o = new byte[s.length() / 2];
        for (int i = 0; i < o.length; i++)
            o[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return o;
    }

    // ---------- QSCrypt 实例 ----------

    /** 无参构造 */
    private UnidbgPointer newObj() {
        UnidbgPointer self = alloc(0x200);
        module.callFunction(emulator, M_CTOR, self.peer);
        return self;
    }

    /**
     * 正确用法（由三轮 trace 反推）：
     *   ctor(key, X2, X3, X4)，X2 写入对象 [0x18]，是「加密模式开关」而非长度。
     *   [0x18] = 0 才启用加解密；=1 时 Encrypt 返回 0 字节；
     *   >1 时 FindEncryptSize 直接短路返回 0。
     * 密钥缓冲落在 [0x08..]，长度由 SetKey 的 X2 单独给。
     */
    private UnidbgPointer newObj(byte[] key, int mode) {
        UnidbgPointer self = alloc(0x200);
        UnidbgPointer k = w(key);
        module.callFunction(emulator, M_CTOR_KEY,
                self.peer, k.peer, (long) mode, 0L, 0L);
        return self;
    }

    /** 读对象偏移 0x18 的一个字节（FindEncryptSize 用它做分支） */
    private int objFlag(UnidbgPointer self) {
        return self.getByte(0x18) & 0xFF;
    }

    /** 转储对象前 0x30 字节，用于看密钥/状态布局 */
    private String dumpObj(UnidbgPointer self) {
        return hex(r(self, 0x30));
    }

    // ---------- 密码学操作 ----------

    public byte[] teaEncrypt(byte[] block8, byte[] key16) {
        UnidbgPointer in = w(block8), k = w(key16), out = alloc(32);
        module.callFunction(emulator, M_TEA_ENC, in.peer, k.peer, out.peer);
        return r(out, 8);
    }

    public byte[] teaDecrypt(byte[] block8, byte[] key16) {
        UnidbgPointer in = w(block8), k = w(key16), out = alloc(32);
        module.callFunction(emulator, M_TEA_DEC, in.peer, k.peer, out.peer);
        return r(out, 8);
    }

    public byte[] md5(byte[] data) {
        UnidbgPointer out = alloc(32), in = w(data);
        module.callFunction(emulator, M_MD5, out.peer, in.peer, (long) data.length);
        return r(out, 16);
    }

    /** 密文长度：成员函数，X0=this，X1=明文长度 */
    public int findEncryptSize(UnidbgPointer self, int plainLen) {
        try {
            Number n = module.callFunction(emulator, M_SIZE, self.peer, (long) plainLen);
            return n == null ? -1 : n.intValue();
        } catch (Throwable t) {
            return -2;
        }
    }

    /** 加密：X0=this X1=in X2=len X3=out X4=&outLen（outLen 纯输出，初值必须 0） */
    public byte[] encrypt(UnidbgPointer self, byte[] plain) {
        UnidbgPointer in = w(plain);
        UnidbgPointer out = alloc(plain.length * 8 + 256);
        UnidbgPointer outLen = alloc(8);
        outLen.setInt(0, 0);
        module.callFunction(emulator, M_ENC, self.peer, in.peer,
                (long) plain.length, out.peer, outLen.peer);
        int n = outLen.getInt(0);
        if (n < 0 || n > plain.length * 8 + 256) n = 0;
        return r(out, n);
    }

    public byte[] decrypt(UnidbgPointer self, byte[] cipher) {
        UnidbgPointer in = w(cipher);
        UnidbgPointer out = alloc(cipher.length * 8 + 256);
        UnidbgPointer outLen = alloc(8);
        outLen.setInt(0, 0);
        module.callFunction(emulator, M_DEC, self.peer, in.peer,
                (long) cipher.length, out.peer, outLen.peer);
        int n = outLen.getInt(0);
        if (n < 0 || n > cipher.length * 8 + 256) n = 0;
        return r(out, n);
    }

    public void close() {
        try { emulator.close(); } catch (Throwable ignored) {}
    }

    // ================= main =================

    public static void main(String[] args) throws Exception {
        String so = args.length > 0 ? args[0]
                : "E:\\安卓逆向工具\\QQ\\work\\ext_libmsfbootV2.so";
        QSecCaller c = new QSecCaller(so);

        // ---- 1. TEA 固定向量 ----
        System.out.println("\n==== 1. TEA-ECB ====");
        byte[] z8 = new byte[8], z16 = new byte[16];
        byte[] e = c.teaEncrypt(z8, z16);
        System.out.println("  E(0^8,0^16) = " + hex(e)
                + ("41ea3a0a94baa940".equals(hex(e)) ? "  ✔ 标准TEA" : "  ← 非标准"));
        System.out.println("  D(该值)     = " + hex(c.teaDecrypt(e, z16)));

        byte[] pt0 = unhex("0011223344556677");
        byte[] k0 = unhex("000102030405060708090a0b0c0d0e0f");
        byte[] c0 = c.teaEncrypt(pt0, k0);
        System.out.println("  pt  = " + hex(pt0));
        System.out.println("  ct  = " + hex(c0));
        System.out.println("  回解 = " + hex(c.teaDecrypt(c0, k0))
                + (hex(c.teaDecrypt(c0, k0)).equals(hex(pt0)) ? "  ✔" : "  ✘"));

        // ---- 2. MD5 ----
        System.out.println("\n==== 2. Md5Hash ====");
        System.out.println("  md5(\"abc\") = " + hex(c.md5("abc".getBytes("UTF-8")))
                + "  期望 900150983cd24fb0d6963f7d28e17f72");

        // ---- 3. 对象布局 ----
        System.out.println("\n==== 3. QSCrypt 对象布局 ====");
        byte[] kk = unhex("00112233445566778899aabbccddeeff");
        UnidbgPointer o0 = c.newObj();
        System.out.println("  无参构造   : " + c.dumpObj(o0));
        System.out.println("  [0x18]     = " + c.objFlag(o0));
        for (int mode = 0; mode <= 2; mode++) {
            UnidbgPointer o = c.newObj(kk, mode);
            System.out.printf("  key16,mode=%d: %s  [0x18]=%d%n",
                    mode, c.dumpObj(o), c.objFlag(o));
        }

        // ---- 4. FindEncryptSize（默认构造，[0x18] 应 <=1）----
        System.out.println("\n==== 4. FindEncryptSize ====");
        UnidbgPointer oS = c.newObj(kk, 0);
        System.out.println("  [0x18] = " + c.objFlag(oS));
        StringBuilder row = new StringBuilder();
        for (int n = 0; n <= 40; n++) {
            int s = c.findEncryptSize(oS, n);
            row.append(String.format("%d→%d ", n, s));
            if (n % 8 == 7) { System.out.println("  " + row); row.setLength(0); }
        }
        if (row.length() > 0) System.out.println("  " + row);

        // ---- 5. Encrypt / Decrypt（SetKey 后，每用新对象）----
        System.out.println("\n==== 5. Encrypt / Decrypt ====");
        String[] samples = {"", "a", "hello qq sec", "0123456789abcdef",
                "0123456789abcdefg", "这是一段中文测试"};
        for (String s : samples) {
            byte[] p = s.getBytes("UTF-8");
            UnidbgPointer oE = c.newObj(kk, 0);
            byte[] ct;
            try {
                ct = c.encrypt(oE, p);
            } catch (Throwable t) {
                System.out.printf("  %-20s ENC异常 %s%n", "[" + s + "]", t.getMessage());
                continue;
            }
            UnidbgPointer oD = c.newObj(kk, 0);
            byte[] back;
            try {
                back = c.decrypt(oD, ct);
            } catch (Throwable t) {
                System.out.printf("  %-20s DEC异常 %s%n", "[" + s + "]", t.getMessage());
                continue;
            }
            boolean ok = back.length >= p.length
                    && java.util.Arrays.equals(
                        java.util.Arrays.copyOf(back, p.length), p);
            System.out.printf("  %-20s %2dB -> ct %2dB : %s%n",
                    "[" + (s.length() > 16 ? s.substring(0, 16) : s) + "]",
                    p.length, ct.length, hex(ct));
            System.out.printf("  %-20s 回解 %2dB : %s  %s%n", "",
                    back.length,
                    hex(java.util.Arrays.copyOf(back, Math.min(back.length, 48))),
                    ok ? "✔ 一致" : "← 不一致");
        }

        // ---- 6. 三种密钥长度的对照（确认 SetKey 生效）----
        System.out.println("\n==== 6. SetKey 是否生效（长度敏感性）====");
        byte[] plain = "0123456789abcdef".getBytes("UTF-8");
        for (int klen : new int[]{0, 8, 16, 24, 32}) {
            byte[] k = new byte[klen];
            for (int i = 0; i < klen; i++) k[i] = (byte) (i + 1);
            try {
                UnidbgPointer o = c.newObj(k, 0);
                byte[] ct = c.encrypt(o, plain);
                System.out.printf("  klen=%-2d ct(%dB) = %s%n",
                        klen, ct.length, ct.length == 0 ? "(空)" : hex(ct));
            } catch (Throwable t) {
                System.out.printf("  klen=%-2d 异常 %s%n", klen, t.getMessage());
            }
        }

        c.close();
        System.out.println("\n==== done ====");
    }
}
