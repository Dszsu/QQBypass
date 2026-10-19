package local.retools;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.File;

/**
 * libtsmqqsc.so 完整调用器 v6 —— 破解前置检查。
 *
 * ================= 关键发现 =================
 *
 * 反汇编 base+0x630a8：
 *     120630a8  adrp  x0, #0x120be000
 *     120630ac  ldr   w0, [x0, #0xcc8]     ; 读全局 int
 *     120630b0  ret
 *
 * 这就是 SM3/SM4/SM2 的「前置检查」：只是读一个全局变量。
 * 该变量非 0 时，各算法返回 -10643 (0x2a93) 类错误。
 *
 * 紧邻的 0x120630b4 是初始化函数，仅在 [0xcc8]==0 时启用。
 *
 * 对策：在调算法前，把 [base+0xbe000+0xcc8] 写成 0。
 * 这是纯数据操作，不需要 Context、不需要 init()。
 */
public class TenpaySc6 {

    private final AndroidEmulator emulator;
    private final Module module;
    private final VM vm;
    private final DvmClass clazz;

    /** 前置标志的绝对地址 = base + 0xbecc8 */
    private final long precheckAddr;

    public TenpaySc6(String soPath) {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        clazz = vm.resolveClass("com/tenpay/qqsc/FitScUtil");

        DalvikModule dm = vm.loadLibrary(new File(soPath), true);
        module = dm.getModule();
        try { dm.callJNI_OnLoad(emulator); } catch (Throwable ignored) { }

        precheckAddr = module.base + 0xbe000 + 0xcc8;
        System.out.printf("加载 OK  base=0x%x  前置标志@0x%x%n",
                module.base, precheckAddr);
    }

    /** 把前置标志置 0，让算法走正常路径 */
    private void clearPrecheck() {
        try {
            UnidbgPointer p = UnidbgPointer.pointer(emulator, precheckAddr);
            int v = p.getInt(0);
            if (v != 0) {
                p.setInt(0, 0);
                System.out.println("    [fix] 前置标志 " + v + " → 0");
            }
        } catch (Throwable t) {
            System.out.println("    [fix失败] " + t);
        }
    }

    private DvmObject<?> obj(String n, Object... a) {
        clearPrecheck();
        return clazz.callStaticJniMethodObject(emulator, n, a);
    }

    private byte[] bytes(String n, Object... a) {
        DvmObject<?> r = obj(n, a);
        return (r instanceof ByteArray) ? ((ByteArray) r).getValue() : null;
    }

    private int i(String n, Object... a) {
        return clazz.callStaticJniMethodInt(emulator, n, a);
    }

    public String ver() { DvmObject<?> r = obj("getVersion");
        return r == null ? null : String.valueOf(r.getValue()); }
    public int err() { return i("getLastError"); }

    public byte[] md5(byte[] d) { return bytes("md5", new ByteArray(vm, d)); }
    public byte[] sha1(byte[] d) { return bytes("sha1", new ByteArray(vm, d)); }
    public byte[] sha256(byte[] d) { return bytes("sha256", new ByteArray(vm, d)); }
    public byte[] sm3(byte[] d) { return bytes("sm3", new ByteArray(vm, d)); }

    public byte[] sm4CbcEnc(byte[] data, byte[] key, byte[] iv, boolean pad) {
        return bytes("sm4CbcEncrypt",
                new ByteArray(vm, data), new ByteArray(vm, key),
                new ByteArray(vm, iv), pad);
    }

    public byte[] sm4CbcDec(byte[] data, byte[] key, byte[] iv, boolean pad) {
        return bytes("sm4CbcDecrypt",
                new ByteArray(vm, data), new ByteArray(vm, key),
                new ByteArray(vm, iv), pad);
    }

    static String hex(byte[] b) {
        if (b == null) return "null";
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static byte[] unhex(String s) {
        byte[] r = new byte[s.length() / 2];
        for (int k = 0; k < r.length; k++)
            r[k] = (byte) Integer.parseInt(s.substring(k * 2, k * 2 + 2), 16);
        return r;
    }

    public static void main(String[] a) throws Exception {
        String so = "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\ext_libtsmqqsc.so";
        TenpaySc6 c = new TenpaySc6(so);

        System.out.println();
        System.out.println("=== 基础（对照）===");
        System.out.println("  getVersion = " + c.ver());
        byte[] abc = "abc".getBytes();
        System.out.println("  md5(abc)    = " + hex(c.md5(abc)));

        System.out.println();
        System.out.println("=== SM3（清前置标志后）===");
        try {
            byte[] r = c.sm3(abc);
            System.out.println("  sm3(abc) = " + hex(r));
            System.out.println("    期望 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
            System.out.println("    err = " + c.err());
        } catch (Throwable t) {
            System.out.println("  [!] " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }

        System.out.println();
        System.out.println("=== SM4 CBC（标准向量）===");
        byte[] key = unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = new byte[16];
        byte[] pt = unhex("0123456789abcdeffedcba9876543210");
        try {
            byte[] ct = c.sm4CbcEnc(pt, key, iv, false);
            System.out.println("  ct  = " + hex(ct));
            System.out.println("  err = " + c.err());
            if (ct != null && ct.length >= 16) {
                byte[] f = new byte[16];
                System.arraycopy(ct, 0, f, 0, 16);
                System.out.println("  首块 = " + hex(f));
                System.out.println("    期望 681edf34d206965e86b3e94f536e4246（CBC-IV=0 时首块=ECB）");
            }
        } catch (Throwable t) {
            System.out.println("  [!] " + t);
        }

        c.emulator.close();
    }
}
