package local.retools;

import capstone.Capstone;
import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.File;
import java.io.PrintWriter;

/**
 * 把 libmsfbootV2.so 里所有加密相关函数反汇编导出成文本，
 * 便于离线分析 QSCrypt 的密钥调度与 txsfcfg 的真实解密路径。
 */
public class DumpCrypto {

    private static final String SEP78 =
            "================================================================================";

    private static final String[] TARGETS = {
            "_ZN7QSCrypt7EncryptEPKhiPhRi",
            "_ZN7QSCrypt7DecryptEPKhiPhRi",
            "_ZN7QSCrypt6SetKeyEPhi",
            "_ZN7QSCrypt8SetArithEhh",
            "_ZN7QSCryptC2EPhhh",
            "_ZN7QSCryptC2Ev",
            "_ZN7QSCrypt15FindEncryptSizeEi",
            "_ZN7QSCrypt7GetLongERlPh",
            "_ZN7QSCrypt8GetShortERsPh",
            "_ZN7QSCrypt8SetLongEPhl",
            "_ZN7QSCrypt8SetShortEPhs",
            "_ZN7QSCrypt7Md5HashEPhPKhi",
            "_ZN7QSCrypt13TeaEncryptECBEPKhS1_Ph",
            "_ZN7QSCrypt13TeaDecryptECBEPKhS1_Ph",
            "_ZN18CNativeConfigStore10loadConfigEP7_JNIEnvP8_jobjecth",
            "_ZN18CNativeConfigStore10SaveToFileEv",
            "_ZN18CNativeConfigStore9getConfigEP7_JNIEnvP8_jstring",
            "_ZN18CNativeConfigStore9setConfigEP7_JNIEnvP8_jstringS3_",
            "_ZN14CConfigStoreSO10SerializeLER13CMSFBufStream",
            "_ZN14CConfigStoreSO12DeSerializeLER13CMSFBufStream",
            "_ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject",
            "_ZN12CMSFJavaUtil7getIMEIEP7_JNIEnvP8_jobjectRNSt6__ndk112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEiB",
    };

    public static void main(String[] args) throws Exception {
        String so = args.length > 0 ? args[0]
                : "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\ext_libmsfbootV2.so";
        String outPath = args.length > 1 ? args[1]
                : "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\libmsfboot_crypto.asm";

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(so), true);
        Module module = dm.getModule();

        PrintWriter w = new PrintWriter(outPath, "UTF-8");
        w.println("# libmsfbootV2.so 加密相关函数反汇编");
        w.println("# base = 0x" + Long.toHexString(module.base));
        w.println();

        for (String sym : TARGETS) {
            long addr = -1;
            String realName = sym;
            for (com.github.unidbg.Symbol s : module.getExportedSymbols()) {
                if (sym.equals(s.getName())) {
                    addr = s.getAddress();
                    realName = s.getName();
                    break;
                }
            }
            if (addr < 0) {
                // 模糊匹配（应对签名差异）
                for (com.github.unidbg.Symbol s : module.getExportedSymbols()) {
                    String n = s.getName();
                    if (n == null) continue;
                    String key = sym.substring(0, Math.min(24, sym.length()));
                    if (n.startsWith(key)) {
                        addr = s.getAddress();
                        realName = n;
                        break;
                    }
                }
            }
            w.println(SEP78);
            if (addr < 0) {
                w.println("## NOT FOUND: " + sym);
                w.println();
                continue;
            }
            w.printf("## %s%n## base+0x%x%n", realName, addr - module.base);
            w.println(SEP78);

            // 先粗扫 2KB 拿到大致长度，最多 800 条
            UnidbgPointer p = UnidbgPointer.pointer(emulator, addr);
            byte[] code = p.getByteArray(0, 4096);
            Capstone cs = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
            Instruction[] insns = cs.disasm(code, addr, 0);
            int n = 0;
            boolean sawRet = false;
            for (Instruction in : insns) {
                String mn = in.getMnemonic();
                w.printf("%08x  %-10s %s%n", in.getAddress(),
                        mn == null ? "" : mn, in.getOpStr());
                n++;
                if ("ret".equals(mn)) {
                    if (sawRet) break;      // 第二个 ret 之后可能是下一个函数
                    sawRet = true;
                }
                if (n > 800) break;
            }
            cs.close();
            w.println();
        }

        w.close();
        emulator.close();
        System.out.println("written: " + outPath);
    }
}
