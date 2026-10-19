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

/**
 * 反汇编 libmsfbootV2.so 的指定符号（capstone 3.1.8 API）。
 *
 * 用法: DisAsm <so> <mangledName> [字节数]
 */
public class DisAsm {

    public static void main(String[] args) throws Exception {
        String so = args[0];
        String target = args.length > 1 ? args[1] : "_ZN7QSCrypt13TeaEncryptECBEPKhS1_Ph";
        int nBytes = args.length > 2 ? Integer.parseInt(args[2]) : 512;

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(so), true);
        Module module = dm.getModule();

        long addr = -1;
        for (com.github.unidbg.Symbol s : module.getExportedSymbols()) {
            if (target.equals(s.getName())) {
                addr = s.getAddress();
                System.out.printf("符号 %s  base+0x%x%n", s.getName(), addr - module.base);
                break;
            }
        }
        if (addr < 0) {
            System.out.println("未找到: " + target);
            for (com.github.unidbg.Symbol s : module.getExportedSymbols()) {
                if (s.getName() != null
                        && s.getName().toLowerCase().contains(target.toLowerCase())) {
                    System.out.printf("  候选 base+0x%x  %s%n",
                            s.getAddress() - module.base, s.getName());
                }
            }
            emulator.close();
            return;
        }

        UnidbgPointer p = UnidbgPointer.pointer(emulator, addr);
        byte[] code = p.getByteArray(0, nBytes);

        Capstone cs = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
        Instruction[] insns = cs.disasm(code, addr, 0);
        System.out.println("---- " + insns.length + " 条 ----");
        for (Instruction in : insns) {
            System.out.printf("%08x  %-8s %s%n",
                    in.getAddress(), in.getMnemonic(), in.getOpStr());
        }
        cs.close();
        emulator.close();
    }
}
