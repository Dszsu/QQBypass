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
 * 解析 libtsmqqsc.so 内部的 JNI 包装函数 0x36268 / 0x36280 / 0x362ac /
 * 0x362e0 / 0x3630c / 0x36344，看它们各自调用 JNIEnv 表的哪个槽位。
 *
 * 手法：反汇编后找 `ldr xN, [env, #offset]`，offset/8 就是槽位号，
 * 对照 JNINativeInterface 标准顺序即可确定函数名。
 */
public class ResolveJni {

    /** JNINativeInterface 前 240 项的常用名字（按标准顺序） */
    private static final String[] JNI_NAMES = new String[240];
    static {
        JNI_NAMES[4] = "GetVersion";
        JNI_NAMES[5] = "DefineClass";
        JNI_NAMES[6] = "FindClass";
        JNI_NAMES[7] = "FromReflectedMethod";
        JNI_NAMES[8] = "FromReflectedField";
        JNI_NAMES[9] = "ToReflectedMethod";
        JNI_NAMES[10] = "GetSuperclass";
        JNI_NAMES[11] = "IsAssignableFrom";
        JNI_NAMES[12] = "ToReflectedField";
        JNI_NAMES[13] = "Throw";
        JNI_NAMES[14] = "ThrowNew";
        JNI_NAMES[15] = "ExceptionOccurred";
        JNI_NAMES[16] = "ExceptionDescribe";
        JNI_NAMES[17] = "ExceptionClear";
        JNI_NAMES[18] = "FatalError";
        JNI_NAMES[21] = "NewGlobalRef";
        JNI_NAMES[22] = "DeleteGlobalRef";
        JNI_NAMES[23] = "DeleteLocalRef";
        JNI_NAMES[24] = "IsSameObject";
        JNI_NAMES[25] = "NewLocalRef";
        JNI_NAMES[26] = "EnsureLocalCapacity";
        JNI_NAMES[27] = "AllocObject";
        JNI_NAMES[28] = "NewObject";
        JNI_NAMES[29] = "NewObjectV";
        JNI_NAMES[30] = "NewObjectA";
        JNI_NAMES[31] = "GetObjectClass";
        JNI_NAMES[32] = "IsInstanceOf";
        JNI_NAMES[33] = "GetMethodID";
        JNI_NAMES[94] = "CallObjectMethod";
        JNI_NAMES[95] = "CallObjectMethodV";
        JNI_NAMES[96] = "CallObjectMethodA";
        JNI_NAMES[113] = "GetFieldID";
        JNI_NAMES[114] = "GetObjectField";
        JNI_NAMES[118] = "GetIntField";
        JNI_NAMES[133] = "GetStaticMethodID";
        JNI_NAMES[144] = "GetStaticObjectField";
        JNI_NAMES[167] = "NewStringUTF";
        JNI_NAMES[168] = "GetStringUTFLength";
        JNI_NAMES[169] = "GetStringUTFChars";
        JNI_NAMES[170] = "ReleaseStringUTFChars";
        JNI_NAMES[171] = "GetArrayLength";
        JNI_NAMES[172] = "NewObjectArray";
        JNI_NAMES[173] = "GetObjectArrayElement";
        JNI_NAMES[174] = "SetObjectArrayElement";
        JNI_NAMES[176] = "NewByteArray";
        JNI_NAMES[177] = "NewShortArray";
        JNI_NAMES[179] = "NewIntArray";
        JNI_NAMES[184] = "GetByteArrayElements";
        JNI_NAMES[185] = "ReleaseByteArrayElements";
        JNI_NAMES[200] = "GetByteArrayRegion";
        JNI_NAMES[201] = "SetByteArrayRegion";
        JNI_NAMES[222] = "GetPrimitiveArrayCritical";
        JNI_NAMES[223] = "ReleasePrimitiveArrayCritical";
    }

    static String jniName(int slot) {
        if (slot >= 0 && slot < JNI_NAMES.length && JNI_NAMES[slot] != null)
            return JNI_NAMES[slot];
        return "slot#" + slot;
    }

    public static void main(String[] args) throws Exception {
        String so = "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\ext_libtsmqqsc.so";
        String out = "E:\\\u5b89\u5353\u9006\u5411\u5de5\u5177\\QQ\\work\\tsmqqsc_jni_wrappers.asm";

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.tencent.mobileqq").build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(so), true);
        Module module = dm.getModule();

        long[] targets = {0x36268, 0x36280, 0x362ac, 0x362e0, 0x3630c, 0x36344, 0x38ce8, 0x36ae0};
        PrintWriter w = new PrintWriter(out, "UTF-8");
        String SEP = "================================================================================";

        for (long t : targets) {
            long va = module.base + t;
            w.println(SEP);
            w.printf("## base+0x%x%n", t);
            w.println(SEP);
            System.out.printf("%n=== base+0x%x ===%n", t);

            UnidbgPointer p = UnidbgPointer.pointer(emulator, va);
            byte[] code = p.getByteArray(0, 400);
            Capstone cs = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
            Instruction[] insns = cs.disasm(code, va, 0);

            int n = 0;
            for (Instruction in : insns) {
                String mn = in.getMnemonic();
                String ops = in.getOpStr() == null ? "" : in.getOpStr();
                w.printf("%08x  %-10s %s%n", in.getAddress(), mn, ops);

                // 找 ldr xN, [xM, #imm] 形式，imm/8 = JNI 槽位
                if ("ldr".equals(mn) && ops.contains(", #")) {
                    try {
                        String imm = ops.substring(ops.lastIndexOf('#') + 1);
                        int off = Integer.decode(imm.startsWith("0x") ? imm : "0x" + imm);
                        if (off > 0 && off % 8 == 0 && off < 240 * 8) {
                            int slot = off / 8;
                            String name = jniName(slot);
                            if (!name.startsWith("slot#")) {
                                System.out.printf("  0x%x: %s  → JNI #%d %s%n",
                                        in.getAddress(), ops, slot, name);
                            }
                        }
                    } catch (Exception ignored) { }
                }
                if ("ret".equals(mn) && ++n > 0) break;
                if (++n > 60) break;
            }
            cs.close();
            w.println();
        }
        w.close();
        emulator.close();
        System.out.println("\nwritten: " + out);
    }
}
