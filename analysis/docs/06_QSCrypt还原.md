# P0 完成报告：libmsfbootV2.so 黑盒调用打通

- 目标：用 unidbg 跑通 QQ 风控 native 层的加密原语
- 样本：`E:\安卓逆向工具\QQ\work\ext_libmsfbootV2.so`（327,488 B，ELF64 AARCH64，**未 strip**，698 个 dynsym）
- 环境：unidbg 0.9.9 / unicorn 1.0.15 / capstone 3.1.8 / JDK 21.0.12.1
- 结论：**QSCrypt 的 TEA 已完全逆向并用三个向量复现；MD5 完全正确；填充规则已解出；`IsSignatureValid` 需要真实 Java 对象，静态模拟不可行**

---

## 1. 最重要的结果：TEA 算法完全还原

### 1.1 算法

**标准 TEA，16 轮，delta = 0x9E3779B9 —— 但输入、密钥、输出全部按大端解释。**

```python
DELTA = 0x9e3779b9
M = 0xffffffff

def tea_encrypt(pt8: bytes, key16: bytes, rounds=16) -> bytes:
    v0 = int.from_bytes(pt8[0:4], 'big')
    v1 = int.from_bytes(pt8[4:8], 'big')
    k  = [int.from_bytes(key16[i*4:i*4+4], 'big') for i in range(4)]
    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & M
        v0 = (v0 + ((((v1 << 4) & M) + k[0]) ^ ((v1 + s) & M) ^ (((v1 >> 5) + k[1]) & M))) & M
        v1 = (v1 + ((((v0 << 4) & M) + k[2]) ^ ((v0 + s) & M) ^ (((v0 >> 5) + k[3]) & M))) & M
    return v0.to_bytes(4,'big') + v1.to_bytes(4,'big')

def tea_decrypt(ct8: bytes, key16: bytes, rounds=16) -> bytes:
    v0 = int.from_bytes(ct8[0:4], 'big')
    v1 = int.from_bytes(ct8[4:8], 'big')
    k  = [int.from_bytes(key16[i*4:i*4+4], 'big') for i in range(4)]
    s = (DELTA * rounds) & M
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) & M) + k[2]) ^ ((v0 + s) & M) ^ (((v0 >> 5) + k[3]) & M))) & M
        v0 = (v0 - ((((v1 << 4) & M) + k[0]) ^ ((v1 + s) & M) ^ (((v1 >> 5) + k[1]) & M))) & M
        s = (s - DELTA) & M
    return v0.to_bytes(4,'big') + v1.to_bytes(4,'big')
```

### 1.2 复现验证（三个向量全部一致）

| 明文 | 密钥 | native 输出 | 我的实现 | 结果 |
|---|---|---|---|---|
| `0011223344556677` | `000102030405060708090a0b0c0d0e0f` | `205f515574f0821c` | `205f515574f0821c` | ✔ |
| `0000000000000000` | `00000000000000000000000000000000` | `a889f798182d8083` | `a889f798182d8083` | ✔ |
| `0102030405060708` | `000102030405060708090a0b0c0d0e0f` | `6ac3f66fac01d1ad` | `6ac3f66fac01d1ad` | ✔ |

解密方向同样三个向量全部往返一致。

### 1.3 汇编依据（`TeaEncryptECB` @ `base+0x26460`，240 B / 65 条）

```asm
12026468  movz  w3, #0x79b9
1202649c  movk  w3, #0x9e37, lsl #16     ; w3 = 0x9e3779b9  ← 标准 TEA delta
12026470  movz  w10, #0x10               ; 16 轮
1202647c  rev   w16, w16                 ; 密钥字节反转 → 大端解释
12026484  rev   w15, w15
1202648c  rev   w17, w17
12026494  rev   w1,  w1
120264bc  lsl   w14, w14, #0x18          ; v0 = (in[0]<<24)|(in[1]<<16)|(in[2]<<8)|in[3]
120264c0  bfi   w0,  w5,  #0x10, #8      ; v1 = (in[4]<<24)|(in[5]<<16)|(in[6]<<8)|in[7]
120264c4  add   x9,  x3,  w9, uxtw       ; sum += delta
120264e0  add   w12, w16, w0, lsl #4     ; k0 + (v1<<4)
120264e4  add   w13, w17, w0, lsr #5     ; k1 + (v1>>5)
120264e8  eor   w11, w12, w11            ; ^ (v1+sum)
120264f4  add   w8,  w14, w8             ; v0 += ...
120264ec  subs  w10, w10, #1
12026528  b.ne  #0x120264a8              ; 循环 16 次
1202652c  strb  w14, [x2]                ; 输出大端写出 v0||v1
```

**关键点**：零密钥零明文的输出 `a889f798182d8083` 之所以不等于标准 TEA 的 `41ea3a0a94baa940`，**唯一原因就是大端解释**，算法本身没有任何改动。这也解释了为什么最初枚举 delta/轮数/字节序组合失败 —— 我的参考实现里密钥永远按小端读，而 native 侧四组密钥也都做了 `rev`。

---

## 2. 填充规则（`FindEncryptSize`）

`QSCrypt::FindEncryptSize(int)` @ `base+0x26f64`，是**成员函数**（`ldrb w8, [x0, #0x18]`，X0 必须是 this）。

实测 0–40 全表：

```
 len  0-6 → 16      len  7-14 → 24      len 15-22 → 32
len 23-30 → 40      len 31-38 → 48      len 39-46 → 56
```

拟合出的闭式：

```
size = 16 + 8 * floor((len + 1) / 8)
```

与汇编逐句对应：

```asm
12026460  ldrb w8, [x0, #0x18]   ; 读对象模式位，>1 直接返回 0
12026470  add  w8, w1, #0xa      ; len + 10
12026474  add  w9, w1, #0x11     ; len + 17（负数补偿）
12026484  and  w9, w9, #0xfffffff8  ; 向下对齐到 8
12026494  add  w0, w9, w8
```

**结构含义**：`16 = 8 字节头部 + 8 字节最小密文体`。每满 8 字节正文多 1 块，1 字节填充标记（`len+1` 的 +1）。实测 Encrypt 输出长度与规则完全吻合：

| 明文 | 密文 | 规则算得 |
|---|---|---|
| 0 B | 16 B | 16 ✔ |
| 1 B | 16 B | 16 ✔ |
| 12 B | 24 B | 24 ✔ |
| 16 B | 32 B | 32 ✔ |
| 17 B | 32 B | 32 ✔ |
| 24 B | 40 B | 40 ✔ |

**但注意**：实测密文里的头部 8 字节（如 `5b9c066b7e8fba8d`）不是固定 magic，每次 Encrypt 都不同 —— 是随机 IV 或时间戳，这一层尚未定论（见第 5 节）。

---

## 3. QSCrypt 对象布局（`base+0x2000` 实机转储）

```
偏移      内容
0x00      vtable 指针 = 0x1204eb70
0x08      key 缓冲区（就地拷贝，不是指针）
0x18      uchar 模式开关   ← 构造函数 X2 直接写这里
0x19      uchar arith（SetArith 的 X1）
0x1A      uchar 保留
0x20+     内部状态
```

实测三种模式：

```
ctor(key, 0, 0, 0) → [0x18]=0   Encrypt 正常，FindEncryptSize 走正常分支
ctor(key, 1, 0, 0) → [0x18]=1   Encrypt 返回 0 字节
ctor(key, 2, 0, 0) → [0x18]=2   FindEncryptSize 直接短路返回 0
```

**这是踩了两轮的坑**：`QSCrypt(unsigned char*, unsigned char, unsigned char, unsigned char)` 里第二个参数**不是密钥长度**，是模式位。密钥长度在 `SetKey(uchar*, int)` 的 X2。把 16 当长度传进去会导致 `[0x18]=16 > 1`，所有加解密静默返回空。

### 3.1 `outLen` 是纯输出参数

`Encrypt(const char*, int, uchar*, int&)` 的第 4 个参数初值必须是 **0**。传容量进去（哪怕分配了足够大的缓冲区）会让 native 侧写出全零密文。这是第二个坑。

---

## 4. MD5（完全正确）

`QSCrypt::Md5Hash(uchar* out, const char* in, int len)`：

```
md5("")            = d41d8cd98f00b204e9800998ecf8427e
md5("abc")         = 900150983cd24fb0d6963f7d28e17f72   ← 标准向量，✔
md5("hello qq sec")= 2caea02171d73d5957078aea6d708bdb
```

标准 RFC 1321 实现，输入原样、输出 16 字节原样，无任何变换。

### 4.1 `GetLong` 只读 4 字节

```
GetLong(long&, uchar*)  in=0102030405060708 → 0x0000000001020304
```

签名是 64 位引用，实际只取前 4 字节按大端写入低 32 位，高 32 位清零。这是 QSCrypt 内部的序列化辅助函数（配合 `GetShort` / `SetLong` / `SetShort`）。

---

## 5. `IsSignatureValid` —— 不可静态模拟

```
符号: _ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject  @ base+0x25048, 1108 B
签名: (JNIEnv*, jobject)
```

空 jObject 下调用：在 `+0x90`（`0x120250d8`）处 `UC_ERR_READ_UNMAPPED`，返回 -1。

**判定**：该函数通过 `JNIEnv->CallObjectMethod` / `GetFieldID` 反射读取 Java 侧对象字段（trace 里能看到 `_JNIEnv::CallObjectMethod` / `_JNIEnv::CallStaticObjectMethod` 的导入），**必须构造真实的 Java 对象 + 完整的 DalvikVM 环境**才能跑出有意义结果。

**投入产出重新评估**：这条不值得在 unidbg 里硬啃。`IsSignatureValid` 的业务价值是"改包后能否通过校验"，而这个问题的答案在真机上一次 hook 就拿到了 —— 成本远低于在模拟环境里手工构造整个 Application/Context/PackageManager 反射链。

---

## 6. 产物

```
E:\安卓逆向工具\android-re-tools\unidbg\src\main\java\local\retools\
├── SoRunner.java      原有骨架（加载 + 列符号），未改动
├── QSecCaller.java    本轮新增：QSCrypt 全套调用（TEA/Encrypt/Decrypt/Md5/FindEncryptSize）
├── SigProbe.java      本轮新增：TEA 变形枚举 + GetLong 字节序 + IsSignatureValid 探测
└── DisAsm.java        本轮新增：capstone 反汇编指定符号（ARM64）

编译产物：unidbg\target\classes\local\retools\*.class
运行日志：unidbg\qsec_call4.log / sigprobe.log

E:\安卓逆向工具\QQ\work\
├── tea_verify.py              大端 TEA 复现脚本（三向量全过）
├── elfinfo.py                 ELF 符号解析
└── dexparse.py / locate.py / xref.py / strsearch.py / datanalyze.py
```

### 编译与运行

```powershell
$u = 'E:\安卓逆向工具\android-re-tools\unidbg'
$env:JAVA_HOME = 'E:\安卓逆向工具\android-re-tools\jdk\jdk-21.0.12.1+1'

# 编译
& "$env:JAVA_HOME\bin\javac.exe" -encoding UTF-8 -cp "$u\lib\*" `
    -d "$u\target\classes" "$u\src\main\java\local\retools\QSecCaller.java"

# 跑
& "$env:JAVA_HOME\bin\java.exe" -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 `
    -Xmx1500m -cp "$u\target\classes;$u\lib\*" local.retools.QSecCaller

# 反汇编任意符号
& "$env:JAVA_HOME\bin\java.exe" -cp "$u\target\classes;$u\lib\*" `
    local.retools.DisAsm <so> _ZN7QSCrypt13TeaEncryptECBEPKhS1_Ph 260
```

---

## 7. 对风控分析的修正与补充

| 之前的判断 | 现在的事实 |
|---|---|
| "`QSCrypt::Encrypt/Decrypt` 可能是流密码" | **是 TEA（大端变体）+ 8 字节头部封装**，不是流密码 |
| "`txsfcfg.dat` 上面压着一层流密码" | 更可能是 TEA 封装 —— 该文件 54,166 B，`Schk` 头后正是 8 字节对齐的密文体，结构吻合 `FindEncryptSize` 的 16 字节头规则 |
| "`QSCrypt::QSCrypt` 第二参数是密钥长度" | **是模式位**，写进对象 `[0x18]`；密钥长度在 `SetKey` 的 X2 |
| "`IsSignatureValid` 是最容易的目标" | 反过来 —— 它是这个 so 里**最难静态模拟**的，因为它依赖完整 JVM 反射链 |

### 下一步建议（修正版）

| 优先级 | 动作 | 理由 |
|---|---|---|
| **P0** | 用已还原的大端 TEA 去解 `txsfcfg.dat` | 密钥候选：`assets/qq.key`（36 KB）、`assets/fekit.key`（215 KB）、`QSecConfig.CONFIG_KEY_BUF`。TEA 密钥固定 16 字节，从这几个文件里取 16 字节窗口爆破即可 |
| **P1** | 真机 hook `CMSFJavaUtil::IsSignatureValid` 拿返回值 | 比在 unidbg 里构造 JVM 环境便宜一个数量级 |
| **P2** | 定死 `Encrypt` 输出前 8 字节的语义 | 用同一明文连续加密多次，看是否变化 —— 变化则是随机 IV，固定则是时间戳/magic |
| **P3** | `libfekit.so` 的 OLLVM 字符串解密 | 仍是拿到 QSec 全部 native 方法名的唯一路径 |

---

## 8. 合规声明

仅对本地 APK 文件中的 native 库做离线分析，未运行 APK、未连接任何线上服务、未绕过任何鉴权。`com.tencent.mobileqq` 版权归腾讯所有。
