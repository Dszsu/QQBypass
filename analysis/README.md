# QQReverseKit

QQ 9.3.65 静态逆向分析资产包。

**样本 SHA-256**：`F63ECBAC6980D2109A7CEB854DB0324668B1318CF50C884C0E7C35752CFFEF84`
**分析环境**：apktool 3.0.3 / baksmali 2.5.2 / JDK 21 / Python 3.12 / unidbg 0.9.9 / capstone 3.1.8

---

## 这个包能做什么

| 你可以 | 文件 |
|---|---|
| 用 Python 加解密 QSCrypt 的数据 | `src/crypto/qscrypt.py` |
| 用纯 Python 算国密 SM3 / SM4 | `src/crypto/gm_crypto.py` |
| 在 unidbg 里调 QQ 的国密库 | `src/unidbg/TenpaySc6.java` |
| 在 unidbg 里调 QSCrypt | `src/unidbg/QSecCaller.java` |
| 按符号名反汇编任意 arm64 函数 | `src/unidbg/DisAsm.java` |
| 扫出哪些 .so 在做检测 | `src/tools/full_detect_scan.py` |
| 找某个类在哪个 dex | `src/tools/locate.py` |
| 找谁调用了某个方法 | `src/tools/xref.py` |
| 查掉线原因（1800 秒周期） | `docs/05_掉线修复规格.md` |

---

## 目录

```
QQReverseKit/
├── README.md                       本文件
│
├── docs/                           分析报告（按问题组织）
│   ├── 00_总览.md                  ★ 从这里开始，全部结论
│   ├── 01_加密体系.md              8 个加密库的构成
│   ├── 02_支付国密.md              SM2/SM3/SM4 跑通过程
│   ├── 03_风控体系.md              QSec 架构与签名链路
│   ├── 04_检测点清单.md            具体检测函数与返回值
│   ├── 05_掉线修复规格.md          ★ 周期性掉线根因与修复
│   ├── 06_QSCrypt还原.md           TEA 算法完整还原过程
│   └── 07_包体结构.md              APK 结构与工具链
│
├── src/
│   ├── crypto/                     可运行的加密实现
│   │   ├── qscrypt.py              ★ QSCrypt 完整实现（三向量验证）
│   │   ├── qscrypt_core.py         链式变换核心
│   │   ├── gm_crypto.py            ★ 纯 Python SM3 / SM4（国标向量全过）
│   │   └── tea_verify.py           TEA 三向量复现
│   │
│   ├── unidbg/                     unidbg 调用器（Java）
│   │   ├── TenpaySc6.java          ★ 支付国密调用器（含前置标志绕过）
│   │   ├── TenpaySm2Full.java      SM2 密钥对 / 签名 / 加密
│   │   ├── QSecCaller.java         QSCrypt 全套（TEA/Enc/Dec/Md5）
│   │   ├── CrossCheck.java         与 native 交叉验证
│   │   ├── DisAsm.java             ★ 按符号名反汇编（capstone）
│   │   ├── DumpCrypto.java         批量反汇编加密函数
│   │   └── ResolveJni.java         JNI 包装函数槽位解析
│   │
│   ├── tools/                      静态分析脚本（Python，零第三方依赖）
│   │   ├── elfinfo.py              ELF64 符号 / section 解析
│   │   ├── dexparse.py             dex 类名解析（流式）
│   │   ├── locate.py               类名 → 所在 dex
│   │   ├── xref.py                 ★ DEX 交叉引用（解析 invoke 指令）
│   │   ├── smaliparse.py           批量提取方法 / 字段 / 字符串
│   │   ├── strsearch.py            全 dex 字符串池搜索
│   │   ├── findstr.py              smali 里搜字符串并打印所在方法
│   │   ├── crypto_survey.py        加密库算法特征扫描
│   │   ├── full_detect_scan.py     ★ 200 个 .so 检测能力矩阵
│   │   ├── detect_spec.py          检测函数 / 字符串汇总
│   │   ├── hidden_scan.py          ★ svc #0 / 高熵段挖掘
│   │   ├── kick_rootcause.py       ★ 掉线根因分析
│   │   ├── fekit_structure.py      libfekit 结构与混淆分析
│   │   ├── parse_pb.py             protobuf 解析（qq.key 容器）
│   │   └── tsmqqsc_summary.py      支付国密结构总结
│   │
│   └── lsposed/                    LSPosed 模块（可直接编译安装）
│       ├── MainHook.java         主入口，26 项环境净化
│       ├── EmulatorHook.java       模拟器检测中和
│       ├── KickDiag.java           踢线诊断
│       ├── FaceEnvHook.java        人脸核身环境数据（lux 等）
│       ├── build.ps1               一键构建脚本
│       └── QQClean.apk             已编译产物
│
├── asm/                            关键函数反汇编
│   ├── libmsfboot_crypto.asm       QSCrypt 全部函数（138 KB）
│   ├── libtsmqqsc.asm              支付国密 30 个函数（99 KB）
│   └── tsmqqsc_jni_wrappers.asm    JNI 包装槽位映射
│
├── libs/                           关键 .so（未 strip，符号可读）
│   ├── libmsfbootV2.so             0.32 MB   QSCrypt 主实现
│   ├── libtsmqqsc.so               0.72 MB   支付国密（150 个导出）
│   ├── libQSec.so                  0.03 MB   反调试壳（42% 加密）
│   └── libfekit.so                 7.28 MB   OLLVM 混淆
│
└── samples/                        加密数据样本
    ├── txsfcfg.dat                 风控检查配置（7-bit 编码）
    ├── qself.dat                   自校验基线
    ├── qq.key                      密钥容器（protobuf）
    └── fekit.key                   密钥容器（含大载荷）
```

---

## 快速开始

### 1. 验证加密实现

```bash
python src/crypto/qscrypt.py selftest
```

期望输出（三个 native 向量全过）：

```
TeaEncryptECB(0011223344556677, 000102..0f) = 205f515574f0821c   ✔
TeaDecryptECB(上一行)                       = 0011223344556677   ✔
40 字节多块往返: len(ct)=48  ✔
```

```bash
python src/crypto/gm_crypto.py
```

期望：

```
sm3(abc) = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0  ✔
sm4 ct   = 681edf34d206965e86b3e94f536e4246  期望 681edf34d206965e86b3e94f536e4246 ✔
```

### 2. 调通支付国密库

```powershell
$u = 'E:\安卓逆向工具\android-re-tools\unidbg'
$jdk = 'E:\安卓逆向工具\android-re-tools\jdk\jdk-21.0.12.1+1'

& "$jdk\bin\javac.exe" -encoding UTF-8 --release 8 -Xlint:-options `
  -cp "$u\lib\*" -d "$u\target\classes" src\unidbg\TenpaySc6.java

& "$jdk\bin\java.exe" -Dfile.encoding=UTF-8 -Xmx2g `
  -cp "$u\target\classes;$u\lib\*" local.retools.TenpaySc6
```

期望：

```
getVersion = 1.7.1
md5(abc)   = 900150983cd24fb0d6963f7d28e17f72
sm3(abc)   = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
SM4 首块   = 681edf34d206965e86b3e94f536e4246
```

### 3. 扫描检测面

```bash
python src/tools/full_detect_scan.py    # 200 个 .so 检测强度排名
python src/tools/hidden_scan.py         # svc #0 与高熵段
python src/tools/kick_rootcause.py      # 掉线周期分析
```

> 这三个脚本默认读 `work/QQ_dec/lib/arm64-v8a/`，需要先把 APK 解包到那里。

---

## 核心结论

### 1. QSCrypt = 标准 TEA + CBC 链

```
标准 TEA / 16 轮 / delta = 0x9E3779B9 / 全部大端

Encrypt:
  IV₁ = R（rand() 生成）
  T_i = TeaEncryptECB(P_i ^ IV_i, KEY)
  C_i = T_i ^ IV_i
  IV_{i+1} = T_i

输出 = R || C₁..Cₙ，长度 = 8 + 8·ceil((len+1)/8)
```

**坑**：`QSCrypt(key, X2, X3, X4)` 里 `[0x18]` 是 Encrypt 开关（必须 0）、`[0x19]` 是 Decrypt 开关（必须非 0），**不是密钥长度**。

### 2. 腾讯支付国密没有魔改

SM3 / SM4 与国标向量完全一致，可直接用标准实现。SM2 密钥对格式也是标准的 `04‖X‖Y`。

**解锁方法**：把 `[base + 0xbecc8]` 的全局 int 写 0（初值 -1 会导致所有算法返回错误）。

### 3. 周期性掉线是 1800 秒定时体检

```
libfekit.so        1800 ×4
libbasic_share.so  1800 ×7
libMSFKernel.so    1800 ×3
```

触发链：`RuntimeEnvCensorTask` → `dl_iterate_phdr` → `/proc/self/maps` → `trpc.o3.report` → 服务端踢线。

**修复优先级**：`dl_iterate_phdr`（7/7 库全覆盖）> `fopen("/proc/self/maps")` > `bytehook_get_records`。

### 4. 检测分三层

| 层 | 载体 | 绕过难度 |
|---|---|---|
| 表面 | libc 函数（`access`/`stat`/`open`） | 易 |
| 中间 | 直接 `svc #0`（116 处 / 9 个库） | 难 |
| 深层 | 读 `libart` 内存结构 | 极难 |

---

## 明确做不到的

| 项目 | 原因 |
|---|---|
| `txsfcfg.dat` 解密 | 密钥服务端下发（`CONFIG_KEY_BUF` 静态初值 null） |
| `libfekit` 静态字符串解密 | `.datadiv_decode` 函数内按需调用，不执行不解密 |
| SM2 sign/encrypt 参数语义 | 4 个 byte[] 只有长度约束，无语义约束 |
| 服务端判定逻辑 | 静态分析不可见 |

---

## 参考

- 参考项目：https://github.com/Dszsu/QQBypass
- 差异：该项目是**运行时绕过**（ByteHook + libc hook），本包是**静态分析资产**（算法还原 + 检测面清单 + 可直接跑的脚本）

---

## 合规

仅对本地 APK 做离线静态分析，未运行 APK、未连接任何线上服务。`com.tencent.mobileqq` 版权归腾讯所有。

---

## 与其他目录的关系

```
E:\安卓逆向工具\QQ\
├── 9.3.65_2a98ecf55b5ee03a.apk     原始样本
├── QQReverseKit\                   ★ 本包：可复用的分析资产（9.25 MB）
│   ├── docs/    分析结论
│   ├── src/     可运行的脚本与源码
│   ├── asm/     关键函数反汇编
│   ├── libs/    关键 .so
│   └── samples/ 加密样本
└── work\                           原始素材区（1.03 GB，可随时重建）
    ├── QQ_dec\        apktool d -s 输出（资源 + lib + Manifest）
    ├── dexnames\      41 个 dex 的类名清单
    └── ext_classes*.dex  按需提取的 dex（重建 smali 用）
```

**本包自包含**：`src/crypto/` 和 `src/lsposed/` 不依赖 `work/`。
`src/tools/` 里的扫描脚本需要 `work/QQ_dec/lib/arm64-v8a/`（解包后的 .so）。

路径解析在 `src/tools/paths.py`，会自动找 APK 和解包目录，也可用环境变量覆盖：

```powershell
$env:QQRK_APK = 'D:\path\to\qq.apk'
$env:QQRK_DEC = 'D:\path\to\QQ_dec'
```

## 重建 work 目录

```powershell
$apktool = 'E:\安卓逆向工具\android-re-tools\apktool\apktool.bat'
& $apktool d -s -f -o work\QQ_dec 9.3.65_2a98ecf55b5ee03a.apk
```

`-s` 表示跳过 smali（只解资源 + lib + Manifest），几分钟完成。
需要某个 dex 的 smali 时再单独 baksmali：

```powershell
$java = 'E:\安卓逆向工具\android-re-tools\jdk\jdk-21.0.12.1+1\bin\java.exe'
$bs   = 'E:\安卓逆向工具\android-re-tools\smali\baksmali-2.5.2.jar'
& $java -Xmx3g -jar $bs d work\ext_classes2.dex -o work\smali_c2
```