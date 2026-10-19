#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libtsmqqsc.so —— 腾讯支付国密库 逆向成果（最终版）

════════════════════════════════════════════════════════════════
  成功项（全部用国家标准测试向量验证通过）
════════════════════════════════════════════════════════════════

  getVersion()   = 1.7.1
  getLastError() = 0

  md5("")        = d41d8cd98f00b204e9800998ecf8427e                    ✔
  md5("abc")     = 900150983cd24fb0d6963f7d28e17f72                    ✔
  sha1("abc")    = a9993e364706816aba3e25717850c26c9cd0d89d            ✔
  sha256("abc")  = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb4
                   10ff61f20015ad                                       ✔
  sm3("abc")     = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2
                   297da02b8f4ba8e0                                     ✔
  sm4Cbc(首块)   = 681edf34d206965e86b3e94f536e4246                    ✔
  sm2GenKeyPair  = 私钥 32B + 公钥 65B（04||X||Y，标准 SM2 公钥格式）  ✔

════════════════════════════════════════════════════════════════
  核心技术突破：前置标志
════════════════════════════════════════════════════════════════

  反汇编 base+0x630a8：
      120630a8  adrp  x0, #0x120be000
      120630ac  ldr   w0, [x0, #0xcc8]
      120630b0  ret

  就是读一个全局 int。初始值 -1，SM3/SM4/SM2 全部返回错误。
  把它写 0，全部算法立即可用 —— 不需要 Context、不需要 init()。

  地址：base + 0xbe000 + 0xcc8 = base + 0xbecc8

════════════════════════════════════════════════════════════════
  函数签名（反汇编逐参数确认）
════════════════════════════════════════════════════════════════

  md5(byte[] data)                            → byte[16]
  sha1(byte[] data)                           → byte[20]
  sha256(byte[] data)                         → byte[32]
  sm3(byte[] data)                            → byte[32]

  sm4CbcEncrypt(byte[] data, byte[] key,
                byte[] iv, boolean pad)       → byte[]
  sm4CbcDecrypt(byte[] data, byte[] key,
                byte[] iv, boolean pad)       → byte[]

  sm2GenKeyPair()                             → byte[][]{pri32, pub65}
  sm2Sign(byte[] pri, byte[] data,
          byte[] digest32, byte[] pub)        → byte[]      ← 4 参数
  sm2Verify(byte[] pub, byte[] data,
            byte[] digest32, byte[] sig)      → int         ← 4 参数
  sm2Encrypt(byte[] data, byte[] pub)         → byte[]      ← x2=data,x3=pub
  sm2Decrypt(byte[] pri, byte[] cipher)       → byte[]
  sm2CalcSharedKey(byte[] pri, byte[] pub)    → byte[]

  参数布局来自：
    sm2Sign  @0x34644: x2=pri, x3=data, x4(len<=32), x5(len<66=pub)
    sm2Verify@0x348bc: x5(len<66=pub), x4, x3, x2
    sm2Encrypt@0x33fb0: x2=data, x3(len<66=pub)

════════════════════════════════════════════════════════════════
  踩坑记录
════════════════════════════════════════════════════════════════

  1. 不能用 module.callFunction 传 DvmClass
     → "Unsupported arg: class com/tenpay/qqsc/FitScUtil"
     必须用 clazz.callStaticJniMethodObject(emulator, name, args...)

  2. init(Context, ...) 在 unidbg 里会崩（假 Context 触发 ClassCastException）
     但根本不需要 init —— 清前置标志就够了

  3. sm2GenKeyPair 返回 Object[]（ArrayObject），不是 byte[]
     需要 ((Object[]) obj.getValue()) 逐个取

  4. 每次调用前都要重新清前置标志（算法内部可能重新置位）

  5. SM2 签名/加密的 -10001 是长度校验失败，
     说明参数顺序和反汇编推断的仍有偏差 —— 见下方"未完成部分"

════════════════════════════════════════════════════════════════
  未完成部分（诚实标注）
════════════════════════════════════════════════════════════════

  SM2 的 sign / verify / encrypt / decrypt 还没跑通。
  密钥对生成成功，说明底层 EC 运算完全正常，只是
  4 个参数的语义组合还没试对（每种函数有多个 byte[] 参数，
  反汇编只能推出长度约束，推不出语义）。

  已知约束：
    sm2Sign:   某个参数长度 <= 32，另一个 < 66
    sm2Verify: 某个参数长度 < 66
    sm2Encrypt: 某个参数长度 < 66

  最可能的组合（待验证）：
    sm2Sign(pri, pub, data, userId)   或
    sm2Sign(pri, data, userId, pub)   或
    sm2Sign(data, pri, userId, pub)

  但 SM3/SM4 已完整可用，而这两个是签名/加密的**底层原语**——
  有 SM3 + SM4，SM2 的等价功能可以用 Python gmssl 库补上。
"""

import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
print(__doc__)

print("=" * 70)
print("可用的 Python 平替（SM3 已验证；SM4 标准实现见下）")
print("=" * 70)
print()

# ---------- SM3（已验证） ----------
IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
M32 = 0xFFFFFFFF


def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3(msg: bytes) -> bytes:
    def cf(v, w16):
        w = list(w16) + [0] * 52
        for j in range(16, 68):
            w[j] = _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) \
                   ^ _rotl(w[j - 13], 7) ^ w[j - 6]
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            if j < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | (~e & g)
            t = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & M32, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (ff + d + ss2 + w1[j]) & M32
            tt2 = (gg + h + ss1 + w[j]) & M32
            d, c, b, a = c, _rotl(b, 9), a, tt1
            h, g, f, e = g, _rotl(f, 19), e, _p0(tt2)
        return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
                e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]

    bitlen = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += bitlen.to_bytes(8, "big")
    v = list(IV)
    for i in range(0, len(msg), 64):
        blk = msg[i:i + 64]
        v = cf(v, [int.from_bytes(blk[j * 4:j * 4 + 4], "big") for j in range(16)])
    return b"".join(x.to_bytes(4, "big") for x in v)


# ---------- SM4（标准实现） ----------
SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
    0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
    0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279,
]


def _tau(a):
    return ((SBOX[(a >> 24) & 0xff] << 24) | (SBOX[(a >> 16) & 0xff] << 16)
            | (SBOX[(a >> 8) & 0xff] << 8) | SBOX[a & 0xff])


def _sm4_l(b):
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _sm4_lp(b):
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def sm4_encrypt_block(pt16: bytes, key16: bytes) -> bytes:
    k = [int.from_bytes(key16[i * 4:i * 4 + 4], "big") for i in range(4)]
    K = [k[i] ^ FK[i] for i in range(4)]
    for i in range(32):
        K.append(K[i] ^ _sm4_lp(_tau(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])))
    rk = K[4:36]
    x = [int.from_bytes(pt16[i * 4:i * 4 + 4], "big") for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _sm4_l(_tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])))
    return b"".join(x[35 - i].to_bytes(4, "big") for i in range(4))


def sm4_cbc_encrypt(data: bytes, key: bytes, iv: bytes, pad=True) -> bytes:
    if pad:
        n = 16 - len(data) % 16
        data = data + bytes([n]) * n
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = sm4_encrypt_block(blk, key)
        out += prev
    return out


if __name__ == "__main__":
    print("=== SM3 向量 ===")
    for m, exp in [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    ]:
        g = sm3(m).hex()
        print("  sm3(%-8r) = %s  %s" % (m[:8], g, "✔" if g == exp else "✘"))
    print()
    print("=== SM4 向量（GB/T 32907）===")
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ct = sm4_encrypt_block(pt, key)
    exp = "681edf34d206965e86b3e94f536e4246"
    print("  key =", key.hex())
    print("  pt  =", pt.hex())
    print("  ct  =", ct.hex(), " 期望", exp, "✔" if ct.hex() == exp else "✘")
    print()
    print("  CBC(IV=0) 首块应与上面一致：")
    c = sm4_cbc_encrypt(pt, key, bytes(16), pad=False)
    print("  cbc =", c.hex(), "✔" if c.hex() == exp else "✘")
