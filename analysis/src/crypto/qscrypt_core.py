#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QSCrypt::Encrypt / Decrypt —— 完整算法（静态逆向 + disasm + PLT 解析还原）
==========================================================================

反汇编依据（libmsfbootV2.so，base+0x2668c / 0x26af4）：

  Encrypt:
    120267a8  bl  0x1204d470   → QSCrypt::TeaDecryptECB   ★反向使用
    120267a0  eor v0.8b, v1.8b, v0.8b        ; T ^ IV
    120267c0..12026834  C_i = out[i] ^ IV[i]
    12026848  str x9,[sp,#0x18]              ; IV ← T （反馈）
    120267f8  bl  0x1204d490   → MD5_Update  ; 密钥/状态派生于 MD5

  Decrypt:
    12026b94  bl  0x1204d480   → rand()      ; 用 rand 状态校验头部
    12026b98  ldrb w8,[sp,#0x10]
    12026ba0  and w9,w8,#7                   ; 低 3 位 = 填充长度
    12026bb8  cmp / b.lt → 返回 0
    12026e3c..12026e48 逐字节比对，不等 → 返回 0   ★自校验

结构（总长 = 8 + 8n）：
    offset 0..7  : S       —— rand()-派生头（含填充长度于低 3 位）
    offset 8..   : C_1..C_n

核心块运算（两个方向都是一次 TeaDecryptECB + 两次异或）：
    T   = TeaDecryptECB( D ^ IV )
    OUT = T ^ IV
    下一个 IV = T

即：同一运算自逆 —— 加密走一遍，解密再走一遍。

由于 QSCrypt 在 Encrypt 里调 TeaDecryptECB、Decrypt 里也调同一个函数，
所以本文件把它记为 core()，只需要一个方向。
"""

import sys, os, struct, ctypes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF
ROUNDS = 16


# ---------------------------------------------------------------- TEA

def _kk(key16):
    return [int.from_bytes(key16[i * 4:i * 4 + 4], "big") for i in range(4)]


def tea_decrypt_block(ct8, key16, rounds=ROUNDS):
    v0 = int.from_bytes(ct8[0:4], "big")
    v1 = int.from_bytes(ct8[4:8], "big")
    k = _kk(key16)
    s = (DELTA * rounds) & MASK
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) & MASK) + k[2]) ^ ((v0 + s) & MASK)
                    ^ (((v0 >> 5) + k[3]) & MASK))) & MASK
        v0 = (v0 - ((((v1 << 4) & MASK) + k[0]) ^ ((v1 + s) & MASK)
                    ^ (((v1 >> 5) + k[1]) & MASK))) & MASK
        s = (s - DELTA) & MASK
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------ 核心块运算（自逆）

def core_block(d8, iv8, key16):
    """对应 native 的 TeaDecryptECB(d ^ iv) ^ iv，反馈 = TeaDecryptECB 输出"""
    t = tea_decrypt_block(_xor(d8, iv8), key16)
    return _xor(t, iv8), t


def qscrypt_transform(data: bytes, key16: bytes, s8: bytes) -> bytes:
    """对 8 字节对齐的 payload 做链式变换（加密/解密同一函数，自逆）"""
    out = bytearray()
    iv = s8
    for i in range(0, len(data) - len(data) % 8, 8):
        o, iv = core_block(data[i:i + 8], iv, key16)
        out += o
    return bytes(out)


# ---------------------------------------------------------------- 自检

def selftest():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("0011223344556677")

    # native 实测 TeaDecryptECB(pt,key)
    d = tea_decrypt_block(pt, key)
    print("TeaDecryptECB(0011223344556677, 000102..0f) =", d.hex())

    # core_block 自逆性
    iv = bytes(range(8))
    o1, fb = core_block(pt, iv, key)
    o2, fb2 = core_block(o1, iv, key)
    print("core 自逆: pt ->", o1.hex(), "-> ", o2.hex(),
          "  ✔" if o2 == pt else "  ✘")

    # 整链自逆
    data = bytes(range(32))
    s = bytes.fromhex("1122334455667788")
    c = qscrypt_transform(data, key, s)
    p = qscrypt_transform(c, key, s)
    print("链式自逆: %d B -> %d B -> %s"
          % (len(data), len(c), "✔" if p == data else "✘"))


# ---------------------------------------------------------------- CLI

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n用法:")
        print("  python qscrypt_core.py selftest")
        print("  python qscrypt_core.py crypt <key_hex32> <s8_hex16> <data_hex|@file>")
        print("  （crypt 是自逆的，加密解密同一个命令）")
        return

    cmd = sys.argv[1]
    if cmd == "selftest":
        selftest()
        return

    if cmd == "crypt":
        key = bytes.fromhex(sys.argv[2])
        s8 = bytes.fromhex(sys.argv[3])
        arg = sys.argv[4]
        data = open(arg[1:], "rb").read() if arg.startswith("@") else bytes.fromhex(arg)
        out = qscrypt_transform(data, key, s8)
        print("in  :", len(data), "B")
        print("out :", out.hex(" "))
        return

    print("未知命令")


if __name__ == "__main__":
    main()
