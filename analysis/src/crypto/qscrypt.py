#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QSCrypt::Encrypt / Decrypt 完整算法还原（静态逆向 + 反汇编验证）

=================== 密文结构（总长 = 8 + N*8）===================

  offset 0..7 : R
  offset 8..  : C_1 .. C_n    每块 8 字节

=================== 加密（Encrypt）===================

  1) 每 8 字节明文一块 P_1..P_n（不足补 0）
  2) IV_1 = R                                  ← 8 字节随机数
  3) for k = 1..n:
        T_k = TeaEncryptECB( P_k ^ IV_k , KEY )     ← 标准 TEA，大端
        C_k = T_k ^ IV_k
        IV_{k+1} = T_k
  4) 输出 = R || C_1 || ... || C_n

=================== 解密（Decrypt）===================

  1) 取 R = ct[0:8]
  2) IV = R
  3) for k = 1..n:
        T_k = C_k ^ IV_k
        P_k = TeaDecryptECB( T_k , KEY ) ^ IV_k
        IV_{k+1} = T_k

=================== 反汇编依据 ====================

  Encrypt @ base+0x2668c:
    120267a8  bl  #0x1204d470      ; TeaEncryptECB(in=&P^IV, key=this+8, out=&T)
    120267a0  eor v0.8b, v1.8b, v0.8b   ; in = P ^ IV
    120267c0-12026834  C_i = out[i] ^ IV[i]   ; 8 条 byte eor
    12026840  ldur x9, [x29,#-0x10]     ; T
    12026848  str  x9, [sp,#0x18]       ; IV = T   ← 反馈
    12026838/12026850  out_len += 8 循环

  模式位 [x0,#0x18] = 0 才走加解密（=1 直接返回空）。

=================== 用法 ====================

  python qscrypt.py enc  <key_hex> <plain_hex>
  python qscrypt.py dec  <key_hex> <cipher_hex|@file>
  python qscrypt.py selftest
"""
import sys, os, struct

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF
ROUNDS = 16


# ------------------------------------------------------------------ TEA

def _k(key16):
    return [int.from_bytes(key16[i * 4:i * 4 + 4], "big") for i in range(4)]


def tea_enc_block(pt8, key16, rounds=ROUNDS):
    v0 = int.from_bytes(pt8[0:4], "big")
    v1 = int.from_bytes(pt8[4:8], "big")
    k = _k(key16)
    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & MASK
        v0 = (v0 + ((((v1 << 4) & MASK) + k[0]) ^ ((v1 + s) & MASK)
                    ^ (((v1 >> 5) + k[1]) & MASK))) & MASK
        v1 = (v1 + ((((v0 << 4) & MASK) + k[2]) ^ ((v0 + s) & MASK)
                    ^ (((v0 >> 5) + k[3]) & MASK))) & MASK
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_dec_block(ct8, key16, rounds=ROUNDS):
    v0 = int.from_bytes(ct8[0:4], "big")
    v1 = int.from_bytes(ct8[4:8], "big")
    k = _k(key16)
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


# ------------------------------------------------------------ QSCrypt API

def qscrypt_encrypt(plain: bytes, key16: bytes, iv=None) -> bytes:
    """iv=None 时用全 0（离线复现用；真实实现取随机数）"""
    if iv is None:
        iv = b"\x00" * 8
    assert len(iv) == 8
    n = (len(plain) + 7) // 8
    out = bytearray(iv)
    cur_iv = iv
    for k in range(n):
        blk = plain[k * 8:(k + 1) * 8]
        if len(blk) < 8:
            blk = blk + b"\x00" * (8 - len(blk))
        t = tea_enc_block(_xor(blk, cur_iv), key16)
        out += _xor(t, cur_iv)
        cur_iv = t
    return bytes(out)


def qscrypt_decrypt(cipher: bytes, key16: bytes) -> bytes:
    if len(cipher) < 16 or (len(cipher) - 8) % 8 != 0:
        raise ValueError("长度不合法: %d" % len(cipher))
    cur_iv = cipher[0:8]
    out = bytearray()
    for i in range(8, len(cipher), 8):
        c = cipher[i:i + 8]
        t = _xor(c, cur_iv)
        out += _xor(tea_dec_block(t, key16), cur_iv)
        cur_iv = t
    return bytes(out)


# --------------------------------------------------------------- 自检

def selftest():
    """用 native 的 TeaEncryptECB 已知向量反推，验证封装逻辑自洽"""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("0011223344556677")

    # native 实测: TeaEncryptECB(pt,key) = 205f515574f0821c
    e = tea_enc_block(pt, key)
    print("TeaEncryptECB(0011223344556677, 000102..0f) =", e.hex(),
          "  期望 205f515574f0821c",
          "  ✔" if e.hex() == "205f515574f0821c" else "  ✘")

    d = tea_dec_block(e, key)
    print("TeaDecryptECB(上一行)                       =", d.hex(),
          "  ✔" if d.hex() == pt.hex() else "  ✘")

    # 封装往返
    for iv in (b"\x00" * 8, bytes(range(8)), bytes.fromhex("deadbeefcafe1234")):
        c = qscrypt_encrypt(pt, key, iv)
        p = qscrypt_decrypt(c, key)
        ok = p[:len(pt)] == pt
        print("封装往返 iv=%s  ct=%s  %s"
              % (iv.hex(), c.hex(), "✔" if ok else "✘"))

    # 多块
    long_pt = b"A" * 40
    c = qscrypt_encrypt(long_pt, key)
    p = qscrypt_decrypt(c, key)
    print("40 字节多块往返: len(ct)=%d  %s"
          % (len(c), "✔" if p == long_pt else "✘"))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]

    if cmd == "selftest":
        selftest()
        return

    if cmd in ("enc", "dec"):
        if len(sys.argv) < 4:
            print("用法: python qscrypt.py %s <key_hex(32)> <data_hex|@file>" % cmd)
            return
        key = bytes.fromhex(sys.argv[2])
        if len(key) != 16:
            print("key 必须是 16 字节（32 个 hex 字符）")
            return
        arg = sys.argv[3]
        if arg.startswith("@"):
            data = open(arg[1:], "rb").read()
        else:
            data = bytes.fromhex(arg)
        if cmd == "enc":
            r = qscrypt_encrypt(data, key)
            print(r.hex())
        else:
            try:
                r = qscrypt_decrypt(data, key)
            except ValueError as e:
                print("解密失败:", e)
                return
            outp = os.path.join(os.getcwd(), "qscrypt.dec.bin")
            open(outp, "wb").write(r)
            print("len =", len(r), "->", outp)
            print("hex :", r[:128].hex(" "))
            try:
                print("text:", r[:300].decode("utf-8"))
            except UnicodeDecodeError:
                pass
        return

    print(__doc__)


if __name__ == "__main__":
    main()
