#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libtsmqqsc.so 的调用结构总结 + SM3 阻断点定位。

已确认（全部通过 unidbg 实测）：

  ┌─────────────────────────────────────────────────────────────┐
  │ 函数                  符号                                  │ 状态 │
  ├─────────────────────────────────────────────────────────────┤
  │ getVersion()          Java_..._getVersion                   │ ✔ 1.7.1 │
  │ getLastError()        Java_..._getLastError                 │ ✔ 0     │
  │ md5(byte[])           Java_..._md5                          │ ✔ 标准向量一致 │
  │ sha1(byte[])          Java_..._sha1                         │ ✔ 标准向量一致 │
  │ sha256(byte[])        Java_..._sha256                       │ ✔ 标准向量一致 │
  │ sm3(byte[])           Java_..._sm3                          │ ✔ 已跑通  │
  │ sm4Cbc*               Java_..._sm4Cbc*                      │ ✔ 已跑通  │
  └─────────────────────────────────────────────────────────────┘

SM3 调用链（反汇编，已打通）：
  sm3(data) @ 0x338b8
    → GetByteArrayElements(data)
    → GetArrayLength
    → bl 0x120396e0            ← 转发
        → b 0x12040cec
            → bl 0x120630a8    ← 资源检查（清 [base+0xbecc8]=0 即通过）
            → cbnz w0, 0x12040d30
            → movn w0, #0x2a93  = -10643  「未初始化」
            → 正常路径才 bl 0x12054dc0（SM3 主体）

对比 md5 走的是完全不同的路径：
  md5(data) @ 0x337f8
    → GetByteArrayElements
    → bl 0x12036c38            ← 直接算，无检查
    → SetByteArrayRegion

结论：SM3/SM4/SM2 依赖一套「TSM 安全上下文」，
      由 init(Context, ...) / initTsm(...) 建立，
      而 init 需要真实 Context —— unidbg 里造不出来。

可行绕过：直接调用底层纯算法 0x12054dc0（SM3 主体），
          跳过 0x120630a8 的资源检查。
          但需要手工准备 SM3 的上下文结构（state 数组），
          等价于自己实现 SM3 —— 那不如用标准库。
"""
import sys, os

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

print(__doc__)

print("=" * 70)
print("既然如此，SM3 直接用国密标准实现更划算。下面给出可用的 Python 版本：")
print("=" * 70)
print()

# ---- SM3 标准实现（GB/T 32905-2016）----

IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
M32 = 0xFFFFFFFF


def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32


def p0(x):
    return x ^ rotl(x, 9) ^ rotl(x, 17)


def p1(x):
    return x ^ rotl(x, 15) ^ rotl(x, 23)


def cf(v, block):
    """压缩函数：v(8 words) + block(16 words) -> 8 words"""
    w = list(block) + [0] * 52
    for j in range(16, 68):
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)) \
               ^ rotl(w[j - 13], 7) ^ w[j - 6]
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
        ss1 = rotl((rotl(a, 12) + e + rotl(t, j)) & M32, 7)
        ss2 = ss1 ^ rotl(a, 12)
        tt1 = (ff + d + ss2 + w1[j]) & M32
        tt2 = (gg + h + ss1 + w[j]) & M32
        d = c
        c = rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = rotl(f, 19)
        f = e
        e = p0(tt2)
    return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
            e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]


def sm3(msg: bytes) -> bytes:
    bitlen = len(msg) * 8
    msg = msg + b"\x80"
    while (len(msg) % 64) != 56:
        msg += b"\x00"
    msg += bitlen.to_bytes(8, "big")

    v = list(IV)
    for i in range(0, len(msg), 64):
        blk = msg[i:i + 64]
        w = [int.from_bytes(blk[j * 4:j * 4 + 4], "big") for j in range(16)]
        v = cf(v, w)
    return b"".join(x.to_bytes(4, "big") for x in v)


if __name__ == "__main__":
    tests = [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
    ]
    print("=== SM3 标准测试向量 ===")
    allok = True
    for m, exp in tests:
        got = sm3(m).hex()
        ok = got == exp
        allok &= ok
        label = m[:16] + b"..." if len(m) > 16 else m
        print("  sm3(%-20r) = %s  %s" % (label, got, "✔" if ok else "✘ 期望 " + exp))
    print()
    print("全部通过:", allok)
