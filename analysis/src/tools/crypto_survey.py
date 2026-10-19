#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量分析 QQ 加密相关 .so 的符号与算法特征。"""
import sys, os, re, collections

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(find_dec() or "", "lib", "arm64-v8a")

TARGETS = [
    "libtsmqqsc.so", "libckeygenerator.so", "libturingxq.so",
    "libturingmfa.so", "libQSec.so", "libfekit.so",
    "libcrypto.so", "libDBEncryptV2.so", "libpiccryptor.so",
    "libMSFKernel.so", "libmsfbootV2.so",
]

# 密码学特征
CRYPTO_PAT = {
    "AES": [b"aes_", b"AES_", b"aes128", b"aes256", b"EVP_aes", b"rijndael", b"Rijndael"],
    "SM2/SM3/SM4": [b"sm2", b"sm3", b"sm4", b"SM2", b"SM3", b"SM4", b"ECC_"],
    "RSA": [b"RSA_", b"rsa_", b"BN_mod", b"pkcs1", b"PKCS1"],
    "TEA/XXTEA": [b"tea", b"Tea", b"TEA", b"xxtea", b"XXTEA", b"delta"],
    "MD5": [b"MD5", b"md5", b"md5_block"],
    "SHA": [b"SHA1", b"SHA256", b"sha256", b"sha1"],
    "HMAC": [b"HMAC", b"hmac"],
    "ChaCha/Salsa": [b"chacha", b"ChaCha", b"salsa", b"Salsa"],
    "Curve25519": [b"curve25519", b"Curve25519", b"x25519"],
    "secp256": [b"secp256", b"secp256r1", b"secp256k1"],
    "OpenSSL": [b"EVP_", b"BIO_", b"SSL_CTX", b"X509_"],
}


def entropy(d):
    if not d:
        return 0
    c = collections.Counter(d)
    n = len(d)
    return -sum(v / n * 2 ** 0 * __import__("math").log2(v / n) for v in c.values())


def main():
    print("=" * 78)
    print("QQ 加密相关 .so 全景分析")
    print("=" * 78)

    for name in TARGETS:
        p = os.path.join(LIB, name)
        if not os.path.isfile(p):
            print("\n### %s  —— 不存在" % name)
            continue
        try:
            e = ELF(p)
        except Exception as ex:
            print("\n### %s  —— 解析失败: %s" % (name, ex))
            continue

        funcs = [s for s in e.dynsym if s["type"] == 2 and s["name"]]
        objs = [s for s in e.dynsym if s["type"] == 1 and s["name"]]
        stripped = "否" if funcs else "是(空 dynsym)"

        print("\n### %s" % name)
        print("    大小 %.2f MB   dynsym=%d  FUNC=%d  OBJECT=%d  已 strip=%s"
              % (len(e.d) / 1048576, len(e.dynsym), len(funcs), len(objs), stripped))

        # 密码学特征扫描（前 2MB）
        blob = e.d[:min(len(e.d), 2 * 1024 * 1024)]
        hits = {}
        for algo, pats in CRYPTO_PAT.items():
            n = 0
            for pat in pats:
                n += blob.count(pat)
            if n:
                hits[algo] = n
        if hits:
            print("    算法特征: " + ", ".join("%s×%d" % (k, v) for k, v in
                                            sorted(hits.items(), key=lambda x: -x[1])))
        else:
            print("    算法特征: 未从字符串中发现（可能符号/字符串已加密）")

        # 高价值符号
        show = [s for s in funcs if re.search(
            r"(?i)(encrypt|decrypt|cipher|crypt|sign|verify|hmac|digest|hash|"
            r"key|sm2|sm3|sm4|aes|rsa|tea|md5|sha|rand|nonce|token)", s["name"])]
        show.sort(key=lambda s: -s["size"])
        if show:
            print("    加密相关导出符号 (%d):" % len(show))
            for s in show[:12]:
                print("      %08x %7d  %s" % (s["value"], s["size"], s["name"][:100]))
            if len(show) > 12:
                print("      ... 还有 %d 个" % (len(show) - 12))
        else:
            print("    加密相关导出符号: 无")


if __name__ == "__main__":
    main()
