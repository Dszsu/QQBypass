#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路径解析：自动定位 QQ APK 与解包目录。

按优先级：
  1. 环境变量 QQRK_APK / QQRK_DEC
  2. 相对本脚本向上找 ../.. 下的 *.apk
  3. 常见位置（E:\\安卓逆向工具\\QQ\\*.apk）
"""
import os, glob, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))


def find_apk():
    v = os.environ.get("QQRK_APK")
    if v and os.path.isfile(v):
        return v
    # 包根目录及其上一级
    for base in (_ROOT, os.path.dirname(_ROOT)):
        hits = glob.glob(os.path.join(base, "*.apk"))
        if hits:
            return hits[0]
    # 常见位置
    for p in (r"E:\安卓逆向工具\QQ", r"E:\安卓逆向工具"):
        hits = glob.glob(os.path.join(p, "*.apk"))
        if hits:
            return hits[0]
    return None


def find_dec():
    """返回解包目录（apktool d 的输出）"""
    v = os.environ.get("QQRK_DEC")
    if v and os.path.isdir(v):
        return v
    # 本包 libs/ 里已有 .so，但完整解包目录在 work/
    for cand in (
        r"E:\安卓逆向工具\QQ\work\QQ_dec",
        os.path.join(_ROOT, "QQ_dec"),
        os.path.join(os.path.dirname(_ROOT), "work", "QQ_dec"),
    ):
        if os.path.isdir(cand):
            return cand
    return None


def dec_lib(name):
    """取解包目录里的 .so，找不到就退回本包 libs/"""
    d = find_dec()
    if d:
        p = os.path.join(d, "lib", "arm64-v8a", name)
        if os.path.isfile(p):
            return p
    p = os.path.join(_ROOT, "libs", name)
    if os.path.isfile(p):
        return p
    return None


if __name__ == "__main__":
    print("apk :", find_apk())
    print("dec :", find_dec())
    print("so  :", dec_lib("libtsmqqsc.so"))
