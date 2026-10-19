import sys, os, re, collections, struct

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import find_dec, dec_lib
from elfinfo import ELF

WORK = os.path.dirname(os.path.abspath(__file__))
P = dec_lib("libfekit.so")

e = ELF(P)
d = e.d
print("=" * 78)
print("libfekit.so 结构分析  (%.2f MB)" % (len(d) / 1048576))
print("=" * 78)

# ---------- section ----------
print("\n--- Section 布局 ---")
for s in e.sh:
    if s["size"] > 0:
        print("  %-22s %-10s addr=0x%08x size=%9d" % (
            s["sname"], str(s["type"]), s["addr"], s["size"]))

# ---------- datadiv_decode ----------
print("\n--- OLLVM .datadiv_decode 函数 ---")
dd = [s for s in e.dynsym if s["name"] and "datadiv" in s["name"]]
for s in dd:
    print("  %08x  size=%d  %s" % (s["value"], s["size"], s["name"]))
if not dd:
    print("  未在 dynsym 中找到，扫描 opcode 特征")

# ---------- 字符串统计 ----------
print("\n--- 字符串分布（判断加密程度）---")
def entries(blob, minlen=5):
    out = []
    for m in re.finditer(rb"[ -~]{%d,}" % minlen, blob):
        out.append(m.group())
    return out

for name in (".rodata", ".data", ".data.rel.ro", ".text"):
    sec = [s for s in e.sh if s["sname"] == name]
    if not sec:
        continue
    s = sec[0]
    seg = d[s["off"]:s["off"] + s["size"]]
    strs = entries(seg)
    total = sum(len(x) for x in strs)
    ratio = total / max(1, len(seg))
    print("  %-14s size=%9d  可打印串 %6d 个 / %8d B  (占比 %.2f%%)"
          % (name, len(seg), len(strs), total, ratio * 100))

# ---------- 可疑常量 ----------
print("\n--- 加密/混淆常量 ---")
blob = d
for pat, label in [
    (b"datadiv", ".datadiv"),
    (b"OLLVM", "OLLVM"),
    (b"ollvm", "ollvm"),
    (b"bcf", "bcf(控制流平坦化)"),
    (b"fla", "fla"),
    (b"sub_", "sub_"),
    (b"\x13\x37\x13\x37", "0x13371337"),
    (struct.pack("<I", 0x9E3779B9), "TEA delta"),
    (struct.pack(">I", 0x9E3779B9), "TEA delta BE"),
]:
    c = blob.count(pat)
    if c:
        print("  %-28s ×%d" % (label, c))

# ---------- 导出符号分类 ----------
print("\n--- 导出符号构成 ---")
funcs = [s for s in e.dynsym if s["type"] == 2 and s["name"]]
java = [s for s in funcs if s["name"].startswith("Java_")]
cpp = [s for s in funcs if s["name"].startswith("_Z")]
plain = [s for s in funcs if not s["name"].startswith("Java_")
         and not s["name"].startswith("_Z")]
print("  总计 %d" % len(funcs))
print("    Java_*   %d" % len(java))
print("    _Z*      %d" % len(cpp))
print("    其他     %d" % len(plain))
if java:
    print("\n  Java_ 导出（前 20）:")
    for s in sorted(java, key=lambda x: -x["size"])[:20]:
        print("    %08x %6d  %s" % (s["value"], s["size"], s["name"][:90]))
if plain:
    print("\n  其他导出（前 20）:")
    for s in sorted(plain, key=lambda x: -x["size"])[:20]:
        print("    %08x %6d  %s" % (s["value"], s["size"], s["name"][:90]))

# ---------- 找 JNI_OnLoad 实际长度 ----------
print("\n--- 关键函数 ---")
for nm in ("JNI_OnLoad", "JNI_OnUnload"):
    for s in e.dynsym:
        if s["name"] == nm:
            print("  %-14s @0x%08x  size=%d" % (nm, s["value"], s["size"]))
            break
