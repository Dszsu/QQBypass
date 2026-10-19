import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from paths import find_dec


def _find_asset(name):
    dec = find_dec()
    if dec:
        p = _os.path.join(dec, "assets", name)
        if _os.path.isfile(p):
            return p
    here = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    for base in (_os.path.join(here, "samples"), here):
        p = _os.path.join(base, name)
        if _os.path.isfile(p):
            return p
    return _os.path.join("samples", name)
import sys, struct
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def read_varint(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        if x < 0x80: return r, i
        s += 7

def parse_pb(data, depth=0, maxdepth=6):
    """尽力解析 protobuf，返回 (fields, consumed)"""
    i = 0; n = len(data); out = []
    while i < n:
        try:
            key, i = read_varint(data, i)
        except IndexError:
            break
        fno = key >> 3; wt = key & 7
        if fno == 0: break
        if wt == 0:
            v, i = read_varint(data, i); out.append((fno, 'varint', v))
        elif wt == 1:
            if i+8 > n: break
            v = data[i:i+8]; i += 8; out.append((fno, 'fixed64', v.hex()))
        elif wt == 2:
            ln, i = read_varint(data, i)
            if i+ln > n: break
            v = data[i:i+ln]; i += ln
            out.append((fno, 'bytes', v))
        elif wt == 5:
            if i+4 > n: break
            v = data[i:i+4]; i += 4; out.append((fno, 'fixed32', v.hex()))
        else:
            break
    return out, i

for name in ["qq.key", "fekit.key"]:
    p = _find_asset(name)
    d = open(p, "rb").read()
    print("="*70)
    print("%s  %d bytes" % (name, len(d)))
    print("head 64:", d[:64].hex(" "))
    import collections, math
    c = collections.Counter(d); nn=len(d)
    ent = -sum(v/nn*math.log2(v/nn) for v in c.values())
    print("entropy: %.3f  unique=%d" % (ent, len(c)))
    fields, used = parse_pb(d)
    print("protobuf 解析: %d 个顶层字段, 消费 %d/%d 字节" % (len(fields), used, len(d)))
    for fno, wt, v in fields[:25]:
        if wt == 'bytes':
            try:
                s = v.decode('utf-8')
                disp = repr(s[:80])
            except UnicodeDecodeError:
                disp = v[:24].hex(" ")
            print("  #%-3d %-8s len=%-5d %s" % (fno, wt, len(v), disp))
        else:
            print("  #%-3d %-8s %s" % (fno, wt, v))