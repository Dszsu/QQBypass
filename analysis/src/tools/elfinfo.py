#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""轻量 ELF64 解析：导出 .dynsym / .symtab 符号、section、依赖库。
不依赖 readelf / pyelftools。"""
import struct, sys, os


class ELF:
    def __init__(self, path):
        self.p = path
        self.d = open(path, "rb").read()
        d = self.d
        assert d[:4] == b"\x7fELF", "not ELF"
        self.cls = d[4]          # 1=32 2=64
        self.end = "<" if d[5] == 1 else ">"
        e = self.end
        self.e_type, self.e_machine = struct.unpack_from(e + "HH", d, 16)
        if self.cls == 2:
            (self.e_phoff, self.e_shoff) = struct.unpack_from(e + "QQ", d, 0x20)
            (self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx) = \
                struct.unpack_from(e + "HHHHH", d, 0x36)
        else:
            (self.e_phoff, self.e_shoff) = struct.unpack_from(e + "II", d, 0x1C)
            (self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx) = \
                struct.unpack_from(e + "HHHHH", d, 0x2A)
        self._sections()
        self._dyn()

    def _sections(self):
        d, e = self.d, self.end
        self.sh = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.cls == 2:
                name, typ, flags, addr, off_, size, link, info, align, entsize = \
                    struct.unpack_from(e + "IIQQQQIIQQ", d, off)
            else:
                name, typ, flags, addr, off_, size, link, info, align, entsize = \
                    struct.unpack_from(e + "IIIIIIIIII", d, off)
            self.sh.append(dict(name=name, type=typ, flags=flags, addr=addr,
                                off=off_, size=size, link=link, info=info,
                                entsize=entsize))
        # shstrtab
        if self.e_shstrndx < len(self.sh) and self.sh[self.e_shstrndx]["off"]:
            base = self.sh[self.e_shstrndx]["off"]
            for s in self.sh:
                s["sname"] = self._cstr(base + s["name"])
        else:
            for s in self.sh:
                s["sname"] = ""

    def _cstr(self, off):
        end = self.d.index(b"\x00", off)
        return self.d[off:end].decode("utf-8", "replace")

    def _dyn(self):
        self.dynstr = b""
        for s in self.sh:
            if s["sname"] == ".dynstr":
                self.dynstr = self.d[s["off"]:s["off"] + s["size"]]
        self.dynsym = []
        for s in self.sh:
            if s["sname"] != ".dynsym":
                continue
            n = s["size"] // 24 if self.cls == 2 else s["size"] // 16
            for i in range(n):
                o = s["off"] + i * (24 if self.cls == 2 else 16)
                if self.cls == 2:
                    nm, info, other, shndx, val, size = struct.unpack_from(self.end + "IBBHQQ", self.d, o)
                else:
                    nm, val, size, info, other, shndx = struct.unpack_from(self.end + "IIIBBH", self.d, o)
                name = self._cstr_str(self.dynstr, nm)
                bind = info >> 4
                typ = info & 0xF
                self.dynsym.append(dict(name=name, value=val, size=size, bind=bind,
                                        type=typ, shndx=shndx))

    def _cstr_str(self, blob, off):
        if off == 0 or off >= len(blob):
            return ""
        end = blob.index(b"\x00", off) if b"\x00" in blob[off:] else len(blob)
        return blob[off:end].decode("utf-8", "replace")

    def sections_report(self):
        out = []
        for s in self.sh:
            out.append("%-22s %-8s addr=0x%08x size=%9d" % (
                s["sname"], {1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 8: "NOBITS",
                             11: "DYNSYM", 2 if False else 6: "DYNAMIC"}.get(s["type"], str(s["type"])),
                s["addr"], s["size"]))
        return out

    def symbols(self):
        return self.dynsym


def main():
    for path in sys.argv[1:]:
        e = ELF(path)
        mach = {0x28: "ARM", 0xB7: "AARCH64", 0x3E: "x86_64"}.get(e.e_machine, hex(e.e_machine))
        print("=" * 70)
        print("%s  %s  %s" % (os.path.basename(path), "ELF64" if e.cls == 2 else "ELF32", mach))
        print(" size %.2f MB  sections=%d  dynsym=%d" % (len(e.d) / 1048576, len(e.sh), len(e.dynsym)))
        print("-" * 70)
        for line in e.sections_report():
            print("  " + line)
        print("-" * 70)
        funcs = [s for s in e.dynsym if s["type"] == 2 and s["name"]]
        objs = [s for s in e.dynsym if s["type"] == 1 and s["name"]]
        print("  exported FUNC: %d   exported OBJECT: %d" % (len(funcs), len(objs)))
        for s in sorted(funcs, key=lambda x: -x["size"])[:60]:
            print("    %08x  %7d  %s" % (s["value"], s["size"], s["name"]))
        if len(funcs) > 60:
            print("    ... %d more funcs" % (len(funcs) - 60))
        for s in sorted(objs, key=lambda x: -x["size"])[:15]:
            print("    OBJ %08x  %7d  %s" % (s["value"], s["size"], s["name"]))


if __name__ == "__main__":
    main()
