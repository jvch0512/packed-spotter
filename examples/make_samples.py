#!/usr/bin/env python3
"""Builds three synthetic PE-like files under examples/. Not real malware: headers plus filler bytes."""
import struct, sys

def lcg_bytes(n, seed):
    out = bytearray(); x = seed
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & (2**64 - 1)
        out.append((x >> 33) & 0xFF)
    return bytes(out)

def text_bytes(n):
    s = (b"The quick brown fox jumps over the lazy dog. config=%s path=C:\\Program Files\\App\\bin error: failed to open handle\n" * 200)
    return (s * (n // len(s) + 1))[:n]

def pe(sections):
    """sections: list of (name, data, virt_size, flags)"""
    n = len(sections); hdr_size = 0x200
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80)
    dos = dos.ljust(0x80, b"\0")
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14c, n, 0, 0, 0, 0xE0, 0x102)
    opt = b"\x0b\x01" + b"\0" * 222
    table = b""; body = b""; off = hdr_size
    for name, data, virt, flags in sections:
        raw = len(data)
        table += name.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", virt, 0x1000, raw, off if raw else 0, 0, 0, 0, 0, flags)
        body += data; off += raw
    head = (dos + coff + opt + table).ljust(hdr_size, b"\0")
    return head + body

X, R, W = 0x20000000, 0x40000000, 0x80000000
CODE, DATA, RSRC = 0x60000020, 0x40000040, 0x40000040
open("examples/normal.exe", "wb").write(pe([(".text", text_bytes(20480), 20480, CODE), (".rdata", text_bytes(8192), 8192, DATA), (".data", b"\0" * 2048, 4096, 0xC0000040), (".rsrc", text_bytes(4096), 4096, RSRC)]))
open("examples/upx-like.exe", "wb").write(pe([("UPX0", b"", 65536, 0xE0000080), ("UPX1", lcg_bytes(24576, 7), 24576, 0xE0000040), (".rsrc", text_bytes(1024), 1024, RSRC)]))
open("examples/encrypted-blob.bin", "wb").write(lcg_bytes(40960, 99))
