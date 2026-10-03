# -*- coding: utf-8 -*-
"""
MCPDecompiler — 高性能 Python 并发版 (port of MCPDecompiler C# / Rotor.Crypto.dll)

用法:
    python mcp_decompile.py 3715.mcp [-o OUTPUT_DIR] [-w WORKERS]
    python mcp_decompile.py --mcs some.mcs [-o out.mcs]     # 单个 mcs 文件解包

实现说明:
  * Rotor 转子密码: 从 Rotor.Crypto.dll (IDA 逆向) 移植的纯 Python 实现,
    每次 Decrypt 调用前状态都会被 DLL 复位, 因此每个文件可完全独立解密 -> 可并行。
  * 并发: ProcessPoolExecutor (多进程绕过 GIL), worker 内对 Rotor 状态只做一次初始化,
    之后每个文件仅复位 6 字节里程计; mcp 数据通过 mmap 零拷贝读取。
"""

import argparse
import mmap
import os
import struct
import sys
import time
import zlib
from concurrent.futures import ProcessPoolExecutor, as_completed

PY27_HEADER = b"\x03\xf3\x0d\x0a\x00\x00\x00\x00"

ROTOR_KEY = 'j2h56ogodh3skj2h56ogodh3skj2h56ogodh3skj2h56ogodh3sk=dziaq;j2h56ogodh3sk|`o=5v7!"-276=dziaq;j2h56ogodh3sk|`o=5v7!"-276=dziaq;j2h56ogodh3sk|`o=5v7!"-276=dziaq;j2h56ogodh3sk|`o=5v7!"-276=dziaq;j2h56ogodh3sk|`o=5v7!"-276$@=dziaq;=dziaq;=dziaq;=dziaq;=dziaq;=dziaq;=dziaq;|`o=5v7!"-276|`o=5v7!"-276&]`'.encode("utf-8")

RC4_KEY = bytes([0x8D, 0x06, 0xE8, 0xC8, 0xB7, 0xD7, 0xB7, 0x28, 0x46, 0x51, 0xAE, 0x04])

OPCODE_MAGIC_MOD = -1135027243
OPCODE_MAGIC_VANILLA = -901139953

VANILLA_MAP = {
    0x01: 0x05, 0x02: 0x4C, 0x03: 0x0F, 0x04: 0x28, 0x05: 0x29, 0x06: 0x2A,
    0x07: 0x2B, 0x08: 0x19, 0x09: 0x48, 0x0A: 0x3B, 0x0B: 0x13, 0x0D: 0x4B,
    0x0E: 0x1B, 0x0F: 0x44, 0x10: 0x38, 0x11: 0x57, 0x12: 0x56, 0x13: 0x1C,
    0x14: 0x36, 0x15: 0x14, 0x17: 0x47, 0x18: 0x39, 0x1A: 0x51, 0x1B: 0x1E,
    0x1C: 0x1F, 0x1D: 0x20, 0x1E: 0x21, 0x1F: 0x3F, 0x23: 0x3C, 0x27: 0x3A,
    0x28: 0x58, 0x29: 0x4D, 0x2A: 0x15, 0x2B: 0x04, 0x2C: 0x0A, 0x2E: 0x50,
    0x2F: 0x49, 0x31: 0x46, 0x33: 0x43, 0x34: 0x03, 0x35: 0x52, 0x36: 0x18,
    0x3B: 0x3E, 0x3C: 0x4E, 0x3E: 0x32, 0x3F: 0x33, 0x40: 0x34, 0x41: 0x35,
    0x42: 0x0D, 0x43: 0x59, 0x44: 0x4F, 0x46: 0x0B, 0x47: 0x1D, 0x48: 0x41,
    0x49: 0x17, 0x4B: 0x16, 0x4D: 0x37, 0x4E: 0x42, 0x4F: 0x55, 0x50: 0x02,
    0x51: 0x53, 0x52: 0x54, 0x53: 0x01, 0x56: 0x0C, 0x57: 0x1A, 0x58: 0x4A,
    0x59: 0x3D, 0x5A: 0x09, 0x5C: 0x40, 0x60: 0x89, 0x66: 0x91, 0x6B: 0x5D,
    0x6E: 0x63, 0x6F: 0x68, 0x74: 0x7A, 0x79: 0x6E, 0x7B: 0x71, 0x84: 0x65,
    0x85: 0x88, 0x86: 0x61, 0x87: 0x5B, 0x88: 0x74, 0x89: 0x6A, 0x8C: 0x7C,
    0x90: 0x83, 0x9F: 0x7D, 0xA1: 0x69, 0xA2: 0x7E, 0xA3: 0x6D, 0xA6: 0x86,
    0xA7: 0x77, 0xAF: 0x67, 0xB6: 0x82, 0xBD: 0x92, 0xC2: 0x8F, 0xC3: 0x6F,
    0xC9: 0x5A, 0xD0: 0x78, 0xD1: 0x79, 0xD4: 0x5F, 0xD5: 0x70, 0xD6: 0x87,
    0xD8: 0x5E, 0xDA: 0x72, 0xDE: 0x64, 0xDF: 0x93, 0xE1: 0x60, 0xE4: 0x6B,
    0xE5: 0x66, 0xE9: 0x8C, 0xEA: 0x8D, 0xEB: 0x8E, 0xF0: 0x62, 0xF3: 0x73,
    0xF7: 0x84, 0xFA: 0x6C, 0xFC: 0x85, 0xFE: 0x5C,
}

MOD_MAP = {
    0x01: 0x53, 0x02: 0x51, 0x04: 0x3E, 0x05: 0x4A, 0x08: 0x1E, 0x09: 0x1F,
    0x0A: 0x20, 0x0B: 0x21, 0x0C: 0x09, 0x0E: 0x37, 0x0F: 0x17, 0x10: 0x0B,
    0x12: 0x52, 0x14: 0x4B, 0x15: 0x44, 0x17: 0x02, 0x1A: 0x15, 0x1B: 0x0D,
    0x1C: 0x3F, 0x1F: 0x42, 0x20: 0x3A, 0x22: 0x04, 0x23: 0x55, 0x24: 0x57,
    0x25: 0x39, 0x26: 0x36, 0x28: 0x4D, 0x2A: 0x4F, 0x2B: 0x41, 0x2C: 0x14,
    0x2D: 0x46, 0x2E: 0x38, 0x2F: 0x3C, 0x30: 0x47, 0x31: 0x1B, 0x32: 0x0C,
    0x33: 0x03, 0x35: 0x16, 0x37: 0x59, 0x38: 0x56, 0x39: 0x43, 0x3B: 0x3A,
    0x3C: 0x28, 0x3D: 0x29, 0x3E: 0x2A, 0x3F: 0x2B, 0x40: 0x1C, 0x41: 0x0F,
    0x43: 0x3D, 0x44: 0x01, 0x45: 0x48, 0x46: 0x1A, 0x47: 0x19, 0x48: 0x3B,
    0x49: 0x50, 0x4A: 0x0A, 0x4C: 0x18, 0x4D: 0x54, 0x4E: 0x05, 0x4F: 0x58,
    0x51: 0x13, 0x54: 0x32, 0x55: 0x33, 0x56: 0x34, 0x57: 0x35, 0x58: 0x40,
    0x59: 0x4C, 0x5B: 0x49, 0x5C: 0x4E, 0x5E: 0x89, 0x61: 0x69, 0x66: 0x63,
    0x72: 0x91, 0x74: 0x83, 0x78: 0x79, 0x82: 0x5F, 0x8B: 0x85, 0x8D: 0x8C,
    0x8E: 0x8D, 0x8F: 0x8E, 0x94: 0x6E, 0x95: 0x5A, 0x99: 0x7E, 0x9E: 0x5C,
    0xAC: 0x86, 0xAF: 0x66, 0xB0: 0x72, 0xB9: 0x7A, 0xBB: 0x93, 0xBC: 0x82,
    0xBE: 0x62, 0xC0: 0x7D, 0xC2: 0x84, 0xC4: 0x70, 0xC6: 0x92, 0xCA: 0x60,
    0xCC: 0x65, 0xCD: 0x88, 0xD1: 0x68, 0xD2: 0x6A, 0xD4: 0x61, 0xD5: 0x6B,
    0xD6: 0x77, 0xD9: 0x87, 0xDB: 0x6D, 0xDC: 0x8F, 0xDD: 0x5B, 0xDF: 0x64,
    0xE5: 0x67, 0xE8: 0x71, 0xE9: 0x78, 0xEB: 0x6C, 0xEE: 0x5D, 0xF2: 0x73,
    0xF3: 0x6F, 0xF4: 0x7C, 0xF7: 0x5E, 0xFD: 0x74,
}

DEFAULT_MAP = {}

# 加密诱饵函数的名称后缀 (来自 FixFinal.py), 命中后替换为空函数
ENCRYPTED_SUFFIXES = (
    b'_01dVersi0n',
    b'_furtureVersion',
    b'_exceptV',
    b'_newVersi0n',
    b'_new_Version2',
)

I32 = struct.Struct("<i").pack


class ParseError(Exception):
    pass


# --------------------------------------------------------------------------
# Rotor 转子密码 (移植自 Rotor.Crypto.dll)
# --------------------------------------------------------------------------

def _rotor_init(key):
    """对应 DLL: SetKey -> sub_10001140 (key 混合) + sub_100013D0 (轮生成)"""
    # --- sub_10001140: key mixing ---
    a = 995    # v19 / s0
    b = 576    # v5  / s1
    c = 767    # v18 / s2
    # v17, v16 仅存入结构体, 不参与后续运算
    for ch in key:
        a = (ch + ((8 * a | (a >> 13)) & 0xFFFF)) & 0xFFFF
        b = ch ^ ((8 * b | (b >> 13)) & 0xFFFF)
        c = (((8 * c | (c >> 13)) & 0xFFFF) - ch) & 0xFFFF

    # 种子按 int16 符号扩展存入 (DLL 用 movsx), 负数种子会改变 RNG 序列
    def _sx(v):
        return v - 0x10000 if v & 0x8000 else v

    s0, s1, s2 = _sx(a), _sx(b | 1), _sx(c)

    # --- Wichmann-Hill 组合随机数 (sub_10001000) ---
    state = [s0, s1, s2]

    def rnd(n):
        s0, s1, s2 = state
        s0 = (171 * s0) % 30269
        s1 = (172 * s1) % 30307
        s2 = (170 * s2) % 30323
        state[0], state[1], state[2] = s0, s1, s2
        x = s0 / 30269.0 + s1 / 30307.0 + s2 / 30323.0
        return int(n * (x - int(x))) % n

    # --- sub_100013D0: 6 层轮 + 里程计 ---
    counter = [1] * 6
    incs = [1] * 6
    inv = [list(range(256)) for _ in range(6)]
    wheels = [list(range(256)) for _ in range(6)]
    for i in range(6):
        counter[i] = rnd(256)
        incs[i] = 2 * rnd(128) + 1
        w = wheels[i]
        row = inv[i]
        n = 256
        while n >= 2:                      # Fisher-Yates (降序)
            j = rnd(n)
            n -= 1
            w[j], w[n] = w[n], w[j]
            row[w[n]] = n
        row[w[0]] = 0
    return inv, counter, incs


def rotor_decrypt(data, inv, counter0, incs):
    """对应 DLL: RotorEncrypt/RotorDecrypt (binary flag = 0 分支)。
    每次调用等价于 DLL 的完整调用(末尾自动复位), 文件间相互独立。"""
    (v0, v1, v2, v3, v4, v5) = inv
    i0, i1, i2, i3, i4, i5 = incs
    c0, c1, c2, c3, c4, c5 = counter0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        r = v5[byte] ^ c5
        r = v4[r] ^ c4
        r = v3[r] ^ c3
        r = v2[r] ^ c2
        r = v1[r] ^ c1
        out[idx] = v0[r] ^ c0
        # 里程计递增 (注意: DLL 的进位是字节加法, 255+1 直接回绕)
        v = c0 + i0
        c0 = v & 0xFF
        if v > 255:
            c1 = (c1 + 1) & 0xFF
        v = c1 + i1
        c1 = v & 0xFF
        if v > 255:
            c2 = (c2 + 1) & 0xFF
        v = c2 + i2
        c2 = v & 0xFF
        if v > 255:
            c3 = (c3 + 1) & 0xFF
        v = c3 + i3
        c3 = v & 0xFF
        if v > 255:
            c4 = (c4 + 1) & 0xFF
        v = c4 + i4
        c4 = v & 0xFF
        if v > 255:
            c5 = (c5 + 1) & 0xFF
        v = c5 + i5
        c5 = v & 0xFF
    return bytes(out)


def rc4(key, data):
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray(len(data))
    a = j = 0
    for i, ch in enumerate(data):
        a = (a + 1) & 0xFF
        j = (j + box[a]) & 0xFF
        box[a], box[j] = box[j], box[a]
        out[i] = ch ^ box[(box[a] + box[j]) & 0xFF]
    return bytes(out)


# --------------------------------------------------------------------------
# ParseMarshal 移植 (3 遍 r_object, 与 C# 逐 case 对应, 含其原始字节级 bug 行为)
# --------------------------------------------------------------------------

class MarshalParser:
    def __init__(self, fix_encrypted=True):
        self.data = b""
        self.pos = 0
        self.is_init = False
        self.is_init2 = False
        self.string_interned = []
        self._si_map = {}
        self.interned = []
        self._in_map = {}
        self.filename = b""
        self.bad_refs = 0
        self.fix_encrypted = fix_encrypted
        self.fixed_count = 0

    # ---- 基础读取 ----
    def _read(self, n):
        p = self.pos
        end = p + n
        if end > len(self.data):
            raise ParseError("unexpected EOF")
        self.pos = end
        return self.data[p:end]

    def r_int(self):
        p = self.pos
        end = p + 4
        if end > len(self.data):
            raise ParseError("unexpected EOF")
        self.pos = end
        return int.from_bytes(self.data[p:end], "little", signed=True)

    # ---- interned 收集 (pass1) ----
    def _collect(self, text):
        if not self.is_init2:
            self._si_map.setdefault(text, len(self.string_interned))
            self.string_interned.append(text)

    # ---- 主递归 ----
    def r_object(self):
        t = self._read(1)[0]
        if t == 0x30 or t == 0x4E or t == 0x54 or t == 0x53 or t == 0x2E:
            return bytes([t])
        if t == 0x46:
            return b"\x45"
        if t == 0x69:
            return b"\x69" + self._read(4)
        if t == 0x49:
            return b"\x49" + self._read(8)
        if t == 0x66:
            n = self._read(1)[0]
            return b"\x66" + bytes((n,)) + self._read(n)
        if t == 0x67:
            return b"\x67" + self._read(8)
        if t == 0x78:
            return b"\x78" + self._read(16)
        if t == 0x79:
            return b"\x79" + self._read(16)
        if t == 0x41:  # -> 0xfe, int32 长度
            n = self.r_int()
            text = self._read(n) if n != 0 else b""
            self._collect(text)
            return b"\xfe" + I32(n) + text
        if t == 0x61:
            n = self.r_int()
            text = self._read(n) if n != 0 else b""
            return b"\x61" + I32(n) + text
        if t == 0x51:  # 'Z' -> 0xfe, byte 长度 (长度为 0 时 C# 写 int32, 保留该行为)
            n = self._read(1)[0]
            if n != 0:
                text = self._read(n)
                self._collect(text)
                return b"\xfe" + bytes((n,)) + text
            self._collect(b"")
            return b"\xfe" + I32(0)
        if t == 0x7A:
            n = self._read(1)[0]
            text = self._read(n) if n != 0 else b""
            return b"\x7A" + bytes((n,)) + text
        if t == 0x6C:  # 'l'
            n = self.r_int()
            body = bytearray()
            if n != 0:
                for _ in range(abs(n)):
                    body += self._read(2)
            return b"\x6C" + I32(abs(n) if n != 0 else 0) + bytes(body)
        if t == 0x73:
            n = self.r_int()
            return b"\x73" + I32(n) + self._read(n)
        if t == 0xFE:  # interned
            n = self.r_int()
            text = self._read(n) if n != 0 else b""
            if self.is_init:  # pass3: 去重 -> 't' 或 'R'
                si = self._si_map.get(text)
                if si is None:
                    return b"\x74" + I32(n) + text
                ii = self._in_map.get(text)
                if ii is not None:
                    return b"\x52" + I32(ii)
                self._in_map.setdefault(text, len(self.interned))
                self.interned.append(text)
                return b"\x74" + I32(n) + text
            return b"\xfe" + I32(n) + text
        if t == 0x74:  # 't' -> 0xfe
            n = self.r_int()
            text = self._read(n) if n != 0 else b""
            self._collect(text)
            return b"\xfe" + I32(n) + text
        if t == 0x0F:  # xor 串 -> 0xfe
            n = self.r_int()
            text = bytes(b ^ 0x8D for b in self._read(n)) if n != 0 else b""
            self._collect(text)
            return b"\xfe" + I32(n) + text
        if t == 0x08:  # xor 串 -> 's'
            n = self.r_int()
            text = bytes(b ^ 0x8D for b in self._read(n)) if n != 0 else b""
            return b"\x73" + I32(n) + text
        if t == 0x0E:  # xor 串 -> 'u'
            n = self.r_int()
            text = bytes(b ^ 0x8D for b in self._read(n)) if n != 0 else b""
            return b"\x75" + I32(n) + text
        if t == 0x6D:  # rc4 串 -> 's'
            n = self.r_int()
            text = rc4(RC4_KEY, self._read(n)) if n != 0 else b""
            return b"\x73" + I32(n) + text
        if t == 0x62:  # rc4 串 -> 0xfe
            n = self.r_int()
            text = rc4(RC4_KEY, self._read(n)) if n != 0 else b""
            self._collect(text)
            return b"\xfe" + I32(n) + text
        if t == 0x31:  # rc4 串 -> 'u'
            n = self.r_int()
            text = rc4(RC4_KEY, self._read(n)) if n != 0 else b""
            return b"\x75" + I32(n) + text
        if t == 0x52:  # 'R' 引用
            n = self.r_int()
            if self.is_init2:  # pass2/3: 展开为具体串
                si = self.string_interned
                if 0 <= n < len(si):
                    text = si[n]
                else:
                    self.bad_refs += 1
                    text = si[-1] if si else b"UnknowType"
                return b"\xfe" + I32(len(text)) + text
            return b"\x52" + I32(n)
        if t == 0x28:  # '(' int 计数
            n = self.r_int()
            body = bytearray()
            for _ in range(n):
                body += self.r_object()
            return b"\x28" + I32(n) + bytes(body)
        if t == 0x29:  # ')' byte 计数
            n = self._read(1)[0]
            body = bytearray()
            for _ in range(n):
                body += self.r_object()
            return b"\x29" + bytes((n,)) + bytes(body)
        if t == 0x5B:  # '[' 读 int32, 写 byte 计数 (保留 C# 行为)
            n = self.r_int()
            body = bytearray()
            for _ in range(n):
                body += self.r_object()
            return b"\x5B" + bytes((n & 0xFF,)) + bytes(body)
        if t == 0x3C:  # '<'
            n = self.r_int()
            body = bytearray()
            for _ in range(n):
                body += self.r_object()
            return b"\x3C" + bytes((n & 0xFF,)) + bytes(body)
        if t == 0x3E:  # '>'
            n = self.r_int()
            body = bytearray()
            for _ in range(n):
                body += self.r_object()
            return b"\x3E" + bytes((n & 0xFF,)) + bytes(body)
        if t == 0x7B:  # '{' C# 直接丢弃
            return b""
        if t == 0x75:
            n = self.r_int()
            text = self._read(n) if n != 0 else b""
            return b"\x75" + I32(n) + text
        if t == 0x72:  # 'r'
            return b"\x72" + I32(self.r_int())
        if t == 0x6F:  # 'o' code object (字段乱序 + opcode 重映射)
            nlocals = self.r_int()
            flags = self.r_int()
            consts = self.r_object()
            stacksize = self.r_int()
            varnames = self.r_object()
            argcount = self.r_int()
            cellvars = self.r_object()
            names = self.r_object()
            freevars = self.r_object()
            name = self.r_object()
            co_code = self.r_object()
            firstlineno = self.r_int()
            lnotab = self.r_object()
            opcode = self.r_int()
            filenames = self.r_object()
            self.filename = filenames[5:]
            if opcode == OPCODE_MAGIC_MOD:
                co_code = self._remap(co_code, MOD_MAP)
            elif opcode == OPCODE_MAGIC_VANILLA:
                co_code = self._remap(co_code, VANILLA_MAP)
            else:
                co_code = self._remap(co_code, DEFAULT_MAP)
            return self._emit_code(argcount, nlocals, stacksize, flags, co_code,
                                   consts, names, varnames, freevars, cellvars,
                                   filenames, name, firstlineno, lnotab)
        if t == 0x63:  # 'c' code object (标准序, 不重映射)
            argcount = self.r_int()
            nlocals = self.r_int()
            stacksize = self.r_int()
            flags = self.r_int()
            co_code = self.r_object()
            consts = self.r_object()
            names = self.r_object()
            varnames = self.r_object()
            freevars = self.r_object()
            cellvars = self.r_object()
            filenames = self.r_object()
            name = self.r_object()
            firstlineno = self.r_int()
            lnotab = self.r_object()
            self.filename = filenames[5:]
            return self._emit_code(argcount, nlocals, stacksize, flags, co_code,
                                   consts, names, varnames, freevars, cellvars,
                                   filenames, name, firstlineno, lnotab)
        if t == 0x4D:  # 'M' code object (另一种字段乱序 + opcode 重映射)
            argcount = self.r_int()
            lnotab = self.r_object()
            cellvars = self.r_object()
            firstlineno = self.r_int()
            varnames = self.r_object()
            consts = self.r_object()
            name = self.r_object()
            stacksize = self.r_int()
            freevars = self.r_object()
            names = self.r_object()
            co_code = self.r_object()
            flags = self.r_int()
            filenames = self.r_object()
            nlocals = self.r_int()
            opcode = self.r_int()
            self.filename = filenames[5:]
            if opcode == OPCODE_MAGIC_MOD:
                co_code = self._remap(co_code, MOD_MAP)
            elif opcode == OPCODE_MAGIC_VANILLA:
                co_code = self._remap(co_code, VANILLA_MAP)
            else:
                co_code = self._remap(co_code, DEFAULT_MAP)
            return self._emit_code(argcount, nlocals, stacksize, flags, co_code,
                                   consts, names, varnames, freevars, cellvars,
                                   filenames, name, firstlineno, lnotab)
        raise ParseError("unknown marshal type 0x%02x @0x%x" % (t, self.pos - 1))

    @staticmethod
    def _remap(co_code, mapping):
        """opcode 重映射: 对应 r_opcode_mod/vanilla/default"""
        if len(co_code) < 6:
            raise ParseError("bad co_code")
        data = co_code[5:]
        out = bytearray(data)
        get = mapping.get
        c = 0
        length = len(data)
        while c < length:
            b = data[c]
            n = get(b)
            out[c] = b if n is None else n
            # C# TryGetValue 未命中时 n 为默认值 0 -> 按 +1 步进
            c += 1 if (n or 0) < 90 else 3
        return b"\x73" + I32(len(out)) + bytes(out)

    @staticmethod
    def _pack_code(argcount, nlocals, stacksize, flags, co_code, consts, names,
                   varnames, freevars, cellvars, filenames, name, firstlineno, lnotab):
        return (b"\x63" + I32(argcount) + I32(nlocals) + I32(stacksize) + I32(flags)
                + co_code + consts + names + varnames + freevars + cellvars
                + filenames + name + I32(firstlineno) + lnotab)

    def _string_content(self, obj):
        """从 marshal 字节对象中提取字符串内容 (解析不了返回 None)"""
        if not obj:
            return None
        t = obj[:1]
        if t in (b"s", b"t", b"u", b"\xfe", b"a", b"A"):
            return obj[5:]
        if t in (b"z", b"f"):
            return obj[2:]
        if t == b"R":
            i = int.from_bytes(obj[1:5], "little", signed=True)
            if 0 <= i < len(self.string_interned):
                return self.string_interned[i]
        return None

    def _emit_code(self, argcount, nlocals, stacksize, flags, co_code, consts, names,
                   varnames, freevars, cellvars, filenames, name, firstlineno, lnotab):
        """FixFinal.py 的字节级等价实现: 命中加密诱饵函数时替换为空函数"""
        if self.fix_encrypted and len(co_code) >= 5:
            codelen = int.from_bytes(co_code[1:5], "little", signed=False)
            if codelen in (112, 117):
                nm = self._string_content(name)
                if (nm is not None and not nm.startswith(b"<")
                        and nm.endswith(ENCRYPTED_SUFFIXES)):
                    self.fixed_count += 1
                    # 等价于 py2: def f(...): pass  ->  LOAD_CONST None; RETURN_VALUE
                    # 空串在 py2 marshal 中写作 't'+len0 (不能用 TYPE_NULL), 与 FixFinal.py 一致
                    return (b"\x63" + I32(argcount) + I32(nlocals) + I32(1) + I32(flags)
                            + b"\x74" + I32(4) + b"d\x00\x00S"
                            + b"\x28" + I32(1) + b"N"
                            + names + varnames + freevars + cellvars
                            + filenames + name + I32(firstlineno) + b"\x74" + I32(0))
        return self._pack_code(argcount, nlocals, stacksize, flags, co_code, consts, names,
                               varnames, freevars, cellvars, filenames, name,
                               firstlineno, lnotab)

    def loads(self, data):
        """对应 ParseMarshal.loads: 3 遍 r_object"""
        self.data = data
        self.is_init = False
        self.is_init2 = False
        self.string_interned = []
        self._si_map = {}
        self.interned = []
        self._in_map = {}
        self.pos = 0
        self.fixed_count = 0
        r1 = self.r_object()          # pass1: 收集 interned
        self.data = bytes(r1)
        self.pos = 0
        self.is_init2 = True
        r2 = self.r_object()          # pass2: R 引用 -> 具体串
        self.data = bytes(r2)
        self.pos = 0
        self.is_init = True
        return self.r_object()        # pass3: fe 去重 -> t / R


def decrypt_mcs(data, rotor):
    """对应 DecryptMcs + MarshalReverseData"""
    inv, counter0, incs = rotor
    data = rotor_decrypt(data, inv, counter0, incs)
    try:
        data = zlib.decompressobj(-15).decompress(data)   # raw deflate
    except zlib.error:
        data = zlib.decompress(data)                      # 兜底 zlib 头
    if len(data) < 130:
        raise ParseError("decompressed too short")
    ba = bytearray(data)
    for i in range(130):
        ba[i] ^= 156
    return bytes(ba[::-1])   # Counter: 整体倒序


# --------------------------------------------------------------------------
# MCP 容器解析 + 并发调度
# --------------------------------------------------------------------------

_ROTOR = None
_OUTDIR = None
_MCP_PATH = None
_FIX = True


def _worker_init(mcp_path, outdir, fix):
    global _ROTOR, _OUTDIR, _MCP_PATH, _FIX
    _ROTOR = _rotor_init(ROTOR_KEY)
    _OUTDIR = outdir
    _MCP_PATH = mcp_path
    _FIX = fix


def _safe_join(path):
    parts = []
    for seg in path.replace("\\", "/").split("/"):
        if seg in ("", ".", ".."):
            continue
        parts.append(seg)
    return os.path.join(*parts) if parts else "unnamed"


def _process_batch(batch):
    """batch: [(entry_index, offset, length), ...] -> [(index, name|None, err|None)]"""
    results = []
    with open(_MCP_PATH, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for index, offset, length in batch:
                name, err, nfix = None, None, 0
                try:
                    raw = mm[offset:offset + length]
                    data = decrypt_mcs(raw, _ROTOR)
                    parser = MarshalParser(fix_encrypted=_FIX)
                    result = parser.loads(data)
                    rel = _safe_join(parser.filename.decode("ascii", "replace"))
                    outpath = os.path.join(_OUTDIR, rel + "c")
                    os.makedirs(os.path.dirname(outpath), exist_ok=True)
                    with open(outpath, "wb") as w:
                        w.write(PY27_HEADER + result)
                    name = rel + "c"
                    nfix = parser.fixed_count
                except Exception as e:
                    err = "%s: %s" % (type(e).__name__, e)
                results.append((index, name, err, nfix))
        finally:
            mm.close()
    return results


def parse_mcp_container(mcp):
    br_pos = 12
    pathindex, fileindex, dataindex = struct.unpack_from("<iii", mcp, br_pos)
    fileb = mcp[fileindex:dataindex + 1]   # 与 C# 一致的 +1
    filenum = len(fileb) // 16
    entries = []
    for i in range(filenum):
        base = fileindex + i * 16
        ofs, length = struct.unpack_from("<ii", mcp, base + 4)
        entries.append((dataindex + ofs, length))
    return entries


# --------------------------------------------------------------------------
# 反编译阶段 (uncompyle6 只能运行于 Python 2.7, 由本进程编排 py2 子进程并发执行)
# --------------------------------------------------------------------------

PY2_WORKER_SOURCE = b"""# -*- coding: utf-8 -*-
import sys
from uncompyle6.main import decompile_file

list_path, err_path = sys.argv[1], sys.argv[2]
errs = []
with open(list_path) as lf:
    for line in lf:
        line = line.strip()
        if not line:
            continue
        src, dst = line.split(chr(9))
        try:
            out = open(dst, "w")
            try:
                decompile_file(src, outstream=out)
            finally:
                out.close()
        except Exception as e:
            errs.append(src + " : " + e.__class__.__name__ + " " + str(e))
with open(err_path, "w") as ef:
    ef.write(chr(10).join(errs))
"""


def decompile_stage(pyc_root, py_root, workers, py2_exe):
    """把 pyc_root 下所有 pyc 反编译为 py_root 下的 .py, 返回 (ok, 失败列表)"""
    import subprocess
    import tempfile

    tasks = []
    for dp, _, fs in os.walk(pyc_root):
        for fn in fs:
            if not fn.endswith(".pyc"):
                continue
            src = os.path.join(dp, fn)
            rel = os.path.relpath(src, pyc_root)
            dst = os.path.join(py_root, rel[:-1])
            d = os.path.dirname(dst)
            if d:
                os.makedirs(d, exist_ok=True)
            tasks.append((src, dst))
    if not tasks:
        print("没有可反编译的 pyc")
        return 0, []

    # 按文件大小降序均衡分批 (每批 16 个), 写入任务分片文件
    tmpdir = tempfile.mkdtemp(prefix="mcpdec_py2_")
    try:
        worker_path = os.path.join(tmpdir, "py2_worker.py")
        with open(worker_path, "wb") as f:
            f.write(PY2_WORKER_SOURCE)

        tasks.sort(key=lambda t: -os.path.getsize(t[0]))
        shards, shard, n = [], [], 0
        for t in tasks:
            shard.append(t)
            n += 1
            if n >= 16:
                shards.append(shard)
                shard, n = [], 0
        if shard:
            shards.append(shard)

        ok, fails, done = 0, [], 0
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def run_shard(idx_shard):
            idx, shard = idx_shard
            list_path = os.path.join(tmpdir, "tasks_%d.txt" % idx)
            err_path = os.path.join(tmpdir, "err_%d.txt" % idx)
            with open(list_path, "w") as f:
                for src, dst in shard:
                    f.write(src + chr(9) + dst + chr(10))
            proc = subprocess.run([py2_exe, worker_path, list_path, err_path],
                                  capture_output=True)
            if proc.returncode != 0:
                return [src + " : py2 worker crash: " + proc.stderr.decode("gbk", "replace")[:200]
                        for src, _ in shard]
            errs = []
            try:
                with open(err_path) as f:
                    errs = [l for l in f.read().splitlines() if l]
            except OSError:
                pass
            return errs

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(run_shard, (i, sh)): sh for i, sh in enumerate(shards)}
            for fut in as_completed(futures):
                errs = fut.result()
                done += len(futures[fut])
                ok += len(futures[fut]) - len(errs)
                fails.extend(errs)
                print("  反编译进度: %d/%d, 失败 %d" % (done, len(tasks), len(fails)))
        return ok, fails
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="MCPDecompiler (Python 并发版)")
    ap.add_argument("input", help="3715.mcp")
    ap.add_argument("-o", "--outdir", help="输出目录 (默认: mcp 文件名去扩展名)")
    ap.add_argument("-w", "--workers", type=int, default=min(os.cpu_count() or 4, 16))
    ap.add_argument("--mcs", action="store_true", help="输入是单个 mcs 文件")
    ap.add_argument("--no-fix", action="store_true",
                    help="不替换加密诱饵函数 (默认替换, 等价于 FixFinal.py 后处理)")
    ap.add_argument("--decompile", action="store_true",
                    help="解包后自动调用 uncompyle6 反编译出 .py 源码")
    ap.add_argument("--py2", default=r"C:\Python27\python.exe",
                    help="Python2.7 解释器路径 (需已安装 uncompyle6)")
    args = ap.parse_args()

    t0 = time.perf_counter()

    if args.mcs:
        outdir = args.outdir or "."
        with open(args.input, "rb") as f:
            data = f.read()
        if data[:1] == b"\x03":
            data = data[8:]
        rotor = _rotor_init(ROTOR_KEY)
        parser = MarshalParser(fix_encrypted=not args.no_fix)
        result = parser.loads(decrypt_mcs(data, rotor))
        outpath = os.path.join(outdir, "unpacked_" + os.path.basename(args.input))
        with open(outpath, "wb") as w:
            w.write(PY27_HEADER + result)
        print("OK ->", outpath)
        return

    with open(args.input, "rb") as f:
        mcp = f.read()

    entries = parse_mcp_container(mcp)
    del mcp
    outdir = args.outdir or os.path.splitext(os.path.basename(args.input))[0]
    os.makedirs(outdir, exist_ok=True)

    print("共 %d 个文件, workers=%d, 输出目录: %s" % (len(entries), args.workers, outdir))

    # 按大小降序分块, 均衡各 worker 负载; 每批 4 个文件减少 IPC 次数
    order = sorted(range(len(entries)), key=lambda i: -entries[i][1])
    batches, batch, batch_sz = [], [], 0
    for i in order:
        batch.append((i, entries[i][0], entries[i][1]))
        batch_sz += 1
        if batch_sz >= 4:
            batches.append(batch)
            batch, batch_sz = [], 0
    if batch:
        batches.append(batch)

    ok, failed, total_fix = 0, [], 0
    done = 0
    with ProcessPoolExecutor(max_workers=args.workers,
                             initializer=_worker_init,
                             initargs=(os.path.abspath(args.input), outdir,
                                       not args.no_fix)) as ex:
        futures = [ex.submit(_process_batch, b) for b in batches]
        for fut in as_completed(futures):
            for index, name, err, nfix in fut.result():
                done += 1
                total_fix += nfix
                if err is None:
                    ok += 1
                    print("[%d/%d] %s" % (done, len(entries), name))
                else:
                    failed.append((index, err))
                    print("[%d/%d] FAILED #%d: %s" % (done, len(entries), index, err))

    print("-" * 60)
    print("解包完成: %d 成功, %d 失败, 替换加密函数 %d 个, 用时 %.2fs"
          % (ok, len(failed), total_fix, time.perf_counter() - t0))
    if failed:
        for index, err in failed:
            print("  #%d: %s" % (index, err))

    rc = 1 if failed else 0
    if args.decompile:
        py_root = outdir + "_src"
        print("-" * 60)
        print("开始反编译 (uncompyle6 via %s, workers=%d) -> %s" % (args.py2, args.workers, py_root))
        d_ok, d_fails = decompile_stage(outdir, py_root, args.workers, args.py2)
        print("反编译完成: %d 成功, %d 失败, 总用时 %.2fs"
              % (d_ok, len(d_fails), time.perf_counter() - t0))
        for line in d_fails[:20]:
            print("  " + line)
        rc = rc or (1 if d_fails else 0)
    return rc

    if failed:
        for index, err in failed:
            print("  #%d: %s" % (index, err))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
