#!/usr/bin/env python3
"""Derive / validate a BDS hook profile for the xuidforward Endstone plugin.

This is the analysis tool behind `plugin/profiles/*.json`. It is deliberately
dependency-free (stdlib only) so it can run on the server itself.

What it does
------------
1. Parses the ELF program headers of a Bedrock Dedicated Server binary and
   builds a virtual-address <-> file-offset map for the executable segments,
   so every hit can be reported as an RVA (what the plugin needs) as well as a
   file offset (what a hex editor needs).
2. Finds OniLink-style "authentication-result move call" sites: a direct
   `call rel32` immediately followed by `cmp byte ptr [rsp+disp], 0`
   (the `std::optional<PlayerAuthenticationInfo>` engaged check in
   ServerNetworkHandler::_validateLoginPacket).
3. Reports, for each hit, the call target RVA, the function-start RVA guessed
   by walking back to the previous `int3` padding / prologue, and the raw bytes
   surrounding the site, so the plugin profile can be written from evidence.
4. `--self-test` re-checks a stored profile against a binary (exact bytes, RVA,
   call target) so a profile is never trusted blindly.

Usage
-----
    python3 elfscan.py scan      <bedrock_server> [--stack-disp 0x80]
    python3 elfscan.py self-test <bedrock_server> <profile.json>
    python3 elfscan.py info      <bedrock_server>
    python3 elfscan.py strings   <bedrock_server> --grep PlayerAuth [--limit 40]
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple, Union

Pattern = Sequence[Union[int, None]]  # None == wildcard byte


# --------------------------------------------------------------------------- ELF

@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    flags: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def end_vaddr(self) -> int:
        return self.vaddr + self.filesz


class Elf:
    """Minimal ELF64 little-endian reader (enough for a BDS binary)."""

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        if self.data[:4] != b"\x7fELF":
            raise SystemExit(f"{path}: not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise SystemExit(f"{path}: only 64-bit little-endian ELF is supported")
        self.e_type = struct.unpack_from("<H", self.data, 16)[0]
        e_phoff, = struct.unpack_from("<Q", self.data, 32)
        e_phentsize, e_phnum = struct.unpack_from("<HH", self.data, 54)
        self.segments: List[Segment] = []
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", self.data, base)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<QQQQ", self.data, base + 8)
            p_align, = struct.unpack_from("<Q", self.data, base + 48)
            self.segments.append(Segment(p_vaddr, p_offset, p_filesz, p_flags, p_align))

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.segments:
            if s.vaddr <= rva < s.end_vaddr:
                return s.offset + (rva - s.vaddr)
        return None

    def offset_to_rva(self, off: int) -> Optional[int]:
        for s in self.segments:
            if s.offset <= off < s.offset + s.filesz:
                return s.vaddr + (off - s.offset)
        return None

    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_offset(rva)
        if off is None:
            raise SystemExit(f"rva {rva:#x} is not inside a loadable segment")
        return self.data[off:off + size]

    def executable_segments(self) -> List[Segment]:
        return [s for s in self.segments if s.executable]

    def text_base(self) -> int:
        return min(s.vaddr for s in self.executable_segments())

    def iter_text(self) -> Iterator[Tuple[int, bytes]]:
        for seg in self.executable_segments():
            yield seg.vaddr, self.data[seg.offset:seg.offset + seg.filesz]


# ----------------------------------------------------------------------- pattern

def mask_of(pattern: Pattern) -> Tuple[List[bool], bytes]:
    fixed = [b is not None for b in pattern]
    expect = bytes(0 if b is None else (b & 0xFF) for b in pattern)
    return fixed, expect


def parse_hex_pattern(text: str) -> Pattern:
    """Parse "E8 ?? ?? ?? ?? 80 BC" into a wildcarded pattern."""
    out: List[Union[int, None]] = []
    for token in text.replace(",", " ").split():
        if token in ("?", "??", "**"):
            out.append(None)
        else:
            if len(token) != 2:
                raise SystemExit(f"bad pattern token {token!r}")
            out.append(int(token, 16))
    return out


def find_pattern(elf: Elf, pattern: Pattern, limit: int = 0) -> List[int]:
    """Return the RVA of every occurrence of `pattern` in executable segments."""
    fixed, expect = mask_of(pattern)
    anchors = [i for i, f in enumerate(fixed) if f]
    if not anchors:
        raise SystemExit("pattern has no fixed bytes")
    first_index = anchors[0]
    first_byte = expect[first_index]
    hits: List[int] = []
    for seg_vaddr, chunk in elf.iter_text():
        pos = 0
        while True:
            found = chunk.find(bytes([first_byte]), pos)
            if found < 0:
                break
            pos = found + 1
            start = found - first_index
            if start < 0 or start + len(expect) > len(chunk):
                continue
            if all(chunk[start + i] == expect[i] for i in anchors):
                hits.append(seg_vaddr + start)
                if limit and len(hits) >= limit:
                    return hits
    return hits


def call_destination(rva: int, data: bytes) -> Optional[int]:
    """Resolve a leading `E8 rel32` to its absolute destination RVA."""
    if len(data) < 5 or data[0] != 0xE8:
        return None
    rel, = struct.unpack_from("<i", data, 1)
    return rva + 5 + rel


def guess_function_start(elf: Elf, rva: int, back: int = 0xC00) -> Optional[int]:
    """Walk backwards for the nearest int3/nop pad or a known prologue marker."""
    start = max(elf.text_base(), rva - back)
    off = elf.rva_to_offset(start)
    if off is None:
        return None
    window = elf.data[off:off + (rva - start)]
    i = len(window) - 1
    while i >= 0:
        if window[i] in (0xCC, 0x90):
            j = i
            while j >= 0 and window[j] in (0xCC, 0x90):
                j -= 1
            if i - j >= 4:
                return start + j + 1
            i = j
        else:
            i -= 1
    for i in range(len(window) - 1, -1, -1):
        if window[i:i + 4] == b"\xf3\x0f\x1e\xfa":  # endbr64
            return start + i
        if window[i] == 0x55 and window[i + 1:i + 3] in (b"\x48\x89", b"\x53", b"\x56"):
            return start + i
    return None


# ------------------------------------------------------------------- analyses

# `E8 rel32` followed by `80 BC 24 <disp32> 00` == call; cmp byte ptr [rsp+disp], 0
SITE_PATTERN: Pattern = [0xE8, None, None, None, None,
                         0x80, 0xBC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x00]


def cmd_info(elf: Elf) -> None:
    print(f"file            : {elf.path}")
    print(f"size            : {len(elf.data)} bytes")
    print(f"text base (rva) : {elf.text_base():#x} ({elf.text_base()})")
    for seg in elf.segments:
        perms = "".join(c if seg.flags & f else "-" for c, f in zip("rwx", (0x2, 0x1, 0x1)))
        print(f"  LOAD rva={seg.vaddr:#012x} off={seg.offset:#012x} "
              f"filesz={seg.filesz:#012x} {perms}")


def cmd_scan(elf: Elf, stack_disp: int, show_offsets: bool) -> int:
    pattern = list(SITE_PATTERN)
    if stack_disp != 0x80:
        pattern[8:12] = list(struct.pack("<I", stack_disp))
    rendered = " ".join("??" if b is None else f"{b:02X}" for b in pattern)
    hits = find_pattern(elf, pattern)
    print(f"pattern        : {rendered}")
    print(f"matches        : {len(hits)}")
    for rva in hits:
        ctx = elf.read_rva(rva, 24)
        dest = call_destination(rva, ctx)
        owner = guess_function_start(elf, rva)
        print(f"\n  site rva       : {rva:#x} ({rva})")
        print(f"  bytes          : {' '.join(f'{b:02X}' for b in ctx[:16])}")
        if dest is not None:
            print(f"  call target rva: {dest:#x} ({dest})")
        if owner is not None:
            print(f"  owner start    : {owner:#x}  (+{rva - owner} bytes into it)")
            print(f"  owner bytes    : {' '.join(f'{b:02X}' for b in elf.read_rva(owner, 16))}")
        if show_offsets:
            print(f"  file offset    : {elf.rva_to_offset(rva)}")
    return len(hits)


def cmd_self_test(elf: Elf, profile_path: str) -> int:
    with open(profile_path, "r", encoding="utf-8") as fh:
        profile = json.load(fh)
    ok = True
    want_size = profile.get("executable_size")
    if want_size and want_size != len(elf.data):
        print(f"MISMATCH size: profile {want_size} != binary {len(elf.data)}")
        ok = False
    site = profile.get("site_rva") or profile.get("target_rva")
    raw = (profile.get("expected_target_bytes") or "").replace(" ", "")
    if site is None or not raw:
        print("profile lacks site_rva / expected_target_bytes")
        return 2
    site = int(str(site), 0)
    want = bytes.fromhex(raw)
    got = elf.read_rva(site, len(want))
    print(f"bytes at {site:#x}: {'match' if got == want else 'MISMATCH'}")
    if got != want:
        print(f"  want {want.hex()}\n  got  {got.hex()}")
        ok = False
    hits = find_pattern(elf, SITE_PATTERN)
    print(f"pattern matches: {len(hits)}"
          + (f" -> {' '.join(hex(h) for h in hits)}" if hits else " (none)"))
    return 0 if ok else 1


def cmd_read(elf: Elf, rva: int, size: int) -> None:
    data = elf.read_rva(rva, size)
    print(f"rva {rva:#x} ({rva}) size {size}")
    print("hex :", " ".join(f"{b:02X}" for b in data))
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)
    print("ascii:", text)
    print("file offset:", elf.rva_to_offset(rva))


def cmd_find(elf: Elf, pattern_text: str, show_offsets: bool, limit: int) -> int:
    pattern = parse_hex_pattern(pattern_text)
    hits = find_pattern(elf, pattern)
    print(f"pattern : {' '.join('??' if b is None else f'{b:02X}' for b in pattern)}")
    print(f"matches : {len(hits)}")
    for rva in hits[:limit] if limit else hits:
        extra = ""
        if pattern[0] == 0xE8 and len(pattern) >= 5:
            dest = call_destination(rva, elf.read_rva(rva, 8))
            if dest is not None:
                extra = f" -> call target {dest:#x}"
        offset = f" off={elf.rva_to_offset(rva)}" if show_offsets else ""
        print(f"  {rva:#x} ({rva}){extra}{offset}")
    return len(hits)


def cmd_xref(elf: Elf, target: int, limit: int) -> None:
    """Heuristic RIP-relative xref finder for a data address (string, vtable...).

    A RIP-relative operand encodes `disp32 = target - (instr_start + instr_len)`.
    We do not decode instructions, so we try the plausible instruction lengths
    used by `lea/mov reg,[rip+disp32]` (6..11 bytes) and require the leading
    opcode bytes to look like a RIP-relative load. Noisy by nature, so it is
    only ever used for cross-checking, never for patching.
    """
    prefixes = (b"\x48\x8d", b"\x4c\x8d", b"\x48\x8b", b"\x4c\x8b", b"\x48\x89",
                b"\x4c\x89", b"\xf3\x0f", b"\x66\x0f", b"\x0f\x10", b"\x0f\x11",
                b"\x48\xc7", b"\x4c\xc7", b"\x48\x8d\x05", b"\x8b", b"\x89")
    found = 0
    for seg in elf.executable_segments():
        chunk = elf.data[seg.offset:seg.offset + seg.filesz]
        for w in range(0, len(chunk) - 4):
            disp = int.from_bytes(chunk[w:w + 4], "little", signed=True)
            for instr_len in (6, 7, 8, 9, 10, 11):
                start = w - (instr_len - 4)
                if start < 0 or start + 4 > len(chunk):
                    continue
                if start + instr_len + disp != target:
                    continue
                head = chunk[start:start + 4]
                if not any(head.startswith(p) for p in prefixes):
                    continue
                print(f"  xref at rva {seg.vaddr + start:#x} ({seg.vaddr + start}) "
                      f"len~{instr_len} bytes={head.hex()}")
                found += 1
                if limit and found >= limit:
                    return
    if not found:
        print("  (no xref found)")


def cmd_template(elf: Elf, rva: int, size: int) -> None:
    """Render a byte range as a wildcarded pattern.

    Any 4-byte field that decodes as a RIP-relative displacement pointing
    somewhere inside the image, or as a `call/jmp rel32` displacement, is
    wildcarded: those are exactly the bytes that change between BDS builds.
    """
    data = elf.read_rva(rva, size)
    wild = set()
    for i in range(0, len(data) - 3):
        disp = int.from_bytes(data[i:i + 4], "little", signed=True)
        for instr_len in (5, 6, 7, 8, 9, 10, 11):
            start = i - (instr_len - 4)
            if start < 0:
                continue
            if elf.rva_to_offset(rva + start + instr_len + disp) is not None:
                for k in range(i, i + 4):
                    wild.add(k)
                break
    toks = ["??" if i in wild else f"{b:02X}" for i, b in enumerate(data)]
    print(f"rva    : {rva:#x} ({rva}) size {size}")
    print("raw    : " + " ".join(f"{b:02X}" for b in data))
    print("pattern: " + " ".join(toks))
    print(f"file offset: {elf.rva_to_offset(rva)}")


def cmd_func(elf: Elf, rva: int, max_size: int) -> None:
    """Estimate a function's extent: from `rva` to the next padding run."""
    data = elf.read_rva(rva, max_size)
    end = None
    i = 0
    while i < len(data):
        if data[i] in (0xCC, 0x90):
            j = i
            while j < len(data) and data[j] in (0xCC, 0x90):
                j += 1
            if j - i >= 8:
                end = i
                break
            i = j
        else:
            i += 1
    print(f"start rva : {rva:#x} ({rva})")
    print(f"prologue  : {' '.join(f'{b:02X}' for b in data[:16])}")
    if end is None:
        print(f"size      : >{max_size} (no padding run found)")
    else:
        print(f"end rva   : {rva + end:#x}   size ~{end} bytes")


def cmd_strings(elf: Elf, grep: str, limit: int) -> None:
    rx = re.compile(grep.encode())
    for seg_vaddr, chunk in elf.iter_text():
        for m in re.finditer(rb"[\x20-\x7e]{5,}", chunk):
            if rx.search(m.group(0)):
                print(f"{seg_vaddr + m.start():#x}  {m.group(0).decode('ascii', 'replace')}")
                limit -= 1
                if limit <= 0:
                    return


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info")
    p.add_argument("binary")

    p = sub.add_parser("scan", help="find authentication-result call sites")
    p.add_argument("binary")
    p.add_argument("--stack-disp", default="0x80")
    p.add_argument("--show-offsets", action="store_true")

    p = sub.add_parser("self-test", help="verify a stored profile against a binary")
    p.add_argument("binary")
    p.add_argument("profile")

    p = sub.add_parser("strings")
    p.add_argument("binary")
    p.add_argument("--grep", required=True)
    p.add_argument("--limit", type=int, default=40)

    p = sub.add_parser("read", help="hex+ascii dump at an RVA")
    p.add_argument("binary")
    p.add_argument("rva")
    p.add_argument("--size", type=int, default=64)

    p = sub.add_parser("find", help="search a wildcarded hex pattern")
    p.add_argument("binary")
    p.add_argument("pattern")
    p.add_argument("--show-offsets", action="store_true")
    p.add_argument("--limit", type=int, default=25, help="0 = no limit")

    p = sub.add_parser("xref", help="find RIP-relative references to an RVA")
    p.add_argument("binary")
    p.add_argument("target")
    p.add_argument("--limit", type=int, default=40, help="0 = no limit")

    p = sub.add_parser("template", help="render a byte range as a wildcarded pattern")
    p.add_argument("binary")
    p.add_argument("rva")
    p.add_argument("--size", type=int, default=48)

    p = sub.add_parser("func", help="estimate a function's size at an RVA")
    p.add_argument("binary")
    p.add_argument("rva")
    p.add_argument("--max-size", type=int, default=4096)

    args = ap.parse_args(argv)
    elf = Elf(args.binary)

    if args.cmd == "info":
        cmd_info(elf)
        return 0
    if args.cmd == "scan":
        return 0 if cmd_scan(elf, int(args.stack_disp, 0), args.show_offsets) else 1
    if args.cmd == "self-test":
        return cmd_self_test(elf, args.profile)
    if args.cmd == "strings":
        cmd_strings(elf, args.grep, args.limit)
        return 0
    if args.cmd == "read":
        cmd_read(elf, int(args.rva, 0), args.size)
        return 0
    if args.cmd == "find":
        return 0 if cmd_find(elf, args.pattern, args.show_offsets, args.limit) else 1
    if args.cmd == "xref":
        cmd_xref(elf, int(args.target, 0), args.limit)
        return 0
    if args.cmd == "template":
        cmd_template(elf, int(args.rva, 0), args.size)
        return 0
    if args.cmd == "func":
        cmd_func(elf, int(args.rva, 0), args.max_size)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
