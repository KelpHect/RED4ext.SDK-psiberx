#!/usr/bin/env python3
"""Retail class sizes straight from the game exe, without running it.

Every native class is registered through the CClass constructor (this, name, size, flags). This scans every direct
call to it and reads the size immediate (`mov r8d, imm` or `lea r8d, [r9 +- imm]` with r9d the flags immediate) and
the class name string (`lea rdx, [rip + str]` before the CName constructor).

Use it on update day to tell which SDK layouts really changed. REDmod's tools/redmod/metadata.json is NOT the retail
layout: on game 2.5 (3.0.88.46235) entIPlacedComponent is 0x120 in the exe (0x66BD67 `mov r8d, 0x120`) but 0x140 in
metadata.json, and 1,727 of the 2,701 classes found in both differ.

Usage:
  python scripts/retail_class_sizes.py --nct-re <NCT repo>/tools/re --ctor 0x6bdf74 --out sizes.json
The CClass ctor RVA is per build. On 2.5 it is 0x6BDF74: the call right after the "entIPlacedComponent" string
reference at 0x66BD4B (`mov r9d, 3; mov r8d, 0x120; mov rcx, rdi; call 0x6BDF74`). Its body writes the name at +0x18
and the size at +0x68, the SDK's CClass::name / CClass::size.
"""
import argparse
import json
import re
import struct
import sys

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--nct-re", required=True, help="NCT tools/re (nctre.py: game discovery and PE helpers)")
ap.add_argument("--ctor", required=True, help="RVA of the CClass constructor (hex)")
ap.add_argument("--out", required=True)
a = ap.parse_args()
sys.path.insert(0, a.nct_re)
import nctre  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: E402

e = nctre.Exe()
print(nctre.header_line(e))
CTOR = int(a.ctor, 16)
md = Cs(CS_ARCH_X86, CS_MODE_64)
d, t0, t1, trva = e.data, e.t0, e.t1, e.trva

sites = []
i = t0
while True:
    i = d.find(b"\xe8", i, t1)
    if i < 0:
        break
    rva = i - t0 + trva
    if rva + 5 + struct.unpack_from("<i", d, i + 1)[0] == CTOR:
        sites.append(rva)
    i += 1

res, fails = {}, 0
for s in sites:
    ins = None
    for back in range(0x50, 0x10, -1):
        cand = list(md.disasm(d[s - back - trva + t0: s - trva + t0 + 5], s - back))
        if cand and cand[-1].address == s:
            ins = cand
            break
    if ins is None:
        fails += 1
        continue
    r9 = 2
    for x in reversed(ins[:-1]):
        m = re.match(r"r9d, (0x[0-9a-f]+|\d+)$", x.op_str)
        if x.mnemonic == "mov" and m:
            r9 = int(m.group(1), 0)
            break
    size = name = None
    for x in reversed(ins[:-1]):
        if size is None and x.mnemonic == "mov" and x.op_str.startswith("r8d, "):
            try:
                size = int(x.op_str.split(", ")[1], 0)
            except ValueError:
                size = -1
        if size is None and x.mnemonic == "lea" and x.op_str.startswith("r8d, [r9 "):
            m = re.match(r"r8d, \[r9 ([+-]) (0x[0-9a-f]+|\d+)\]", x.op_str)
            if m:
                size = r9 + int(m.group(2), 0) * (1 if m.group(1) == "+" else -1)
        if name is None and x.mnemonic == "lea" and x.op_str.startswith("rdx, [rip"):
            m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", x.op_str)
            tgt = x.address + x.size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
            name = e.string_at(tgt, 200, 1)
    if size is not None and size >= 0 and name:
        res[name] = size
    else:
        fails += 1
print("sites %d parsed %d fails %d" % (len(sites), len(res), fails))
json.dump(res, open(a.out, "w"), indent=0, sort_keys=True)
