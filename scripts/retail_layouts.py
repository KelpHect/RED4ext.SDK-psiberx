#!/usr/bin/env python3
"""Runtime class layouts (class sizes, alignments, parents, native property offsets) read offline from the game
exe's own reflection registration code, without running the game. It extends retail_class_sizes.py (sizes only)
with property offsets, parents and alignment; metadata_dump.py --retail overlays its output on an older live dump.

Why: on update day the SDK's generated headers, the hand-written overrides and the plugins' asserts need the
*runtime* layout of the new build. REDmod's metadata.json describes the editor build, not the retail exe (game 2.5:
entIPlacedComponent 0x120 in the exe, 0x140 in metadata.json); a live RTTI dump needs a plugin that loads, which a
new game version usually breaks. The exe registers every native class itself, with the numbers as immediates:

  class:    lea rdx,"entSlotComponent"; call CName::CName; mov r9d,<flags>; mov r8d,<size>; mov rcx,<storage>;
            mov rdx,[rax]; call CClass::CClass                     (2.5: 0xEC1A3A mov r8d,0x1a0 -> call 0x6BDF74)
  property: lea rdx,"slots"; call CName::CName; mov r8d,<offset>; mov rdx,<class>; mov r9,[rax];
            call CProperty::Create                                 (2.5: 0x124B835 mov r8d,0x120 -> call 0xB919FC)
  parent:   mov [<class>+0x10], <parent class>;  alignment: mov dword [<storage>+0x74], <align>

The three helpers are found per build from anchor class names, never hard-coded. Each function is swept linearly
(.pdata bounds) with simple register tracking; the class a property belongs to is followed through
`mov [rip+G], <storage>` globals and up to three caller levels, and a registration function the linker folded for
several classes gives its properties to each. Every record keeps the RVA of its instruction.

Checked on game 2.31 (3.0.80.51928) against the live RTTI dump: 8,959 classes, sizes 8,959/8,959, offsets
18,577/18,577, parents 3,519/3,519, alignment 8,246/8,247; 469 dump properties not located (2.5 %, plus the props
Codeware adds at runtime, which are not in the exe).

Needs nctre.py from the NCT repo (tools/re: game discovery, PE helpers, fingerprint) and capstone + pefile.

usage:
  python scripts/retail_layouts.py --nct-re <NCT>/tools/re scan --out <table.json> [--exe <path>]
  python scripts/retail_layouts.py --nct-re <NCT>/tools/re validate <table.json> <live rtti dump dir>
  python scripts/retail_layouts.py --nct-re <NCT>/tools/re diff <old.json> <new.json> --out <d.json> [--md <d.md>]
  python scripts/retail_layouts.py --nct-re <NCT>/tools/re show <table.json> <class>
Exit codes: 0 ok, 1 validation below --min-match (default 0.98), 2 usage / anchors not found.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _nct_re_path(argv):
    """--nct-re <dir> (stripped from argv), else $NCT_RE, else this file's directory (when it lives in tools/re)."""
    import os
    for i, a in enumerate(argv):
        if a == "--nct-re" and i + 1 < len(argv):
            p = argv[i + 1]
            del argv[i:i + 2]
            return p
        if a.startswith("--nct-re="):
            del argv[i]
            return a.split("=", 1)[1]
    return os.environ.get("NCT_RE") or str(Path(__file__).resolve().parent)

ANCHOR_CLASSES = ["entSlotComponent", "entEntity", "entIComponent", "gameObject", "entIPlacedComponent",
                  "CMesh", "entAnimatedComponent", "gamePuppet"]

# capstone register names folded onto their 64-bit parent
_GPR = {}
for full, subs in {
        "rax": "eax ax al ah", "rbx": "ebx bx bl bh", "rcx": "ecx cx cl ch", "rdx": "edx dx dl dh",
        "rsi": "esi si sil", "rdi": "edi di dil", "rbp": "ebp bp bpl", "rsp": "esp sp spl"}.items():
    _GPR[full] = full
    for s in subs.split():
        _GPR[s] = full
for i in range(8, 16):
    for suf in ("", "d", "w", "b"):
        _GPR["r%d%s" % (i, suf)] = "r%d" % i
ALIGN_OFF = 0x74
VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")


def fnv1a64(s: str) -> int:
    h = 0xCBF29CE484222325
    for c in s.encode():
        h = ((h ^ c) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


class Image:
    """The exe plus .pdata function bounds and a rel32 call/jmp index."""

    def __init__(self, path=None):
        import capstone
        import nctre
        self.exe = nctre.Exe(path)
        self.header = nctre.header_line(self.exe)
        self.fingerprint = self.exe.fingerprint()
        e = self.exe
        pd = e.secs[".pdata"]
        raw = e.data[pd.PointerToRawData:pd.PointerToRawData + pd.Misc_VirtualSize]
        fb, fe = [], []
        for i in range(len(raw) // 12):
            b, en, _ = struct.unpack_from("<III", raw, i * 12)
            if b == 0:
                continue
            fb.append(b)
            fe.append(en)
        order = sorted(range(len(fb)), key=fb.__getitem__)
        self.fbeg = [fb[i] for i in order]
        self.fend = [fe[i] for i in order]
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self._calls = None
        self._leas = None

    def func_of(self, rva):
        i = bisect.bisect_right(self.fbeg, rva) - 1
        if i >= 0 and self.fbeg[i] <= rva < self.fend[i]:
            return self.fbeg[i], self.fend[i]
        return None

    def calls_to(self):
        """{target rva: [(site rva, 'call'|'jmp')]} for every E8/E9 rel32 in .text whose target is a function start."""
        if self._calls is None:
            e = self.exe
            d = e.data
            starts = set(self.fbeg)
            idx = defaultdict(list)
            base = e.trva - e.t0
            for m in re.finditer(rb"[\xe8\xe9]", d[e.t0:e.t1 - 5]):
                o = e.t0 + m.start()
                tgt = o + base + 5 + struct.unpack_from("<i", d, o + 1)[0]
                if tgt in starts:
                    idx[tgt].append((o + base, "call" if d[o] == 0xE8 else "jmp"))
            self._calls = idx
        return self._calls

    def lea_refs(self, targets):
        """Sites of `lea r64,[rip+X]` for X in targets."""
        e = self.exe
        d = e.data
        out = defaultdict(list)
        base = e.trva - e.t0
        for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", d[e.t0:e.t1 - 7]):
            o = e.t0 + m.start()
            dest = o + base + 7 + struct.unpack_from("<i", d, o + 3)[0]
            if dest in targets:
                out[dest].append(o + base)
        return out

    def cstring_rva(self, s):
        m = re.search(b"\0" + re.escape(s.encode()) + b"\0", self.exe.data)
        return self.exe.off2rva(m.start() + 1) if m else None

    def insns(self, beg, end):
        o = self.exe.rva2off(beg)
        return self.md.disasm(self.exe.data[o:o + (end - beg)], beg)


class Emu:
    """Linear register tracking over one function. Values are tuples:
    ('imm', v) ('a', rva) lea of rip ('g', rva) load of [rip] ('arg', reg) value at entry ('cnameptr', s)
    ('cname', s) ('ret', target)."""

    def __init__(self, img: Image, cname_fn: int):
        self.img = img
        self.cname_fn = cname_fn
        self.cache = {}

    def run(self, beg, end):
        key = beg
        if key in self.cache:
            return self.cache[key]
        import capstone.x86 as X
        img = self.img
        regs = {r: ("arg", r) for r in ("rcx", "rdx", "r8", "r9")}
        stack = {}
        events = []     # (site, kind, target, snapshot)
        gstores = []    # (site, global rva, value)
        mstores = []    # (site, base value, disp, value)
        before_call = None
        for ins in img.insns(beg, end):
            ops = ins.operands
            mn = ins.mnemonic
            # the stack probe (`mov eax,N; call __chkstk; sub rsp,rax`) preserves every register but rax
            if before_call is not None and mn == "sub" and ins.op_str == "rsp, rax":
                regs = dict(before_call)
                regs.pop("rax", None)
            before_call = None
            if mn in ("call", "jmp") and len(ops) == 1 and ops[0].type == X.X86_OP_IMM:
                tgt = ops[0].imm
                if mn == "jmp" and beg <= tgt < end:
                    continue
                snap = {r: regs.get(r) for r in ("rcx", "rdx", "r8", "r9")}
                events.append((ins.address, mn, tgt, snap))
                if mn == "call":
                    rdx, rcx = regs.get("rdx"), regs.get("rcx")
                    s = img.exe.string_at(rdx[1], 200, 1) if rdx and rdx[0] == "a" else None
                    res = ("ret", tgt)
                    if tgt == self.cname_fn and s is not None:
                        res = ("cnameptr", s)
                    # CName built in place from a string (a second constructor shape): lea rcx,[rsp+X]; lea rdx,str
                    if s is not None and rcx and rcx[0] == "stk":
                        stack[(rcx[1], rcx[2])] = ("cname", s)
                        res = ("cnameptr", s)
                    before_call = dict(regs)
                    for r in VOLATILE:
                        regs.pop(r, None)
                    if res:
                        regs["rax"] = res
                continue
            if mn in ("call", "jmp") or mn.startswith("ret"):
                if mn == "call":
                    for r in VOLATILE:
                        regs.pop(r, None)
                continue
            if len(ops) == 2:
                d0, s0 = ops
                dreg = _GPR.get(ins.reg_name(d0.reg)) if d0.type == X.X86_OP_REG else None
                val = None
                handled = False
                if mn in ("mov", "movabs") and dreg:
                    handled = True
                    if s0.type == X.X86_OP_IMM:
                        val = ("imm", s0.imm & 0xFFFFFFFFFFFFFFFF)
                    elif s0.type == X.X86_OP_REG:
                        val = regs.get(_GPR.get(ins.reg_name(s0.reg)))
                        if d0.size == 4 and val and val[0] != "imm":
                            val = val  # 32-bit move of a pointer: keep for r8d=reg imm cases
                    elif s0.type == X.X86_OP_MEM:
                        m = s0.mem
                        if m.base == X.X86_REG_RIP:
                            val = ("g", ins.address + ins.size + m.disp)
                        elif m.index == 0:
                            b = regs.get(_GPR.get(ins.reg_name(m.base)))
                            if b and b[0] == "cnameptr" and m.disp == 0:
                                val = ("cname", b[1])
                            elif b and b[0] == "a" and m.disp == 0:
                                val = ("g", b[1])
                            elif _GPR.get(ins.reg_name(m.base)) in ("rsp", "rbp"):
                                val = stack.get((_GPR.get(ins.reg_name(m.base)), m.disp))
                elif mn == "lea" and dreg:
                    handled = True
                    m = s0.mem
                    if m.base == X.X86_REG_RIP:
                        val = ("a", ins.address + ins.size + m.disp)
                    elif m.index == 0 and m.base:
                        b = _GPR.get(ins.reg_name(m.base))
                        bv = regs.get(b)
                        if b in ("rsp", "rbp"):
                            val = ("stk", b, m.disp)
                        elif bv and bv[0] == "imm":
                            val = ("imm", (bv[1] + m.disp) & 0xFFFFFFFF)
                elif mn == "xor" and dreg and s0.type == X.X86_OP_REG and \
                        _GPR.get(ins.reg_name(s0.reg)) == dreg:
                    handled = True
                    val = ("imm", 0)
                elif mn == "mov" and d0.type == X.X86_OP_MEM:
                    handled = True
                    m = d0.mem
                    sv = None
                    if s0.type == X.X86_OP_REG:
                        sv = regs.get(_GPR.get(ins.reg_name(s0.reg)))
                    elif s0.type == X.X86_OP_IMM:
                        sv = ("imm", s0.imm & 0xFFFFFFFFFFFFFFFF)
                    if m.base == X.X86_REG_RIP:
                        gstores.append((ins.address, ins.address + ins.size + m.disp, sv))
                    elif m.index == 0:
                        breg = _GPR.get(ins.reg_name(m.base))
                        if breg in ("rsp", "rbp"):
                            stack[(breg, m.disp)] = sv
                        else:
                            mstores.append((ins.address, regs.get(breg), m.disp, sv))
                if handled:
                    if dreg:
                        if val is None:
                            regs.pop(dreg, None)
                        else:
                            regs[dreg] = val
                    continue
            # anything else: drop whatever it writes
            try:
                _, written = ins.regs_access()
            except Exception:
                written = []
            for r in written:
                g = _GPR.get(ins.reg_name(r))
                if g:
                    regs.pop(g, None)
        res = (events, gstores, mstores)
        self.cache[key] = res
        return res


def _imm(v):
    return v[1] if v and v[0] == "imm" else None


def find_helpers(img: Image, log):
    """CName-from-string, the class constructor and the property creator, voted from anchor class names."""
    srvas = {}
    for n in ANCHOR_CLASSES:
        r = img.cstring_rva(n)
        if r:
            srvas[r] = n
    refs = img.lea_refs(set(srvas))
    cname_votes, ctor_votes = Counter(), Counter()
    import capstone.x86 as X
    for srva, sites in refs.items():
        for site in sites:
            seq = list(img.insns(site, site + 64))
            calls = [i for i in seq if i.mnemonic == "call" and i.operands[0].type == X.X86_OP_IMM]
            if len(calls) >= 2:
                txt = " ".join("%s %s" % (i.mnemonic, i.op_str) for i in seq if calls[0].address < i.address < calls[1].address)
                if "r8d" in txt:
                    cname_votes[calls[0].operands[0].imm] += 1
                    ctor_votes[calls[1].operands[0].imm] += 1
    if not cname_votes:
        raise SystemExit("rttiscan: no anchor class registration found (anchors %s)" % ANCHOR_CLASSES)
    cname_fn = cname_votes.most_common(1)[0][0]
    ctor_fn = ctor_votes.most_common(1)[0][0]
    log("helpers: CName(str) %#x votes %s; CClass ctor %#x votes %s" % (
        cname_fn, dict(cname_votes), ctor_fn, dict(ctor_votes)))
    return cname_fn, ctor_fn


def scan(path=None, log=print):
    img = Image(path)
    log(img.header)
    cname_fn, ctor_fn = find_helpers(img, log)
    calls = img.calls_to()
    emu = Emu(img, cname_fn)

    def funcs_calling(tgt):
        fs = set()
        for site, _ in calls.get(tgt, ()):
            f = img.func_of(site)
            if f:
                fs.add(f)
        return fs

    # 1. classes: every CClass ctor call with a CName and an immediate size
    classes = {}        # storage rva -> record
    gptr = {}           # global rva -> storage rva (mov [rip+G], storage)
    ctor_miss = []
    ctor_funcs = funcs_calling(ctor_fn)
    for f in ctor_funcs:
        events, gstores, _ = emu.run(*f)
        for site, kind, tgt, snap in events:
            if tgt != ctor_fn:
                continue
            nm, rcx = snap.get("rdx"), snap.get("rcx")
            if not (nm and nm[0] == "cname" and rcx and rcx[0] == "a"):
                ctor_miss.append({"site": "%#x" % site, "rdx": repr(nm), "rcx": repr(rcx),
                                  "r8": repr(snap.get("r8")), "r9": repr(snap.get("r9"))})
                continue
            classes[rcx[1]] = {"name": nm[1], "size": _imm(snap.get("r8")), "flags": _imm(snap.get("r9")),
                               "storage": rcx[1], "ctorSite": site, "props": {}}
        for site, g, v in gstores:
            if v and v[0] == "a":
                gptr.setdefault(g, v[1])
            # CClass::alignment (+0x74; the ctor stores a default 4 there: 2.5 0x6BDFF0 `mov dword ptr [rdi+0x74], 4`)
            if v and v[0] == "imm" and (g - ALIGN_OFF) in classes:
                classes[g - ALIGN_OFF]["align"] = v[1]
                classes[g - ALIGN_OFF]["alignSite"] = site
    log("classes: %d constructor calls in %d functions" % (len(classes), len(ctor_funcs)))

    # 2. the property creator: the call after a CName with r9 = the CName and r8 = an immediate offset
    votes = Counter()
    cname_funcs = funcs_calling(cname_fn)
    for f in cname_funcs:
        events, gstores, _ = emu.run(*f)
        for site, g, v in gstores:
            if v and v[0] == "a" and v[1] in classes:
                gptr.setdefault(g, v[1])
        for site, kind, tgt, snap in events:
            r9, r8 = snap.get("r9"), snap.get("r8")
            if r9 and r9[0] == "cname" and r8 and r8[0] == "imm" and tgt not in (cname_fn, ctor_fn):
                votes[tgt] += 1
    prop_fn, nvotes = votes.most_common(1)[0]
    log("helpers: CProperty create %#x (%d sites; next %s)" % (
        prop_fn, nvotes, [("%#x" % t, c) for t, c in votes.most_common(4)[1:]]))

    def resolve(val, depth, func):
        """A value -> the set of class storage rvas it can be. Identical registration code is folded by the
        linker (one function, several callers with different classes): such a property belongs to each class."""
        if not val:
            return set()
        k = val[0]
        if k == "a":
            return {val[1]} if val[1] in classes else set()
        if k == "g":
            c = gptr.get(val[1])
            return {c} if c in classes else set()
        if k == "ret":
            fb = img.func_of(val[1])
            if not fb or depth <= 0:
                return set()
            ev, gs, _ = emu.run(*fb)
            cands = [gptr.get(g) for _, g, v in gs] + [v[1] for _, g, v in gs if v and v[0] == "a"]
            cands = {c for c in cands if c in classes}
            return cands if len(cands) == 1 else set()
        if k == "arg" and depth > 0 and func:
            outs = set()
            for site, _ in calls.get(func[0], ()):
                cf = img.func_of(site)
                if not cf:
                    continue
                ev, _, _ = emu.run(*cf)
                for s, kind, tgt, snap in ev:
                    if s == site:
                        outs |= resolve(snap.get(val[1]), depth - 1, cf)
            return outs
        return set()

    # 3. properties
    prop_funcs = funcs_calling(prop_fn)
    unresolved = []
    nprops = 0
    parents = {}
    for f in prop_funcs:
        events, _, mstores = emu.run(*f)
        for site, kind, tgt, snap in events:
            if tgt != prop_fn:
                continue
            nm, off = snap.get("r9"), _imm(snap.get("r8"))
            name = nm[1] if nm and nm[0] == "cname" else None
            cls = resolve(snap.get("rdx"), 3, f)
            if name is None or off is None or not cls:
                unresolved.append({"site": "%#x" % site, "func": "%#x" % f[0], "name": name,
                                   "off": off, "cls": repr(snap.get("rdx"))})
                continue
            for c in cls:
                rec = {"off": off, "site": site}
                if len(cls) > 1:
                    rec["shared"] = True
                classes[c]["props"].setdefault(name, rec)
                nprops += 1
        # parent: mov [<class>+0x10], <parent class ptr>
        for site, base, disp, v in mstores:
            if disp != 0x10 or not base:
                continue
            c = resolve(base, 3, f)
            p = resolve(v, 1, f) if v else set()
            if len(p) == 1:
                for cc in c - p:
                    parents.setdefault(cc, (next(iter(p)), site))
    for c, (p, site) in parents.items():
        classes[c]["parent"] = classes[p]["name"]
        classes[c]["parentSite"] = site
    log("properties: %d placed, %d unresolved, in %d functions; parents %d" % (
        nprops, len(unresolved), len(prop_funcs), len(parents)))

    out = {"tool": "rttiscan", "fingerprint": img.fingerprint,
           "helpers": {"cnameFromString": "%#x" % cname_fn, "classCtor": "%#x" % ctor_fn,
                       "propertyCreate": "%#x" % prop_fn},
           "counts": {"classes": len(classes), "props": nprops, "unresolvedProps": len(unresolved),
                      "parents": len(parents)},
           "classes": {}, "unresolved": unresolved, "ctorMisses": ctor_miss}
    dup = Counter(c["name"] for c in classes.values())
    for c in sorted(classes.values(), key=lambda c: c["name"]):
        rec = {"size": c["size"], "flags": c["flags"], "ctorSite": "%#x" % c["ctorSite"],
               "storage": "%#x" % c["storage"]}
        if "align" in c:
            rec["align"] = c["align"]
            rec["alignSite"] = "%#x" % c["alignSite"]
        if "parent" in c:
            rec["parent"] = c["parent"]
            rec["parentSite"] = "%#x" % c["parentSite"]
        rec["props"] = {n: dict(p, site="%#x" % p["site"])
                        for n, p in sorted(c["props"].items(), key=lambda kv: (kv[1]["off"], kv[0]))}
        if dup[c["name"]] > 1:
            rec["duplicate"] = True
        prev = out["classes"].get(c["name"])
        if prev is None or len(rec["props"]) > len(prev["props"]):
            out["classes"][c["name"]] = rec
    return out


# ---- validation against a live dump -----------------------------------------------------------------------

def load_dump(d: Path):
    classes = {}
    with open(d / "classes.jsonl", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                c = json.loads(line)
                classes[c["n"]] = c
    props = defaultdict(dict)
    with open(d / "props.jsonl", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            p = json.loads(line)
            if p.get("holder"):
                continue
            props[p["c"]][p["p"]] = p["off"]
    return classes, props


def declared(dclasses, dprops, name):
    """Props a native class declares itself: its list minus the parent's (same name and offset)."""
    own = dict(dprops.get(name, {}))
    par = dclasses.get(name, {}).get("parent")
    if par:
        for n, o in dprops.get(par, {}).items():
            if own.get(n) == o:
                own.pop(n)
    return own


def validate(table, dump_dir: Path):
    dclasses, dprops = load_dump(dump_dir)
    tc = table["classes"]
    r = Counter()
    bad = []
    for name, dc in dclasses.items():
        if not dc.get("native"):
            continue
        r["dumpNative"] += 1
        t = tc.get(name)
        if not t:
            r["classMissing"] += 1
            continue
        r["classFound"] += 1
        if t["size"] == dc["size"]:
            r["sizeMatch"] += 1
        else:
            r["sizeMismatch"] += 1
            bad.append(("size", name, dc["size"], t["size"], t["ctorSite"]))
        if "parent" in t:
            r["parentChecked"] += 1
            if t["parent"] == (dc.get("parent") or ""):
                r["parentMatch"] += 1
            else:
                bad.append(("parent", name, dc.get("parent"), t["parent"], t.get("parentSite")))
        own = declared(dclasses, dprops, name)
        for pn, off in own.items():
            r["dumpProps"] += 1
            tp = t["props"].get(pn)
            if tp is None:
                r["propMissing"] += 1
            elif tp["off"] == off:
                r["propMatch"] += 1
            else:
                r["propMismatch"] += 1
                bad.append(("prop", "%s.%s" % (name, pn), off, tp["off"], tp["site"]))
        for pn in t["props"]:
            if pn not in dprops.get(name, {}):
                r["propExtra"] += 1
    for name in tc:
        if name not in dclasses:
            r["classExtra"] += 1
    return dict(r), bad


# ---- diff between two scans --------------------------------------------------------------------------------

def diff(old, new, only=None):
    oc, nc = old["classes"], new["classes"]
    res = {"from": old["fingerprint"], "to": new["fingerprint"], "resized": [], "moved": [], "added": [],
           "removed": [], "propsAdded": [], "propsRemoved": [], "reparented": [], "classesAdded": [],
           "classesRemoved": []}
    cnt = Counter()
    for name in sorted(set(oc) | set(nc)):
        if only is not None and name not in only:
            continue
        a, b = oc.get(name), nc.get(name)
        if a is None:
            res["classesAdded"].append(name)
            continue
        if b is None:
            res["classesRemoved"].append(name)
            continue
        cnt["classesBoth"] += 1
        if a["size"] != b["size"]:
            res["resized"].append({"class": name, "old": a["size"], "new": b["size"], "oldSite": a["ctorSite"],
                                   "newSite": b["ctorSite"]})
        if a.get("parent") and b.get("parent") and a["parent"] != b["parent"]:
            res["reparented"].append({"class": name, "old": a["parent"], "new": b["parent"]})
        for pn in sorted(set(a["props"]) | set(b["props"])):
            pa, pb = a["props"].get(pn), b["props"].get(pn)
            if pa and pb:
                cnt["propsBoth"] += 1
                if pa["off"] == pb["off"]:
                    cnt["propsSame"] += 1
                else:
                    res["moved"].append({"class": name, "prop": pn, "old": pa["off"], "new": pb["off"],
                                         "oldSite": pa["site"], "newSite": pb["site"]})
            elif pb:
                res["propsAdded"].append({"class": name, "prop": pn, "off": pb["off"], "site": pb["site"]})
            else:
                res["propsRemoved"].append({"class": name, "prop": pn, "off": pa["off"], "site": pa["site"]})
    res["counts"] = dict(cnt, resized=len(res["resized"]), moved=len(res["moved"]),
                         propsAdded=len(res["propsAdded"]), propsRemoved=len(res["propsRemoved"]),
                         reparented=len(res["reparented"]), classesAdded=len(res["classesAdded"]),
                         classesRemoved=len(res["classesRemoved"]))
    return res


def diff_md(d):
    L = ["# rttiscan diff", "", "from `%s` to `%s`" % (d["from"]["sha256"][:16], d["to"]["sha256"][:16]), "",
         "counts: " + ", ".join("%s %s" % kv for kv in d["counts"].items()), "",
         "## Resized classes", "", "| class | old | new | new site |", "|---|---|---|---|"]
    for r in d["resized"]:
        L.append("| %s | %#x | %#x | %s |" % (r["class"], r["old"], r["new"], r["newSite"]))
    L += ["", "## Moved properties", "", "| class | property | old | new | new site |", "|---|---|---|---|---|"]
    for r in d["moved"]:
        L.append("| %s | %s | %#x | %#x | %s |" % (r["class"], r["prop"], r["old"], r["new"], r["newSite"]))
    for key in ("reparented", "propsAdded", "propsRemoved"):
        L += ["", "## " + key, ""]
        for r in d[key]:
            L.append("- " + json.dumps(r))
    return "\n".join(L) + "\n"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    sys.path.insert(0, _nct_re_path(argv))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--exe")
    s.add_argument("--out", required=True)
    v = sub.add_parser("validate")
    v.add_argument("table")
    v.add_argument("dump")
    v.add_argument("--min-match", type=float, default=0.98)
    v.add_argument("--bad", help="write every mismatch here (jsonl)")
    df = sub.add_parser("diff")
    df.add_argument("old")
    df.add_argument("new")
    df.add_argument("--out", required=True)
    df.add_argument("--md")
    df.add_argument("--only", help="file with one class name per line")
    sh = sub.add_parser("show")
    sh.add_argument("table")
    sh.add_argument("cls")
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        t = scan(a.exe, log=lambda m: print(m, file=sys.stderr))
        Path(a.out).write_text(json.dumps(t, indent=1), encoding="utf-8")
        print(json.dumps(t["counts"]))
        return 0
    if a.cmd == "validate":
        t = json.loads(Path(a.table).read_text(encoding="utf-8"))
        r, bad = validate(t, Path(a.dump))
        print(json.dumps(r, indent=1))
        if a.bad:
            with open(a.bad, "w", encoding="utf-8") as f:
                for b in bad:
                    f.write(json.dumps(b) + "\n")
        checked = r.get("propMatch", 0) + r.get("propMismatch", 0)
        rate = r.get("propMatch", 0) / checked if checked else 0
        srate = r.get("sizeMatch", 0) / max(1, r.get("classFound", 0))
        print("offsets matching %.4f (%d/%d), sizes matching %.4f" % (rate, r.get("propMatch", 0), checked, srate))
        return 0 if rate >= a.min_match and srate >= a.min_match else 1
    if a.cmd == "diff":
        o = json.loads(Path(a.old).read_text(encoding="utf-8"))
        n = json.loads(Path(a.new).read_text(encoding="utf-8"))
        only = None
        if a.only:
            with open(a.only, encoding="utf-8") as f:
                only = {l.strip() for l in f if l.strip()}
        d = diff(o, n, only)
        Path(a.out).write_text(json.dumps(d, indent=1), encoding="utf-8")
        if a.md:
            Path(a.md).write_text(diff_md(d), encoding="utf-8")
        print(json.dumps(d["counts"]))
        return 0
    if a.cmd == "show":
        t = json.loads(Path(a.table).read_text(encoding="utf-8"))
        print(json.dumps(t["classes"].get(a.cls), indent=1))
        return 0


if __name__ == "__main__":
    sys.exit(main())
