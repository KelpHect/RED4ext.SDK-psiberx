#!/usr/bin/env python3
"""Offline twin of the in-game reflection dumper (include/RED4ext/Dump/Reflection-inl.hpp).

The in-game dumper needs a running game. On update day the game may not boot (the SDK itself is what is broken), so
this script emits the same class headers from an offline type schema:

  --metadata <tools/redmod/metadata.json>   CDPR's own type schema shipped with REDmod (native classes, own
                                             properties with offsets, enums, bitfields, simple types, aliases);
                                             --script-index adds the scripted class/enum names the in-game dumper
                                             would see (only for the namespace/directory hierarchy)
  --rtti-live <dir>                          an NCT live RTTI snapshot (classes/props/types/enums/bitfields .jsonl),
                                             used to check this port against the headers the in-game dumper wrote

Every formatting decision follows Reflection-inl.hpp line for line (ClassFileDescriptor::EmitFile, TypeToString,
ClassDependencyBuilder::Accumulate/ToFileDescriptor, the prefix hierarchy, the parent-property hoisting). Enums and
bitfields are emitted only with --enums.

Usage:
  python scripts/metadata_dump.py --metadata metadata.json [--script-index index.json] --out <dir> [--only a,b]
  python scripts/metadata_dump.py --rtti-live <dir> --out <dir>
  python scripts/metadata_dump.py ... --apply --sdk-include include   # rewrite the existing generated headers
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FUNDAMENTAL = {"Int8": (1, 1), "Uint8": (1, 1), "Int16": (2, 2), "Uint16": (2, 2), "Int32": (4, 4), "Uint32": (4, 4),
               "Int64": (8, 8), "Uint64": (8, 8), "Float": (4, 4), "Double": (8, 8), "Bool": (1, 1)}
TYPE_MAP = {"Int8": "int8_t", "Int16": "int16_t", "Int32": "int32_t", "Int64": "int64_t", "Uint8": "uint8_t",
            "Uint16": "uint16_t", "Uint32": "uint32_t", "Uint64": "uint64_t", "Float": "float", "Bool": "bool",
            "String": "CString", "gameItemID": "ItemID", "Double": "double"}
FIXED_MAPPING = {"ISerializable": "ISerializable", "IScriptable": "Scripting/IScriptable",
                 "ScriptGameInstance": "Scripting/Natives/ScriptGameInstance", "gameItemID": "NativeTypes",
                 "CBaseEngine": "GameEngine", "BaseGameEngine": "GameEngine", "CGameEngine": "GameEngine",
                 "UpdateBucketEnum": "SystemUpdate", "worldGlobalNodeRef": "NativeTypes"}
INVALID_CHARS = re.compile(r"-|'|\(|\)|\]|\[|/|\.|\s|:")
INVALID_KEYWORDS = re.compile(r"\bregister\b|\bbool\b|\bint\b|\btemplate\b|\bdefault\b|\btrue\b|\bfalse\b|\bsmall\b"
                              r"|\bswitch\b|\bPlane\b")
# '[N]X' is a NativeArray in RTTI, except these, which are RT_FixedArray (2.31 live RTTI, props.jsonl "k")
FIXED_ARRAYS = {"[3]inkTextureSlot", "[5][6]Uint16"}


def sanitize(name: str):
    mod = bool(INVALID_CHARS.search(name) or INVALID_KEYWORDS.search(name))
    out = INVALID_KEYWORDS.sub(lambda m: m.group(0) + "_", INVALID_CHARS.sub("_", name))
    if name and name[0].isdigit():
        out = "_" + out
        mod = True
    return out, mod


# ---------------------------------------------------------------------------------------------------- the schema
class T:
    """An RTTI type: kind (Class, Enum, BitField, Fundamental, Simple, Name, Handle, WeakHandle, Array, StaticArray,
    NativeArray, FixedArray, ResourceReference, ResourceAsyncReference, Curve), name, inner, length, size, align."""

    __slots__ = ("kind", "name", "inner", "length", "size", "align")

    def __init__(self, kind, name, inner=None, length=0, size=0, align=1):
        self.kind, self.name, self.inner, self.length, self.size, self.align = kind, name, inner, length, size, align

    def key(self):
        return self.name


class Schema:
    def __init__(self):
        self.classes = {}    # name -> dict(parent, size, align, props=[(name, typestr, offset)], holder=[...])
        self.enums = {}      # name -> dict(size, members=[(name, value)], aliases=[(name, value)], scripted)
        self.bitfields = {}  # name -> dict(size, align, bits={name: index})
        self.simple = {}     # name -> (size, align)
        self.alias = {}      # native name -> script name
        self.extra_names = set()  # scripted class/enum names (prefix hierarchy only)
        self._cache = {}

    def type(self, s: str) -> T:
        t = self._cache.get(s)
        if t is None:
            t = self._parse(s)
            self._cache[s] = t
        return t

    def _parse(self, s: str) -> T:
        for pre, kind in (("handle:", "Handle"), ("whandle:", "WeakHandle")):
            if s.startswith(pre):
                return T(kind, s, self.type(s[len(pre):]), size=16, align=8)
        if s.startswith("array:"):
            return T("Array", s, self.type(s[6:]), size=16, align=8)
        if s.startswith("raRef:"):
            return T("ResourceAsyncReference", s, self.type(s[6:]), size=8, align=8)
        if s.startswith("rRef:"):
            return T("ResourceReference", s, self.type(s[5:]), size=24, align=8)
        if s.startswith("curveData:"):
            return T("Curve", s, self.type(s[10:]), size=0x38, align=8)
        if s.startswith("static:"):
            n, inner = s[7:].split(",", 1)
            it = self.type(inner)
            al = max(it.align, 4)
            size = (int(n) * it.size + 4 + al - 1) // al * al
            return T("StaticArray", s, it, int(n), size, al)
        m = re.match(r"^\[(\d+)\](.*)$", s)
        if m:
            it = self.type(m.group(2))
            return T("FixedArray" if s in FIXED_ARRAYS else "NativeArray", s, it, int(m.group(1)),
                     int(m.group(1)) * it.size, it.align)
        if s in FUNDAMENTAL:
            return T("Fundamental", s, size=FUNDAMENTAL[s][0], align=FUNDAMENTAL[s][1])
        if s == "CName":
            return T("Name", s, size=8, align=8)
        if s in self.simple:
            return T("Simple", s, size=self.simple[s][0], align=self.simple[s][1])
        if s in self.classes:
            c = self.classes[s]
            return T("Class", s, size=c["size"], align=c["align"])
        if s in self.enums:
            return T("Enum", s, size=self.enums[s]["size"], align=self.enums[s]["size"])
        if s in self.bitfields:
            b = self.bitfields[s]
            return T("BitField", s, size=b["size"], align=b.get("align", b["size"]))
        return T("Unknown", s, size=0, align=1)


def load_metadata(path: Path, script_index: Path | None) -> Schema:
    d = json.loads(path.read_text(encoding="utf-8"))
    sc = Schema()
    for st in d["simple_types"]:
        sc.simple[st["name"]] = (st["size"], st["alignment"])
    for c in d["classes"]:
        props = [(p["name"], p["type"], p["offset"]) for p in c["properties"] if not (p["flags"] >> 21) & 1]
        holder = [(p["name"], p["type"], p["offset"]) for p in c["properties"] if (p["flags"] >> 21) & 1]
        sc.classes[c["name"]] = {"parent": c["parent"] or None, "size": c["size"], "align": c["alignment"],
                                 "props": props, "holder": holder}
    for e in d["enums"]:
        # metadata lists aliases among the options; the in-game hash list keeps one name per value and the alias list
        # the rest. Without the split, the first name of a value is the member, later ones are aliases.
        members, aliases, seen = [], [], set()
        for name, val in e["options"].items():
            if val in seen:
                aliases.append((name, val))
            else:
                seen.add(val)
                members.append((name, val))
        sc.enums[e["name"]] = {"size": e["size"], "members": members, "aliases": aliases, "scripted": False}
    for b in d["bitfields"]:
        sc.bitfields[b["name"]] = {"size": b["size"], "align": b["alignment"], "bits": b["bits"]}
    sc.alias = dict(d.get("aliases", {}))
    if script_index:
        idx = json.loads(script_index.read_text(encoding="utf-8"))
        for name, c in idx.get("classes", {}).items():
            if not c.get("native"):
                sc.extra_names.add(name)
        for name in idx.get("enums", {}):
            if name not in sc.enums:
                sc.extra_names.add(name)
    return sc


def load_rtti_live(root: Path) -> Schema:
    sc = Schema()
    rd = lambda n: [json.loads(l) for l in (root / n).open(encoding="utf-8") if l.strip()]
    for t in rd("types.jsonl"):
        if t["k"] == "Simple":
            sc.simple[t["n"]] = (t["size"], min(t["size"], 8) if t["size"] else 1)
    for t in rd("types.jsonl"):
        if t["k"] == "Simple" and t["n"] in ("CGUID", "CDateTime", "DataBuffer", "serializationDeferredDataBuffer",
                                            "SharedDataBuffer", "TweakDBID"):
            sc.simple[t["n"]] = (t["size"], 4)
    classes = rd("classes.jsonl")
    natives = {c["n"]: c for c in classes if c["native"]}
    for c in classes:
        if not c["native"]:
            sc.extra_names.add(c["n"])
    byclass = {}
    for p in rd("props.jsonl"):
        byclass.setdefault(p["c"], []).append(p)
    for n, c in natives.items():
        sc.classes[n] = {"parent": c["parent"] or None, "size": c["size"], "align": c["align"], "props": [],
                         "holder": []}
        if c.get("scriptName") and c["scriptName"] != n:
            sc.alias[n] = c["scriptName"]
    for n in natives:
        parent = natives[n]["parent"]
        inherited = {(p["p"], p["off"], p["holder"]) for p in byclass.get(parent, [])} if parent else set()
        for p in sorted(byclass.get(n, []), key=lambda p: p["off"]):
            if (p["p"], p["off"], p["holder"]) in inherited:
                continue
            if not p["holder"]:  # the SDK headers are dumped without aPropertyHolders
                sc.classes[n]["props"].append((p["p"], p["t"], p["off"]))
    for e in rd("enums.jsonl"):
        if e["n"].startswith("$"):
            continue
        sc.enums[e["n"]] = {"size": e["size"], "members": [tuple(m) for m in e["members"]],
                            "aliases": [tuple(a) for a in e["aliases"]], "scripted": e["scripted"]}
    for b in rd("bitfields.jsonl"):
        sc.bitfields[b["n"]] = {"size": b["size"], "align": b["size"], "bits": {}}
    return sc


# ---------------------------------------------------------------------------------------------------- naming
UNIQUE_NS = (("AI", False), ("GpuApi", True), ("GpuWrapApiVertexPacking", True), ("GpuWrapApi", True))


def get_prefix(s: str) -> str:
    i = 0
    for name, special in UNIQUE_NS:
        if s.startswith(name):
            i = len(name)
            if special:
                return s[:i]
    if s.startswith("inGame"):
        return ""
    while i < len(s) and not s[i].isupper():
        i += 1
    return s[:i] if i else ""


class Naming:
    def __init__(self, names):
        h = {}
        for n in names:
            p = get_prefix(n)
            if p:
                h[p] = []
        for prefix, children in h.items():
            if prefix not in ("localization", "render"):
                for i in range(len(prefix)):
                    tp = prefix[: i + 1]
                    if tp in h:
                        children.append(tp)
            else:
                children.append(prefix)
            orig = list(children)
            for k in range(len(children) - 1, 0, -1):
                children[k] = orig[k][len(orig[k - 1]):]
        self.h = h

    def ns(self, prefix):
        return "::".join(self.h.get(prefix, [])) if prefix else ""

    def strip(self, name):
        return name[len(get_prefix(name)):]

    def qualified(self, name):
        p = get_prefix(name)
        ns = self.ns(p)
        s = name[len(p):]
        return ns + "::" + s if ns else s

    def path(self, name):
        p = get_prefix(name)
        out = ""
        if p:
            out = "/".join(self.h[p]) if p in self.h else p
            out += "/"
        return "Scripting/Natives/Generated/" + out


def type_to_string(t: T, xf) -> str:
    k = t.kind
    if k == "WeakHandle":
        s = "WeakHandle<" + type_to_string(t.inner, xf) + ">"
    elif k == "Handle":
        s = "Handle<" + type_to_string(t.inner, xf) + ">"
    elif k == "Array":
        s = "DynArray<" + type_to_string(t.inner, xf) + ">"
    elif k == "ResourceAsyncReference":
        s = "RaRef<" + type_to_string(t.inner, xf) + ">"
    elif k == "ResourceReference":
        s = "Ref<" + type_to_string(t.inner, xf) + ">"
    elif k == "Curve":
        s = "CurveData<" + type_to_string(t.inner, xf) + ">"
    elif k == "StaticArray":
        s = ("alignas(%d) " % t.align) if t.align >= 8 else ""
        s += "StaticArray<" + type_to_string(t.inner, xf) + ", %d>" % t.length
    elif k == "NativeArray":
        s = "NativeArray<" + type_to_string(t.inner, xf) + ", %d>" % t.length
    elif k in ("Name", "Fundamental", "Class", "Simple", "Enum", "BitField"):
        s = TYPE_MAP.get(t.name) or xf(t.name)
    else:
        rt = {"FixedArray": "RT_FixedArray"}.get(k, "RT_" + k)
        s = "std::array<uint8_t, %d>/* UNHANDLED: %s (%s) */" % (t.size, t.name, rt)
    return s


# ---------------------------------------------------------------------------------------------------- emission
def hx(v):
    return "%X" % v


def build_maps(sc: Schema):
    """Own properties per native class, after the dumper's second pass (a property whose offset fits inside an
    ancestor that is itself a native class is hoisted into that ancestor)."""
    maps = {n: {off: (pn, ts) for pn, ts, off in c["props"]} for n, c in sc.classes.items()}
    for n, c in sc.classes.items():
        stack = []
        p = c["parent"]
        while p:
            stack.append(p)
            p = sc.classes[p]["parent"] if p in sc.classes else None
        m = maps[n]
        keys = sorted(m)
        i = 0
        while i < len(keys) and stack:
            parent = stack[-1]
            off = keys[i]
            psize = sc.classes[parent]["size"] if parent in sc.classes else 0
            if off < psize:
                if parent in maps:
                    maps[parent][off] = m.pop(off)
                    keys = sorted(m)
                    continue
            else:
                keys = sorted(m)
                i = 0
                stack.pop()
                continue
            i += 1
    return maps


def emit_class(sc: Schema, nm: Naming, name: str, propmap: dict, override: str | None) -> tuple[str, str, set]:
    c = sc.classes[name]
    direct, indirect, order = set(), set(), []

    def acc(t: T):
        if t.kind in ("WeakHandle", "Handle", "ResourceAsyncReference", "ResourceReference"):
            indirect.add(t.inner.name)
            direct.add(t.name)
            order.append(t)
        elif t.kind == "Curve":
            acc(t.inner)
            direct.add(t.name)
            order.append(t)
        elif t.kind in ("Array", "NativeArray", "StaticArray"):
            acc(t.inner)
            direct.add(t.name)
            order.append(t)
        else:
            indirect.discard(t.name)
            direct.add(t.name)
            order.append(t)

    if c["parent"]:
        acc(sc.type(c["parent"]))
    props = [(off, pn, sc.type(ts)) for off, (pn, ts) in sorted(propmap.items())]
    for _, _, t in props:
        acc(t)
    holder = sorted(((off, pn, sc.type(ts)) for pn, ts, off in c["holder"]), key=lambda x: x[0])
    for _, _, t in holder:
        acc(t)

    types = {t.name: t for t in order}
    includes = set()
    for dn in direct:
        t = types[dn]
        k = t.kind
        if k in ("Enum", "BitField", "Class"):
            includes.add(FIXED_MAPPING.get(dn) or (nm.path(dn) + nm.strip(dn)))
        elif k == "Array":
            includes.add("Containers/DynArray")
        elif k == "Name":
            includes.add("CName")
        elif k in ("WeakHandle", "Handle"):
            includes.add("Handle")
        elif k == "StaticArray":
            includes.add("Containers/StaticArray")
        elif k in ("NativeArray", "ResourceReference", "ResourceAsyncReference", "Curve", "Simple"):
            includes.add("NativeTypes")
    fwd = sorted({nm.qualified(i) for i in indirect})

    sname = nm.strip(name)
    qname = nm.qualified(name)
    alias = sc.alias.get(name)
    if alias and (alias in sc.classes or alias in sc.enums or alias in sc.bitfields or alias in sc.extra_names):
        alias = None
    size, align = c["size"], c["align"]
    parent_size = sc.classes[c["parent"]]["size"] if c["parent"] in sc.classes else 0

    o = ["#pragma once\n\n", "// clang-format off\n\n", "// This file is generated from the Game's Reflection data\n\n"]
    if override:
        o.append("#include <RED4ext/%s>\n\n" % override)
        o.append("namespace RED4ext\n{\n")
        o.append("RED4EXT_ASSERT_SIZE(%s, 0x%s);\n" % (qname, hx(size)))
        if sname != name:
            o.append("using %s = %s;\n" % (name, qname))
        if alias and alias != name:
            o.append("using %s = %s;\n" % (alias, qname))
        o.append("} // namespace RED4ext\n\n/*\n")
    o.append("#include <cstdint>\n#include <RED4ext/Common.hpp>\n")
    for inc in sorted(includes):
        o.append("#include <RED4ext/%s.hpp>\n" % inc)
    o.append("\nnamespace RED4ext\n{\n")
    if fwd:
        for f in fwd:
            if f != qname:
                idx = f.rfind(":")
                if idx != -1:
                    o.append("namespace %s { struct %s; }\n" % (f[: idx - 1], f[idx + 1:]))
                else:
                    o.append("struct %s;\n" % f)
        o.append("\n")
    nsi = qname.rfind(":")
    if nsi != -1:
        o.append("namespace %s\n{\n" % qname[: nsi - 1])
    o.append("struct ")
    if align == 0x10:
        o.append("__declspec(align(0x%s)) " % hx(align))
    o.append(sname if nsi != -1 else qname)
    if c["parent"]:
        o.append(" : " + nm.qualified(c["parent"]))
    o.append("\n{\n")
    o.append('    static constexpr const char* NAME = "%s";\n' % name)
    o.append('    static constexpr const char* ALIAS = "%s";\n' % alias if alias else
             "    static constexpr const char* ALIAS = NAME;\n")
    o.append("\n")

    def members(lst, indent, start):
        last_off, last_size = start, 0
        for off, pn, t in lst:
            if off - (last_off + last_size) > 0:
                gs = last_off + last_size
                o.append("%suint8_t unk%02X[0x%X - 0x%X]; // %X\n" % (indent, gs, off, gs, gs))
            ts = type_to_string(t, nm.strip)
            if t.align >= 8 and ts.startswith("alignas"):
                o.append("#pragma warning(suppress : 4324)\n")
            pname, mod = sanitize(pn)
            valid = bool(pn)
            o.append("%s%s %s; // %02X%s\n" % (indent, type_to_string(t, nm.qualified),
                                                pname if valid else "unk%02X" % off, off,
                                                (" -- " + pn) if (not valid or mod) else ""))
            last_off, last_size = off, t.size

    if holder:
        o.append("    struct PropertyHolder\n    {\n")
        members(holder, "        ", 0)
        o.append("    };\n\n")
    if props:
        members(props, "    ", parent_size)
        boff, _, bt = props[-1]
        if boff + bt.size < size:
            gs = boff + bt.size
            o.append("    uint8_t unk%02X[0x%X - 0x%X]; // %X\n" % (gs, size, gs, gs))
    elif size - parent_size > 0:
        o.append("    uint8_t unk%02X[0x%X - 0x%X]; // %X\n" % (parent_size, size, parent_size, parent_size))
    o.append("};\n")
    o.append("RED4EXT_ASSERT_SIZE(%s, 0x%s);\n" % (sname, hx(size)))
    if nsi != -1:
        o.append("} // namespace %s\n" % qname[: nsi - 1])
    if sname != name:
        o.append("using %s = %s;\n" % (name, qname))
    if alias and alias != name:
        o.append("using %s = %s;\n" % (alias, qname))
    o.append("} // namespace RED4ext\n")
    if override:
        o.append("*/\n")
    o.append("\n// clang-format on\n")
    rel = nm.path(name) + sname + ".hpp"
    return rel, "".join(o), includes


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--metadata", type=Path)
    src.add_argument("--rtti-live", type=Path)
    ap.add_argument("--script-index", type=Path)
    ap.add_argument("--sdk-include", type=Path, default=Path(__file__).resolve().parents[1] / "include")
    ap.add_argument("--out", type=Path, help="write the headers under <out>/RED4ext/...")
    ap.add_argument("--only", help="comma-separated native class names")
    ap.add_argument("--report", type=Path, help="write a JSON list of {name, path, override}")
    ap.add_argument("--bundle", type=Path, help="write every header into one JSON {path: text} instead of files")
    a = ap.parse_args(argv)

    sc = load_metadata(a.metadata, a.script_index) if a.metadata else load_rtti_live(a.rtti_live)
    nm = Naming(list(sc.classes) + list(sc.enums) + list(sc.bitfields) + sorted(sc.extra_names))
    maps = build_maps(sc)
    only = set(a.only.split(",")) if a.only else None
    unknown = set()
    report = []
    bundle = {}
    n = 0
    for name in sorted(sc.classes):
        if name in FIXED_MAPPING or (only and name not in only):
            continue
        ovr = "Scripting/Natives/%s.hpp" % name
        override = ovr if (a.sdk_include / "RED4ext" / ovr).exists() else None
        rel, text, _ = emit_class(sc, nm, name, maps[name], override)
        for _, ts in maps[name].values():
            if sc.type(ts).kind == "Unknown" or (sc.type(ts).inner and sc.type(ts).inner.kind == "Unknown"):
                unknown.add(ts)
        report.append({"name": name, "path": rel, "override": override})
        if a.bundle:
            bundle[rel] = text
        if a.out:
            p = a.out / "RED4ext" / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(text.encode("utf-8"))
        n += 1
    if a.bundle:
        a.bundle.write_text(json.dumps(bundle), encoding="utf-8")
    if a.report:
        a.report.write_text(json.dumps(report, indent=0), encoding="utf-8")
    print("classes emitted: %d" % n)
    if unknown:
        print("types without a schema entry (emitted as UNHANDLED): %d, e.g. %s" % (len(unknown), sorted(unknown)[:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
