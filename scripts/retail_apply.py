#!/usr/bin/env python3
"""Apply regenerated layouts to the SDK's generated headers, touching only what the generator owns.

Inputs are two trees written by metadata_dump.py --out from the same old live dump: <old> without and <new> with
--retail (the new exe's layouts). For every header that differs between them:
  * the SDK file equals <old> (line endings ignored): it is replaced by <new>;
  * the SDK file differs from <old>: it carries hand edits, so it is listed and left alone (patch it by hand);
  * <new> has no such header (the class is gone from the new exe): listed, left alone.

Usage:
  python scripts/retail_apply.py --old <dir> --new <dir> [--sdk-include include] [--dry-run] [--report out.json]
"""
import argparse
import json
from pathlib import Path


def norm(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", type=Path, required=True)
    ap.add_argument("--new", type=Path, required=True)
    ap.add_argument("--sdk-include", type=Path, default=Path(__file__).resolve().parents[1] / "include")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", type=Path)
    a = ap.parse_args(argv)
    rep = {"replaced": [], "handEdited": [], "gone": [], "notInSdk": []}
    for p in sorted(a.old.rglob("*.hpp")):
        rel = p.relative_to(a.old)
        q, s = a.new / rel, a.sdk_include / rel
        old = norm(p.read_bytes())
        if not q.exists():
            if s.exists():
                rep["gone"].append(rel.as_posix())
            continue
        new = norm(q.read_bytes())
        if new == old:
            continue
        if not s.exists():
            rep["notInSdk"].append(rel.as_posix())
            continue
        cur = s.read_bytes()
        if norm(cur) != old:
            rep["handEdited"].append(rel.as_posix())
            continue
        rep["replaced"].append(rel.as_posix())
        if not a.dry_run:
            crlf = b"\r\n" in cur
            s.write_bytes(new.replace(b"\n", b"\r\n") if crlf else new)
    print(", ".join("%s %d" % (k, len(v)) for k, v in rep.items()))
    for k in ("handEdited", "gone"):
        for r in rep[k]:
            print("%s: %s" % (k, r))
    if a.report:
        a.report.write_text(json.dumps(rep, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
