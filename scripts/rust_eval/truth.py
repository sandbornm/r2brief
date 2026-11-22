#!/usr/bin/env python3
"""Per-function ground truth for the stripped twins of one symbolized build.

For each `<profile>=<twin>` pair, reads every STT_FUNC in .text of the
symbolized twin `<root>/bins/<target>/<twin>/<bin>`, demangles
it with the independent `rust_demangler` package (not r2b's own demangler),
and labels a function `user` when its owning crate is the user crate. Writes
`<root>/dataset/truth/<target>/<profile>/<bin>.jsonl` after checking that
the stripped binary's .text and .rodata are byte-identical to the twin's, so
the addresses transfer.

usage: truth.py <root> <target> <bin> <user-crate> <profile>=<twin>...
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

STD = {
    "core", "std", "alloc", "compiler_builtins", "std_detect", "hashbrown", "gimli",
    "addr2line", "miniz_oxide", "rustc_demangle", "object", "adler2", "panic_unwind",
    "panic_abort", "unwind", "memchr_std",
}


def demangle(raw: str) -> str:
    # A missing package must fail the job, not silently leave every name raw.
    from rust_demangler import demangle as _demangle

    try:
        name = _demangle(raw)
    except Exception:  # C/asm symbols and odd names stay raw
        name = raw
    return re.sub(r"::h[0-9a-f]{16}$", "", name)


def require_user(recs: list[dict], user_crate: str, where: str) -> int:
    """Return the user-function count; zero means truth is broken, not r2b."""
    n_user = sum(r["kind"] == "user" for r in recs)
    if n_user == 0:
        raw = sum(r["name"].startswith(("_ZN", "_R")) for r in recs)
        raise SystemExit(
            f"{where}: no `{user_crate}` functions among {len(recs)} "
            f"({raw} names still mangled); demangling or crate attribution failed"
        )
    return n_user


def first_crate(s: str) -> str | None:
    s = s.lstrip("<&*( ")
    for prefix in ("mut ", "const ", "dyn ", "impl "):
        if s.startswith(prefix):
            s = s[len(prefix):].lstrip("<&*( ")
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)::", s)
    return m.group(1) if m else None


def crate_of(name: str) -> str:
    if name.startswith("OUTLINED_FUNCTION_"):
        return "llvm_outlined"
    m = re.match(r"<(.+?) as (.+?)>::", name)
    if m:
        a, b = first_crate(m.group(1)), first_crate(m.group(2))
        if a and a not in STD:
            return a
        if b and b not in STD:
            return b
        return a or b or "?"
    return first_crate(name) or ("c/asm" if not name.startswith("_") else "?")


def section_digests(elf: ELFFile) -> dict[str, str]:
    out = {}
    for sec in elf.iter_sections():
        if sec.name in (".text", ".rodata"):
            out[sec.name] = f"{sec['sh_addr']:x}:{hashlib.sha256(sec.data()).hexdigest()}"
    return out


def records(sym_path: Path, user_crate: str) -> list[dict]:
    with open(sym_path, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        symtab = elf.get_section_by_name(".symtab")
        if text is None or symtab is None:
            raise SystemExit(f"{sym_path}: needs .text and .symtab")
        lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
        by_addr: dict[int, list[tuple[str, int]]] = {}
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC" or not lo <= sym["st_value"] < hi:
                continue
            by_addr.setdefault(sym["st_value"] & ~1, []).append((sym.name, sym["st_size"]))
    recs = []
    for addr in sorted(by_addr):
        raw, size = max(by_addr[addr], key=lambda item: item[1])
        name = demangle(raw)
        crate = crate_of(name)
        recs.append({
            "addr": addr, "size": size, "name": name, "crate": crate,
            "kind": "user" if crate == user_crate else "other",
        })
    for i, rec in enumerate(recs):
        if rec["size"] == 0:
            rec["size"] = (recs[i + 1]["addr"] if i + 1 < len(recs) else hi) - rec["addr"]
    return recs


def main(argv: list[str]) -> int:
    root, target, binary, user_crate, *pairs = argv
    bins = Path(root) / "bins" / target
    for pair in pairs:
        profile, twin = pair.split("=", 1)
        recs = records(bins / twin / binary, user_crate)
        with open(bins / twin / binary, "rb") as fh:
            want = section_digests(ELFFile(fh))
        with open(bins / profile / binary, "rb") as fh:
            elf = ELFFile(fh)
            got = section_digests(elf)
            has_symtab = elf.get_section_by_name(".symtab") is not None
        if got != want:
            raise SystemExit(f"{profile}: .text/.rodata differ from {twin}")
        if has_symtab:
            raise SystemExit(f"{profile}: still has .symtab")
        n_user = require_user(recs, user_crate, f"{twin}/{binary}")
        out = Path(root) / "dataset" / "truth" / target / profile / f"{binary}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(json.dumps(r) + "\n" for r in recs))
        print(json.dumps({"binary": f"{target}/{profile}/{binary}", "twin": twin,
                          "n_funcs": len(recs), "n_user": n_user}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
