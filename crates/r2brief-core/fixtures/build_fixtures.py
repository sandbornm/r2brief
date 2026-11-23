#!/usr/bin/env python3
"""Build synthetic ELF fixtures for r2brief-core evaluation.

All binaries are compiled from fixtures/triage_fixture.c (original MIT code).
Infected samples are produced by rewriting our own binaries with documented
techniques (PT_NOTE->PT_LOAD, text-padding LOAD, RWX flag, init_array hijack,
unusual interpreter). No third-party malware is used or redistributed.
"""
from __future__ import annotations

import json
import re
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "triage_fixture.c"
BIN = ROOT / "bin"
TRUTH = ROOT / "truth"
BIN.mkdir(parents=True, exist_ok=True)
TRUTH.mkdir(parents=True, exist_ok=True)

ARCHES = []
# Detect available compilers.
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

if have("x86_64-linux-gnu-gcc"):
    ARCHES.append(("x86_64", "x86_64-linux-gnu-", "x86-64"))
elif have("gcc") and have("objdump"):
    # Native may be aarch64; still useful.
    pass
if have("aarch64-linux-gnu-gcc"):
    ARCHES.append(("aarch64", "aarch64-linux-gnu-", "aarch64"))
# Also try native gcc labeled by uname.
uname = subprocess.check_output(["uname", "-m"], text=True).strip()
if uname in ("x86_64", "amd64") and not any(a[0] == "x86_64" for a in ARCHES) and have("gcc"):
    ARCHES.append(("x86_64", "", "x86-64"))
if uname in ("aarch64", "arm64") and not any(a[0] == "aarch64" for a in ARCHES) and have("gcc"):
    ARCHES.append(("aarch64", "", "aarch64"))

if not ARCHES:
    print("no usable gcc found", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.check_call(cmd)


def nm_funcs(prefix: str, path: Path) -> list[dict]:
    """Ground truth: every STT_FUNC in .symtab with a nonzero value that lies in
    an SHF_EXECINSTR section other than PLT stubs (readelf is the reference)."""
    secs = []
    for line in subprocess.check_output([f"{prefix}readelf", "-SW", str(path)], text=True).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S*)", line)
        if m and "X" in m.group(4) and not (m.group(1).startswith(".plt") or m.group(1) == ".iplt"):
            secs.append((int(m.group(2), 16), int(m.group(2), 16) + int(m.group(3), 16)))
    by_addr: dict[int, dict] = {}
    for line in subprocess.check_output([f"{prefix}readelf", "-sW", str(path)], text=True).splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
            addr = int(parts[1], 16)
            if addr and any(s <= addr < e for s, e in secs):
                name = parts[7].split("@")[0]
                if addr not in by_addr or parts[4] == "GLOBAL":
                    by_addr[addr] = {"name": name, "addr": addr, "bind": parts[4]}
    return [by_addr[a] for a in sorted(by_addr)]


def _old_nm_funcs(prefix: str, path: Path) -> list[dict]:
    """Return function symbols from nm -n (address ascending)."""
    out = subprocess.check_output([f"{prefix}nm", "-n", "--defined-only", str(path)], text=True)
    funcs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr_s, kind, name = parts[0], parts[1], parts[2]
        if kind.upper() not in {"T", "t", "W"}:
            continue
        if name.startswith(".") or name in {"_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini"}:
            # Keep _start out of "user function" truth; keep constructors.
            if name in {"_init", "_fini", "_start", "__libc_csu_init", "__libc_csu_fini"}:
                continue
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        funcs.append({"name": name, "addr": addr, "kind": kind})
    # Dedup by addr (prefer non-local).
    by_addr: dict[int, dict] = {}
    for f in funcs:
        prev = by_addr.get(f["addr"])
        if prev is None or (prev["kind"].islower() and f["kind"].isupper()):
            by_addr[f["addr"]] = f
    return [by_addr[k] for k in sorted(by_addr)]


# --- ELF helpers for infection ---

class ElfMut:
    def __init__(self, data: bytearray):
        self.data = data
        assert data[:4] == b"\x7fELF"
        self.le = data[5] == 1
        self.c64 = data[4] == 2
        self.ehsize = 64 if self.c64 else 52

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H" if self.le else ">H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I" if self.le else ">I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q" if self.le else ">Q", self.data, off)[0]

    def wu16(self, off: int, v: int) -> None:
        struct.pack_into("<H" if self.le else ">H", self.data, off, v)

    def wu32(self, off: int, v: int) -> None:
        struct.pack_into("<I" if self.le else ">I", self.data, off, v)

    def wu64(self, off: int, v: int) -> None:
        struct.pack_into("<Q" if self.le else ">Q", self.data, off, v)

    def word(self, off: int) -> int:
        return self.u64(off) if self.c64 else self.u32(off)

    def wword(self, off: int, v: int) -> None:
        if self.c64:
            self.wu64(off, v)
        else:
            self.wu32(off, v)

    @property
    def phoff(self) -> int:
        return self.u64(32) if self.c64 else self.u32(28)

    @property
    def phentsize(self) -> int:
        return self.u16(54 if self.c64 else 42)

    @property
    def phnum(self) -> int:
        return self.u16(56 if self.c64 else 44)

    def phdr(self, i: int) -> int:
        return self.phoff + i * self.phentsize

    def ph_type(self, i: int) -> int:
        return self.u32(self.phdr(i))

    def set_ph_type(self, i: int, t: int) -> None:
        self.wu32(self.phdr(i), t)

    def ph_flags_off(self, i: int) -> int:
        return self.phdr(i) + (4 if self.c64 else 24)

    def ph_flags(self, i: int) -> int:
        return self.u32(self.ph_flags_off(i))

    def set_ph_flags(self, i: int, f: int) -> None:
        self.wu32(self.ph_flags_off(i), f)

    def ph_field(self, i: int, name: str) -> int:
        # offsets within phdr for 64-bit LE layout
        if self.c64:
            off = {"type": 0, "flags": 4, "offset": 8, "vaddr": 16, "paddr": 24,
                   "filesz": 32, "memsz": 40, "align": 48}[name]
        else:
            off = {"type": 0, "offset": 4, "vaddr": 8, "paddr": 12,
                   "filesz": 16, "memsz": 20, "flags": 24, "align": 28}[name]
        o = self.phdr(i) + off
        if name in {"type", "flags"}:
            return self.u32(o)
        return self.word(o)

    def set_ph_field(self, i: int, name: str, v: int) -> None:
        if self.c64:
            off = {"type": 0, "flags": 4, "offset": 8, "vaddr": 16, "paddr": 24,
                   "filesz": 32, "memsz": 40, "align": 48}[name]
        else:
            off = {"type": 0, "offset": 4, "vaddr": 8, "paddr": 12,
                   "filesz": 16, "memsz": 20, "flags": 24, "align": 28}[name]
        o = self.phdr(i) + off
        if name in {"type", "flags"}:
            self.wu32(o, v)
        else:
            self.wword(o, v)

    def find_phdr(self, ptype: int) -> int | None:
        for i in range(self.phnum):
            if self.ph_type(i) == ptype:
                return i
        return None


PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PF_X, PF_W, PF_R = 1, 2, 4


def infect_note_to_load(src: Path, dst: Path) -> dict:
    """Rewrite a PT_NOTE into a small executable PT_LOAD (ElfMaster-style)."""
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    note = e.find_phdr(PT_NOTE)
    if note is None:
        # Some links only have GNU_PROPERTY as note; try any NOTE.
        raise SystemExit(f"no PT_NOTE in {src}")
    # Point the new LOAD at the note's own file bytes; give it a high VA.
    file_off = e.ph_field(note, "offset")
    file_sz = e.ph_field(note, "filesz")
    if file_sz < 16:
        # Expand: append a tiny parasite and retarget.
        parasite = b"\x90" * 64 if e.c64 else b"\x00" * 64
        # For aarch64 use BRK; for x86-64 use NOPs ending in RET.
        # Detect machine:
        machine = e.u16(18)
        if machine == 183:  # EM_AARCH64
            # RET x30
            parasite = b"\xc0\x03\x5f\xd6" * 16
        else:
            parasite = b"\x90" * 63 + b"\xc3"
        file_off = len(data)
        data.extend(parasite)
        e = ElfMut(data)
        file_sz = len(parasite)
    # Choose a VA far from existing loads.
    max_va = 0
    for i in range(e.phnum):
        if e.ph_type(i) == PT_LOAD:
            max_va = max(max_va, e.ph_field(i, "vaddr") + e.ph_field(i, "memsz"))
    new_va = (max_va + 0x200000) & ~0xfff
    e.set_ph_type(note, PT_LOAD)
    e.set_ph_field(note, "flags", PF_R | PF_X)
    e.set_ph_field(note, "offset", file_off)
    e.set_ph_field(note, "vaddr", new_va)
    e.set_ph_field(note, "paddr", new_va)
    e.set_ph_field(note, "filesz", file_sz)
    e.set_ph_field(note, "memsz", file_sz)
    e.set_ph_field(note, "align", 0x1000)
    dst.write_bytes(data)
    return {
        "technique": "pt_note_to_load",
        "phdr_index": note,
        "vaddr": new_va,
        "offset": file_off,
        "filesz": file_sz,
        "expected_finding_ids": [f"elf:pt_note_to_load:{note}"],
    }


def infect_text_padding(src: Path, dst: Path) -> dict:
    """Insert a small executable PT_LOAD in the page padding after .text.

    We convert an existing PT_NOTE (or reuse a slot) — same rewrite, but the
    VA is placed inside the page slack of the first executable LOAD.
    """
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    # Find first executable LOAD.
    text = None
    for i in range(e.phnum):
        if e.ph_type(i) == PT_LOAD and e.ph_flags(i) & PF_X:
            text = i
            break
    if text is None:
        raise SystemExit("no executable LOAD")
    text_end = e.ph_field(text, "offset") + e.ph_field(text, "filesz")
    page_end = (text_end + 0xfff) & ~0xfff
    slack = page_end - text_end
    if slack < 64:
        # Force slack by shrinking filesz of text by 0? Can't without breaking.
        # Instead append and claim the padding VA range that already exists
        # (the loader maps the whole page). We'll place file bytes after EOF
        # but set offset into the existing page padding if any zeros exist;
        # if not, expand the file into the padding by extending filesz of a
        # converted NOTE that points into the padding bytes (must be zeros).
        raise SystemExit(f"insufficient text padding ({slack} bytes) in {src}")
    note = e.find_phdr(PT_NOTE)
    if note is None:
        raise SystemExit("no PT_NOTE")
    # Use the padding bytes in-file as the parasite home.
    # Fill with architecture-correct ret.
    machine = e.u16(18)
    if machine == 183:
        blob = b"\xc0\x03\x5f\xd6" * (slack // 4)
    else:
        blob = b"\x90" * (slack - 1) + b"\xc3"
    data[text_end:text_end + len(blob)] = blob[:slack]
    e = ElfMut(data)
    new_va = e.ph_field(text, "vaddr") + e.ph_field(text, "filesz")
    e.set_ph_type(note, PT_LOAD)
    e.set_ph_field(note, "flags", PF_R | PF_X)
    e.set_ph_field(note, "offset", text_end)
    e.set_ph_field(note, "vaddr", new_va)
    e.set_ph_field(note, "paddr", new_va)
    e.set_ph_field(note, "filesz", slack)
    e.set_ph_field(note, "memsz", slack)
    e.set_ph_field(note, "align", 1)
    dst.write_bytes(data)
    return {
        "technique": "text_padding",
        "phdr_index": note,
        "text_index": text,
        "vaddr": new_va,
        "offset": text_end,
        "filesz": slack,
        "expected_finding_ids": [
            f"elf:text_padding:{text}:{note}",
        ],
    }


def infect_rwx(src: Path, dst: Path) -> dict:
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    text = None
    for i in range(e.phnum):
        if e.ph_type(i) == PT_LOAD and e.ph_flags(i) & PF_X:
            text = i
            break
    if text is None:
        raise SystemExit("no executable LOAD")
    e.set_ph_flags(text, PF_R | PF_W | PF_X)
    dst.write_bytes(data)
    return {
        "technique": "rwx",
        "phdr_index": text,
        "expected_finding_ids": [f"elf:rwx_segment:{text}"],
    }


def infect_interp(src: Path, dst: Path) -> dict:
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    interp = e.find_phdr(PT_INTERP)
    if interp is None:
        raise SystemExit("no PT_INTERP")
    off = e.ph_field(interp, "offset")
    sz = e.ph_field(interp, "filesz")
    fake = b"/tmp/evil-ld.so\x00"
    if len(fake) > sz:
        # Overwrite what fits and keep a NUL.
        fake = b"/tmp/x\x00"
    data[off:off + len(fake)] = fake
    # Zero the rest of the old path.
    for i in range(off + len(fake), off + sz):
        data[i] = 0
    dst.write_bytes(data)
    return {
        "technique": "interp_tamper",
        "phdr_index": interp,
        "path": fake.split(b"\0")[0].decode(),
        "expected_finding_ids": ["elf:interp_unusual"],
    }


def infect_init_array(src: Path, dst: Path) -> dict:
    """Point the first DT_INIT_ARRAY entry at a non-executable address."""
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    # Find PT_DYNAMIC and walk for DT_INIT_ARRAY / SZ.
    dyn = e.find_phdr(PT_DYNAMIC)
    if dyn is None:
        raise SystemExit("no PT_DYNAMIC")
    dyn_off = e.ph_field(dyn, "offset")
    dyn_end = dyn_off + e.ph_field(dyn, "filesz")
    ent = 16 if e.c64 else 8
    init_array = None
    init_arraysz = None
    off = dyn_off
    while off + ent <= dyn_end:
        tag = e.u64(off) if e.c64 else e.u32(off)
        # signed
        if e.c64:
            tag_s = struct.unpack_from("<q" if e.le else ">q", data, off)[0]
        else:
            tag_s = struct.unpack_from("<i" if e.le else ">i", data, off)[0]
        val_off = off + (8 if e.c64 else 4)
        val = e.word(val_off)
        if tag_s == 25:  # DT_INIT_ARRAY
            init_array = val
        elif tag_s == 27:  # DT_INIT_ARRAYSZ
            init_arraysz = val
        elif tag_s == 0:
            break
        off += ent
    if not init_array or not init_arraysz or init_arraysz < (8 if e.c64 else 4):
        raise SystemExit(f"no usable DT_INIT_ARRAY in {src}")
    # Map VA to file.
    file_off = None
    for i in range(e.phnum):
        if e.ph_type(i) != PT_LOAD:
            continue
        va = e.ph_field(i, "vaddr")
        fo = e.ph_field(i, "offset")
        fsz = e.ph_field(i, "filesz")
        if va <= init_array < va + fsz:
            file_off = fo + (init_array - va)
            break
    if file_off is None:
        raise SystemExit("init_array not in a LOAD")
    bogus = 0x7fff_0000_0000  # high VA outside any PT_LOAD on our fixtures
    # The loader applies R_*_RELATIVE addends and ignores the in-file slot, so a
    # real hijack on PIE patches the addend. We patch ONLY the addend (slot left
    # intact) so a checker that reads the raw slot misses it.
    rela = relasz = None
    off = dyn_off
    while off + ent <= dyn_end:
        tag_s = struct.unpack_from("<q" if e.le else ">q", data, off)[0] if e.c64 else 0
        val = e.word(off + (8 if e.c64 else 4))
        if tag_s == 7:
            rela = val
        elif tag_s == 8:
            relasz = val
        elif tag_s == 0:
            break
        off += ent
    rel_type = {62: 8, 183: 1027}.get(e.u16(18))
    patched = "slot"
    if e.c64 and rela and relasz and rel_type:
        rela_off = None
        for i in range(e.phnum):
            if e.ph_type(i) != PT_LOAD:
                continue
            va = e.ph_field(i, "vaddr"); fo = e.ph_field(i, "offset"); fsz = e.ph_field(i, "filesz")
            if va <= rela < va + fsz:
                rela_off = fo + (rela - va)
        for k in range(relasz // 24):
            o = rela_off + k * 24
            r_off, r_info = e.u64(o), e.u64(o + 8)
            if r_off == init_array and (r_info & 0xffffffff) == rel_type:
                e.wu64(o + 16, bogus)
                patched = "rela_addend"
                break
    if patched == "slot":
        if e.c64:
            e.wu64(file_off, bogus)
        else:
            e.wu32(file_off, bogus)
    dst.write_bytes(data)
    return {
        "technique": "init_array_hijack",
        "init_array": init_array,
        "bogus_entry": bogus,
        "patched": patched,
        "expected_finding_ids": ["elf:dt_init_array:entry0:outside_text"],
    }


def sstrip(src: Path, dst: Path) -> None:
    """Drop the section header table (sstrip-style): zero e_shoff/e_shnum/
    e_shstrndx and truncate to the end of the last segment's file bytes."""
    data = bytearray(src.read_bytes())
    e = ElfMut(data)
    end = 0
    for i in range(e.phnum):
        end = max(end, e.ph_field(i, "offset") + e.ph_field(i, "filesz"))
    end = max(end, e.phoff + e.phnum * e.phentsize)
    if e.c64:
        e.wu64(40, 0); e.wu16(60, 0); e.wu16(62, 0)
    else:
        e.wu32(32, 0); e.wu16(48, 0); e.wu16(50, 0)
    dst.write_bytes(bytes(data[:end]))


def build_one(arch: str, prefix: str, label: str) -> list[dict]:
    records = []
    base = BIN / f"triage-{arch}"
    # Normal PIE with symbols + frame pointers for prologue clarity.
    cflags = ["-O1", "-fno-omit-frame-pointer", "-g0", "-Wl,--build-id=none"]
    if arch == "x86_64":
        cflags += ["-fcf-protection=full"]  # endbr64
    run([f"{prefix}gcc", *cflags, "-o", str(base), str(SRC)])
    funcs = nm_funcs(prefix, base)
    truth = {"binary": base.name, "arch": label, "functions": funcs}
    (TRUTH / f"{base.name}.json").write_text(json.dumps(truth, indent=2) + "\n")
    records.append({"name": base.name, "kind": "normal", "arch": label, "truth": f"{base.name}.json"})

    stripped = BIN / f"triage-{arch}-stripped"
    run([f"{prefix}strip", "-o", str(stripped), str(base)])
    # Same truth (addresses preserved by strip).
    (TRUTH / f"{stripped.name}.json").write_text(json.dumps({
        "binary": stripped.name, "arch": label, "functions": funcs,
        "twin": base.name,
    }, indent=2) + "\n")
    records.append({"name": stripped.name, "kind": "stripped", "arch": label, "truth": f"{stripped.name}.json"})

    # Extra variants: legacy non-PIE layout (data ~2 MiB above text) must not
    # trip layout heuristics; no-unwind-tables exercises the sparse-eh_frame path.
    variants = [
        ("nopie", "clean-nopie", ["-no-pie", "-Wl,-z,noseparate-code"]),
        ("noeh", "stripped-noeh", ["-fno-asynchronous-unwind-tables", "-fno-unwind-tables"]),
    ]
    for suffix, kind, extra in variants:
        vb = BIN / f"triage-{arch}-{suffix}-sym"
        run([f"{prefix}gcc", *cflags, *extra, "-o", str(vb), str(SRC)])
        vfuncs = nm_funcs(prefix, vb)
        vs = BIN / f"triage-{arch}-{suffix}"
        run([f"{prefix}strip", "-o", str(vs), str(vb)])
        vb.unlink()
        (TRUTH / f"{vs.name}.json").write_text(json.dumps({
            "binary": vs.name, "arch": label, "functions": vfuncs, "flags": extra,
        }, indent=2) + "\n")
        records.append({"name": vs.name, "kind": kind, "arch": label, "truth": f"{vs.name}.json"})

    # Infections applied to the stripped twin so findings aren't masked by symbols.
    for technique, fn in [
        ("note", infect_note_to_load),
        ("pad", infect_text_padding),
        ("rwx", infect_rwx),
        ("interp", infect_interp),
        ("init", infect_init_array),
    ]:
        out = BIN / f"triage-{arch}-{technique}"
        try:
            meta = fn(stripped, out)
        except SystemExit as exc:
            print(f"skip {technique}/{arch}: {exc}", file=sys.stderr)
            continue
        meta.update({
            "binary": out.name,
            "arch": label,
            "kind": "infected",
            "source": stripped.name,
            "functions": funcs,  # code addresses unchanged for these rewrites
        })
        (TRUTH / f"{out.name}.json").write_text(json.dumps(meta, indent=2) + "\n")
        records.append({"name": out.name, "kind": "infected", "arch": label,
                        "technique": meta["technique"], "truth": f"{out.name}.json"})
    # Sectionless (sstrip) twins: clean and PT_NOTE-infected. This is the
    # "stripped + infected" sample the demo opens first.
    ss = BIN / f"triage-{arch}-sstrip"
    sstrip(stripped, ss)
    (TRUTH / f"{ss.name}.json").write_text(json.dumps({"binary": ss.name, "arch": label, "functions": funcs}, indent=2) + "\n")
    records.append({"name": ss.name, "kind": "sectionless", "arch": label, "truth": f"{ss.name}.json"})
    note = BIN / f"triage-{arch}-note"
    if note.exists():
        ns = BIN / f"triage-{arch}-note-sstrip"
        sstrip(note, ns)
        meta = json.loads((TRUTH / f"{note.name}.json").read_text())
        meta.update({"binary": ns.name, "source": note.name, "sectionless": True})
        meta["expected_finding_ids"] = meta["expected_finding_ids"] + ["elf:no_section_headers"]
        (TRUTH / f"{ns.name}.json").write_text(json.dumps(meta, indent=2) + "\n")
        records.append({"name": ns.name, "kind": "infected", "arch": label,
                        "technique": "pt_note_to_load+sstrip", "truth": f"{ns.name}.json"})
    return records


def main() -> None:
    all_recs = []
    for arch, prefix, label in ARCHES:
        all_recs.extend(build_one(arch, prefix, label))
    manifest = {
        "schema_version": "r2brief.core.fixtures.v1",
        "source": "triage_fixture.c",
        "arches": [a[2] for a in ARCHES],
        "binaries": all_recs,
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
