//! Structural ELF anomaly checks that cite exact file offsets.
//!
//! Each check returns Findings with a rule id that matches documented
//! infection / anti-forensics techniques (ElfMaster PT_NOTE->PT_LOAD,
//! reverse-text / text-padding, RWX, init_array hijack, interpreter
//! tampering). Findings that cannot be verified against a fixture are
//! not emitted.

use crate::dynamic::DynamicInfo;
use crate::elf::{
    hex, ptype_name, Elf, Phdr, PF_W, PF_X, PT_INTERP,
    SHT_DYNSYM, SHT_SYMTAB,
};
use crate::report::{Evidence, Finding};

pub fn check_all(elf: &Elf<'_>, dyninfo: Option<&DynamicInfo>) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(check_entry(elf));
    out.extend(check_rwx(elf));
    out.extend(check_overlapping_loads(elf));
    out.extend(check_note_to_load(elf));
    out.extend(check_text_padding(elf));
    out.extend(check_reverse_text(elf));
    out.extend(check_load_oob(elf));
    out.extend(check_sections(elf));
    out.extend(check_interp(elf));
    out.extend(check_stripped(elf));
    if let Some(d) = dyninfo {
        out.extend(check_init_hijack(elf, d));
        out.extend(check_needed(d));
    }
    out
}

fn finding(
    id: &str,
    title: &str,
    why: &str,
    score: f64,
    tags: &[&str],
    evidence: Vec<Evidence>,
) -> Finding {
    Finding {
        id: id.into(),
        title: title.into(),
        why: why.into(),
        score,
        tags: tags.iter().map(|s| (*s).into()).collect(),
        evidence,
        ask: format!("Confirm {title} against readelf -l / -S / -d and the fixture truth."),
    }
}

fn check_entry(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let e = elf.hdr.e_entry;
    if e == 0 {
        return out;
    }
    if elf.exec_load_at_va(e).is_none() {
        out.push(finding(
            "elf:entry_outside_text",
            "Entry point outside executable PT_LOAD",
            &format!(
                "e_entry 0x{e:x} is not covered by any PF_X PT_LOAD. A loader that honors e_entry will jump into non-executable or nonexistent mapped memory."
            ),
            95.0,
            &["entry", "anomaly"],
            vec![Evidence {
                kind: "header".into(),
                offset: Some(if elf.hdr.class64 { 24 } else { 24 }),
                address: Some(e),
                length: Some(if elf.hdr.class64 { 8 } else { 4 }),
                bytes_hex: None,
                detail: Some(format!("e_entry=0x{e:x}")),
            }],
        ));
        return out;
    }
    if let Some(sec) = elf.section_at_va(e) {
        if !sec.exec() {
            out.push(finding(
                "elf:entry_non_exec_section",
                "Entry point lands in a non-executable section",
                &format!(
                    "e_entry 0x{e:x} is in section '{}' which lacks SHF_EXECINSTR.",
                    sec.name
                ),
                85.0,
                &["entry", "anomaly", "section"],
                vec![Evidence {
                    kind: "section".into(),
                    offset: Some(sec.sh_offset),
                    address: Some(e),
                    length: Some(sec.sh_size),
                    bytes_hex: None,
                    detail: Some(format!("section={} flags=0x{:x}", sec.name, sec.sh_flags)),
                }],
            ));
        }
    }
    out
}

fn check_rwx(elf: &Elf<'_>) -> Vec<Finding> {
    elf.loads()
        .filter(|p| p.p_flags & (PF_W | PF_X) == PF_W | PF_X)
        .map(|p| {
            finding(
                &format!("elf:rwx_segment:{}", p.index),
                "RWX PT_LOAD segment",
                &format!(
                    "PT_LOAD[{}] flags={} (RWX) at file 0x{:x}+0x{:x} / VA 0x{:x}. Writable+executable mappings are a classic backdoor landing zone and break W^X.",
                    p.index,
                    p.flags_str(),
                    p.p_offset,
                    p.p_filesz,
                    p.p_vaddr
                ),
                92.0,
                &["segment", "rwx", "anomaly"],
                vec![ph_evidence(p)],
            )
        })
        .collect()
}

// Unchecked arithmetic here is bounded: indices bounded by loads.len().

#[allow(clippy::arithmetic_side_effects)]

fn check_overlapping_loads(elf: &Elf<'_>) -> Vec<Finding> {
    let loads: Vec<&Phdr> = elf.loads().collect();
    let mut out = Vec::new();
    for i in 0..loads.len() {
        for j in (i + 1)..loads.len() {
            let a = loads[i];
            let b = loads[j];
            let Some(a_end) = a.p_vaddr.checked_add(a.p_memsz) else { continue };
            let Some(b_end) = b.p_vaddr.checked_add(b.p_memsz) else { continue };
            if a.p_vaddr < b_end && b.p_vaddr < a_end {
                out.push(finding(
                    &format!("elf:overlap_load:{}:{}", a.index, b.index),
                    "Overlapping PT_LOAD virtual ranges",
                    &format!(
                        "PT_LOAD[{}] VA 0x{:x}-0x{:x} overlaps PT_LOAD[{}] VA 0x{:x}-0x{:x}. Overlaps are used by some infection techniques and confuse naive VA→file maps.",
                        a.index, a.p_vaddr, a_end, b.index, b.p_vaddr, b_end
                    ),
                    88.0,
                    &["segment", "overlap", "anomaly"],
                    vec![ph_evidence(a), ph_evidence(b)],
                ));
            }
        }
    }
    out
}

/// PT_NOTE whose type was rewritten to PT_LOAD (ElfMaster note infection).
///
/// Structural rule, independent of address layout: GNU ld, gold and lld emit
/// exactly one PF_X PT_LOAD and keep all PT_LOAD entries contiguous and
/// ascending in the program header table. A converted note sits where the
/// PT_NOTE was (after PT_DYNAMIC), so it is an executable PT_LOAD that is
/// out of the contiguous LOAD run, while another executable LOAD exists.
// Unchecked arithmetic here is bounded: phdr indices bounded by phdrs.len(); p.index > run_end >= 0.
#[allow(clippy::arithmetic_side_effects)]
fn check_note_to_load(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let exec_loads = elf.loads().filter(|p| p.exec()).count();
    if exec_loads < 2 {
        return out;
    }
    let Some(first) = elf.phdrs.iter().position(|p| p.is_load()) else { return out };
    let mut run_end = first;
    while run_end + 1 < elf.phdrs.len() && elf.phdrs[run_end + 1].is_load() {
        run_end += 1;
    }
    for p in elf.phdrs.iter().skip(run_end + 1) {
        if !(p.is_load() && p.exec()) {
            continue;
        }
        let prev = &elf.phdrs[p.index - 1];
        out.push(finding(
            &format!("elf:pt_note_to_load:{}", p.index),
            "Suspected PT_NOTE→PT_LOAD infection",
            &format!(
                "PT_LOAD[{}] (flags {}, file 0x{:x}+0x{:x}, VA 0x{:x}) is executable but sits outside the contiguous PT_LOAD run [{}..={}], after PT_{}[{}]. Link editors emit one executable LOAD and keep LOADs contiguous; a rewritten PT_NOTE lands exactly here.",
                p.index, p.flags_str(), p.p_offset, p.p_filesz, p.p_vaddr, first, run_end,
                ptype_name(prev.p_type), prev.index
            ),
            90.0,
            &["infection", "pt_note", "anomaly"],
            vec![ph_evidence(p)],
        ));
    }
    out
}

/// Text-padding: an executable LOAD whose filesz is much smaller than memsz
/// leaving a large BSS-like hole that some infectors fill with parasite code
/// at runtime — but more commonly, a second executable LOAD squeezed into
/// the page padding between .text and .data.
fn check_text_padding(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let loads: Vec<&Phdr> = elf.loads().collect();
    let texts: Vec<&Phdr> = loads.iter().copied().filter(|p| p.exec() && p.p_filesz > 0).collect();
    for i in 0..texts.len() {
        for j in 0..texts.len() {
            if i == j {
                continue;
            }
            let a = texts[i];
            let b = texts[j];
            // b sits in the file-gap / page-pad of a.
            let Some(a_file_end) = a.file_end() else { continue };
            let Some(a_page_end) = a_file_end.checked_add(0xfff).map(|x| x & !0xfff) else { continue };
            if b.p_offset >= a_file_end && b.p_offset < a_page_end && b.p_filesz > 0 && b.p_filesz <= 0x1000 {
                out.push(finding(
                    &format!("elf:text_padding:{}:{}", a.index, b.index),
                    "Executable segment in text page padding",
                    &format!(
                        "PT_LOAD[{}] (filesz=0x{:x}) sits in the page padding after PT_LOAD[{}] file end 0x{:x} (page end 0x{:x}). Text-padding infection places a parasite in that unused aligned slack.",
                        b.index, b.p_filesz, a.index, a_file_end, a_page_end
                    ),
                    91.0,
                    &["infection", "text_padding", "anomaly"],
                    vec![ph_evidence(a), ph_evidence(b)],
                ));
            }
        }
    }
    out
}

/// Reverse-text: an executable LOAD whose vaddr is below the ELF header /
/// below other LOADs and whose file offset is 0 or near 0, extending the
/// text segment "backwards" (ElfMaster reverse text infection).
// Unchecked arithmetic here is bounded: e_phentsize * e_phnum are u16s widened to u64.
#[allow(clippy::arithmetic_side_effects)]
fn check_reverse_text(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let loads: Vec<&Phdr> = elf.loads().filter(|p| p.exec()).collect();
    if loads.len() < 2 {
        return out;
    }
    let min_va = loads.iter().map(|p| p.p_vaddr).min().unwrap_or(0);
    for p in &loads {
        // Candidate: lowest VA among executable loads, with p_offset==0 and
        // a large filesz that covers the ELF header itself (infectors extend
        // the text segment downward and prepend parasite bytes).
        if p.p_vaddr != min_va {
            continue;
        }
        if p.p_offset != 0 {
            continue;
        }
        // Normal PIE/ET_DYN also has a LOAD at offset 0 covering the header.
        // Distinguish by: another executable LOAD exists whose VA is higher,
        // AND the low LOAD's memsz is larger than the file's first "real"
        // content would suggest (parasite prepended), measured as:
        // the gap between this VA+filesz and the next LOAD's VA is negative
        // or the segment contains both header and a large prepended region.
        // Practical check used by the fixture: the first LOAD's filesz is
        // larger than e_phoff + e_phentsize*e_phnum by more than a page AND
        // e_entry lands near the start of this segment (parasite entry).
        let hdr_end = elf.hdr.e_phoff.saturating_add(u64::from(elf.hdr.e_phentsize) * u64::from(elf.hdr.e_phnum));
        if p.p_filesz <= hdr_end.saturating_add(0x1000) {
            continue;
        }
        let entry = elf.hdr.e_entry;
        if entry >= p.p_vaddr && entry < p.p_vaddr.saturating_add(0x200) {
            out.push(finding(
                &format!("elf:reverse_text:{}", p.index),
                "Suspected reverse-text infection",
                &format!(
                    "Executable PT_LOAD[{}] starts at file offset 0 / VA 0x{:x} with filesz 0x{:x}, and e_entry 0x{:x} is within the first 0x200 bytes. That pattern matches reverse-text infection: the text segment was extended downward and the parasite was prepended.",
                    p.index, p.p_vaddr, p.p_filesz, entry
                ),
                89.0,
                &["infection", "reverse_text", "anomaly"],
                vec![ph_evidence(p)],
            ));
        }
    }
    out
}

fn check_load_oob(elf: &Elf<'_>) -> Vec<Finding> {
    elf.loads()
        .filter(|p| p.file_end().map(|e| e > elf.len()).unwrap_or(true))
        .map(|p| {
            finding(
                &format!("elf:load_oob:{}", p.index),
                "PT_LOAD file range runs past end of file",
                &format!(
                    "PT_LOAD[{}] claims file 0x{:x}+0x{:x} but the file is 0x{:x} bytes. Truncated or tampered; analysis uses only the readable prefix.",
                    p.index, p.p_offset, p.p_filesz, elf.len()
                ),
                80.0,
                &["segment", "anomaly"],
                vec![ph_evidence(p)],
            )
        })
        .collect()
}

fn check_sections(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    if !elf.has_sections() {
        out.push(finding(
            "elf:no_section_headers",
            "Section header table absent",
            "e_shoff/e_shnum indicate no section headers. The binary is fully sectionless; only program headers are available for triage.",
            40.0,
            &["section", "stripped"],
            vec![Evidence {
                kind: "header".into(),
                offset: Some(if elf.hdr.class64 { 40 } else { 32 }),
                address: None,
                length: Some(8),
                bytes_hex: None,
                detail: Some(format!("e_shoff=0x{:x} e_shnum={}", elf.hdr.e_shoff, elf.hdr.e_shnum)),
            }],
        ));
        return out;
    }
    for s in &elf.shdrs {
        if s.has_file_bytes() && s.sh_size > 0 {
            let Some(end) = s.sh_offset.checked_add(s.sh_size) else {
                out.push(finding(
                    &format!("elf:section_oob:{}", s.index),
                    "Section size overflows",
                    &format!("Section '{}' offset+size overflows u64.", s.name),
                    80.0,
                    &["section", "anomaly"],
                    vec![],
                ));
                continue;
            };
            if end > elf.len() {
                out.push(finding(
                    &format!("elf:section_oob:{}", s.index),
                    "Section extends past end of file",
                    &format!(
                        "Section '{}' (index {}) claims file 0x{:x}+0x{:x} but the file is only 0x{:x} bytes.",
                        s.name, s.index, s.sh_offset, s.sh_size, elf.len()
                    ),
                    80.0,
                    &["section", "anomaly"],
                    vec![Evidence {
                        kind: "section".into(),
                        offset: Some(s.entry_offset),
                        address: Some(s.sh_addr),
                        length: Some(s.sh_size),
                        bytes_hex: None,
                        detail: Some(format!("name={} sh_offset=0x{:x}", s.name, s.sh_offset)),
                    }],
                ));
            }
        }
        if s.alloc() && s.has_file_bytes() && s.sh_size > 0 {
            // Allocated section whose file bytes are not covered by any PT_LOAD.
            let covered = elf.loads().any(|p| {
                match (p.file_end(), s.sh_offset.checked_add(s.sh_size.min(1))) {
                    (Some(pend), Some(send)) => s.sh_offset >= p.p_offset && send <= pend,
                    _ => false,
                }
            });
            if !covered {
                out.push(finding(
                    &format!("elf:section_not_in_load:{}", s.index),
                    "Allocated section not covered by PT_LOAD",
                    &format!(
                        "Section '{}' is SHF_ALLOC at file 0x{:x} but no PT_LOAD covers those bytes. Section headers and segments disagree.",
                        s.name, s.sh_offset
                    ),
                    75.0,
                    &["section", "segment", "anomaly"],
                    vec![Evidence {
                        kind: "section".into(),
                        offset: Some(s.sh_offset),
                        address: Some(s.sh_addr),
                        length: Some(s.sh_size),
                        bytes_hex: None,
                        detail: Some(format!("name={}", s.name)),
                    }],
                ));
            }
        }
    }
    out
}

fn check_interp(elf: &Elf<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(p) = elf.phdrs.iter().find(|p| p.p_type == PT_INTERP) else {
        return out;
    };
    let interp_len = p.p_filesz.min(4096);
    let Some(raw) = elf.rd().bytes(p.p_offset, interp_len) else {
        out.push(finding(
            "elf:interp_oob",
            "PT_INTERP points outside the file",
            &format!("PT_INTERP filesz=0x{:x} at offset 0x{:x} is unreadable.", p.p_filesz, p.p_offset),
            85.0,
            &["interp", "anomaly"],
            vec![ph_evidence(p)],
        ));
        return out;
    };
    let path = match raw.iter().position(|&b| b == 0) {
        Some(i) => String::from_utf8_lossy(&raw[..i]).into_owned(),
        None => String::from_utf8_lossy(raw).into_owned(),
    };
    let expected = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib/ld-linux-x86-64.so.2",
        "/lib/ld-linux.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/lib64/ld-linux-aarch64.so.1",
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
    ];
    if path.is_empty() || !path.starts_with('/') {
        out.push(finding(
            "elf:interp_invalid",
            "Invalid PT_INTERP path",
            &format!("PT_INTERP path {path:?} is empty or not absolute."),
            90.0,
            &["interp", "anomaly"],
            vec![Evidence {
                kind: "interp".into(),
                offset: Some(p.p_offset),
                address: Some(p.p_vaddr),
                length: Some(p.p_filesz),
                bytes_hex: Some(hex(&raw[..raw.len().min(256)])),
                detail: Some(path),
            }],
        ));
    } else if !expected.iter().any(|e| path == *e) {
        out.push(finding(
            "elf:interp_unusual",
            "Unusual PT_INTERP",
            &format!(
                "PT_INTERP is {path:?}. Not one of the common glibc/musl loaders; may be a custom loader or interpreter rewrite."
            ),
            70.0,
            &["interp", "anomaly"],
            vec![Evidence {
                kind: "interp".into(),
                offset: Some(p.p_offset),
                address: Some(p.p_vaddr),
                length: Some(p.p_filesz),
                bytes_hex: Some(hex(&raw[..raw.len().min(256)])),
                detail: Some(path),
            }],
        ));
    }
    out
}

fn check_stripped(elf: &Elf<'_>) -> Vec<Finding> {
    let has_symtab = elf.shdrs.iter().any(|s| s.sh_type == SHT_SYMTAB);
    let has_dynsym = elf.shdrs.iter().any(|s| s.sh_type == SHT_DYNSYM);
    if !has_symtab {
        let why = if has_dynsym {
            "No SHT_SYMTAB; only SHT_DYNSYM remains (typical strip). Function names for non-exported symbols are gone."
        } else if !elf.has_sections() {
            "No section headers and no symbol table."
        } else {
            "No SHT_SYMTAB and no SHT_DYNSYM; fully stripped of symbols."
        };
        return vec![finding(
            "elf:stripped_symbols",
            "Symbol table stripped",
            why,
            35.0,
            &["stripped", "symbols"],
            vec![],
        )];
    }
    vec![]
}

// Unchecked arithmetic here is bounded: ws is the constant 4 or 8.

#[allow(clippy::arithmetic_side_effects)]

fn check_init_hijack(elf: &Elf<'_>, d: &DynamicInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    // DT_INIT / DT_FINI point outside executable LOADs.
    for (tag, va) in [("DT_INIT", d.dt_init), ("DT_FINI", d.dt_fini)] {
        let Some(va) = va else { continue };
        if va == 0 {
            continue; // same convention as zero .init_array slots
        }
        if elf.exec_load_at_va(va).is_none() {
            out.push(finding(
                &format!("elf:{}:outside_text", tag.to_lowercase()),
                &format!("{tag} outside executable PT_LOAD"),
                &format!("{tag}=0x{va:x} is not in any PF_X PT_LOAD."),
                93.0,
                &["dynamic", "init", "anomaly"],
                vec![Evidence {
                    kind: "dynamic".into(),
                    offset: None,
                    address: Some(va),
                    length: None,
                    bytes_hex: None,
                    detail: Some(format!("{tag}=0x{va:x}")),
                }],
            ));
        }
    }
    // DT_*ARRAYSZ that claims more slots than the file backs.
    let ws = if elf.hdr.class64 { 8 } else { 4 };
    for (name, sz, got) in [
        ("DT_INIT_ARRAYSZ", d.init_array_sz, d.init_array.len()),
        ("DT_FINI_ARRAYSZ", d.fini_array_sz, d.fini_array.len()),
        ("DT_PREINIT_ARRAYSZ", d.preinit_array_sz, d.preinit_array.len()),
    ] {
        let Some(sz) = sz else { continue };
        if sz % ws != 0 || sz / ws > got as u64 {
            out.push(finding(
                &format!("elf:{}:oversized", name.to_lowercase()),
                &format!("{name} exceeds file-backed array"),
                &format!(
                    "{name}=0x{sz:x} claims {} slots but only {got} are readable from PT_LOAD file bytes (or size is not a multiple of {ws}). The loader would walk past the array.",
                    sz / ws
                ),
                85.0,
                &["dynamic", "init_array", "anomaly"],
                vec![Evidence {
                    kind: "dynamic".into(),
                    offset: None,
                    address: None,
                    length: Some(sz),
                    bytes_hex: None,
                    detail: Some(format!("{name}=0x{sz:x} readable_slots={got}")),
                }],
            ));
        }
    }
    // Array entries that point outside executable memory.
    for (name, entries) in [
        ("DT_INIT_ARRAY", d.init_array.as_slice()),
        ("DT_FINI_ARRAY", d.fini_array.as_slice()),
        ("DT_PREINIT_ARRAY", d.preinit_array.as_slice()),
    ] {
        for (i, &va) in entries.iter().enumerate() {
            if va == 0 {
                continue;
            }
            if elf.exec_load_at_va(va).is_none() {
                out.push(finding(
                    &format!("elf:{}:entry{i}:outside_text", name.to_lowercase()),
                    &format!("{name}[{i}] outside executable PT_LOAD"),
                    &format!("{name}[{i}]=0x{va:x} is not in any PF_X PT_LOAD; common .init_array/.ctors hijack."),
                    94.0,
                    &["dynamic", "init_array", "anomaly", "infection"],
                    vec![Evidence {
                        kind: "dynamic".into(),
                        offset: None,
                        address: Some(va),
                        length: None,
                        bytes_hex: None,
                        detail: Some(format!("{name}[{i}]=0x{va:x}")),
                    }],
                ));
            }
        }
    }
    out
}

fn check_needed(d: &DynamicInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in &d.needed {
        // Empty or non-.so names are odd.
        if n.is_empty() || !n.contains(".so") {
            out.push(finding(
                &format!("elf:dt_needed_odd:{}", n),
                "Unusual DT_NEEDED entry",
                &format!("DT_NEEDED {n:?} does not look like a shared library soname."),
                55.0,
                &["dynamic", "needed"],
                vec![Evidence {
                    kind: "dynamic".into(),
                    offset: None,
                    address: None,
                    length: None,
                    bytes_hex: None,
                    detail: Some(format!("DT_NEEDED={n}")),
                }],
            ));
        }
    }
    out
}

fn ph_evidence(p: &Phdr) -> Evidence {
    Evidence {
        kind: "phdr".into(),
        offset: Some(p.entry_offset),
        address: Some(p.p_vaddr),
        length: Some(p.p_filesz),
        bytes_hex: None,
        detail: Some(format!(
            "PT_{}[{}] flags={} file=0x{:x}+0x{:x} va=0x{:x}+0x{:x}",
            ptype_name(p.p_type),
            p.index,
            p.flags_str(),
            p.p_offset,
            p.p_filesz,
            p.p_vaddr,
            p.p_memsz
        )),
    }
}


