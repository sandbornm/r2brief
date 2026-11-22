//! Imported-symbol enumeration from SHT_DYNSYM / DT_SYMTAB.
//! Mirrors the dangerous-import set used by r2b's Python briefing.

use crate::dynamic::DynamicInfo;
use crate::elf::{Elf, SHT_DYNSYM};

/// Same set as `r2b.analysis.briefing._DANGEROUS_IMPORTS`.
pub const DANGEROUS: &[&str] = &[
    "system", "popen", "execve", "execl", "execlp", "execvp", "execv", "execlpe", "execvpe",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "memmove",
    "realpath", "tmpnam",
];

/// Same set as `_VERIFY_IMPORTS` — the ones `r2b verify --import` auto-queues.
pub const VERIFY: &[&str] = &["system", "popen", "execve", "execl", "execvp", "execv"];

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportSym {
    pub name: String,
    pub bind: u8,
    pub typ: u8,
    pub dangerous: bool,
}

// Unchecked arithmetic here is bounded: entsize checked nonzero above.

#[allow(clippy::arithmetic_side_effects)]

pub fn list_imports(elf: &Elf<'_>, dyninfo: Option<&DynamicInfo>) -> Vec<ImportSym> {
    let mut out = Vec::new();
    // Prefer the section if present; else walk DT_SYMTAB until we hit a null name.
    if let Some(sec) = elf.shdrs.iter().find(|s| s.sh_type == SHT_DYNSYM) {
        let link = sec.sh_link as usize;
        let Some(strsec) = elf.shdrs.get(link) else {
            return out;
        };
        let entsize = if sec.sh_entsize == 0 {
            if elf.hdr.class64 {
                24
            } else {
                16
            }
        } else {
            sec.sh_entsize
        };
        if entsize == 0 {
            return out;
        }
        // Only walk bytes that actually exist in the file.
        let readable = elf.len().saturating_sub(sec.sh_offset);
        let span = sec.sh_size.min(readable);
        let n = (span / entsize).min(65_536);
        let r = elf.rd();
        for i in 0..n {
            let o = sec.sh_offset.saturating_add(i.saturating_mul(entsize));
            if r.bytes(o, entsize).is_none() {
                break;
            }
            let (name_off, info, shndx) = if elf.hdr.class64 {
                match (r.u32(o), r.u8(o.saturating_add(4)), r.u16(o.saturating_add(6))) {
                    (Some(a), Some(b), Some(c)) => (a, b, c),
                    _ => break,
                }
            } else {
                match (r.u32(o), r.u8(o.saturating_add(12)), r.u16(o.saturating_add(14))) {
                    (Some(a), Some(b), Some(c)) => (a, b, c),
                    _ => break,
                }
            };
            // STB_GLOBAL/WEAK + STT_FUNC/NOTYPE + SHN_UNDEF → import.
            if shndx != 0 {
                continue;
            }
            let bind = info >> 4;
            let typ = info & 0xf;
            if bind != 1 && bind != 2 {
                continue; // not GLOBAL/WEAK
            }
            let Some(name_abs) = strsec.sh_offset.checked_add(name_off as u64) else {
                break;
            };
            let Some((name_bytes, _)) = r.cstr(name_abs, 512) else {
                continue;
            };
            if name_bytes.is_empty() {
                continue;
            }
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            let base = name.split('@').next().unwrap_or(&name);
            let dangerous = DANGEROUS.iter().any(|d| *d == base);
            out.push(ImportSym { name, bind, typ, dangerous });
        }
        return out;
    }
    // Fallback via DT_SYMTAB — walk a bounded number of entries.
    if let Some(d) = dyninfo {
        if let (Some(symtab), Some(strtab), Some(strsz)) = (d.symtab, d.strtab, d.strsz) {
            let syment = d.syment.unwrap_or(if elf.hdr.class64 { 24 } else { 16 });
            let r = elf.rd();
            let mut bad_run = 0u32;
            for i in 0..4096u64 {
                let Some(sym_off) = i.checked_mul(syment).and_then(|d| symtab.checked_add(d)).and_then(|va| elf.va_to_off(va)) else { break };
                let (name_off, info, shndx) = if elf.hdr.class64 {
                    (
                        r.u32(sym_off).unwrap_or(0),
                        r.u8(sym_off.saturating_add(4)).unwrap_or(0),
                        r.u16(sym_off.saturating_add(6)).unwrap_or(0),
                    )
                } else {
                    (
                        r.u32(sym_off).unwrap_or(0),
                        r.u8(sym_off.saturating_add(12)).unwrap_or(0),
                        r.u16(sym_off.saturating_add(14)).unwrap_or(0),
                    )
                };
                if name_off as u64 >= strsz {
                    bad_run = bad_run.saturating_add(1);
                    if bad_run > 64 {
                        break;
                    }
                    continue;
                }
                bad_run = 0;
                if shndx != 0 {
                    continue;
                }
                let bind = info >> 4;
                if bind != 1 && bind != 2 {
                    continue;
                }
                let Some(str_off) = strtab.checked_add(name_off as u64).and_then(|a| elf.va_to_off(a)) else { continue };
                let Some((name_bytes, _)) = r.cstr(str_off, 512) else { continue };
                if name_bytes.is_empty() {
                    if i == 0 {
                        continue;
                    }
                    break;
                }
                let name = String::from_utf8_lossy(name_bytes).into_owned();
                let base = name.split('@').next().unwrap_or(&name);
                let dangerous = DANGEROUS.iter().any(|d| *d == base);
                out.push(ImportSym {
                    name,
                    bind,
                    typ: info & 0xf,
                    dangerous,
                });
            }
        }
    }
    out
}

pub fn dangerous_names(imports: &[ImportSym]) -> Vec<String> {
    let mut v: Vec<String> = imports
        .iter()
        .filter(|i| i.dangerous)
        .map(|i| i.name.split('@').next().unwrap_or(&i.name).to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}
