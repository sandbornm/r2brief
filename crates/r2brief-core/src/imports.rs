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
        let n = if entsize == 0 { 0 } else { sec.sh_size / entsize };
        let r = elf.rd();
        for i in 0..n {
            let o = sec.sh_offset + i * entsize;
            let (name_off, info, shndx) = if elf.hdr.class64 {
                (
                    r.u32(o).unwrap_or(0),
                    r.u8(o + 4).unwrap_or(0),
                    r.u16(o + 6).unwrap_or(0),
                )
            } else {
                (
                    r.u32(o).unwrap_or(0),
                    r.u8(o + 12).unwrap_or(0),
                    r.u16(o + 14).unwrap_or(0),
                )
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
            let Some((name_bytes, _)) = r.cstr(strsec.sh_offset + name_off as u64, 512) else {
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
            for i in 0..4096u64 {
                let Some(sym_off) = elf.va_to_off(symtab + i * syment) else { break };
                let (name_off, info, shndx) = if elf.hdr.class64 {
                    (
                        r.u32(sym_off).unwrap_or(0),
                        r.u8(sym_off + 4).unwrap_or(0),
                        r.u16(sym_off + 6).unwrap_or(0),
                    )
                } else {
                    (
                        r.u32(sym_off).unwrap_or(0),
                        r.u8(sym_off + 12).unwrap_or(0),
                        r.u16(sym_off + 14).unwrap_or(0),
                    )
                };
                if name_off as u64 >= strsz {
                    break;
                }
                if shndx != 0 {
                    continue;
                }
                let bind = info >> 4;
                if bind != 1 && bind != 2 {
                    continue;
                }
                let Some(str_off) = elf.va_to_off(strtab + name_off as u64) else { continue };
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
