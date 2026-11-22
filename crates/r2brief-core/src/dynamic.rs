//! DT_* parsing from PT_DYNAMIC. Used for init/fini hijack checks,
//! DT_NEEDED listing, and PLT/GOT orientation. No relocation walking yet.

use crate::elf::{Elf, PT_DYNAMIC};

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_PREINIT_ARRAY: i64 = 32;
pub const DT_PREINIT_ARRAYSZ: i64 = 33;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_ff00;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

#[derive(Debug, Default, Clone)]
pub struct DynamicInfo {
    pub entries: Vec<(i64, u64)>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub runpath: Option<String>,
    pub rpath: Option<String>,
    pub strtab: Option<u64>,
    pub strsz: Option<u64>,
    pub symtab: Option<u64>,
    pub syment: Option<u64>,
    pub pltgot: Option<u64>,
    pub jmprel: Option<u64>,
    pub pltrelsz: Option<u64>,
    pub pltrel: Option<u64>,
    pub dt_init: Option<u64>,
    pub dt_fini: Option<u64>,
    pub init_array_addr: Option<u64>,
    pub init_array_sz: Option<u64>,
    pub fini_array_addr: Option<u64>,
    pub fini_array_sz: Option<u64>,
    pub preinit_array_addr: Option<u64>,
    pub preinit_array_sz: Option<u64>,
    pub init_array: Vec<u64>,
    pub fini_array: Vec<u64>,
    pub preinit_array: Vec<u64>,
    pub textrel: bool,
    pub bind_now: bool,
}

pub fn parse(elf: &Elf<'_>) -> Option<DynamicInfo> {
    let ph = elf.phdrs.iter().find(|p| p.p_type == PT_DYNAMIC)?;
    let r = elf.rd();
    let ent = r.word_size() * 2;
    let mut info = DynamicInfo::default();
    let mut off = ph.p_offset;
    let end = ph.file_end();
    while off + ent <= end {
        let _tag = r.word(off)? as i64;
        // On ELFCLASS64 Dyn.d_tag is signed; treat the raw word as i64 via cast.
        let tag = if r.c64 {
            // reinterpret
            let raw = r.u64(off)?;
            raw as i64
        } else {
            r.u32(off)? as i32 as i64
        };
        let val = r.word(off + r.word_size())?;
        info.entries.push((tag, val));
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => {} // resolved after strtab
            DT_STRTAB => info.strtab = Some(val),
            DT_STRSZ => info.strsz = Some(val),
            DT_SYMTAB => info.symtab = Some(val),
            DT_SYMENT => info.syment = Some(val),
            DT_PLTGOT => info.pltgot = Some(val),
            DT_JMPREL => info.jmprel = Some(val),
            DT_PLTRELSZ => info.pltrelsz = Some(val),
            DT_PLTREL => info.pltrel = Some(val),
            DT_INIT => info.dt_init = Some(val),
            DT_FINI => info.dt_fini = Some(val),
            DT_INIT_ARRAY => info.init_array_addr = Some(val),
            DT_INIT_ARRAYSZ => info.init_array_sz = Some(val),
            DT_FINI_ARRAY => info.fini_array_addr = Some(val),
            DT_FINI_ARRAYSZ => info.fini_array_sz = Some(val),
            DT_PREINIT_ARRAY => info.preinit_array_addr = Some(val),
            DT_PREINIT_ARRAYSZ => info.preinit_array_sz = Some(val),
            DT_SONAME => {}
            DT_RPATH => {}
            DT_RUNPATH => {}
            DT_TEXTREL => info.textrel = true,
            DT_BIND_NOW => info.bind_now = true,
            DT_FLAGS if val & 0x4 != 0 => info.textrel = true, // DF_TEXTREL
            DT_FLAGS if val & 0x8 != 0 => info.bind_now = true, // DF_BIND_NOW
            DT_FLAGS_1 if val & 0x1 != 0 => info.bind_now = true, // DF_1_NOW
            _ => {}
        }
        off += ent;
    }
    // Resolve string-table references.
    if let (Some(strtab), Some(strsz)) = (info.strtab, info.strsz) {
        let read_str = |off: u64| -> Option<String> {
            if off >= strsz {
                return None;
            }
            let (b, _) = elf.rd().cstr(elf.va_to_off(strtab + off)?, 4096)?;
            Some(String::from_utf8_lossy(b).into_owned())
        };
        for &(tag, val) in &info.entries {
            match tag {
                DT_NEEDED => {
                    if let Some(s) = read_str(val) {
                        info.needed.push(s);
                    }
                }
                DT_SONAME => info.soname = read_str(val),
                DT_RPATH => info.rpath = read_str(val),
                DT_RUNPATH => info.runpath = read_str(val),
                _ => {}
            }
        }
    }
    let read_array = |addr: Option<u64>, sz: Option<u64>| -> Vec<u64> {
        let (Some(addr), Some(sz)) = (addr, sz) else {
            return Vec::new();
        };
        let ws = r.word_size();
        let n = (sz / ws) as usize;
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            if let Some(w) = elf.word_at_va(addr + (i as u64) * ws) {
                v.push(w);
            }
        }
        v
    };
    info.init_array = read_array(info.init_array_addr, info.init_array_sz);
    info.fini_array = read_array(info.fini_array_addr, info.fini_array_sz);
    info.preinit_array = read_array(info.preinit_array_addr, info.preinit_array_sz);
    Some(info)
}
