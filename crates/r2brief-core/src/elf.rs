//! Minimal, bounds-checked ELF reader that keeps the file offset of every
//! field it reads, so findings can cite exact bytes. It never trusts a size
//! or count without checking it against the file length.

use serde::Serialize;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;

pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

#[derive(Debug, Clone, Serialize)]
pub struct Ehdr {
    pub class64: bool,
    pub little_endian: bool,
    pub osabi: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Phdr {
    pub index: usize,
    /// File offset of this program header entry.
    pub entry_offset: u64,
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Phdr {
    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }
    pub fn exec(&self) -> bool {
        self.p_flags & PF_X != 0
    }
    pub fn contains_vaddr(&self, va: u64) -> bool {
        match self.p_vaddr.checked_add(self.p_memsz) {
            Some(end) => va >= self.p_vaddr && va < end,
            None => false,
        }
    }
    pub fn contains_file_vaddr(&self, va: u64) -> bool {
        match self.p_vaddr.checked_add(self.p_filesz) {
            Some(end) => va >= self.p_vaddr && va < end,
            None => false,
        }
    }
    pub fn file_end(&self) -> Option<u64> {
        self.p_offset.checked_add(self.p_filesz)
    }
    pub fn flags_str(&self) -> String {
        let mut s = String::new();
        s.push(if self.p_flags & PF_R != 0 { 'R' } else { ' ' });
        s.push(if self.p_flags & PF_W != 0 { 'W' } else { ' ' });
        s.push(if self.p_flags & PF_X != 0 { 'E' } else { ' ' });
        s
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Shdr {
    pub index: usize,
    pub entry_offset: u64,
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Shdr {
    pub fn alloc(&self) -> bool {
        self.sh_flags & SHF_ALLOC != 0
    }
    pub fn exec(&self) -> bool {
        self.sh_flags & SHF_EXECINSTR != 0
    }
    pub fn has_file_bytes(&self) -> bool {
        self.sh_type != SHT_NOBITS && self.sh_type != 0
    }
    pub fn contains_vaddr(&self, va: u64) -> bool {
        if !self.alloc() {
            return false;
        }
        match self.sh_addr.checked_add(self.sh_size) {
            Some(end) => va >= self.sh_addr && va < end,
            None => false,
        }
    }
}

#[derive(Debug)]
pub struct Elf<'a> {
    pub data: &'a [u8],
    pub hdr: Ehdr,
    pub phdrs: Vec<Phdr>,
    pub shdrs: Vec<Shdr>,
    /// Problems found while parsing; they become findings, never panics.
    pub parse_notes: Vec<String>,
}

#[derive(Debug)]
pub enum ParseError {
    TooSmall,
    NotElf,
    BadClass(u8),
    BadData(u8),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooSmall => write!(f, "file is smaller than an ELF header"),
            ParseError::NotElf => write!(f, "missing \\x7fELF magic"),
            ParseError::BadClass(c) => write!(f, "unsupported EI_CLASS {c}"),
            ParseError::BadData(d) => write!(f, "unsupported EI_DATA {d}"),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Rd<'a> {
    pub data: &'a [u8],
    pub le: bool,
    pub c64: bool,
}

impl<'a> Rd<'a> {
    pub fn bytes(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        self.data.get(start..end)
    }
    pub fn u8(&self, off: u64) -> Option<u8> {
        self.bytes(off, 1).map(|b| b[0])
    }
    pub fn u16(&self, off: u64) -> Option<u16> {
        let b: [u8; 2] = self.bytes(off, 2)?.try_into().ok()?;
        Some(if self.le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    }
    pub fn u32(&self, off: u64) -> Option<u32> {
        let b: [u8; 4] = self.bytes(off, 4)?.try_into().ok()?;
        Some(if self.le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    }
    pub fn u64(&self, off: u64) -> Option<u64> {
        let b: [u8; 8] = self.bytes(off, 8)?.try_into().ok()?;
        Some(if self.le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    }
    /// Native word: 8 bytes for ELFCLASS64, 4 for ELFCLASS32.
    pub fn word(&self, off: u64) -> Option<u64> {
        if self.c64 {
            self.u64(off)
        } else {
            self.u32(off).map(u64::from)
        }
    }
    pub fn word_size(&self) -> u64 {
        if self.c64 {
            8
        } else {
            4
        }
    }
    pub fn cstr(&self, off: u64, max: usize) -> Option<(&'a [u8], bool)> {
        let start = usize::try_from(off).ok()?;
        let tail = self.data.get(start..)?;
        let lim = tail.len().min(max);
        match tail[..lim].iter().position(|&b| b == 0) {
            Some(p) => Some((&tail[..p], true)),
            None => Some((&tail[..lim], false)),
        }
    }
}

/// Section names longer than this are truncated (bounds memory on hostile shstrtab).
pub const MAX_SECTION_NAME: u64 = 256;

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 16 {
            return Err(ParseError::TooSmall);
        }
        if &data[..4] != b"\x7fELF" {
            return Err(ParseError::NotElf);
        }
        let c64 = match data[4] {
            1 => false,
            2 => true,
            c => return Err(ParseError::BadClass(c)),
        };
        let le = match data[5] {
            1 => true,
            2 => false,
            d => return Err(ParseError::BadData(d)),
        };
        let need = if c64 { 64 } else { 52 };
        if data.len() < need {
            return Err(ParseError::TooSmall);
        }
        let r = Rd { data, le, c64 };
        let g16 = |o| r.u16(o).unwrap_or(0);
        let hdr = if c64 {
            Ehdr {
                class64: true,
                little_endian: le,
                osabi: data[7],
                e_type: g16(16),
                e_machine: g16(18),
                e_entry: r.u64(24).unwrap_or(0),
                e_phoff: r.u64(32).unwrap_or(0),
                e_shoff: r.u64(40).unwrap_or(0),
                e_ehsize: g16(52),
                e_phentsize: g16(54),
                e_phnum: g16(56),
                e_shentsize: g16(58),
                e_shnum: g16(60),
                e_shstrndx: g16(62),
            }
        } else {
            Ehdr {
                class64: false,
                little_endian: le,
                osabi: data[7],
                e_type: g16(16),
                e_machine: g16(18),
                e_entry: r.u32(24).unwrap_or(0) as u64,
                e_phoff: r.u32(28).unwrap_or(0) as u64,
                e_shoff: r.u32(32).unwrap_or(0) as u64,
                e_ehsize: g16(40),
                e_phentsize: g16(42),
                e_phnum: g16(44),
                e_shentsize: g16(46),
                e_shnum: g16(48),
                e_shstrndx: g16(50),
            }
        };
        let mut elf = Elf { data, hdr, phdrs: Vec::new(), shdrs: Vec::new(), parse_notes: Vec::new() };
        elf.parse_phdrs();
        elf.parse_shdrs();
        Ok(elf)
    }

    pub fn rd(&self) -> Rd<'a> {
        Rd { data: self.data, le: self.hdr.little_endian, c64: self.hdr.class64 }
    }

    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // Unchecked arithmetic here is bounded: i < e_phnum (u16) and want <= 64.
    #[allow(clippy::arithmetic_side_effects)]
    fn parse_phdrs(&mut self) {
        let h = &self.hdr;
        let want = if h.class64 { 56 } else { 32 };
        if h.e_phnum == 0 {
            return;
        }
        if h.e_phentsize as u64 != want {
            self.parse_notes.push(format!("e_phentsize {} != {}", h.e_phentsize, want));
            return;
        }
        let r = self.rd();
        for i in 0..h.e_phnum as u64 {
            let o = h.e_phoff.saturating_add(i * want);
            if r.bytes(o, want).is_none() {
                self.parse_notes.push(format!("program header {i} lies outside the file"));
                break;
            }
            let p = if h.class64 {
                Phdr {
                    index: i as usize,
                    entry_offset: o,
                    p_type: r.u32(o).unwrap(),
                    p_flags: r.u32(o.saturating_add(4)).unwrap(),
                    p_offset: r.u64(o.saturating_add(8)).unwrap(),
                    p_vaddr: r.u64(o.saturating_add(16)).unwrap(),
                    p_paddr: r.u64(o.saturating_add(24)).unwrap(),
                    p_filesz: r.u64(o.saturating_add(32)).unwrap(),
                    p_memsz: r.u64(o.saturating_add(40)).unwrap(),
                    p_align: r.u64(o.saturating_add(48)).unwrap(),
                }
            } else {
                Phdr {
                    index: i as usize,
                    entry_offset: o,
                    p_type: r.u32(o).unwrap(),
                    p_offset: r.u32(o.saturating_add(4)).unwrap() as u64,
                    p_vaddr: r.u32(o.saturating_add(8)).unwrap() as u64,
                    p_paddr: r.u32(o.saturating_add(12)).unwrap() as u64,
                    p_filesz: r.u32(o.saturating_add(16)).unwrap() as u64,
                    p_memsz: r.u32(o.saturating_add(20)).unwrap() as u64,
                    p_flags: r.u32(o.saturating_add(24)).unwrap(),
                    p_align: r.u32(o.saturating_add(28)).unwrap() as u64,
                }
            };
            self.phdrs.push(p);
        }
    }

    // Unchecked arithmetic here is bounded: i < e_shnum (u16), want <= 64; ss - name_off guarded by name_off < ss.
    #[allow(clippy::arithmetic_side_effects)]
    fn parse_shdrs(&mut self) {
        let h = &self.hdr;
        let want = if h.class64 { 64 } else { 40 };
        if h.e_shoff == 0 || h.e_shnum == 0 {
            return;
        }
        if h.e_shentsize as u64 != want {
            self.parse_notes.push(format!("e_shentsize {} != {}", h.e_shentsize, want));
            return;
        }
        let r = self.rd();
        let mut raw = Vec::new();
        for i in 0..h.e_shnum as u64 {
            let o = h.e_shoff.saturating_add(i * want);
            if r.bytes(o, want).is_none() {
                self.parse_notes.push(format!("section header {i} lies outside the file"));
                break;
            }
            let s = if h.class64 {
                Shdr {
                    index: i as usize,
                    entry_offset: o,
                    name: String::new(),
                    sh_type: r.u32(o.saturating_add(4)).unwrap(),
                    sh_flags: r.u64(o.saturating_add(8)).unwrap(),
                    sh_addr: r.u64(o.saturating_add(16)).unwrap(),
                    sh_offset: r.u64(o.saturating_add(24)).unwrap(),
                    sh_size: r.u64(o.saturating_add(32)).unwrap(),
                    sh_link: r.u32(o.saturating_add(40)).unwrap(),
                    sh_info: r.u32(o.saturating_add(44)).unwrap(),
                    sh_addralign: r.u64(o.saturating_add(48)).unwrap(),
                    sh_entsize: r.u64(o.saturating_add(56)).unwrap(),
                }
            } else {
                Shdr {
                    index: i as usize,
                    entry_offset: o,
                    name: String::new(),
                    sh_type: r.u32(o.saturating_add(4)).unwrap(),
                    sh_flags: r.u32(o.saturating_add(8)).unwrap() as u64,
                    sh_addr: r.u32(o.saturating_add(12)).unwrap() as u64,
                    sh_offset: r.u32(o.saturating_add(16)).unwrap() as u64,
                    sh_size: r.u32(o.saturating_add(20)).unwrap() as u64,
                    sh_link: r.u32(o.saturating_add(24)).unwrap(),
                    sh_info: r.u32(o.saturating_add(28)).unwrap(),
                    sh_addralign: r.u32(o.saturating_add(32)).unwrap() as u64,
                    sh_entsize: r.u32(o.saturating_add(36)).unwrap() as u64,
                }
            };
            let name_off = r.u32(o).unwrap();
            raw.push((s, name_off));
        }
        let strtab = raw.get(h.e_shstrndx as usize).map(|(s, _)| (s.sh_offset, s.sh_size));
        if strtab.is_none() {
            self.parse_notes.push(format!("e_shstrndx {} has no section", h.e_shstrndx));
        }
        for (mut s, name_off) in raw {
            if let Some((so, ss)) = strtab {
                if (name_off as u64) < ss {
                    if let Some(name_abs) = so.checked_add(name_off as u64) {
                        if let Some((b, _)) = r.cstr(name_abs, (ss - name_off as u64).min(MAX_SECTION_NAME) as usize) {
                            s.name = String::from_utf8_lossy(b).into_owned();
                        }
                    }
                }
            }
            self.shdrs.push(s);
        }
    }

    pub fn has_sections(&self) -> bool {
        !self.shdrs.is_empty()
    }

    pub fn section(&self, name: &str) -> Option<&Shdr> {
        self.shdrs.iter().find(|s| s.name == name)
    }

    pub fn loads(&self) -> impl Iterator<Item = &Phdr> {
        self.phdrs.iter().filter(|p| p.is_load())
    }

    /// Map a virtual address to a file offset through PT_LOAD file ranges.
    pub fn va_to_off(&self, va: u64) -> Option<u64> {
        let p = self.loads().find(|p| p.contains_file_vaddr(va))?;
        let delta = va.checked_sub(p.p_vaddr)?;
        p.p_offset.checked_add(delta)
    }

    pub fn off_to_va(&self, off: u64) -> Option<u64> {
        let p = self.loads().find(|p| {
            p.file_end()
                .map(|end| off >= p.p_offset && off < end)
                .unwrap_or(false)
        })?;
        let delta = off.checked_sub(p.p_offset)?;
        p.p_vaddr.checked_add(delta)
    }

    pub fn read_va(&self, va: u64, len: u64) -> Option<&'a [u8]> {
        let off = self.va_to_off(va)?;
        let seg = self.loads().find(|p| p.contains_file_vaddr(va))?;
        let end = va.checked_add(len)?;
        let seg_end = seg.p_vaddr.checked_add(seg.p_filesz)?;
        if end > seg_end {
            return None;
        }
        self.rd().bytes(off, len)
    }

    pub fn word_at_va(&self, va: u64) -> Option<u64> {
        let off = self.va_to_off(va)?;
        self.rd().word(off)
    }

    pub fn section_at_va(&self, va: u64) -> Option<&Shdr> {
        self.shdrs.iter().filter(|s| s.sh_size > 0).find(|s| s.contains_vaddr(va))
    }

    pub fn exec_load_at_va(&self, va: u64) -> Option<&Phdr> {
        self.loads().find(|p| p.exec() && p.contains_vaddr(va))
    }

    pub fn machine_name(&self) -> &'static str {
        match self.hdr.e_machine {
            EM_X86_64 => "x86-64",
            EM_AARCH64 => "aarch64",
            EM_386 => "x86",
            EM_ARM => "arm",
            8 => "mips",
            20 => "ppc",
            21 => "ppc64",
            243 => "riscv",
            _ => "unknown",
        }
    }
}

pub fn ptype_name(t: u32) -> String {
    match t {
        0 => "NULL".into(),
        PT_LOAD => "LOAD".into(),
        PT_DYNAMIC => "DYNAMIC".into(),
        PT_INTERP => "INTERP".into(),
        PT_NOTE => "NOTE".into(),
        5 => "SHLIB".into(),
        PT_PHDR => "PHDR".into(),
        PT_TLS => "TLS".into(),
        PT_GNU_EH_FRAME => "GNU_EH_FRAME".into(),
        PT_GNU_STACK => "GNU_STACK".into(),
        PT_GNU_RELRO => "GNU_RELRO".into(),
        PT_GNU_PROPERTY => "GNU_PROPERTY".into(),
        0x7000_0001 => "ARM_EXIDX".into(),
        0x7000_0003 => "AARCH64_MEMTAG_MTE".into(),
        _ => format!("0x{t:x}"),
    }
}

// Unchecked arithmetic here is bounded: len*2 of an in-memory slice.
#[allow(clippy::arithmetic_side_effects)]
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
