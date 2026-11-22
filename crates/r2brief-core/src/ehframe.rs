//! Minimal .eh_frame / DWARF CIE+FDE walker.
//!
//! We only need FDE start addresses as high-confidence function entry
//! candidates. Full unwinding is out of scope; if the parse fails we
//! return what we have so far and never invent entries.

use crate::elf::{Elf, PT_GNU_EH_FRAME};

#[derive(Debug, Default)]
pub struct EhFrame {
    pub fde_starts: Vec<u64>,
    pub cie_count: usize,
    pub fde_count: usize,
    pub notes: Vec<String>,
}

pub fn parse(elf: &Elf<'_>) -> EhFrame {
    let mut out = EhFrame::default();
    // Prefer the section; fall back to PT_GNU_EH_FRAME (which points at
    // .eh_frame_hdr, not .eh_frame — we handle both).
    if let Some(sec) = elf.section(".eh_frame") {
        walk_eh_frame(elf, sec.sh_offset, sec.sh_size, &mut out);
        return out;
    }
    if let Some(sec) = elf.section(".eh_frame_hdr") {
        if let Some(eh) = eh_frame_from_hdr(elf, sec.sh_offset, sec.sh_size) {
            walk_eh_frame(elf, eh.0, eh.1, &mut out);
            return out;
        }
    }
    if let Some(ph) = elf.phdrs.iter().find(|p| p.p_type == PT_GNU_EH_FRAME) {
        if let Some(eh) = eh_frame_from_hdr(elf, ph.p_offset, ph.p_filesz) {
            walk_eh_frame(elf, eh.0, eh.1, &mut out);
        }
    }
    out
}

fn eh_frame_from_hdr(elf: &Elf<'_>, off: u64, size: u64) -> Option<(u64, u64)> {
    // eh_frame_hdr: version(1), eh_frame_ptr_enc(1), fde_count_enc(1),
    // table_enc(1), then encoded eh_frame_ptr.
    if size < 8 {
        return None;
    }
    let r = elf.rd();
    let ver = r.u8(off)?;
    if ver != 1 {
        return None;
    }
    let enc = r.u8(off.saturating_add(1))?;
    let ptr_off = off.saturating_add(4);
    // DW_EH_PE_pcrel is relative to the *address* of the field, not its file offset.
    let ptr_va = elf.off_to_va(ptr_off).unwrap_or(ptr_off);
    let (ptr, _) = read_encoded(elf, ptr_off, enc, ptr_va)?;
    // We don't know the size of .eh_frame from the header alone; walk until
    // a zero-length CIE terminator, capped by remaining file bytes.
    let start_off = elf.va_to_off(ptr)?;
    let max = elf.len().saturating_sub(start_off);
    Some((start_off, max.min(16 * 1024 * 1024)))
}

fn walk_eh_frame(elf: &Elf<'_>, start: u64, size: u64, out: &mut EhFrame) {
    let r = elf.rd();
    let mut off = start;
    let end = start.saturating_add(size);
    let mut cie_aug_enc: Vec<(u64, u8)> = Vec::new(); // cie_off -> FDE pointer encoding
    while off.saturating_add(8) <= end {
        let Some(length) = r.u32(off) else { break };
        if length == 0 {
            break; // terminator
        }
        let id_off = off.saturating_add(4);
        let next = if length == 0xffff_ffff {
            // 64-bit DWARF length; rare in .eh_frame.
            let Some(len64) = r.u64(off.saturating_add(4)) else { break };
            let id_off64 = off.saturating_add(12);
            let end_rec = id_off64.saturating_add(len64);
            if end_rec > end {
                out.notes.push("eh_frame record overruns section".into());
                break;
            }
            let Some(id) = r.u64(id_off64) else { break };
            if id == 0 {
                out.cie_count = out.cie_count.saturating_add(1);
                if let Some(enc) = parse_cie_aug(elf, id_off64.saturating_add(8), end_rec) {
                    cie_aug_enc.push((off, enc));
                }
            } else {
                out.fde_count = out.fde_count.saturating_add(1);
            }
            end_rec
        } else {
            let end_rec = id_off.saturating_add(length as u64);
            if end_rec > end {
                out.notes.push("eh_frame record overruns section".into());
                break;
            }
            let Some(id) = r.u32(id_off) else { break };
            if id == 0 {
                out.cie_count = out.cie_count.saturating_add(1);
                if let Some(enc) = parse_cie_aug(elf, id_off.saturating_add(4), end_rec) {
                    cie_aug_enc.push((off, enc));
                }
            } else {
                // FDE: id is offset back to CIE.
                out.fde_count = out.fde_count.saturating_add(1);
                let cie_pos = id_off.saturating_sub(id as u64);
                let enc = cie_aug_enc
                    .iter()
                    .find(|(o, _)| *o == cie_pos)
                    .map(|(_, e)| *e)
                    .unwrap_or(0);
                // pc_begin starts right after the CIE pointer.
                let pc_off = id_off.saturating_add(4);
                let pc_va = elf.off_to_va(pc_off).unwrap_or(pc_off);
                if let Some((pc, _)) = read_encoded(elf, pc_off, enc, pc_va) {
                    if pc != 0 {
                        out.fde_starts.push(pc);
                    }
                }
            }
            end_rec
        };
        if next <= off {
            out.notes.push("eh_frame record did not advance".into());
            break;
        }
        off = next;
        if out.fde_count > 100_000 {
            out.notes.push("eh_frame FDE cap reached".into());
            break;
        }
    }
    out.fde_starts.sort_unstable();
    out.fde_starts.dedup();
}

fn parse_cie_aug(elf: &Elf<'_>, mut off: u64, end: u64) -> Option<u8> {
    // CIE: version, augmentation string, code_align (uleb), data_align (sleb),
    // return_register, then augmentation data if 'z' present.
    let r = elf.rd();
    let _ver = r.u8(off)?;
    off = off.saturating_add(1);
    let (aug, _) = r.cstr(off, 64)?;
    off = off.saturating_add(aug.len() as u64).saturating_add(1);
    let (_, n) = read_uleb(elf, off, end)?;
    off = off.saturating_add(n);
    let (_, n) = read_sleb(elf, off, end)?;
    off = off.saturating_add(n);
    // return register: uleb in v4+, u8 in v1. Be permissive.
    let (_, n) = read_uleb(elf, off, end)?;
    off = off.saturating_add(n);
    if !aug.contains(&b'z') {
        // Look for 'R' without length prefix — uncommon; default to abs pointer.
        return Some(if aug.contains(&b'R') { 0 } else { 0 });
    }
    let (aug_len, n) = read_uleb(elf, off, end)?;
    off = off.checked_add(n)?;
    let aug_end = off.checked_add(aug_len)?;
    let mut fde_enc = 0u8;
    for &ch in aug {
        match ch {
            b'z' => {}
            b'L' => {
                off = off.saturating_add(1);
            } // LSDA encoding
            b'P' => {
                // personality encoding + pointer
                let enc = r.u8(off)?;
                off = off.saturating_add(1);
                let base = elf.off_to_va(off).unwrap_or(off);
                let (_, n) = read_encoded(elf, off, enc, base)?;
                off = off.saturating_add(n);
            }
            b'R' => {
                fde_enc = r.u8(off)?;
                off = off.saturating_add(1);
            }
            b'S' => {}
            _ => {}
        }
        if off > aug_end {
            break;
        }
    }
    Some(fde_enc)
}

fn read_encoded(elf: &Elf<'_>, off: u64, enc: u8, pc_rel_base: u64) -> Option<(u64, u64)> {
    // encoding low 4 = format, high 4 = application.
    if enc == 0xff {
        return Some((0, 0)); // omit
    }
    let r = elf.rd();
    let fmt = enc & 0x0f;
    let app = enc & 0xf0;
    let (val, size) = match fmt {
        0x0 => {
            // pointer-sized absolute
            let w = r.word_size();
            (r.word(off)?, w)
        }
        0x1 => {
            let (v, n) = read_uleb(elf, off, off.saturating_add(16))?;
            (v, n)
        }
        0x2 => (r.u16(off)? as u64, 2),
        0x3 => (r.u32(off)? as u64, 4),
        0x4 => (r.u64(off)?, 8),
        0x9 => {
            let (v, n) = read_sleb(elf, off, off.saturating_add(16))?;
            (v as u64, n)
        }
        0xa => (r.u16(off)? as i16 as i64 as u64, 2),
        0xb => (r.u32(off)? as i32 as i64 as u64, 4),
        0xc => (r.u64(off)?, 8),
        _ => return None,
    };
    let abs = match app {
        0x00 => val,                                  // absptr
        0x10 => pc_rel_base.wrapping_add(val),        // pcrel — val may be signed
        0x20 => val,                                  // textrel — treat as abs (best effort)
        0x30 => val,                                  // datarel
        0x40 => val,                                  // funcrel
        0x50 => {
            // aligned — skip padding then recurse as abs
            val
        }
        _ if app == 0x80 || app == 0x90 => {
            // indirect: val is a pointer to the real value
            let ptr = if app == 0x90 {
                pc_rel_base.wrapping_add(val)
            } else {
                val
            };
            elf.word_at_va(ptr).unwrap_or(ptr)
        }
        _ => val,
    };
    // For signed pcrel formats, re-interpret.
    let abs = if matches!(fmt, 0x9 | 0xa | 0xb | 0xc) && app == 0x10 {
        let signed = match fmt {
            0xa => r.u16(off)? as i16 as i64,
            0xb => r.u32(off)? as i32 as i64,
            0xc => r.u64(off)? as i64,
            0x9 => read_sleb(elf, off, off.saturating_add(16))?.0,
            _ => 0,
        };
        (pc_rel_base as i64).wrapping_add(signed) as u64
    } else {
        abs
    };
    Some((abs, size))
}

fn read_uleb(elf: &Elf<'_>, off: u64, end: u64) -> Option<(u64, u64)> {
    let r = elf.rd();
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut n = 0u64;
    loop {
        if off.saturating_add(n) >= end {
            return None;
        }
        let b = r.u8(off.saturating_add(n))?;
        n = n.saturating_add(1);
        result |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            return Some((result, n));
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return None;
        }
    }
}

fn read_sleb(elf: &Elf<'_>, off: u64, end: u64) -> Option<(i64, u64)> {
    let r = elf.rd();
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut n = 0u64;
    let mut b;
    loop {
        if off.saturating_add(n) >= end {
            return None;
        }
        b = r.u8(off.saturating_add(n))?;
        n = n.saturating_add(1);
        result |= i64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return None;
        }
    }
    if shift < 64 && (b & 0x40) != 0 {
        result |= (!0i64).checked_shl(shift).unwrap_or(0);
    }
    Some((result, n))
}
