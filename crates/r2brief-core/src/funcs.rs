//! Function-boundary recovery for stripped x86-64 and AArch64 ELFs.
//!
//! Sources, in priority order:
//! 1. .eh_frame FDE start addresses (high confidence when present)
//! 2. Direct call targets (CALL rel32 / BL imm26)
//! 3. Architecture-specific prologue patterns at symbol-less starts
//! 4. Executable-segment entry (e_entry) and DT_INIT / init_array
//!
//! End addresses are the next start (or the end of the containing LOAD).
//! Precision/recall is measured against a symbol-keeping twin in eval/.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use serde::Serialize;

use crate::dynamic::DynamicInfo;
use crate::ehframe::EhFrame;
use crate::elf::{Elf, EM_AARCH64, EM_X86_64, PF_X, PT_LOAD};

#[derive(Debug, Clone, Serialize)]
pub struct Func {
    pub start: u64,
    pub end: u64,
    pub sources: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuncRecovery {
    pub arch: String,
    pub functions: Vec<Func>,
    pub call_targets: usize,
    pub eh_frame_starts: usize,
    pub prologue_hits: usize,
    /// Code pointers found in data (R_*_RELATIVE addends) or formed in code
    /// (x86-64 RIP-relative LEA, AArch64 ADRP+ADD) that land in PF_X memory.
    pub address_taken: usize,
    /// Starts that fall in .plt / .plt.sec / .plt.got / .iplt: import stubs,
    /// reported separately and not counted as functions.
    pub plt_stubs: Vec<u64>,
    pub notes: Vec<String>,
}

// Unchecked arithmetic here is bounded: i indexes merged.

#[allow(clippy::arithmetic_side_effects)]

pub fn recover(elf: &Elf<'_>, dyninfo: Option<&DynamicInfo>, eh: &EhFrame) -> FuncRecovery {
    let mut notes = Vec::new();
    let arch = match elf.hdr.e_machine {
        EM_X86_64 => "x86-64",
        EM_AARCH64 => "aarch64",
        _ => {
            notes.push(format!(
                "function recovery unsupported for e_machine={}",
                elf.hdr.e_machine
            ));
            return FuncRecovery {
                arch: elf.machine_name().into(),
                functions: Vec::new(),
                call_targets: 0,
                eh_frame_starts: eh.fde_starts.len(),
                prologue_hits: 0,
                address_taken: 0,
                plt_stubs: Vec::new(),
                notes,
            };
        }
    };

    // Seed set: address → source tags.
    let mut seeds: Vec<(u64, String, f64)> = Vec::new();
    for &s in &eh.fde_starts {
        if elf.exec_load_at_va(s).is_some() {
            seeds.push((s, "eh_frame".into(), 0.95));
        }
    }
    if elf.hdr.e_entry != 0 && elf.exec_load_at_va(elf.hdr.e_entry).is_some() {
        seeds.push((elf.hdr.e_entry, "e_entry".into(), 0.99));
    }
    if let Some(d) = dyninfo {
        for (va, tag) in [(d.dt_init, "dt_init"), (d.dt_fini, "dt_fini")] {
            if let Some(va) = va {
                if va != 0 && elf.exec_load_at_va(va).is_some() {
                    seeds.push((va, tag.into(), 0.9));
                }
            }
        }
        for &va in d
            .init_array
            .iter()
            .chain(d.fini_array.iter())
            .chain(d.preinit_array.iter())
        {
            if va != 0 && elf.exec_load_at_va(va).is_some() {
                seeds.push((va, "init_array".into(), 0.9));
            }
        }
    }

    let (calls, prologues, mut taken) = match elf.hdr.e_machine {
        EM_X86_64 => scan_x86_64(elf, &mut notes),
        EM_AARCH64 => scan_aarch64(elf, &mut notes),
        _ => (Vec::new(), Vec::new(), Vec::new()),
    };
    if let Some(d) = dyninfo {
        taken.extend(d.relative.values().copied().filter(|&a| elf.exec_load_at_va(a).is_some()));
    }
    taken.sort_unstable();
    taken.dedup();
    let address_taken = taken.len();
    for va in taken {
        seeds.push((va, "address_taken".into(), 0.8));
    }
    let call_targets = calls.len();
    let prologue_hits = prologues.len();
    for va in calls {
        seeds.push((va, "call_target".into(), 0.8));
    }
    // When .eh_frame is rich, FDE starts already cover almost every function
    // that has unwind info. Prologue scanning in that case mostly adds false
    // positives inside function bodies (nested push rbp patterns), so skip it.
    // Call targets still help for leaves/thunks without FDEs.
    if eh.fde_starts.len() < 8 {
        let seed_addrs: std::collections::HashSet<u64> =
            seeds.iter().map(|(a, _, _)| *a).collect();
        for va in prologues {
            if seed_addrs.contains(&va) || va & 0xf == 0 {
                seeds.push((va, "prologue".into(), 0.55));
            }
        }
    } else {
        notes.push(format!(
            "skipped prologue scan: {} eh_frame FDEs present",
            eh.fde_starts.len()
        ));
    }

    // A PF_X segment can also map .rodata/.eh_frame (single-RX layouts), so
    // with section headers every start must sit in an SHF_EXECINSTR section.
    // Without them, an address-taken pointer alone is not trusted.
    if elf.has_sections() {
        seeds.retain(|(a, _, _)| elf.section_at_va(*a).map(|s| s.exec()).unwrap_or(false));
    } else {
        let confirmed: std::collections::HashSet<u64> = seeds
            .iter()
            .filter(|(_, s, _)| s != "address_taken")
            .map(|(a, _, _)| *a)
            .collect();
        seeds.retain(|(a, s, _)| s != "address_taken" || confirmed.contains(a));
    }
    // Split off PLT stubs when section headers name them.
    let is_plt = |va: u64| {
        if elf.has_sections() {
            elf.section_at_va(va)
                .map(|s| s.name.starts_with(".plt") || s.name == ".iplt")
                .unwrap_or(false)
        } else {
            looks_like_plt_stub(elf, va)
        }
    };
    let mut plt_stubs: Vec<u64> = seeds.iter().map(|(a, _, _)| *a).filter(|&a| is_plt(a)).collect();
    plt_stubs.sort_unstable();
    plt_stubs.dedup();
    seeds.retain(|(a, _, _)| !is_plt(*a));

    // Merge seeds at the same address.
    seeds.sort_by_key(|(a, _, _)| *a);
    let mut merged: Vec<(u64, Vec<String>, f64)> = Vec::new();
    for (va, src, conf) in seeds {
        if let Some(last) = merged.last_mut() {
            if last.0 == va {
                if !last.1.contains(&src) {
                    last.1.push(src);
                }
                last.2 = last.2.max(conf);
                continue;
            }
        }
        merged.push((va, vec![src], conf));
    }

    // Assign end = next start, clipped to containing LOAD.
    let mut functions = Vec::with_capacity(merged.len());
    for (i, (start, sources, conf)) in merged.iter().enumerate() {
        let load_end = elf
            .loads()
            .find(|p| p.exec() && p.contains_vaddr(*start))
            .and_then(|p| p.p_vaddr.checked_add(p.p_memsz))
            .unwrap_or(*start);
        let next = merged.get(i + 1).map(|(s, _, _)| *s).unwrap_or(load_end);
        let end = next.min(load_end).max(*start);
        functions.push(Func {
            start: *start,
            end,
            sources: sources.clone(),
            confidence: *conf,
        });
    }

    FuncRecovery {
        arch: arch.into(),
        functions,
        call_targets,
        eh_frame_starts: eh.fde_starts.len(),
        prologue_hits,
        address_taken,
        plt_stubs,
        notes,
    }
}

// Unchecked arithmetic here is bounded: usize index math guarded by i + 4 <= slice.len().

#[allow(clippy::arithmetic_side_effects)]

fn scan_x86_64(elf: &Elf<'_>, notes: &mut Vec<String>) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut taken = Vec::new();
    let mut calls = Vec::new();
    let mut prologues = Vec::new();
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0) {
        let avail = ph.p_filesz.min(elf.len().saturating_sub(ph.p_offset));
        let Some(bytes) = elf.rd().bytes(ph.p_offset, avail) else {
            notes.push(format!("x86-64: PT_LOAD[{}] unreadable", ph.index));
            continue;
        };
        // Cap decode to keep wasm responsive on huge binaries.
        let take = bytes.len().min(8 * 1024 * 1024);
        let slice = &bytes[..take];
        let mut decoder = Decoder::with_ip(64, slice, ph.p_vaddr, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            if instr.mnemonic() == Mnemonic::Call && instr.op0_kind() == OpKind::NearBranch64 {
                let t = instr.near_branch64();
                if elf.exec_load_at_va(t).is_some() {
                    calls.push(t);
                }
            }
            // lea reg, [rip+disp] forming a code pointer (callbacks, tables).
            if instr.mnemonic() == Mnemonic::Lea && instr.is_ip_rel_memory_operand() {
                let t = instr.ip_rel_memory_address();
                if elf.exec_load_at_va(t).is_some() {
                    taken.push(t);
                }
            }
        }
        // Prologue scan: endbr64 (f3 0f 1e fa) or classic push rbp; mov rbp,rsp.
        let mut i = 0usize;
        while i + 4 <= slice.len() {
            if slice[i..i + 4] == [0xf3, 0x0f, 0x1e, 0xfa] {
                if let Some(va) = ph.p_vaddr.checked_add(i as u64) { prologues.push(va); }
                i += 4;
                continue;
            }
            // 55 48 89 e5  or  55 48 8b ec
            if slice[i] == 0x55 && i + 4 <= slice.len() {
                if slice[i + 1..i + 4] == [0x48, 0x89, 0xe5] || slice[i + 1..i + 4] == [0x48, 0x8b, 0xec]
                {
                    // Prefer positions that look like function starts: previous
                    // byte is INT3/NOP/RET or start of segment.
                    let ok = i == 0
                        || matches!(slice[i - 1], 0x90 | 0xcc | 0xc3 | 0xc2 | 0x00)
                        || (i >= 4 && slice[i - 4..i] == [0xf3, 0x0f, 0x1e, 0xfa]);
                    if ok {
                        if let Some(va) = ph.p_vaddr.checked_add(i as u64) { prologues.push(va); }
                    }
                }
            }
            i += 1;
        }
    }
    calls.sort_unstable();
    calls.dedup();
    prologues.sort_unstable();
    prologues.dedup();
    (calls, prologues, taken)
}

// Unchecked arithmetic here is bounded: usize index math guarded by slice.len(); imm is a 21-bit field.

#[allow(clippy::arithmetic_side_effects)]

fn scan_aarch64(elf: &Elf<'_>, notes: &mut Vec<String>) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut taken = Vec::new();
    let mut calls = Vec::new();
    let mut prologues = Vec::new();
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0) {
        let avail = ph.p_filesz.min(elf.len().saturating_sub(ph.p_offset));
        let Some(bytes) = elf.rd().bytes(ph.p_offset, avail) else {
            notes.push(format!("aarch64: PT_LOAD[{}] unreadable", ph.index));
            continue;
        };
        let take = bytes.len().min(8 * 1024 * 1024);
        let slice = &bytes[..take];
        let le = elf.hdr.little_endian;
        let mut i = 0usize;
        while i + 4 <= slice.len() {
            let w = if le {
                u32::from_le_bytes(slice[i..i + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(slice[i..i + 4].try_into().unwrap())
            };
            let Some(pc) = ph.p_vaddr.checked_add(i as u64) else { break; };
            // BL imm26: 1001 01ii iiii iiii iiii iiii iiii iiii
            if w & 0xfc00_0000 == 0x9400_0000 {
                let imm26 = w & 0x03ff_ffff;
                // Sign-extend 26-bit immediate without overflowing a debug shift.
                let imm = if imm26 & (1 << 25) != 0 {
                    (imm26 | 0xfc00_0000) as i32 as i64
                } else {
                    imm26 as i64
                };
                let target = (pc as i64).wrapping_add(imm.wrapping_mul(4)) as u64;
                if elf.exec_load_at_va(target).is_some() {
                    calls.push(target);
                }
            }
            // ADRP Xd, page ; ADD Xd, Xd, #imm  -> code pointer.
            if w & 0x9f00_0000 == 0x9000_0000 && i + 8 <= slice.len() {
                let rd = w & 0x1f;
                let immlo = ((w >> 29) & 0x3) as i64;
                let immhi = ((w >> 5) & 0x7_ffff) as i64;
                let mut imm = (immhi << 2) | immlo;
                if imm & (1 << 20) != 0 {
                    imm -= 1 << 21;
                }
                let page = ((pc & !0xfff) as i64).wrapping_add(imm << 12) as u64;
                let n = if le {
                    u32::from_le_bytes(slice[i + 4..i + 8].try_into().unwrap())
                } else {
                    u32::from_be_bytes(slice[i + 4..i + 8].try_into().unwrap())
                };
                // ADD (immediate, 64-bit, no shift): 1001 0001 00ii ... Rn Rd
                if n & 0xffc0_0000 == 0x9100_0000 && (n & 0x1f) == rd && ((n >> 5) & 0x1f) == rd {
                    let t = page.wrapping_add(((n >> 10) & 0xfff) as u64);
                    if elf.exec_load_at_va(t).is_some() {
                        taken.push(t);
                    }
                }
            }
            // Prologue: STP x29, x30, [sp, #-N]!  (64-bit, pre-index).
            // opc=10 101 V=0 011 L=0 | imm7 | Rt2=x30 | Rn=sp | Rt=x29, with a
            // negative imm7 (bit 21). e.g. a9bf7bfd = stp x29, x30, [sp, #-16]!
            if (w & 0xffc0_7fff) == 0xa980_7bfd && (w & (1 << 21)) != 0
            {
                let ok = i == 0
                    || (i >= 4 && is_aarch64_align_or_ret(if le {
                        u32::from_le_bytes(slice[i - 4..i].try_into().unwrap())
                    } else {
                        u32::from_be_bytes(slice[i - 4..i].try_into().unwrap())
                    }));
                if ok {
                    prologues.push(pc);
                }
            }
            // PACIASP hint: d503233f — often first insn of a signed function.
            if w == 0xd503_233f {
                prologues.push(pc);
            }
            i += 4;
        }
    }
    calls.sort_unstable();
    calls.dedup();
    prologues.sort_unstable();
    prologues.dedup();
    (calls, prologues, taken)
}

fn is_aarch64_align_or_ret(w: u32) -> bool {
    // RET: d65f03c0; NOP: d503201f; BTI/PAC hints; zero padding.
    w == 0xd65f_03c0
        || w == 0xd503_201f
        || w == 0
        || (w & 0xffff_fc1f) == 0xd65f_0000 // RET Rn
        || w == 0xd503_24ff // BTI jc etc — broad
}

/// Sectionless PLT-stub recognizer, by instruction shape:
/// x86-64: [endbr64] [bnd] jmp qword ptr [rip+disp] (or PLT0's push [rip+disp])
/// AArch64: [bti c] adrp x16, P ; ldr x17, [x16, #off]
// Unchecked arithmetic here is bounded: indices < 4 into a 16-byte read.
#[allow(clippy::arithmetic_side_effects)]
fn looks_like_plt_stub(elf: &Elf<'_>, va: u64) -> bool {
    let Some(b) = elf.read_va(va, 16) else { return false };
    match elf.hdr.e_machine {
        EM_X86_64 => {
            let mut d = Decoder::with_ip(64, b, va, DecoderOptions::NONE);
            let mut ins = Instruction::default();
            for _ in 0..2 {
                if !d.can_decode() {
                    return false;
                }
                d.decode_out(&mut ins);
                if ins.mnemonic() == Mnemonic::Endbr64 {
                    continue;
                }
                // PLT entry `jmp [rip+GOT]`, or PLT0 `push [rip+GOT+8]`.
                return matches!(ins.mnemonic(), Mnemonic::Jmp | Mnemonic::Push)
                    && ins.is_ip_rel_memory_operand();
            }
            false
        }
        EM_AARCH64 if elf.hdr.little_endian => {
            let w = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
            let k = if w(0) == 0xd503_245f { 1 } else { 0 };
            (w(k) & 0x9f00_001f) == 0x9000_0010 && (w(k + 1) & 0xffc0_03ff) == 0xf940_0211
        }
        _ => false,
    }
}
