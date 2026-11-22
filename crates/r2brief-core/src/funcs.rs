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
    pub notes: Vec<String>,
}

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
        if let Some(va) = d.dt_init {
            if elf.exec_load_at_va(va).is_some() {
                seeds.push((va, "dt_init".into(), 0.9));
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

    let (calls, prologues) = match elf.hdr.e_machine {
        EM_X86_64 => scan_x86_64(elf, &mut notes),
        EM_AARCH64 => scan_aarch64(elf, &mut notes),
        _ => (Vec::new(), Vec::new()),
    };
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
            .map(|p| p.p_vaddr + p.p_memsz)
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
        notes,
    }
}

fn scan_x86_64(elf: &Elf<'_>, notes: &mut Vec<String>) -> (Vec<u64>, Vec<u64>) {
    let mut calls = Vec::new();
    let mut prologues = Vec::new();
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0) {
        let Some(bytes) = elf.rd().bytes(ph.p_offset, ph.p_filesz) else {
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
        }
        // Prologue scan: endbr64 (f3 0f 1e fa) or classic push rbp; mov rbp,rsp.
        let mut i = 0usize;
        while i + 4 <= slice.len() {
            if slice[i..i + 4] == [0xf3, 0x0f, 0x1e, 0xfa] {
                prologues.push(ph.p_vaddr + i as u64);
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
                        prologues.push(ph.p_vaddr + i as u64);
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
    (calls, prologues)
}

fn scan_aarch64(elf: &Elf<'_>, notes: &mut Vec<String>) -> (Vec<u64>, Vec<u64>) {
    let mut calls = Vec::new();
    let mut prologues = Vec::new();
    for ph in elf.phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0) {
        let Some(bytes) = elf.rd().bytes(ph.p_offset, ph.p_filesz) else {
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
            let pc = ph.p_vaddr + i as u64;
            // BL imm26: 1001 01ii iiii iiii iiii iiii iiii iiii
            if w & 0xfc00_0000 == 0x9400_0000 {
                let imm26 = (w & 0x03ff_ffff) as i32;
                // sign-extend 26 bits
                let imm = ((imm26 << 6) >> 6) as i64;
                let target = (pc as i64).wrapping_add(imm * 4) as u64;
                if elf.exec_load_at_va(target).is_some() {
                    calls.push(target);
                }
            }
            // Prologue: STP x29, x30, [sp, #imm]!  (pre-index)  a9bf7bfd etc.
            // Encoding: 1010 1001 1xii iiii iiii 1x 11110 11101  (STP paired)
            // Common: stp x29, x30, [sp, #-N]! = 0xa9bx7bfd family.
            if w & 0xffc0_07ff == 0xa980_03fd || w & 0xffc0_07ff == 0xa9a0_7bfd {
                // weak match — refine:
            }
            // Concrete common forms:
            // a9bf7bfd  stp x29, x30, [sp, #-16]!
            // a9bd7bfd  stp x29, x30, [sp, #-48]!
            // a9bc7bfd  ...
            if (w & 0xffc0_07ff) == 0xa980_07bd
                || (w & 0xffc0_07ff) == 0xa980_03fd
                || (w & 0xffc0_07ff) == 0xa9a0_7bfd
                || (0xa9b0_7bfd..=0xa9bf_7bfd).contains(&w) && (w & 0x3ff) == 0x3fd
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
    (calls, prologues)
}

fn is_aarch64_align_or_ret(w: u32) -> bool {
    // RET: d65f03c0; NOP: d503201f; BTI/PAC hints; zero padding.
    w == 0xd65f_03c0
        || w == 0xd503_201f
        || w == 0
        || (w & 0xffff_fc1f) == 0xd65f_0000 // RET Rn
        || w == 0xd503_24ff // BTI jc etc — broad
}
