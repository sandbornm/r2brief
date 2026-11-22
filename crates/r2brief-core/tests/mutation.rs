//! Deterministic mutation smoke test. Run in debug (CI does), where integer
//! overflow panics, so any unchecked offset math on hostile bytes fails here.
use std::path::PathBuf;

fn fixture(name: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/bin").join(name);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var_os("CI").is_some() => panic!("missing fixture {}", p.display()),
        Err(_) => None,
    }
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

const NASTY: [u64; 6] = [0, 1, 0x7fff_ffff, 0xffff_ffff, 0x7fff_ffff_ffff_ffff, u64::MAX];

#[test]
fn mutated_fixtures_do_not_panic() {
    let names = [
        "triage-x86_64-stripped",
        "triage-x86_64-note-sstrip",
        "triage-aarch64-stripped",
        "triage-aarch64-sstrip",
    ];
    for name in names {
        let Some(orig) = fixture(name) else { return };
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15 ^ orig.len() as u64);
        for _ in 0..1500 {
            let mut d = orig.clone();
            for _ in 0..(1 + rng.next() % 6) {
                // Bias toward the ELF/phdr header page, where offsets live.
                let span = if rng.next() % 4 == 0 { d.len() } else { d.len().min(0x1000) };
                let at = (rng.next() as usize) % span;
                if rng.next() % 2 == 0 {
                    d[at] = rng.next() as u8;
                } else {
                    let v = NASTY[(rng.next() as usize) % NASTY.len()].to_le_bytes();
                    let at = at & !7;
                    let end = (at + 8).min(d.len());
                    d[at..end].copy_from_slice(&v[..end - at]);
                }
            }
            let _ = r2brief_core::analyze(name, &d);
        }
    }
}

// ---- targeted hostile inputs from review round 6 (ELF64 LE helpers) ----

fn rd64(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn rd32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn wr64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn wr32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn phdrs(d: &[u8]) -> Vec<usize> {
    let phoff = rd64(d, 32) as usize;
    let n = u16::from_le_bytes([d[56], d[57]]) as usize;
    (0..n).map(|i| phoff + i * 56).collect()
}

/// Two PF_X LOADs, the first at file offset 0 with a VA near u64::MAX and
/// e_entry inside it: exercises the reverse-text `p_vaddr + 0x200` path.
#[test]
fn reverse_text_with_high_vaddr_does_not_panic() {
    let Some(mut d) = fixture("triage-x86_64-stripped") else { return };
    let first = *phdrs(&d).iter().find(|&&o| rd32(&d, o) == 1).unwrap();
    assert_eq!(rd64(&d, first + 8), 0, "first LOAD should map offset 0");
    wr32(&mut d, first + 4, 5); // R|X
    wr64(&mut d, first + 16, 0xffff_ffff_ffff_fe80);
    wr64(&mut d, first + 32, 0x2000);
    wr64(&mut d, first + 40, 0x2000);
    // The other exec LOAD must sit higher so the first is the lowest-VA one.
    let other = *phdrs(&d)
        .iter()
        .find(|&&o| o != first && rd32(&d, o) == 1 && rd32(&d, o + 4) & 1 != 0)
        .unwrap();
    wr64(&mut d, other + 16, 0xffff_ffff_ffff_ff00);
    wr64(&mut d, 24, 0xffff_ffff_ffff_fe90); // e_entry
    let _ = r2brief_core::analyze("rt", &d);
}

/// Sectionless file whose DT_SYMENT is near u64::MAX: exercises the
/// DT_SYMTAB fallback's `symtab + i * syment`.
#[test]
fn huge_dt_syment_does_not_panic() {
    let Some(mut d) = fixture("triage-x86_64-sstrip") else { return };
    let dynp = *phdrs(&d).iter().find(|&&o| rd32(&d, o) == 2).unwrap();
    let (off, sz) = (rd64(&d, dynp + 8) as usize, rd64(&d, dynp + 32) as usize);
    let mut hit = false;
    for e in (off..off + sz).step_by(16) {
        if rd64(&d, e) == 11 {
            // DT_SYMENT
            wr64(&mut d, e + 8, u64::MAX - 1);
            hit = true;
        }
    }
    assert!(hit, "fixture has DT_SYMENT");
    let report = r2brief_core::analyze("se", &d).unwrap();
    assert!(report.subject.import_count <= 1, "wrapped VAs must not become imports");
}

/// `.eh_frame` section header pointing just below u64::MAX.
#[test]
fn eh_frame_offset_near_max_does_not_panic() {
    let Some(mut d) = fixture("triage-x86_64-stripped") else { return };
    let shoff = rd64(&d, 40) as usize;
    let shnum = u16::from_le_bytes([d[60], d[61]]) as usize;
    let shstrndx = u16::from_le_bytes([d[62], d[63]]) as usize;
    let strtab = rd64(&d, shoff + shstrndx * 64 + 24) as usize;
    let mut hit = false;
    for i in 0..shnum {
        let sh = shoff + i * 64;
        let name = strtab + rd32(&d, sh) as usize;
        if d[name..].starts_with(b".eh_frame\0") {
            wr64(&mut d, sh + 24, u64::MAX - 4);
            hit = true;
        }
    }
    assert!(hit);
    let _ = r2brief_core::analyze("eh", &d);
}
