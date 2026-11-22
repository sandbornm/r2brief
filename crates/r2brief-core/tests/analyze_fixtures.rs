use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/bin")
        .join(name)
}

fn require_fixture(path: &PathBuf) {
    if path.exists() {
        return;
    }
    if std::env::var_os("CI").is_some() || std::env::var_os("R2B_REQUIRE_FIXTURES").is_some() {
        panic!("missing fixture {} (run fixtures/build_fixtures.py)", path.display());
    }
    eprintln!("skip: fixtures not built ({})", path.display());
}

#[test]
fn note_infection_x86() {
    let path = fixture("triage-x86_64-note");
    if !path.exists() {
        require_fixture(&path);
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let report = r2brief_core::analyze("triage-x86_64-note", &data).unwrap();
    assert!(
        report.findings.iter().any(|f| f.id.contains("pt_note_to_load")),
        "expected pt_note_to_load, got {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(!report.bundle_bytes.is_empty());
    assert_eq!(report.briefing["schema_version"], "r2b.briefing.v1");
}

#[test]
fn clean_has_no_infection_alarm() {
    let path = fixture("triage-x86_64-stripped");
    if !path.exists() {
        require_fixture(&path);
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let report = r2brief_core::analyze("triage-x86_64-stripped", &data).unwrap();
    let bad = report
        .findings
        .iter()
        .filter(|f| {
            f.tags.iter().any(|t| t == "infection")
                || f.id.contains("pt_note")
                || f.id.contains("text_padding")
                || f.id.contains("rwx")
        })
        .map(|f| f.id.as_str())
        .collect::<Vec<_>>();
    assert!(bad.is_empty(), "false infection on clean binary: {bad:?}");
}

#[test]
fn hostile_init_arraysz_does_not_abort() {
    let path = fixture("triage-x86_64-stripped");
    if !path.exists() {
        require_fixture(&path);
        return;
    }
    let mut data = std::fs::read(&path).unwrap();
    // Locate PT_DYNAMIC and set DT_INIT_ARRAYSZ to u64::MAX.
    assert_eq!(&data[0..4], b"\x7fELF");
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    let mut dyn_off = None;
    let mut dyn_sz = 0usize;
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let ptype = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        if ptype == 2 {
            dyn_off = Some(u64::from_le_bytes(data[o + 8..o + 16].try_into().unwrap()) as usize);
            dyn_sz = u64::from_le_bytes(data[o + 32..o + 40].try_into().unwrap()) as usize;
            break;
        }
    }
    let dyn_off = dyn_off.expect("PT_DYNAMIC");
    let mut off = dyn_off;
    while off + 16 <= dyn_off + dyn_sz {
        let tag = i64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        if tag == 27 {
            data[off + 8..off + 16].copy_from_slice(&u64::MAX.to_le_bytes());
            break;
        }
        if tag == 0 {
            break;
        }
        off += 16;
    }
    let report = r2brief_core::analyze("hostile-init", &data).expect("must not abort");
    assert!(report.findings.len() >= 1);
}

#[test]
fn handoff_keeps_supplied_path() {
    let path = fixture("triage-x86_64-stripped");
    if !path.exists() {
        require_fixture(&path);
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let supplied = format!("/tmp/outside/{}", path.file_name().unwrap().to_string_lossy());
    let report = r2brief_core::analyze(&supplied, &data).unwrap();
    assert_eq!(report.subject.name, path.file_name().unwrap().to_string_lossy());
    let argv = report.briefing["handoff"]["next_argv"].as_array().unwrap();
    if let Some(first) = argv.iter().find(|c| c.as_str().unwrap_or("").contains("verify")) {
        assert!(
            first.as_str().unwrap().contains("/tmp/outside/"),
            "handoff lost path: {first}"
        );
    }
}

#[test]
fn hostile_load_vaddr_does_not_panic() {
    // Minimal ELF64 LE with one PF_X PT_LOAD whose vaddr+memsz overflows.
    let mut data = vec![0u8; 128];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // class64
    data[5] = 1; // LE
    data[6] = 1; // version
    // e_type ET_DYN, e_machine x86_64
    data[16] = 3;
    data[18] = 62;
    // e_entry = 0xfffffffffffff000
    data[24..32].copy_from_slice(&0xfffffffffffff000u64.to_le_bytes());
    // e_phoff = 64
    data[32..40].copy_from_slice(&64u64.to_le_bytes());
    data[52] = 64; // ehsize
    data[54] = 56; // phentsize
    data[56] = 1; // phnum
    // phdr at 64
    let o = 64;
    data[o..o + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    data[o + 4..o + 8].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    data[o + 8..o + 16].copy_from_slice(&0u64.to_le_bytes()); // offset
    data[o + 16..o + 24].copy_from_slice(&0xfffffffffffff000u64.to_le_bytes()); // vaddr
    data[o + 32..o + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz
    data[o + 40..o + 48].copy_from_slice(&0x2000u64.to_le_bytes()); // memsz overflows with vaddr
    let report = r2brief_core::analyze("hostile-overflow", &data).expect("must not panic");
    assert!(!report.subject.sha256.is_empty());
}

#[test]
fn aarch64_backward_bl_does_not_panic() {
    let path = fixture("triage-aarch64-stripped");
    if !path.exists() {
        require_fixture(&path);
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let report = r2brief_core::analyze("triage-aarch64-stripped", &data).expect("must not panic");
    assert!(report.functions.call_targets > 0);
    assert!(report.functions.eh_frame_starts > 0);
}
