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
