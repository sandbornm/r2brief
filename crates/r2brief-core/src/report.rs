//! Top-level triage report. Shaped so it can feed an r2b.briefing.v1 and
//! the analysis.json half of an .r2br evidence bundle.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::anomalies;
use crate::bundle;
use crate::dynamic;
use crate::ehframe;
use crate::elf::{ptype_name, Elf, ParseError, ET_DYN, ET_EXEC};
use crate::funcs::{self, FuncRecovery};
use crate::imports::{self, ImportSym};

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub why: String,
    pub score: f64,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub ask: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SegmentInfo {
    pub index: usize,
    pub type_name: String,
    pub flags: String,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,
    pub sh_type: u32,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub format: String,
    pub arch: String,
    pub class64: bool,
    pub little_endian: bool,
    pub etype: String,
    pub entry: u64,
    pub stripped: bool,
    pub dangerous_imports: Vec<String>,
    pub import_count: usize,
    pub function_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: String,
    pub producer: String,
    pub subject: Subject,
    pub findings: Vec<Finding>,
    pub segments: Vec<SegmentInfo>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportSym>,
    pub functions: FuncRecovery,
    pub needed: Vec<String>,
    pub parse_notes: Vec<String>,
    /// r2b.briefing.v1 document derived from findings.
    pub briefing: serde_json::Value,
    /// Public analysis document (analysis.json).
    pub analysis: serde_json::Value,
    /// Deterministic .r2br zip bytes (target excluded).
    pub bundle_bytes: Vec<u8>,
}

pub fn analyze(name: &str, data: &[u8]) -> Result<Report, String> {
    let sha = {
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    };
    let elf = Elf::parse(data).map_err(|e: ParseError| e.to_string())?;
    let dyninfo = dynamic::parse(&elf);
    let eh = ehframe::parse(&elf);
    let mut findings = anomalies::check_all(&elf, dyninfo.as_ref());
    let imports = imports::list_imports(&elf, dyninfo.as_ref());
    let dangerous = imports::dangerous_names(&imports);
    let funcs = funcs::recover(&elf, dyninfo.as_ref(), &eh);

    // Surface dangerous imports as findings so they show up in the briefing.
    for name in &dangerous {
        findings.push(Finding {
            id: format!("import:dangerous:{name}"),
            title: format!("Dangerous import: {name}"),
            why: format!(
                "{name} is in r2b's dangerous-import set. Use `r2b verify --import {name}` to classify call-site arguments."
            ),
            score: if imports::VERIFY.contains(&name.as_str()) {
                70.0
            } else {
                55.0
            },
            tags: vec!["import".into(), "dangerous".into()],
            evidence: vec![],
            ask: format!("Verify callers of {name}."),
        });
    }

    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });

    let stripped = !elf.shdrs.iter().any(|s| s.sh_type == crate::elf::SHT_SYMTAB);
    let etype = match elf.hdr.e_type {
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        1 => "ET_REL",
        4 => "ET_CORE",
        _ => "ET_OTHER",
    };
    let subject = Subject {
        name: name.to_string(),
        sha256: sha.clone(),
        size: data.len() as u64,
        format: "elf".into(),
        arch: elf.machine_name().into(),
        class64: elf.hdr.class64,
        little_endian: elf.hdr.little_endian,
        etype: etype.into(),
        entry: elf.hdr.e_entry,
        stripped,
        dangerous_imports: dangerous.clone(),
        import_count: imports.len(),
        function_count: funcs.functions.len(),
    };

    let segments: Vec<SegmentInfo> = elf
        .phdrs
        .iter()
        .map(|p| SegmentInfo {
            index: p.index,
            type_name: ptype_name(p.p_type),
            flags: p.flags_str(),
            offset: p.p_offset,
            vaddr: p.p_vaddr,
            filesz: p.p_filesz,
            memsz: p.p_memsz,
        })
        .collect();
    let sections: Vec<SectionInfo> = elf
        .shdrs
        .iter()
        .map(|s| SectionInfo {
            index: s.index,
            name: s.name.clone(),
            sh_type: s.sh_type,
            addr: s.sh_addr,
            offset: s.sh_offset,
            size: s.sh_size,
            flags: s.sh_flags,
        })
        .collect();

    let briefing = build_briefing(&subject, &findings, &funcs);
    let analysis = build_analysis(&subject, &findings, &funcs, &segments, &imports);
    let tools = serde_json::json!({
        "r2brief-core": { "available": true, "version": env!("CARGO_PKG_VERSION"), "mode": "wasm-or-native" }
    });
    let bundle_bytes = bundle::build(&briefing, &analysis, &tools, &subject)
        .map_err(|e| format!("bundle: {e}"))?;

    let mut parse_notes = elf.parse_notes.clone();
    parse_notes.extend(eh.notes.iter().cloned());
    parse_notes.extend(funcs.notes.iter().cloned());

    Ok(Report {
        schema_version: "r2brief.core.report.v1".into(),
        producer: format!("r2brief-core {}", env!("CARGO_PKG_VERSION")),
        subject,
        findings,
        segments,
        sections,
        imports,
        functions: funcs,
        needed: dyninfo.map(|d| d.needed).unwrap_or_default(),
        parse_notes,
        briefing,
        analysis,
        bundle_bytes,
    })
}

fn build_briefing(
    subject: &Subject,
    findings: &[Finding],
    funcs: &FuncRecovery,
) -> serde_json::Value {
    let regions: Vec<serde_json::Value> = findings
        .iter()
        .take(6)
        .map(|f| {
            let addr = f.evidence.iter().find_map(|e| e.address);
            let offset = f.evidence.iter().find_map(|e| e.offset);
            let detail = f
                .evidence
                .iter()
                .filter_map(|e| e.detail.as_ref())
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            serde_json::json!({
                "id": f.id,
                "title": f.title,
                "why": f.why,
                "score": f.score,
                "tags": f.tags,
                "ask": f.ask,
                "next_actions": [],
                "snippet": {
                    "source": "r2brief-core",
                    "kind": "evidence",
                    "text": detail,
                    "address": addr.map(|a| format!("0x{a:x}")),
                    "function": null,
                    "artifact_id": offset.map(|o| format!("off:0x{o:x}")),
                }
            })
        })
        .collect();

    let summary = format!(
        "{} looks like ELF {}; {}; entry 0x{:x}; {} findings; {} recovered functions{}.",
        subject.name,
        subject.arch,
        subject.etype,
        subject.entry,
        findings.len(),
        funcs.functions.len(),
        if subject.stripped { "; stripped" } else { "" }
    );

    let mut next_argv = Vec::new();
    for name in subject.dangerous_imports.iter().filter(|n| imports::VERIFY.contains(&n.as_str())).take(4)
    {
        next_argv.push(format!("r2b verify {} --import {name} --json", subject.name));
    }

    serde_json::json!({
        "schema_version": "r2b.briefing.v1",
        "binary": subject.name,
        "subject": {
            "name": subject.name,
            "sha256": subject.sha256,
            "size": subject.size,
            "format": subject.format,
            "arch": subject.arch,
            "stripped": subject.stripped,
            "dangerous_imports": subject.dangerous_imports,
            "import_count": subject.import_count,
            "function_count": subject.function_count,
            "subject_class": "elf",
        },
        "summary": summary,
        "regions": regions,
        "overall_ask": "Confirm each finding against readelf/objdump and the fixture ground truth.",
        "next_steps": [
            "Inspect program headers for infection patterns.",
            "Cross-check recovered function starts against nm -n on the unstripped twin.",
            "Run r2b verify on dangerous imports when a full toolchain is available."
        ],
        "handoff": {
            "schema_version": "r2b.handoff.v1",
            "binary": subject.name,
            "record_id": null,
            "summary": summary,
            "subject": {
                "name": subject.name,
                "format": subject.format,
                "arch": subject.arch,
                "stripped": subject.stripped,
            },
            "regions": regions.iter().map(|r| serde_json::json!({
                "id": r["id"],
                "title": r["title"],
                "addr": r["snippet"]["address"],
                "why": r["why"],
                "tags": r["tags"],
                "snippet": r["snippet"]["text"],
            })).collect::<Vec<_>>(),
            "next_argv": next_argv,
            "named_imports": subject.dangerous_imports.iter()
                .filter(|n| !imports::VERIFY.contains(&n.as_str()))
                .cloned().collect::<Vec<_>>(),
            "verified_sites": [],
            "decompile_addrs": [],
            "requires_scope": false,
        }
    })
}

fn build_analysis(
    subject: &Subject,
    findings: &[Finding],
    funcs: &FuncRecovery,
    segments: &[SegmentInfo],
    imports: &[ImportSym],
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "r2b.analysis_result.v1",
        "tool_status": {
            "r2brief-core": { "available": true, "version": env!("CARGO_PKG_VERSION") }
        },
        "subject": subject,
        "findings": findings,
        "functions": funcs,
        "segments": segments,
        "imports": imports,
        "provenance": {
            "schema_version": "r2b.provenance.v1",
            "producer": format!("r2brief-core {}", env!("CARGO_PKG_VERSION")),
            "mode": "static-client-side",
            "notes": ["no network", "no upload", "deterministic"]
        }
    })
}

/// Tiny hex encoder so we don't pull a hex crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let b = bytes.as_ref();
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}
