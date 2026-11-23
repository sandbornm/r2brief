//! CLI: r2brief-core <elf> [--json] [--bundle out.r2br]

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("usage: r2brief-core <elf> [--json] [--bundle OUT.r2br]");
        return ExitCode::from(2);
    }
    let mut json = false;
    let mut bundle_out: Option<String> = None;
    let mut path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--bundle" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--bundle needs a path");
                    return ExitCode::from(2);
                }
                bundle_out = Some(args[i].clone());
            }
            s if !s.starts_with('-') => path = Some(args[i].clone()),
            s => {
                eprintln!("unknown flag {s}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("missing ELF path");
            return ExitCode::from(2);
        }
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let report = match r2brief_core::analyze(&path, &data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("analyze: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(out) = bundle_out {
        if let Err(e) = fs::write(&out, &report.bundle_bytes) {
            eprintln!("write bundle: {e}");
            return ExitCode::from(1);
        }
    }
    if json {
        let mut v = serde_json::to_value(&report).expect("serialize");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("bundle_bytes");
            obj.insert(
                "bundle_sha256".into(),
                serde_json::Value::String({
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(&report.bundle_bytes);
                    format!("{:x}", h.finalize())
                }),
            );
        }
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!(
            "{}  {}  {}  entry=0x{:x}  findings={}  funcs={}  stripped={}",
            report.subject.name,
            report.subject.arch,
            report.subject.etype,
            report.subject.entry,
            report.findings.len(),
            report.functions.functions.len(),
            report.subject.stripped
        );
        for f in report.findings.iter().take(12) {
            println!("  [{:>5.1}] {}  {}", f.score, f.id, f.title);
            for e in &f.evidence {
                if let Some(d) = &e.detail {
                    println!("           {}", d);
                }
            }
        }
        if let Some(out) = env::args().find(|_| false) {
            let _ = out;
        }
    }
    // silence unused
    let _ = args;
    ExitCode::SUCCESS
}
