//! Deterministic .r2br (ZIP) writer matching r2b.bundle.v1.
//!
//! Stored (no compression) so we don't need a deflate crate in wasm.
//! The Python reader accepts ZIP_STORED. Timestamps and order are fixed.

use sha2::{Digest, Sha256};

use crate::report::Subject;

const MEDIA: &[u8] = b"application/vnd.r2brief.bundle+zip";

pub fn build(
    briefing: &serde_json::Value,
    analysis: &serde_json::Value,
    tools: &serde_json::Value,
    subject: &Subject,
) -> Result<Vec<u8>, String> {
    let briefing_b = canon(briefing)?;
    let analysis_b = canon(analysis)?;
    let tools_b = canon(tools)?;

    let mut entries = vec![
        entry("analysis.json", "analysis", &analysis_b),
        entry("briefing.json", "briefing", &briefing_b),
        entry("tools.json", "tool_status", &tools_b),
    ];
    if let Some(prov) = analysis.get("provenance") {
        let pb = canon(prov)?;
        entries.push(entry("provenance.json", "provenance", &pb));
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = serde_json::json!({
        "schema_version": "r2b.bundle.v1",
        "container": "zip",
        "producer": { "name": "r2b", "version": env!("CARGO_PKG_VERSION") },
        "subject": {
            "name": subject.name,
            "sha256": subject.sha256,
            "size": subject.size,
            "bytes_included": false,
        },
        "requires_scope": false,
        "entries": entries.iter().map(|e| serde_json::json!({
            "path": e.path,
            "role": e.role,
            "media_type": "application/json",
            "sha256": e.sha256,
            "size": e.data.len(),
        })).collect::<Vec<_>>(),
    });
    let manifest_b = canon(&manifest)?;

    let mut members: Vec<(&str, &[u8], bool)> = Vec::new();
    members.push(("mimetype", MEDIA, true)); // stored, first
    members.push(("manifest.json", &manifest_b, true));
    // Keep owned bytes alive.
    let owned: Vec<(String, Vec<u8>)> = entries
        .into_iter()
        .map(|e| (e.path, e.data))
        .collect();
    // Rebuild member list with owned data.
    let mut zip_members: Vec<(String, Vec<u8>, bool)> = Vec::new();
    zip_members.push(("mimetype".into(), MEDIA.to_vec(), true));
    zip_members.push(("manifest.json".into(), manifest_b, true));
    for (p, d) in owned {
        zip_members.push((p, d, true));
    }
    Ok(write_zip(&zip_members))
}

struct E {
    path: String,
    role: String,
    sha256: String,
    data: Vec<u8>,
}

fn entry(path: &str, role: &str, data: &[u8]) -> E {
    let mut h = Sha256::new();
    h.update(data);
    E {
        path: path.into(),
        role: role.into(),
        sha256: crate_hex(&h.finalize()),
        data: data.to_vec(),
    }
}

fn canon(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    // serde_json::to_vec doesn't sort keys; use a BTreeMap round-trip.
    let sorted = sort_value(v);
    let mut s = serde_json::to_string(&sorted).map_err(|e| e.to_string())?;
    s.push('\n');
    Ok(s.into_bytes())
}

fn sort_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            for k in keys {
                out.insert(k.clone(), sort_value(&map[&k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(sort_value).collect())
        }
        other => other.clone(),
    }
}

fn crate_hex(bytes: impl AsRef<[u8]>) -> String {
    let b = bytes.as_ref();
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Minimal ZIP writer: local headers + central directory + EOCD.
/// All timestamps fixed to 1980-01-01 00:00:00; method = store (0).
fn write_zip(members: &[(String, Vec<u8>, bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let dos_time: u16 = 0;
    let dos_date: u16 = 0x21; // 1980-01-01
    for (name, data, _stored) in members {
        let name_b = name.as_bytes();
        let crc = crc32(data);
        let offset = out.len() as u32;
        // Local file header
        out.extend_from_slice(&0x04034b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method store
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);
        // Central directory header
        central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central.extend_from_slice(&0x0314u16.to_le_bytes()); // version made by (Unix 3.0 + 20)
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&dos_time.to_le_bytes());
        central.extend_from_slice(&dos_date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
        central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes()); // ext attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_b);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    // EOCD
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    // IEEE CRC-32
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1); // 0 or 0xffffffff
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc_empty() {
        assert_eq!(crc32(b""), 0);
    }
    #[test]
    fn crc_known() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
