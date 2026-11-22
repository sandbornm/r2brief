//! wasm-bindgen surface: one function that takes bytes and returns JSON.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze_elf(name: &str, data: &[u8]) -> Result<String, JsValue> {
    // Hard cap so a dropped multi-hundred-MB file cannot OOM the tab.
    if data.len() > 64 * 1024 * 1024 {
        return Err(JsValue::from_str("ELF larger than 64 MiB; refused in the browser demo"));
    }
    let report = crate::analyze(name, data).map_err(|e| JsValue::from_str(&e))?;
    let mut v = serde_json::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if let Some(obj) = v.as_object_mut() {
        let bytes = report.bundle_bytes;
        obj.insert("bundle_base64".into(), serde_json::Value::String(b64(&bytes)));
        obj.remove("bundle_bytes");
    }
    // JSON numbers cannot carry full u64; rewrite address-like fields as hex strings
    // so the demo does not round them.
    stringify_u64_fields(&mut v);
    serde_json::to_string(&v).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

fn stringify_u64_fields(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if matches!(
                    k.as_str(),
                    "start" | "end" | "address" | "offset" | "entry" | "vaddr" | "addr"
                        | "filesz" | "memsz" | "size" | "sh_offset" | "length"
                ) {
                    if let Some(serde_json::Value::Number(n)) = map.get(&k) {
                        if let Some(u) = n.as_u64() {
                            map.insert(k.clone(), serde_json::Value::String(format!("0x{u:x}")));
                            continue;
                        }
                    }
                }
                if let Some(child) = map.get_mut(&k) {
                    stringify_u64_fields(child);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                stringify_u64_fields(child);
            }
        }
        _ => {}
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = u32::from(data[i]) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}
