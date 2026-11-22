//! wasm-bindgen surface: one function that takes bytes and returns JSON.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn analyze_elf(name: &str, data: &[u8]) -> Result<String, JsValue> {
    let report = crate::analyze(name, data).map_err(|e| JsValue::from_str(&e))?;
    // Drop the raw bundle bytes from the JSON view; expose them separately.
    let mut v = serde_json::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if let Some(obj) = v.as_object_mut() {
        let bytes = report.bundle_bytes;
        obj.insert(
            "bundle_base64".into(),
            serde_json::Value::String(b64(&bytes)),
        );
        obj.remove("bundle_bytes");
    }
    serde_json::to_string(&v).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").into()
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
