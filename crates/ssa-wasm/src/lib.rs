use iori_cenc::{decrypt_mp4, decrypt_mp4_with_initial_segment};
use js_sys::Uint8Array;
use std::collections::HashMap;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

fn invalid_arg(message: &str) -> JsValue {
    JsValue::from_str(message)
}

fn validate_hex_32(name: &str, value: &str) -> Result<(), JsValue> {
    if value.len() != 32 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_arg(&format!("{name} must be 32 hex chars")));
    }
    Ok(())
}

fn parse_keyid_key(keyid_key: &str) -> Result<(String, String), JsValue> {
    if keyid_key.contains(';') {
        return Err(invalid_arg("keyid:key must contain a single pair"));
    }
    let Some((kid, key)) = keyid_key.split_once(':') else {
        return Err(invalid_arg("keyid:key format is required"));
    };
    validate_hex_32("keyid", kid)?;
    validate_hex_32("key", key)?;
    Ok((kid.to_string(), key.to_string()))
}

fn parse_keyid_keys(keyid_keys: Vec<String>) -> Result<HashMap<String, String>, JsValue> {
    let mut keys = HashMap::new();
    for keyid_key in keyid_keys {
        let (kid, key) = parse_keyid_key(&keyid_key)?;
        keys.insert(kid, key);
    }
    Ok(keys)
}

#[wasm_bindgen(js_name = decryptSegment)]
pub fn decrypt_segment(
    input: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let key_vec = key.to_vec();
    let iv_vec = iv.to_vec();

    if key_vec.len() != 16 {
        return Err(invalid_arg("key must be 16 bytes"));
    }
    if iv_vec.len() != 16 {
        return Err(invalid_arg("iv must be 16 bytes"));
    }

    let key_bytes: [u8; 16] = key_vec
        .try_into()
        .map_err(|_| invalid_arg("key must be 16 bytes"))?;
    let iv_bytes: [u8; 16] = iv_vec
        .try_into()
        .map_err(|_| invalid_arg("iv must be 16 bytes"))?;

    let mut output = Vec::new();
    iori_ssa::decrypt(
        Cursor::new(input.to_vec()),
        &mut output,
        key_bytes,
        iv_bytes,
    )
    .map_err(|err| invalid_arg(&format!("iori-ssa error: {err:?}")))?;

    Ok(Uint8Array::from(output.as_slice()))
}

#[wasm_bindgen(js_name = decryptSegmentCenc)]
pub fn decrypt_segment_cenc(
    input: Uint8Array,
    keyid_keys: Vec<String>,
    initial_segment: Option<Uint8Array>,
) -> Result<Uint8Array, JsValue> {
    let keys = parse_keyid_keys(keyid_keys)?;

    let input = input.to_vec();
    let initial_segment = initial_segment.filter(|segment| segment.length() > 0);
    let output = if let Some(initial_segment) = initial_segment {
        let initial_segment = initial_segment.to_vec();
        decrypt_mp4_with_initial_segment(input, &initial_segment, &keys)
    } else {
        decrypt_mp4(input, &keys)
    }
    .map_err(|err| invalid_arg(&format!("iori-cenc error: {err}")))?;

    Ok(Uint8Array::from(output.as_slice()))
}

#[wasm_bindgen(js_name = decryptSegmentCencWithInit)]
pub fn decrypt_segment_cenc_with_init(
    input: Uint8Array,
    initial_segment: Uint8Array,
    keyid_keys: Vec<String>,
) -> Result<Uint8Array, JsValue> {
    let keys = parse_keyid_keys(keyid_keys)?;
    let initial_segment = initial_segment.to_vec();
    if initial_segment.is_empty() {
        return Err(invalid_arg(
            "initialSegment must contain a DASH/fMP4 initialization segment with a moov box",
        ));
    }

    let output = decrypt_mp4_with_initial_segment(input.to_vec(), &initial_segment, &keys)
        .map_err(|err| invalid_arg(&format!("iori-cenc error: {err}")))?;

    Ok(Uint8Array::from(output.as_slice()))
}
