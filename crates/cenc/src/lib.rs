#![forbid(unsafe_code)]

mod cleanup;
mod crypto;
mod errors;
mod jobs;
mod types;

pub use crate::cleanup::normalize_decrypted_fmp4;
pub use crate::errors::{CencError, Result};
pub use crate::types::{CbcPattern, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample};

use std::collections::HashMap;

pub fn decrypt_mp4(mut input: Vec<u8>, keys: &HashMap<String, String>) -> Result<Vec<u8>> {
    let key_map = KeyMap::from_hex_pairs(keys)?;
    let parsed = ParsedCenc::parse(&input)?;
    parsed.decrypt_in_place(&mut input, &key_map, 0)?;
    Ok(input)
}

pub fn decrypt_mp4_with_initial_segment(
    mut input: Vec<u8>,
    initial_segment: &[u8],
    keys: &HashMap<String, String>,
) -> Result<Vec<u8>> {
    let key_map = KeyMap::from_hex_pairs(keys)?;
    let parsed = ParsedCenc::parse_with_init(&input, initial_segment)?;
    parsed.decrypt_in_place(&mut input, &key_map, 0)?;
    Ok(input)
}
