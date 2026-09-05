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

pub fn decrypt_mp4(input: &mut [u8], keys: &HashMap<String, String>) -> Result<()> {
    let key_map = KeyMap::from_hex_pairs(keys)?;
    let parsed = ParsedCenc::parse(input)?;
    parsed.decrypt_in_place(input, &key_map, 0)?;
    Ok(())
}

pub fn decrypt_mp4_with_initial_segment(
    input: &mut [u8],
    initial_segment: &[u8],
    keys: &HashMap<String, String>,
) -> Result<()> {
    let key_map = KeyMap::from_hex_pairs(keys)?;
    let parsed = ParsedCenc::parse_with_init(input, initial_segment)?;
    parsed.decrypt_in_place(input, &key_map, 0)?;
    Ok(())
}
