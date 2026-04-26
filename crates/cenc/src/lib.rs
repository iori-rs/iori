#![forbid(unsafe_code)]

mod cleanup;
mod crypto;
mod errors;
mod jobs;
mod types;

pub mod error;

pub use crate::cleanup::normalize_decrypted_fmp4;
pub use crate::crypto::decrypt_in_place;
pub use crate::error::V3Error;
pub use crate::errors::{CencError, Result};
pub use crate::jobs::{parse_decrypt_jobs, parse_decrypt_jobs_with_initial_segment};
pub use crate::types::{CbcPattern, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample};

use std::collections::HashMap;

pub fn decrypt_mp4(mut input: Vec<u8>, keys: &HashMap<String, String>) -> Result<Vec<u8>> {
    let key_map = jobs::parse_key_map(keys)?;
    let parsed = parse_decrypt_jobs(&input)?;
    decrypt_in_place(&mut input, &parsed.jobs, &key_map, 0)?;
    Ok(input)
}

pub fn decrypt_mp4_with_initial_segment(
    mut input: Vec<u8>,
    initial_segment: &[u8],
    keys: &HashMap<String, String>,
) -> Result<Vec<u8>> {
    let key_map = jobs::parse_key_map(keys)?;
    let parsed = parse_decrypt_jobs_with_initial_segment(&input, initial_segment)?;
    decrypt_in_place(&mut input, &parsed.jobs, &key_map, 0)?;
    Ok(input)
}
