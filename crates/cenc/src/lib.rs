#![forbid(unsafe_code)]

mod cleanup;
mod crypto;
mod errors;
mod jobs;
mod types;

mod api;
mod context;
mod decrypt;
pub mod error;
mod orchestrator;
mod parse;

pub use crate::api::decrypt;
pub use crate::cleanup::normalize_decrypted_fmp4;
pub use crate::crypto::decrypt_in_place;
pub use crate::error::V3Error;
pub use crate::errors::{CencError, Result};
pub use crate::jobs::parse_decrypt_jobs;
pub use crate::types::{CbcPattern, DecryptJob, KeyMap, ParsedCenc, SchemeType, Subsample};

use std::collections::HashMap;

pub fn decrypt_mp4(input: &[u8], keys: &HashMap<String, String>) -> Result<Vec<u8>> {
    let key_map = jobs::parse_key_map(keys)?;
    let parsed = parse_decrypt_jobs(input)?;
    let mut output = input.to_vec();
    decrypt_in_place(&mut output, &parsed.jobs, &key_map, 0)?;
    Ok(output)
}
