//! Public API for V3 streaming CENC decryption

use crate::error::Result;
use crate::orchestrator;
use crate::types::KeyMap;
use std::io::{Read, Write};

/// Decrypt fMP4 CENC-encrypted stream in a single pass
///
/// This function decrypts a fragmented MP4 (fMP4) file that uses Common Encryption (CENC).
/// It processes the input stream incrementally without loading the entire file into memory.
///
/// # Arguments
///
/// * `input` - Input stream containing encrypted fMP4 data
/// * `output` - Output stream for decrypted fMP4 data
/// * `keys` - Map of Key IDs (KID) to decryption keys (both 16 bytes)
///
/// # Supported Schemes
///
/// - `cenc` - AES-CTR mode, full sample encryption
/// - `cens` - AES-CTR mode, subsample encryption
/// - `cbc1` - AES-CBC mode, full sample encryption
/// - `cbcs` - AES-CBC mode, subsample encryption with pattern
///
/// # Memory Usage
///
/// This implementation uses O(buffer_size) memory, not O(file_size).
/// Specifically:
/// - Metadata boxes (moov, moof): Fully buffered (~1MB typically)
/// - Data boxes (mdat): Streamed sample-by-sample
/// - Maximum memory: Size of largest sample (typically <10MB)
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
/// use std::collections::HashMap;
/// use iori_cenc::decrypt;
///
/// let input = File::open("encrypted.mp4")?;
/// let output = File::create("decrypted.mp4")?;
///
/// let mut keys = HashMap::new();
/// keys.insert(
///     [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
///      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
///     [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
///      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
/// );
///
/// decrypt(input, output, keys)?;
/// # Ok::<(), iori_cenc::V3Error>(())
/// ```
///
/// # Errors
///
/// Returns error if:
/// - Input is not a valid fMP4 file
/// - Required encryption metadata is missing
/// - Decryption keys are missing for any track
/// - I/O errors occur during reading or writing
/// - Box structure is invalid or corrupted
///
/// # Limitations
///
/// - **fMP4 only**: This implementation only supports fragmented MP4 files.
///   Non-fragmented MP4 files are not supported (would require Seek trait).
/// - **Single pass**: The implementation makes a single forward pass through the file.
///   This is possible because fMP4 places metadata (moov, moof) before data (mdat).
/// - **No seeking**: The input and output streams need only implement Read/Write,
///   not Seek. This allows decryption from pipes, sockets, etc.
pub fn decrypt<R: Read, W: Write>(input: R, output: W, keys: KeyMap) -> Result<()> {
    orchestrator::decrypt_stream(input, output, keys)
}
