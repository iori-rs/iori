//! Main streaming orchestrator for V3 CENC decryption

use crate::types::KeyMap;
use crate::context::DecryptionContext;
use crate::error::{Result, V3Error};
use crate::parse::box_header;
use crate::{decrypt, parse};
use shiguredo_mp4::BoxType;
use std::io::{Read, Write};
use winnow::stream::Partial;

/// Local box header for the streaming reader (read from a Read stream, not a winnow parser)
struct BoxHeader {
    box_type: [u8; 4],
    size: u64,
    header_size: usize,
}

/// Decrypt fMP4 stream in a single pass
///
/// This function orchestrates the entire streaming decryption process:
/// 1. Read box headers incrementally
/// 2. For metadata boxes (ftyp, moov, moof): buffer and parse
/// 3. For data boxes (mdat): decrypt sample-by-sample while streaming
/// 4. For other boxes: pass through unchanged
///
/// Memory usage: O(buffer_size), not O(file_size)
pub fn decrypt_stream<R: Read, W: Write>(mut input: R, mut output: W, keys: KeyMap) -> Result<()> {
    let mut context = DecryptionContext::new(keys);
    let mut reader = StreamingReader::new(&mut input);

    loop {
        // Read box header

        let header = match reader.read_box_header() {
            Ok(h) => h,
            Err(V3Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // End of stream
                break;
            }
            Err(e) => return Err(e),
        };

        let payload_size = (header.size as usize)
            .checked_sub(header.header_size)
            .ok_or_else(|| {
                V3Error::InvalidBoxStructure(format!(
                    "Box size {} smaller than header size {}",
                    header.size, header.header_size
                ))
            })?;

        match &header.box_type {
            b"moov" => {
                // Movie metadata - buffer, parse, and pass through
                let payload = reader.read_exact(payload_size)?;

                // Parse track encryption metadata
                let tracks = parse::parse_moov(&payload)?;
                context.set_tracks(tracks);

                // Validate we have all required keys
                context.validate_keys()?;

                // Write moov box to output
                write_box_header(&mut output, &header)?;
                output.write_all(&payload)?;
            }

            b"moof" => {
                // Movie fragment metadata - buffer, parse, and pass through
                let payload = reader.read_exact(payload_size)?;

                // Determine which track this fragment is for
                // We need to extract track_id from tfhd to get the right track metadata
                let track_id = extract_track_id_from_moof(&payload)?;
                let track_metadata = context.track_metadata(track_id)?;

                // Parse fragment metadata
                let fragment = parse::parse_moof(&payload, track_metadata)?;
                context.set_current_fragment(fragment);

                // Strip encryption metadata boxes (senc/saiz/saio) from moof
                let clean_payload = strip_moof_encryption_boxes(&payload);
                let clean_header = BoxHeader {
                    box_type: header.box_type,
                    size: header.header_size as u64 + clean_payload.len() as u64,
                    header_size: header.header_size,
                };

                // Write cleaned moof box to output
                write_box_header(&mut output, &clean_header)?;
                output.write_all(&clean_payload)?;
            }

            b"mdat" => {
                // Media data - decrypt sample-by-sample while streaming
                let fragment = context.current_fragment()?;
                let track_metadata = context.track_metadata(fragment.track_id)?;

                // Write mdat header to output
                write_box_header(&mut output, &header)?;

                // Decrypt mdat content
                decrypt::decrypt_mdat(
                    &mut reader.inner,
                    &mut output,
                    payload_size,
                    fragment,
                    track_metadata,
                    context.keys(),
                )?;

                // Clear current fragment after processing
                context.clear_current_fragment();
            }

            _ => {
                // File type box - pass through
                // Unknown box - pass through unchanged
                write_box_header(&mut output, &header)?;
                copy_exact(&mut reader.inner, &mut output, payload_size)?;
            }
        }
    }

    Ok(())
}

/// Strip senc/saiz/saio boxes from traf payload, returning new bytes
fn strip_traf_encryption_boxes(traf_payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(traf_payload.len());
    let mut offset = 0;

    while offset + 8 <= traf_payload.len() {
        let size = u32::from_be_bytes(traf_payload[offset..offset + 4].try_into().unwrap()) as usize;
        let box_type: [u8; 4] = traf_payload[offset + 4..offset + 8].try_into().unwrap();

        let (actual_size, _header_size) = if size == 1 {
            if offset + 16 > traf_payload.len() {
                break;
            }
            let ext = u64::from_be_bytes(traf_payload[offset + 8..offset + 16].try_into().unwrap()) as usize;
            (ext, 16)
        } else if size == 0 {
            (traf_payload.len() - offset, 8)
        } else {
            (size, 8)
        };

        if actual_size < 8 || offset + actual_size > traf_payload.len() {
            result.extend_from_slice(&traf_payload[offset..]);
            break;
        }

        if box_type != *b"senc" && box_type != *b"saiz" && box_type != *b"saio" {
            result.extend_from_slice(&traf_payload[offset..offset + actual_size]);
        }

        offset += actual_size;
    }

    result
}

/// Strip encryption metadata boxes (senc/saiz/saio) from moof payload
fn strip_moof_encryption_boxes(moof_payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(moof_payload.len());
    let mut offset = 0;

    while offset + 8 <= moof_payload.len() {
        let size = u32::from_be_bytes(moof_payload[offset..offset + 4].try_into().unwrap()) as usize;
        let box_type: [u8; 4] = moof_payload[offset + 4..offset + 8].try_into().unwrap();

        let (actual_size, header_size) = if size == 1 {
            if offset + 16 > moof_payload.len() {
                break;
            }
            let ext = u64::from_be_bytes(moof_payload[offset + 8..offset + 16].try_into().unwrap()) as usize;
            (ext, 16usize)
        } else if size == 0 {
            (moof_payload.len() - offset, 8usize)
        } else {
            (size, 8usize)
        };

        if actual_size < header_size || offset + actual_size > moof_payload.len() {
            result.extend_from_slice(&moof_payload[offset..]);
            break;
        }

        if box_type == *b"traf" {
            let traf_payload = &moof_payload[offset + header_size..offset + actual_size];
            let new_traf = strip_traf_encryption_boxes(traf_payload);
            let new_traf_size = header_size + new_traf.len();
            if header_size == 8 {
                result.extend_from_slice(&(new_traf_size as u32).to_be_bytes());
                result.extend_from_slice(b"traf");
            } else {
                result.extend_from_slice(&1u32.to_be_bytes());
                result.extend_from_slice(b"traf");
                result.extend_from_slice(&(new_traf_size as u64).to_be_bytes());
            }
            result.extend_from_slice(&new_traf);
        } else {
            result.extend_from_slice(&moof_payload[offset..offset + actual_size]);
        }

        offset += actual_size;
    }

    result
}

/// Helper to extract track_id from moof box (from tfhd inside traf)
fn extract_track_id_from_moof(moof_payload: &[u8]) -> Result<u32> {
    use winnow::Parser;

    let mut input = Partial::new(moof_payload);

    // Find traf box
    while !input.is_empty() {
        let header = box_header(&mut input)?;
        let payload_size = header.box_size.get() as usize - header.external_size();

        if header.box_type == BoxType::Normal(*b"traf") {
            let traf_payload: &[u8] =
                winnow::token::take::<_, _, winnow::error::ErrMode<winnow::error::ContextError>>(
                    payload_size,
                )
                .parse_next(&mut input)?;

            // Find tfhd box in traf
            let mut traf_input = Partial::new(traf_payload);
            while !traf_input.is_empty() {
                let tfhd_header = box_header(&mut traf_input)?;
                let tfhd_payload_size = tfhd_header.box_size.get() as usize - tfhd_header.external_size();

                if tfhd_header.box_type == BoxType::Normal(*b"tfhd") {
                    let tfhd_payload: &[u8] =
                        winnow::token::take::<_, _, winnow::error::ErrMode<winnow::error::ContextError>>(
                            tfhd_payload_size,
                        )
                        .parse_next(&mut traf_input)?;

                    // Parse tfhd to get track_id
                    let mut tfhd_input = Partial::new(tfhd_payload);
                    let _full_header = parse::full_box_header(&mut tfhd_input)?;
                    let track_id = winnow::binary::be_u32::<Partial<&[u8]>, winnow::error::ErrMode<winnow::error::ContextError>>
                        .parse_next(&mut tfhd_input)?;

                    return Ok(track_id);
                } else {
                    winnow::token::take::<_, _, winnow::error::ErrMode<winnow::error::ContextError>>(
                        tfhd_payload_size,
                    )
                    .parse_next(&mut traf_input)?;
                }
            }
        } else {
            winnow::token::take::<_, _, winnow::error::ErrMode<winnow::error::ContextError>>(
                payload_size,
            )
            .parse_next(&mut input)?;
        }
    }

    Err(V3Error::MissingMetadata(
        "No tfhd found in moof".to_string(),
    ))
}

/// Streaming reader helper
struct StreamingReader<'a, R: Read> {
    inner: &'a mut R,
}

impl<'a, R: Read> StreamingReader<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self { inner: reader }
    }

    /// Read box header from stream
    fn read_box_header(&mut self) -> Result<BoxHeader> {
        // Read initial 8 bytes
        let mut header_buf = [0u8; 16];
        self.inner.read_exact(&mut header_buf[..8])?;

        let size = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        let box_type: [u8; 4] = header_buf[4..8].try_into().unwrap();

        let (actual_size, header_size) = if size == 1 {
            // Extended size - read 8 more bytes
            self.inner.read_exact(&mut header_buf[8..16])?;
            let ext_size = u64::from_be_bytes(header_buf[8..16].try_into().unwrap());
            (ext_size, 16)
        } else if size == 0 {
            // Box extends to EOF - not supported in streaming
            return Err(V3Error::UnsupportedFeature(
                "Box with size=0 (extends to EOF) not supported".to_string(),
            ));
        } else {
            (size as u64, 8)
        };

        Ok(BoxHeader {
            box_type,
            size: actual_size,
            header_size,
        })
    }

    /// Read exact number of bytes into a new buffer
    fn read_exact(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Write box header to output
fn write_box_header<W: Write>(output: &mut W, header: &BoxHeader) -> Result<()> {
    if header.header_size == 8 {
        // Normal header
        output.write_all(&(header.size as u32).to_be_bytes())?;
        output.write_all(&header.box_type)?;
    } else {
        // Extended header
        output.write_all(&1u32.to_be_bytes())?;
        output.write_all(&header.box_type)?;
        output.write_all(&header.size.to_be_bytes())?;
    }
    Ok(())
}

/// Copy exact number of bytes from input to output
fn copy_exact<R: Read, W: Write>(input: &mut R, output: &mut W, size: usize) -> Result<()> {
    const BUFFER_SIZE: usize = 65536; // 64KB buffer

    let mut remaining = size;
    let mut buffer = vec![0u8; BUFFER_SIZE.min(size)];

    while remaining > 0 {
        let to_read = remaining.min(buffer.len());
        input.read_exact(&mut buffer[..to_read])?;
        output.write_all(&buffer[..to_read])?;
        remaining -= to_read;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_box_header_normal() {
        let mut output = Vec::new();
        let header = BoxHeader {
            box_type: *b"mdat",
            size: 1024,
            header_size: 8,
        };

        write_box_header(&mut output, &header).unwrap();

        assert_eq!(
            output,
            vec![
                0x00, 0x00, 0x04, 0x00, // size = 1024
                b'm', b'd', b'a', b't', // type
            ]
        );
    }

    #[test]
    fn test_write_box_header_extended() {
        let mut output = Vec::new();
        let header = BoxHeader {
            box_type: *b"mdat",
            size: 100000,
            header_size: 16,
        };

        write_box_header(&mut output, &header).unwrap();

        assert_eq!(
            output,
            vec![
                0x00, 0x00, 0x00, 0x01, // size = 1 (extended)
                b'm', b'd', b'a', b't', // type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, // extended size = 100000
            ]
        );
    }

    #[test]
    fn test_copy_exact() {
        let data = vec![0x42u8; 1000];
        let mut input = Cursor::new(data);
        let mut output = Vec::new();

        copy_exact(&mut input, &mut output, 1000).unwrap();

        assert_eq!(output.len(), 1000);
        assert_eq!(output, vec![0x42u8; 1000]);
    }
}
