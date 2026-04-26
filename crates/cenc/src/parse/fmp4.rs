//! High-level fMP4 structure parsers

use super::boxes::*;
use super::combinators::*;
use crate::jobs;
use shiguredo_mp4::BoxType;
use shiguredo_mp4::Decode;
use shiguredo_mp4::boxes::MoovBox;
use winnow::binary::be_u32;
use winnow::error::{ContextError, ErrMode};
use winnow::stream::Partial;
use winnow::token::take;
use winnow::{ModalResult, Parser};

/// Track metadata extracted from moov box
#[derive(Debug, Clone, PartialEq)]
pub struct TrackMetadata {
    pub track_id: u32,
    pub encryption_info: TrackEncryptionInfo,
}

/// Fragment metadata extracted from moof box
#[derive(Debug, Clone, PartialEq)]
pub struct FragmentMetadata {
    pub track_id: u32,
    pub sample_encryption: Vec<SampleEncryptionEntry>,
    pub sample_sizes: Vec<u32>,
    pub data_offset: u64,
}

/// Track Run (trun) box data
#[derive(Debug, Clone, Default)]
struct TrunData {
    sample_sizes: Vec<u32>,
    data_offset: Option<u32>,
}

/// Parse trun box (Track Run Box)
///
/// Structure:
/// - version (1) + flags (3)
/// - sample_count (u32)
/// - data_offset (i32) - optional, if flags & 0x01
/// - first_sample_flags (u32) - optional, if flags & 0x04
/// - For each sample (controlled by flags):
///   - sample_duration (u32) - if flags & 0x100
///   - sample_size (u32) - if flags & 0x200
///   - sample_flags (u32) - if flags & 0x400
///   - sample_composition_time_offset (u32 or i32) - if flags & 0x800
fn parse_trun(input: &mut Partial<&[u8]>, version: u8, flags: u32) -> ModalResult<TrunData> {
    let sample_count = be_u32.parse_next(input)?;

    // Data offset (if flags & 0x01)
    let data_offset = if (flags & 0x01) != 0 {
        Some(be_u32.parse_next(input)?)
    } else {
        None
    };

    // First sample flags (if flags & 0x04)
    if (flags & 0x04) != 0 {
        take(4usize).void().parse_next(input)?;
    }

    // Per-sample data
    let has_duration = (flags & 0x100) != 0;
    let has_size = (flags & 0x200) != 0;
    let has_flags = (flags & 0x400) != 0;
    let has_composition = (flags & 0x800) != 0;

    let mut sample_sizes = Vec::new();

    for _ in 0..sample_count {
        if has_duration {
            take(4usize).void().parse_next(input)?;
        }
        if has_size {
            sample_sizes.push(be_u32.parse_next(input)?);
        }
        if has_flags {
            take(4usize).void().parse_next(input)?;
        }
        if has_composition {
            if version == 0 {
                take(4usize).void().parse_next(input)?;
            } else {
                take(4usize).void().parse_next(input)?; // signed in v1, but same size
            }
        }
    }

    Ok(TrunData {
        sample_sizes,
        data_offset,
    })
}

/// Parse tfhd box (Track Fragment Header Box)
fn parse_tfhd(input: &mut Partial<&[u8]>, flags: u32) -> ModalResult<u32> {
    // Track ID is always present
    let track_id = be_u32.parse_next(input)?;

    // Skip optional fields based on flags
    if (flags & 0x01) != 0 {
        // base-data-offset-present
        take(8usize).void().parse_next(input)?;
    }
    if (flags & 0x02) != 0 {
        // sample-description-index-present
        take(4usize).void().parse_next(input)?;
    }
    if (flags & 0x08) != 0 {
        // default-sample-duration-present
        take(4usize).void().parse_next(input)?;
    }
    if (flags & 0x10) != 0 {
        // default-sample-size-present
        take(4usize).void().parse_next(input)?;
    }
    if (flags & 0x20) != 0 {
        // default-sample-flags-present
        take(4usize).void().parse_next(input)?;
    }

    Ok(track_id)
}

/// Parse moov box and extract all track encryption info
///
/// Box hierarchy: moov → trak → mdia → minf → stbl → sinf → schi → tenc
/// Also need: moov → trak → mdia → minf → stbl → sinf → schm (for scheme type)
pub fn parse_moov(input: &[u8]) -> ModalResult<Vec<TrackMetadata>> {
    let size = u32::try_from(input.len() + 8).map_err(|_| ErrMode::Cut(ContextError::new()))?;
    let mut moov_bytes = Vec::with_capacity(input.len() + 8);
    moov_bytes.extend_from_slice(&size.to_be_bytes());
    moov_bytes.extend_from_slice(b"moov");
    moov_bytes.extend_from_slice(input);

    let (moov, _) = MoovBox::decode(&moov_bytes).map_err(|_| ErrMode::Cut(ContextError::new()))?;
    let track_map = jobs::get_track_map(&moov).map_err(|_| ErrMode::Cut(ContextError::new()))?;

    let mut tracks = Vec::new();
    for (track_id, infos) in track_map {
        if let Some(info) = infos.into_iter().flatten().find(|info| info.is_protected) {
            tracks.push(TrackMetadata {
                track_id,
                encryption_info: TrackEncryptionInfo {
                    is_protected: u8::from(info.is_protected),
                    iv_size: info.iv_size,
                    kid: info.kid,
                    scheme: info.scheme,
                    pattern: info.pattern,
                    constant_iv: info.constant_iv,
                },
            });
        }
    }

    Ok(tracks)
}

/// Parse moof box and extract fragment metadata
///
/// Box hierarchy: moof → traf → [tfhd, trun, senc/saiz/saio]
pub fn parse_moof(input: &[u8], track_metadata: &TrackMetadata) -> ModalResult<FragmentMetadata> {
    let mut remaining = Partial::new(input);
    let mut fragment: Option<FragmentMetadata> = None;

    // Find traf box
    while !remaining.is_empty() {
        let header = match box_header(&mut remaining) {
            Ok(h) => h,
            Err(_) => break,
        };

        if header.box_type == BoxType::Normal(*b"traf") {
            let payload_size = header.box_size.get() as usize - header.external_size();
            let traf_payload: &[u8] = take(payload_size).parse_next(&mut remaining)?;

            // Parse traf contents
            let mut traf_input = Partial::new(traf_payload);
            let mut track_id = 0u32;
            let mut trun_data = TrunData::default();
            let mut senc_entries: Option<Vec<SampleEncryptionEntry>> = None;

            while !traf_input.is_empty() {
                let inner_header = match box_header(&mut traf_input) {
                    Ok(h) => h,
                    Err(_) => break,
                };

                let payload_size =
                    inner_header.box_size.get() as usize - inner_header.external_size();
                let payload: &[u8] = take(payload_size).parse_next(&mut traf_input)?;

                if inner_header.box_type == BoxType::Normal(*b"tfhd") {
                    let mut tfhd_input = Partial::new(payload);
                    let tfhd_header = full_box_header(&mut tfhd_input)?;
                    track_id = parse_tfhd(&mut tfhd_input, tfhd_header.flags)?;
                } else if inner_header.box_type == BoxType::Normal(*b"trun") {
                    let mut trun_input = Partial::new(payload);
                    let trun_header = full_box_header(&mut trun_input)?;
                    trun_data =
                        parse_trun(&mut trun_input, trun_header.version, trun_header.flags)?;
                } else if inner_header.box_type == BoxType::Normal(*b"senc") {
                    let mut senc_input = Partial::new(payload);
                    let senc_header = full_box_header(&mut senc_input)?;
                    let sample_count = be_u32.parse_next(&mut senc_input)?;

                    senc_entries = Some(parse_senc_entries(
                        &mut senc_input,
                        sample_count,
                        track_metadata.encryption_info.iv_size,
                        senc_header.flags,
                    )?);
                }
                // Unknown boxes are skipped
            }

            // Validate we got all required data
            if track_id != 0 && let Some(sample_encryption) = senc_entries {
                fragment = Some(FragmentMetadata {
                    track_id,
                    sample_encryption,
                    sample_sizes: trun_data.sample_sizes,
                    data_offset: trun_data.data_offset.unwrap_or(0) as u64,
                });
                break;
            }
        } else {
            // Skip non-traf boxes
            let payload_size = header.box_size.get() as usize - header.external_size();
            take(payload_size).void().parse_next(&mut remaining)?;
        }
    }

    fragment.ok_or_else(|| ErrMode::Cut(ContextError::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tfhd() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // track_id = 1
        ];
        let mut input = Partial::new(&data[..]);
        let track_id = parse_tfhd(&mut input, 0).unwrap();

        assert_eq!(track_id, 1);
    }

    #[test]
    fn test_parse_trun() {
        let data = [
            0x00, 0x00, 0x00, 0x03, // sample_count = 3
            0x00, 0x00, 0x10, 0x00, // data_offset = 4096 (flags & 0x01)
            // Sample sizes (flags & 0x200)
            0x00, 0x00, 0x00, 0x64, // size 1 = 100
            0x00, 0x00, 0x00, 0xc8, // size 2 = 200
            0x00, 0x00, 0x01, 0x2c, // size 3 = 300
        ];
        let mut input = Partial::new(&data[..]);
        let trun = parse_trun(&mut input, 0, 0x01 | 0x200).unwrap();

        assert_eq!(trun.data_offset, Some(4096));
        assert_eq!(trun.sample_sizes, vec![100, 200, 300]);
    }
}
