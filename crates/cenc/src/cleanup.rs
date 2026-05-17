use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    BOX_MDIA, BOX_MINF, BOX_STBL, BOX_TRAK, EncryptedAudioSampleEntryBox,
    EncryptedVideoSampleEntryBox, OriginalFormatBox, ProtectionSchemeInfoBox, PsshBox, RawMp4Box,
    SaioBox, SaizBox, SampleEncryptionBox, SbgpBox, SgpdSeigBox,
};
use shiguredo_mp4::boxes::{
    Av01Box, Avc1Box, FlacBox, FreeBox, Hev1Box, Hvc1Box, MoofBox, MoovBox, Mp4aBox, OpusBox,
    StsdBox, TrafBox, Vp08Box, Vp09Box,
};
use shiguredo_mp4::{BoxType, Decode};

const VISUAL_SAMPLE_ENTRY_SIZE: usize = 78;
const AUDIO_SAMPLE_ENTRY_SIZE: usize = 28;

pub fn normalize_decrypted_fmp4(data: &mut [u8]) -> Result<()> {
    let top = match parse_boxes_range(data, 0, data.len()) {
        Ok(boxes) => boxes,
        Err(_) => return Ok(()),
    };
    for b in &top {
        if b.box_type == MoovBox::TYPE {
            normalize_moov(data, b)?;
        } else if b.box_type == MoofBox::TYPE {
            normalize_moof(data, b)?;
        }
    }
    Ok(())
}

fn normalize_moov(data: &mut [u8], moov: &RawMp4Box) -> Result<()> {
    let moov_children =
        parse_boxes_range(data, moov.start + moov.header_size, moov.start + moov.size)?;
    for child in &moov_children {
        if child.box_type == PsshBox::TYPE {
            // Zero out pssh from moov: hls.js collects moov-level pssh boxes and
            // uses them to trigger EME key session setup.
            free_box(data, child);
        } else if child.box_type == BOX_TRAK {
            normalize_trak(data, *child)?;
        }
    }
    Ok(())
}

fn normalize_moof(data: &mut [u8], moof: &RawMp4Box) -> Result<()> {
    let moof_children =
        parse_boxes_range(data, moof.start + moof.header_size, moof.start + moof.size)?;
    for child in &moof_children {
        if child.box_type == PsshBox::TYPE {
            // Zero out pssh: hls.js uses pssh presence to trigger EME key loading.
            free_box(data, child);
        } else if child.box_type == TrafBox::TYPE {
            normalize_traf(data, *child)?;
        }
    }
    Ok(())
}

fn normalize_traf(data: &mut [u8], traf: RawMp4Box) -> Result<()> {
    let traf_children =
        parse_boxes_range(data, traf.start + traf.header_size, traf.start + traf.size)?;
    for child in &traf_children {
        if child.box_type == SampleEncryptionBox::TYPE
            || child.box_type == SaizBox::TYPE
            || child.box_type == SaioBox::TYPE
            || child.box_type == SbgpBox::TYPE
            || child.box_type == SgpdSeigBox::TYPE
        {
            // Replace box type with 'free' and zero out payload (in-place).
            // senc/saiz/saio carry per-sample encryption info.
            // sbgp/sgpd seig signal sample-group encryption to media players.
            free_box(data, child);
        }
    }
    Ok(())
}

fn normalize_trak(data: &mut [u8], trak: RawMp4Box) -> Result<()> {
    let trak_children =
        parse_boxes_range(data, trak.start + trak.header_size, trak.start + trak.size)?;
    let Some(mdia) = find_box(&trak_children, BOX_MDIA) else {
        return Ok(());
    };
    let mdia_children =
        parse_boxes_range(data, mdia.start + mdia.header_size, mdia.start + mdia.size)?;
    let Some(minf) = find_box(&mdia_children, BOX_MINF) else {
        return Ok(());
    };
    let minf_children =
        parse_boxes_range(data, minf.start + minf.header_size, minf.start + minf.size)?;
    let Some(stbl) = find_box(&minf_children, BOX_STBL) else {
        return Ok(());
    };
    let stbl_children =
        parse_boxes_range(data, stbl.start + stbl.header_size, stbl.start + stbl.size)?;
    let Some(stsd) = find_box(&stbl_children, StsdBox::TYPE) else {
        return Ok(());
    };
    normalize_stsd(data, *stsd)
}

fn normalize_stsd(data: &mut [u8], stsd: RawMp4Box) -> Result<()> {
    let stsd_payload_start = stsd.start + stsd.header_size;
    let stsd_payload_end = stsd.start + stsd.size;
    if stsd_payload_end < stsd_payload_start + 8 {
        return Err(CencError::MetadataCleanup("stsd too short".to_string()));
    }
    let entry_count = read_u32(data, stsd_payload_start + 4)? as usize;
    let mut offset = stsd_payload_start + 8;
    for _ in 0..entry_count {
        let entry_size = read_u32(data, offset)? as usize;
        if entry_size < 8 || offset + entry_size > stsd_payload_end {
            return Err(CencError::MetadataCleanup(
                "invalid stsd entry size".to_string(),
            ));
        }
        let entry_type = read_box_type(data, offset + 4)?;
        let base_size = match entry_type {
            // Standard CENC encrypted wrappers
            EncryptedVideoSampleEntryBox::TYPE => VISUAL_SAMPLE_ENTRY_SIZE,
            EncryptedAudioSampleEntryBox::TYPE => AUDIO_SAMPLE_ENTRY_SIZE,
            // CMAF cbcs: original codec type used directly with sinf appended
            Avc1Box::TYPE
            | Hvc1Box::TYPE
            | Hev1Box::TYPE
            | Vp08Box::TYPE
            | Vp09Box::TYPE
            | Av01Box::TYPE => VISUAL_SAMPLE_ENTRY_SIZE,
            Mp4aBox::TYPE | OpusBox::TYPE | FlacBox::TYPE => AUDIO_SAMPLE_ENTRY_SIZE,
            _ => {
                offset += entry_size;
                continue;
            }
        };
        let entry_payload_start = offset + 8;
        let entry_payload_end = offset + entry_size;
        if entry_payload_start + base_size < entry_payload_end {
            normalize_sample_entry(data, entry_payload_start, entry_payload_end, base_size)?;
        }
        offset += entry_size;
    }
    Ok(())
}

fn normalize_sample_entry(
    data: &mut [u8],
    entry_payload_start: usize,
    entry_payload_end: usize,
    base_size: usize,
) -> Result<()> {
    let children_start = entry_payload_start + base_size;
    let children = parse_boxes_range(data, children_start, entry_payload_end)?;
    let Some(sinf) = find_box(&children, ProtectionSchemeInfoBox::TYPE) else {
        return Ok(());
    };

    // Rewrite the sample entry's box type to the original codec format from frma.
    // For CMAF cbcs (avc1 with sinf where frma.original_format == avc1) this is a
    // no-op but is still correct.
    let sinf_children =
        parse_boxes_range(data, sinf.start + sinf.header_size, sinf.start + sinf.size)?;
    if let Some(frma) = find_box(&sinf_children, OriginalFormatBox::TYPE)
        && frma.size >= frma.header_size + 4
    {
        let original_format = read_type(data, frma.start + frma.header_size)?;
        let entry_type_offset = entry_payload_start - 4;
        data[entry_type_offset..entry_type_offset + 4].copy_from_slice(&original_format);
    }

    // Zero out sinf in-place: replace box type with 'free' and zero the payload.
    // We cannot shrink the entry (in-place), so 'free' makes players skip the bytes.
    free_box(data, sinf);

    Ok(())
}

/// Replace a box's type with `free` and zero its payload in-place.
/// This keeps the file size unchanged while signaling to parsers that the bytes are free space.
fn free_box(data: &mut [u8], b: &RawMp4Box) {
    data[b.start + 4..b.start + 8].copy_from_slice(FreeBox::TYPE.as_bytes());
    let payload_start = b.start + b.header_size;
    let payload_end = b.start + b.size;
    data[payload_start..payload_end].fill(0);
}

fn parse_boxes_range(data: &[u8], start: usize, end: usize) -> Result<Vec<RawMp4Box>> {
    RawMp4Box::parse_range(data, start, end, 0)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))
}

fn find_box(boxes: &[RawMp4Box], typ: BoxType) -> Option<&RawMp4Box> {
    boxes.iter().find(|b| b.box_type == typ)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    decode_at(data, offset, "u32")
}

fn read_type(data: &[u8], offset: usize) -> Result<[u8; 4]> {
    decode_at(data, offset, "type")
}

fn read_box_type(data: &[u8], offset: usize) -> Result<BoxType> {
    Ok(BoxType::Normal(read_type(data, offset)?))
}

fn decode_at<T: Decode>(data: &[u8], offset: usize, name: &str) -> Result<T> {
    let mut offset = offset;
    T::decode_at(data, &mut offset)
        .map_err(|_| CencError::MetadataCleanup(format!("{name} out of bounds")))
}
