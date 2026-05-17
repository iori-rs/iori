use crate::errors::{CencError, Result};
use crate::jobs::boxes::{
    OriginalFormatBox, ProtectionSchemeInfoBox, PsshBox, RawMp4Box, SampleDescriptionBoxHeader,
    find_raw_box, is_fragment_encryption_metadata_box, protected_sample_entry_base_size,
};
use shiguredo_mp4::boxes::{
    FreeBox, MdiaBox, MinfBox, MoofBox, MoovBox, StblBox, StsdBox, TrafBox, TrakBox,
};

pub fn normalize_decrypted_fmp4(data: &mut [u8]) -> Result<()> {
    let top = match RawMp4Box::parse_all(data, 0) {
        Ok(boxes) => boxes,
        Err(_) => return Ok(()),
    };
    for b in &top {
        if b.is_type(MoovBox::TYPE) {
            normalize_moov(data, b)?;
        } else if b.is_type(MoofBox::TYPE) {
            normalize_moof(data, b)?;
        }
    }
    Ok(())
}

fn normalize_moov(data: &mut [u8], moov: &RawMp4Box) -> Result<()> {
    let moov_children = moov
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    for child in &moov_children {
        if child.is_type(PsshBox::TYPE) {
            // Zero out pssh from moov: hls.js collects moov-level pssh boxes and
            // uses them to trigger EME key session setup.
            free_box(data, child);
        } else if child.is_type(TrakBox::TYPE) {
            normalize_trak(data, *child)?;
        }
    }
    Ok(())
}

fn normalize_moof(data: &mut [u8], moof: &RawMp4Box) -> Result<()> {
    let moof_children = moof
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    for child in &moof_children {
        if child.is_type(PsshBox::TYPE) {
            // Zero out pssh: hls.js uses pssh presence to trigger EME key loading.
            free_box(data, child);
        } else if child.is_type(TrafBox::TYPE) {
            normalize_traf(data, *child)?;
        }
    }
    Ok(())
}

fn normalize_traf(data: &mut [u8], traf: RawMp4Box) -> Result<()> {
    let traf_children = traf
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    for child in &traf_children {
        if is_fragment_encryption_metadata_box(child.box_type) {
            // Replace box type with 'free' and zero out payload (in-place).
            // senc/saiz/saio carry per-sample encryption info.
            // sbgp/sgpd seig signal sample-group encryption to media players.
            free_box(data, child);
        }
    }
    Ok(())
}

fn normalize_trak(data: &mut [u8], trak: RawMp4Box) -> Result<()> {
    let trak_children = trak
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let Some(mdia) = find_raw_box(&trak_children, MdiaBox::TYPE) else {
        return Ok(());
    };
    let mdia_children = mdia
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let Some(minf) = find_raw_box(&mdia_children, MinfBox::TYPE) else {
        return Ok(());
    };
    let minf_children = minf
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let Some(stbl) = find_raw_box(&minf_children, StblBox::TYPE) else {
        return Ok(());
    };
    let stbl_children = stbl
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let Some(stsd) = find_raw_box(&stbl_children, StsdBox::TYPE) else {
        return Ok(());
    };
    normalize_stsd(data, *stsd)
}

fn normalize_stsd(data: &mut [u8], stsd: RawMp4Box) -> Result<()> {
    let stsd_payload_start = stsd.payload_start();
    let stsd_payload_end = stsd.end();
    if stsd_payload_end < stsd_payload_start + 8 {
        return Err(CencError::MetadataCleanup("stsd too short".to_string()));
    }
    let stsd_header = SampleDescriptionBoxHeader::decode_payload(stsd.payload(data))
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let entry_count = stsd_header.entry_count as usize;
    let entries = RawMp4Box::parse_n_range(
        data,
        stsd_payload_start + 8,
        stsd_payload_end,
        0,
        entry_count,
    )
    .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    if entries.len() != entry_count {
        return Err(CencError::MetadataCleanup(
            "stsd entry count exceeds payload".to_string(),
        ));
    }
    for entry in entries {
        let Some(base_size) = protected_sample_entry_base_size(entry.box_type) else {
            continue;
        };
        let entry_payload_start = entry.payload_start();
        let entry_payload_end = entry.end();
        if entry_payload_start + base_size < entry_payload_end {
            normalize_sample_entry(data, entry, base_size)?;
        }
    }
    Ok(())
}

fn normalize_sample_entry(data: &mut [u8], entry: RawMp4Box, base_size: usize) -> Result<()> {
    let children = entry
        .parse_payload_children_from(data, base_size)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    let Some(sinf) = find_raw_box(&children, ProtectionSchemeInfoBox::TYPE) else {
        return Ok(());
    };

    // Rewrite the sample entry's box type to the original codec format from frma.
    // For CMAF cbcs (avc1 with sinf where frma.original_format == avc1) this is a
    // no-op but is still correct.
    let sinf_children = sinf
        .parse_children(data)
        .map_err(|err| CencError::MetadataCleanup(err.to_string()))?;
    if let Some(frma) = find_raw_box(&sinf_children, OriginalFormatBox::TYPE)
        && frma.size >= frma.header_size + 4
    {
        let original_format =
            OriginalFormatBox::decode_payload(frma.payload(data))?.original_format;
        entry.write_type(data, original_format);
    }

    // Zero out sinf in-place: replace box type with 'free' and zero the payload.
    // We cannot shrink the entry (in-place), so 'free' makes players skip the bytes.
    free_box(data, sinf);

    Ok(())
}

/// Replace a box's type with `free` and zero its payload in-place.
/// This keeps the file size unchanged while signaling to parsers that the bytes are free space.
fn free_box(data: &mut [u8], b: &RawMp4Box) {
    b.write_type(data, FreeBox::TYPE);
    b.clear_payload(data);
}
