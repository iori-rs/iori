//! Exercise nonfragmented encryption metadata through public parsing and decryption.
mod common;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use iori_cenc::{KeyMap, ParsedCenc};
use shiguredo_mp4::boxes::{MoovBox, StcoBox, StscEntry, StszBox, SttsEntry, UnknownBox};
use shiguredo_mp4::{Decode, Either, Encode};

fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut data = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    data.extend_from_slice(kind);
    data.extend_from_slice(payload);
    data
}
fn unknown(kind: &[u8; 4], payload: &[u8]) -> UnknownBox {
    UnknownBox::decode(&boxed(kind, payload)).unwrap().0
}
fn movie(clear: bool, per_sample: bool, extra: Vec<UnknownBox>) -> MoovBox {
    let fixture = include_bytes!("fixtures/fmp4/cbcs.mp4");
    let layout = common::find_top_level_box(fixture, b"moov").unwrap();
    let mut bytes = fixture[layout.start..layout.start + layout.size].to_vec();
    let tenc = bytes.windows(4).position(|w| w == b"tenc").unwrap();
    bytes[tenc + 10] = u8::from(!clear);
    bytes[tenc + 11] = if per_sample { 16 } else { 0 };
    bytes[tenc + 12..tenc + 28].fill(1);
    bytes[tenc + 29..tenc + 45].fill(7);
    let mut movie = MoovBox::decode(&bytes).unwrap().0;
    movie.mvex_box = None;
    movie.trak_boxes.truncate(1);
    let table = &mut movie.trak_boxes[0].mdia_box.minf_box.stbl_box;
    table.stts_box.entries = vec![SttsEntry {
        sample_count: 1,
        sample_delta: 1,
    }];
    table.stsc_box.entries = vec![StscEntry {
        first_chunk: 1.try_into().unwrap(),
        sample_per_chunk: 1,
        sample_description_index: 1.try_into().unwrap(),
    }];
    table.stsz_box = StszBox::Fixed {
        sample_size: 16.try_into().unwrap(),
        sample_count: 1,
    };
    table.stco_or_co64_box = Either::A(StcoBox {
        chunk_offsets: vec![8],
    });
    table.stss_box = None;
    table.ctts_box = None;
    table.unknown_boxes = extra;
    movie
}
fn group() -> UnknownBox {
    let mut payload = vec![2, 0, 0, 0];
    payload.extend_from_slice(b"seig");
    payload.extend_from_slice(&37u32.to_be_bytes());
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&1u32.to_be_bytes());
    payload.extend_from_slice(&[0, 0x19, 1, 0]);
    payload.extend_from_slice(&[9; 16]);
    payload.push(16);
    payload.extend_from_slice(&[7; 16]);
    unknown(b"sgpd", &payload)
}
fn check(movie: MoovBox, auxiliary: &[u8], kid: [u8; 16]) {
    let plain = [0x42; 16];
    let mut encrypted = GenericArray::clone_from_slice(&plain);
    for b in encrypted.iter_mut() {
        *b ^= 7;
    }
    Aes128::new(GenericArray::from_slice(&[3; 16])).encrypt_block(&mut encrypted);
    let mut payload = encrypted.to_vec();
    payload.extend_from_slice(auxiliary);
    let mut file = boxed(b"mdat", &payload);
    file.extend(movie.encode_to_vec().unwrap());
    let original = file.clone();
    let parsed = ParsedCenc::parse(&file).unwrap();
    assert_eq!(parsed.jobs.len(), 1);
    assert_eq!((parsed.jobs[0].offset, parsed.jobs[0].size), (8, 16));
    assert_eq!(parsed.jobs[0].kid, kid);
    let mut keys = KeyMap::new();
    keys.insert(kid, [3; 16]);
    parsed.decrypt_in_place(&mut file, &keys, 0).unwrap();
    assert_eq!(&file[8..24], &plain);
    assert_eq!(file.len(), original.len());
    assert_eq!(&file[24..24 + auxiliary.len()], auxiliary);
    assert_eq!(
        common::top_level_box_layout(&file),
        common::top_level_box_layout(&original)
    );
}
#[test]
fn constant_iv_defaults_need_no_senc_or_groups() {
    check(movie(false, false, vec![]), &[], [1; 16]);
}
#[test]
fn default_seig_activates_encryption_on_clear_track() {
    check(movie(true, false, vec![group()]), &[], [9; 16]);
}
#[test]
fn absolute_auxiliary_offset_supplies_per_sample_iv_without_senc() {
    let mut sizes = vec![0; 4];
    sizes.push(16);
    sizes.extend_from_slice(&1u32.to_be_bytes());
    let mut offsets = vec![0; 4];
    offsets.extend_from_slice(&1u32.to_be_bytes());
    offsets.extend_from_slice(&24u32.to_be_bytes());
    check(
        movie(
            false,
            true,
            vec![unknown(b"saiz", &sizes), unknown(b"saio", &offsets)],
        ),
        &[7; 16],
        [1; 16],
    );
}

#[test]
fn sample_tables_cannot_point_at_box_headers() {
    let mut moov = movie(false, false, vec![]);
    moov.trak_boxes[0]
        .mdia_box
        .minf_box
        .stbl_box
        .stco_or_co64_box = Either::A(StcoBox {
        chunk_offsets: vec![0],
    });
    let mut file = boxed(b"mdat", &[0; 16]);
    file.extend(moov.encode_to_vec().unwrap());
    assert!(matches!(
        ParsedCenc::parse(&file),
        Err(iori_cenc::CencError::OutOfBounds)
    ));
}
