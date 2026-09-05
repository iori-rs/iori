mod common;
use common::read_mdat_payload;
use iori_cenc::decrypt_mp4;
use std::collections::{HashMap, HashSet};

#[test]
fn decrypt_bbb_fixtures_with_zero_key() {
    let zero_key = "00000000000000000000000000000000".to_string();

    let fixtures = [
        (
            "bbb_144p_h264_enc.mp4",
            include_bytes!("fixtures/bbb/bbb_144p_h264_enc.mp4").as_slice(),
        ),
        (
            "bbb_144p_h265_enc.mp4",
            include_bytes!("fixtures/bbb/bbb_144p_h265_enc.mp4").as_slice(),
        ),
    ];

    for (name, encrypted) in fixtures {
        let parsed = iori_cenc::ParsedCenc::parse(encrypted).unwrap();
        let kids: HashSet<[u8; 16]> = parsed.jobs.iter().map(|job| job.kid).collect();
        let keys = kids
            .into_iter()
            .map(|kid| (hex::encode(kid), zero_key.clone()))
            .collect::<HashMap<_, _>>();
        let mut decrypted = encrypted.to_vec();
        decrypt_mp4(&mut decrypted, &keys).unwrap();
        let encrypted_mdat = read_mdat_payload(encrypted).unwrap();
        let decrypted_mdat = read_mdat_payload(&decrypted).unwrap();
        assert_ne!(encrypted_mdat, decrypted_mdat, "mdat unchanged for {name}");
    }
}
