mod common;

use common::{read_all_mdat_payloads, top_level_box_layout};
use iori_cenc::decrypt_mp4;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const VIDEO_KID: &str = "00112233445566778899aabbccddeeff";
const VIDEO_KEY: &str = "0123456789abcdef0123456789abcdef";
const AUDIO_KID: &str = "ffeeddccbbaa99887766554433221100";
const AUDIO_KEY: &str = "fedcba9876543210fedcba9876543210";

#[test]
fn generated_cenc_matrix_matches_bento4_oracles() {
    let matrix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("matrix")
        .join("generated");
    let manifest = matrix.join("manifest.tsv");
    if !manifest.exists() {
        return;
    }

    let keys = HashMap::from([
        (VIDEO_KID.to_string(), VIDEO_KEY.to_string()),
        (AUDIO_KID.to_string(), AUDIO_KEY.to_string()),
    ]);
    let manifest = fs::read_to_string(manifest).unwrap();

    for line in manifest.lines().skip(1).filter(|line| !line.is_empty()) {
        let entry = MatrixEntry::parse(line);
        let encrypted = fs::read(matrix.join(entry.encrypted)).unwrap();
        let oracle = fs::read(matrix.join(entry.oracle)).unwrap();
        let encrypted_layout = top_level_box_layout(&encrypted).unwrap();

        let mut decrypted = encrypted.clone();
        decrypt_mp4(&mut decrypted, &keys).unwrap();

        assert_eq!(
            encrypted.len(),
            decrypted.len(),
            "size changed for {} ({})",
            entry.name,
            entry.kind
        );
        assert_eq!(
            encrypted_layout,
            top_level_box_layout(&decrypted).unwrap(),
            "top-level layout changed for {} ({})",
            entry.name,
            entry.kind
        );
        assert_eq!(
            read_all_mdat_payloads(&oracle).unwrap(),
            read_all_mdat_payloads(&decrypted).unwrap(),
            "mdat payload mismatch for {} ({})",
            entry.name,
            entry.kind
        );
    }
}

struct MatrixEntry<'a> {
    name: &'a str,
    kind: &'a str,
    encrypted: &'a Path,
    oracle: &'a Path,
}

impl<'a> MatrixEntry<'a> {
    fn parse(line: &'a str) -> Self {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap();
        let kind = fields.next().unwrap();
        let encrypted = Path::new(fields.next().unwrap());
        let oracle = Path::new(fields.next().unwrap());
        assert!(
            fields.next().is_none(),
            "unexpected manifest fields: {line}"
        );
        Self {
            name,
            kind,
            encrypted,
            oracle,
        }
    }
}
