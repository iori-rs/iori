mod common;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const VIDEO_KID: &str = "00112233445566778899aabbccddeeff";
const VIDEO_KEY: &str = "0123456789abcdef0123456789abcdef";
const AUDIO_KID: &str = "ffeeddccbbaa99887766554433221100";
const AUDIO_KEY: &str = "fedcba9876543210fedcba9876543210";

#[test]
#[ignore = "external fixture check; use tests/conformance/run.py for required three-decryptor coverage"]
fn generated_encryption_matrix_matches_bento4_oracles() {
    let matrix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("matrix")
        .join("generated");
    let manifest = matrix.join("manifest.tsv");
    assert!(manifest.exists(), "generated fixture manifest is required");

    let keys = HashMap::from([
        (VIDEO_KID.to_string(), VIDEO_KEY.to_string()),
        (AUDIO_KID.to_string(), AUDIO_KEY.to_string()),
    ]);
    let manifest = fs::read_to_string(manifest).unwrap();

    for line in manifest.lines().skip(1).filter(|line| !line.is_empty()) {
        let entry = MatrixEntry::parse(line);
        let encrypted = fs::read(matrix.join(entry.encrypted)).unwrap();
        let oracle = fs::read(matrix.join(entry.oracle)).unwrap();
        common::assert_bento4_decryption(
            &encrypted,
            &oracle,
            &keys,
            &format!("{} ({}, {})", entry.name, entry.kind, entry.method),
        );
    }
}

struct MatrixEntry<'a> {
    name: &'a str,
    kind: &'a str,
    method: &'a str,
    encrypted: &'a Path,
    oracle: &'a Path,
}

impl<'a> MatrixEntry<'a> {
    fn parse(line: &'a str) -> Self {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap();
        let kind = fields.next().unwrap();
        let method = fields.next().unwrap();
        let encrypted = Path::new(fields.next().unwrap());
        let oracle = Path::new(fields.next().unwrap());
        assert!(
            fields.next().is_none(),
            "unexpected manifest fields: {line}"
        );
        Self {
            name,
            kind,
            method,
            encrypted,
            oracle,
        }
    }
}
