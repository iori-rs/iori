mod common;

use common::{read_all_mdat_payloads, top_level_box_layout};
use iori_cenc::decrypt_mp4;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const VIDEO_KID: &str = "00112233445566778899aabbccddeeff";
const VIDEO_KEY: &str = "0123456789abcdef0123456789abcdef";
const AUDIO_KID: &str = "ffeeddccbbaa99887766554433221100";
const AUDIO_KEY: &str = "fedcba9876543210fedcba9876543210";

/// Compare `iori-cenc` CENC decryption with Shaka Packager raw-key decryption.
///
/// This test is intentionally optional: set `SHAKA_PACKAGER` to the `packager`
/// executable path to enable it. It consumes the generated Bento4 matrix
/// fixtures when they are present, then asks Shaka Packager to decrypt the same
/// single-track assets. The oracle comparison is the decrypted `mdat` payload,
/// because `iori-cenc` preserves the original file size and box layout while
/// Shaka Packager may rewrite metadata.
#[test]
fn generated_single_track_matrix_matches_shaka_packager_when_configured() {
    let Ok(packager) = env::var("SHAKA_PACKAGER") else {
        return;
    };

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
        if entry.kind == "audio-video" {
            continue;
        }

        let encrypted_path = matrix.join(entry.encrypted);
        let encrypted = fs::read(&encrypted_path).unwrap();
        let encrypted_layout = top_level_box_layout(&encrypted).unwrap();

        let shaka_output = temp_output_path("iori-cenc-shaka", "mp4");
        let status = Command::new(&packager)
            .arg(format!(
                "input={},stream={},output={}",
                encrypted_path.display(),
                entry.stream_name(),
                shaka_output.display()
            ))
            .arg("--enable_raw_key_decryption")
            .arg("--keys")
            .arg(format!(
                "label=:key_id={}:key={},label=:key_id={}:key={}",
                VIDEO_KID, VIDEO_KEY, AUDIO_KID, AUDIO_KEY
            ))
            .status()
            .unwrap_or_else(|err| panic!("failed to run {packager}: {err}"));
        assert!(
            status.success(),
            "Shaka Packager decryption failed for {} ({}, {}): {status}",
            entry.name,
            entry.kind,
            entry.method
        );

        let shaka = fs::read(&shaka_output).unwrap();
        let _ = fs::remove_file(&shaka_output);

        let mut iori = encrypted.clone();
        decrypt_mp4(&mut iori, &keys).unwrap();

        assert_eq!(
            encrypted.len(),
            iori.len(),
            "size changed for {} ({}, {})",
            entry.name,
            entry.kind,
            entry.method
        );
        assert_eq!(
            encrypted_layout,
            top_level_box_layout(&iori).unwrap(),
            "top-level layout changed for {} ({}, {})",
            entry.name,
            entry.kind,
            entry.method
        );
        assert_eq!(
            read_all_mdat_payloads(&shaka).unwrap(),
            read_all_mdat_payloads(&iori).unwrap(),
            "mdat payload mismatch for {} ({}, {})",
            entry.name,
            entry.kind,
            entry.method
        );
    }
}

struct MatrixEntry<'a> {
    name: &'a str,
    kind: &'a str,
    method: &'a str,
    encrypted: &'a Path,
}

impl<'a> MatrixEntry<'a> {
    fn parse(line: &'a str) -> Self {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap();
        let kind = fields.next().unwrap();
        let method = fields.next().unwrap();
        let encrypted = Path::new(fields.next().unwrap());
        let _oracle = fields.next().unwrap();
        assert!(
            fields.next().is_none(),
            "unexpected manifest fields: {line}"
        );
        Self {
            name,
            kind,
            method,
            encrypted,
        }
    }

    fn stream_name(&self) -> &'static str {
        match self.kind {
            "audio" => "audio",
            "video" => "video",
            other => panic!("unsupported Shaka differential fixture kind: {other}"),
        }
    }
}

fn temp_output_path(prefix: &str, extension: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!(
        "{prefix}-{}-{unique}.{extension}",
        std::process::id()
    ))
}
