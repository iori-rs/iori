mod common;

use common::read_mdat_payload;
use iori_cenc::decrypt_mp4;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const KID_HEX: &str = "00112233445566778899aabbccddeeff";
const KEY_HEX: &str = "0123456789abcdef0123456789abcdef";

/// Compare `iori-cenc` CENC decryption with Bento4 `mp4decrypt`.
///
/// This test is intentionally optional: set `BENTO4_MP4DECRYPT` to the
/// `mp4decrypt` executable path to enable it. The oracle comparison is the
/// decrypted `mdat` payload, not the whole file, because `iori-cenc` preserves
/// the original file size and box layout while Bento4 may rewrite metadata.
#[test]
fn cenc_mdat_matches_bento4_mp4decrypt_when_configured() {
    let Ok(mp4decrypt) = env::var("BENTO4_MP4DECRYPT") else {
        return;
    };

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fmp4");
    let encrypted_path = base.join("cenc.mp4");

    let bento_output = temp_output_path("iori-cenc-bento4-cenc", "mp4");
    let status = Command::new(&mp4decrypt)
        .arg("--key")
        .arg(format!("{KID_HEX}:{KEY_HEX}"))
        .arg(&encrypted_path)
        .arg(&bento_output)
        .status()
        .unwrap_or_else(|err| panic!("failed to run {mp4decrypt}: {err}"));
    assert!(status.success(), "Bento4 mp4decrypt failed: {status}");

    let bento = fs::read(&bento_output).unwrap();
    let _ = fs::remove_file(&bento_output);

    let keys = HashMap::from([(KID_HEX.to_string(), KEY_HEX.to_string())]);
    let mut iori = fs::read(encrypted_path).unwrap();
    decrypt_mp4(&mut iori, &keys).unwrap();

    assert_eq!(
        read_mdat_payload(&bento).unwrap(),
        read_mdat_payload(&iori).unwrap()
    );
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
