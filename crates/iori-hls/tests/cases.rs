use comparable::{Changed, assert_changes};

#[test]
fn test_accuracy_radiko_01() {
    let data = include_bytes!("./fixtures/radiko_01.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_eq!(old_result, new_result);
}

#[test]
fn test_accuracy_archive_01() {
    let data = include_bytes!("./fixtures/archive_01.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_changes!(old_result, new_result, Changed::Unchanged);
}

#[test]
fn test_accuracy_archive_03() {
    let data = include_bytes!("./fixtures/archive_03.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_changes!(old_result, new_result, Changed::Unchanged);
}
