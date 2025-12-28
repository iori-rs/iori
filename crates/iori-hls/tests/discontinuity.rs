use comparable::{Changed, assert_changes};

#[test]
fn test_accuracy_discontinuity() {
    let data = include_bytes!("./fixtures/discontinuity/playlist.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_changes!(old_result, new_result, Changed::Unchanged);

    let media_playlist = match new_result {
        iori_hls::Playlist::MediaPlaylist(media_playlist) => media_playlist,
        _ => panic!("Expected media playlist"),
    };
    assert_eq!(media_playlist.discontinuity_sequence, 5);

    let segments = media_playlist.segments;
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].part_index, 5);
    assert_eq!(segments[1].part_index, 6);
    assert_eq!(segments[2].part_index, 7);
}

#[test]
fn test_accuracy_discontinuity_02() {
    let data = include_bytes!("./fixtures/discontinuity/playlist2.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_changes!(old_result, new_result, Changed::Unchanged);
}

#[test]
fn test_accuracy_discontinuity_no_seq() {
    let data = include_bytes!("./fixtures/discontinuity/no_seq.m3u8");
    let old_result = iori_hls::m3u8_rs::parse_playlist_res(data);
    let new_result = iori_hls::parse::parse_playlist_res(data);

    let old_result = old_result.expect("Old parse engine should not error");
    let new_result = new_result.expect("New parse engine should not error");
    assert_changes!(old_result, new_result, Changed::Unchanged);

    let media_playlist = match new_result {
        iori_hls::Playlist::MediaPlaylist(media_playlist) => media_playlist,
        _ => panic!("Expected media playlist"),
    };
    assert_eq!(media_playlist.discontinuity_sequence, 0);

    let segments = media_playlist.segments;
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].part_index, 0);
    assert_eq!(segments[1].part_index, 1);
}
