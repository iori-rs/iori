use iori::{
    HttpClient, StreamingSource,
    dash::{archive::CommonDashArchiveSource, live::CommonDashLiveSource},
};

use crate::{AssertWrapper, dash::setup_mock_server};

// SegmentTemplate + SegmentTimeline
#[tokio::test]
async fn test_lemino_sokosaku_235() -> anyhow::Result<()> {
    let data = include_str!("../fixtures/dash/static/lemino-sokosaku-235.mpd");
    let (playlist_uri, server) = setup_mock_server(data).await;

    let client = HttpClient::default();
    let playlist = CommonDashLiveSource::new(client.clone(), playlist_uri.parse()?, None)?;

    let mut info = playlist.fetch_info().await?;

    let segments_live = info.recv().await.assert_success()?;
    assert_eq!(segments_live.len(), 506);
    // no further segments
    info.recv().await.assert_error();

    let playlist = CommonDashArchiveSource::new(client, playlist_uri.parse()?, None, None)?;
    let mut info = playlist.fetch_info().await?;

    let mut segments_archive = Vec::new();
    let segments = info.recv().await.assert_success()?;
    assert_eq!(segments.len(), 253);
    segments_archive.extend(segments);
    let segments = info.recv().await.assert_success()?;
    assert_eq!(segments.len(), 253);
    segments_archive.extend(segments);
    // no further segments
    info.recv().await.assert_error();

    for (i, segment) in segments_archive.iter().enumerate() {
        assert_eq!(segment.url, segments_live[i].url);
        assert_eq!(segment.initial_segment, segments_live[i].initial_segment);
        assert_eq!(segment.byte_range, segments_live[i].byte_range);
    }

    let mut i = 0;
    let mut time: i64 = 0;
    let video_bandwidth = 5329413;
    let timeline: [[i64; 2]; 4] = [
        [60060000, 165 + 1],
        [50050000, 1],
        [60060000, 84 + 1],
        [24691333, 1],
    ];

    for [duration, count] in timeline {
        for _ in 0..count {
            let live_segment = &segments_live[i];
            assert_eq!(
                (i, live_segment.url.as_str()),
                (
                    i,
                    format!("{}/video_{video_bandwidth}/{time}.m4s", server.uri()).as_str()
                )
            );
            time += duration;
            i += 1;
        }
    }

    time = 0;
    let audio_bandwidth = 102993;
    let timeline = [
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [49920000, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 2],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946667, 1],
        [60160000, 1],
        [59946666, 1],
        [60160000, 1],
        [59946667, 1],
        [24746667, 1],
    ];
    for [duration, count] in timeline {
        for _ in 0..count {
            let live_segment = &segments_live[i];
            assert_eq!(
                (i, live_segment.url.as_str()),
                (
                    i,
                    format!("{}/audio_{audio_bandwidth}/{time}.m4s", server.uri()).as_str()
                )
            );
            time += duration;
            i += 1;
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_h46() -> anyhow::Result<()> {
    let data = include_str!("../fixtures/dash/static/h46.mpd");
    let (playlist_uri, _server) = setup_mock_server(data).await;

    let client = HttpClient::default();
    let playlist = CommonDashLiveSource::new(client.clone(), playlist_uri.parse()?, None)?;

    let mut info = playlist.fetch_info().await?;

    let segments_live = info.recv().await.assert_success()?;
    assert_eq!(segments_live.len(), 506);
    // no further segments
    info.recv().await.assert_error();

    let playlist = CommonDashArchiveSource::new(client, playlist_uri.parse()?, None, None)?;
    let mut info = playlist.fetch_info().await?;

    let mut segments_archive = Vec::new();
    let segments = info.recv().await.assert_success()?;
    assert_eq!(segments.len(), 253);
    segments_archive.extend(segments);
    let segments = info.recv().await.assert_success()?;
    assert_eq!(segments.len(), 253);
    segments_archive.extend(segments);
    // no further segments
    info.recv().await.assert_error();

    Ok(())
}
