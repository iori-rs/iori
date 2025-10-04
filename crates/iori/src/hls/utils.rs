use m3u8_rs::{MediaPlaylist, Playlist};
use reqwest::{Client, Url};

use crate::{
    error::{IoriError, IoriResult},
    util::http::HttpClient,
};

pub async fn load_playlist_with_retry(
    client: &Client,
    url: &Url,
    total_retry: u32,
) -> IoriResult<Playlist> {
    let mut retry = total_retry;
    let m3u8_parsed = loop {
        if retry == 0 {
            return Err(IoriError::ManifestFetchError);
        }

        match client.get(url.clone()).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(m3u8_bytes) => match m3u8_rs::parse_playlist_res(&m3u8_bytes) {
                    Ok(parsed) => break parsed,
                    Err(error) => {
                        tracing::warn!("Failed to parse M3U8 file: {error}");
                        retry -= 1;
                    }
                },
                Err(error) => {
                    tracing::warn!("Failed to fetch M3U8 file: {error}");
                    retry -= 1;
                }
            },
            Err(error) => {
                tracing::warn!("Failed to fetch M3U8 file: {error}");
                retry -= 1;
            }
        }
    };

    Ok(m3u8_parsed)
}

#[async_recursion::async_recursion]
pub async fn load_m3u8(
    client: &HttpClient,
    url: Url,
    total_retry: u32,
) -> IoriResult<(Url, MediaPlaylist)> {
    tracing::info!("Start fetching M3U8 file.");

    let mut retry = total_retry;
    let m3u8_parsed = loop {
        if retry == 0 {
            return Err(IoriError::ManifestFetchError);
        }

        match client.get(url.clone()).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(m3u8_bytes) => match m3u8_rs::parse_playlist_res(&m3u8_bytes) {
                    Ok(parsed) => break parsed,
                    Err(error) => {
                        tracing::warn!("Failed to parse M3U8 file: {error}");
                        retry -= 1;
                    }
                },
                Err(error) => {
                    tracing::warn!("Failed to fetch M3U8 file: {error}");
                    retry -= 1;
                }
            },
            Err(error) => {
                tracing::warn!("Failed to fetch M3U8 file: {error}");
                retry -= 1;
            }
        }
    };
    tracing::info!("M3U8 file fetched.");

    match m3u8_parsed {
        Playlist::MasterPlaylist(pl) => {
            tracing::info!("Master playlist input detected. Auto selecting best quality streams.");
            let mut variants = pl.variants;
            variants.sort_by(|a, b| {
                // compare resolution first
                if let (Some(a), Some(b)) = (a.resolution, b.resolution)
                    && a.width != b.width
                {
                    return b.width.cmp(&a.width);
                }

                // compare framerate then
                if let (Some(a), Some(b)) = (a.frame_rate, b.frame_rate) {
                    let a = a as u64;
                    let b = b as u64;
                    if a != b {
                        return b.cmp(&a);
                    }
                }

                // compare bandwidth finally
                b.bandwidth.cmp(&a.bandwidth)
            });
            let variant = variants.first().expect("No variant found");
            let url = url.join(&variant.uri).expect("Invalid variant uri");

            tracing::info!(
                "Best stream: {url}; Bandwidth: {bandwidth}",
                bandwidth = variant.bandwidth
            );
            load_m3u8(client, url, total_retry).await
        }
        Playlist::MediaPlaylist(pl) => Ok((url, pl)),
    }
}
