use std::path::PathBuf;

use reqwest::header::RANGE;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    InitialSegment, RemoteStreamingSegment, StreamingSegment, ToSegmentData,
    error::{IoriError, IoriResult},
    util::http::HttpClient,
};

pub async fn fetch_segment<S, W>(
    client: HttpClient,
    segment: &S,
    tmp_file: &mut W,
    shaka_packager_command: Option<PathBuf>,
) -> IoriResult<()>
where
    S: StreamingSegment + ToSegmentData,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    let bytes = segment.to_segment_data(client).await?;

    // TODO: use bytes_stream to improve performance
    // .bytes_stream();
    let decryptor = segment
        .key()
        .map(|key| key.to_decryptor(segment.format(), shaka_packager_command));
    if let Some(decryptor) = decryptor {
        let decrypted_bytes = match segment.initial_segment() {
            crate::InitialSegment::Encrypted(data) => {
                let mut result = data.to_vec();
                result.extend_from_slice(&bytes);
                decryptor.decrypt(&result).await?
            }
            crate::InitialSegment::Clear(data) => {
                tmp_file.write_all(&data).await?;
                decryptor.decrypt(&bytes).await?
            }
            crate::InitialSegment::None => decryptor.decrypt(&bytes).await?,
        };
        tmp_file.write_all(&decrypted_bytes).await?;
    } else {
        // If no key is provided, no matter whether the initial segment is encrypted or not,
        // we should write the initial segment to the file.
        if let InitialSegment::Clear(initial_segment) | InitialSegment::Encrypted(initial_segment) =
            segment.initial_segment()
        {
            tmp_file.write_all(&initial_segment).await?;
        }
        tmp_file.write_all(&bytes).await?;
    }
    tmp_file.flush().await?;

    Ok(())
}

impl<T> ToSegmentData for T
where
    T: RemoteStreamingSegment,
{
    fn to_segment_data(
        &self,
        client: HttpClient,
    ) -> impl Future<Output = IoriResult<bytes::Bytes>> + Send {
        let url = self.url();
        let byte_range = self.byte_range();
        let headers = self.headers();
        async move {
            let mut request = client.get(url);
            if let Some(headers) = headers {
                request = request.headers(headers);
            }
            if let Some(byte_range) = byte_range {
                request = request.header(RANGE, byte_range.to_http_range());
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                let status = response.status();
                if let Ok(body) = response.text().await {
                    tracing::warn!("Error body: {body}");
                }
                return Err(IoriError::HttpError(status));
            }

            let bytes = response.bytes().await?;
            Ok(bytes)
        }
    }
}
