use crate::{M3u8ParseError, models::*};
use quick_m3u8::{
    HlsLine, Reader,
    config::ParsingOptionsBuilder,
    tag::{KnownTag, hls},
};

pub fn parse_playlist_res(input: &[u8]) -> Result<Playlist, M3u8ParseError> {
    let options = ParsingOptionsBuilder::new()
        .with_parsing_for_all_tags()
        .build();
    let mut reader = Reader::from_bytes(input, options);

    let mut is_master = false;

    // <FOR MASTER PLAYLIST>
    let mut variants = Vec::new();
    let mut alternatives = Vec::new();

    // <FOR MEDIA PLAYLIST>
    // [RFC8216 Section 4.3.3.2](https://datatracker.ietf.org/doc/html/rfc8216#section-4.3.3.2)
    // > If the Media Playlist file does not contain an EXT-X-MEDIA-SEQUENCE
    // > tag, then the Media Sequence Number of the first Media Segment in the
    // > Media Playlist SHALL be considered to be 0.
    let mut media_sequence = 0;
    // [RFC8216 Section 4.3.3.3](https://datatracker.ietf.org/doc/html/rfc8216#section-4.3.3.3)
    // > If the Media Playlist does not contain an EXT-X-DISCONTINUITY-
    // > SEQUENCE tag, then the Discontinuity Sequence Number of the first
    // > Media Segment in the Playlist SHALL be considered to be 0.
    let mut discontinuity_sequence = 0;
    let mut segments: Vec<MediaSegment> = Vec::new();
    let mut end_list = false;

    // Maps(initial segment information) and keys(encryption information)
    let mut current_key: Option<Key> = None;
    let mut current_map: Option<Map> = None;
    let mut current_part_index = 0;

    // Pending tags, which should be cleared after the URI line is processed
    let mut pending_inf: Option<hls::Inf> = None;
    let mut pending_byterange: Option<ByteRange> = None;
    let mut pending_stream_inf: Option<hls::StreamInf> = None;

    while let Some(line) = reader.read_line()? {
        match line {
            HlsLine::KnownTag(KnownTag::Hls(tag)) => match tag {
                hls::Tag::MediaSequence(seq) => media_sequence = seq.media_sequence(),
                hls::Tag::DiscontinuitySequence(seq) => {
                    discontinuity_sequence = seq.discontinuity_sequence();
                    current_part_index = discontinuity_sequence;
                }
                hls::Tag::Discontinuity(_) => {
                    current_part_index += 1;
                }
                hls::Tag::Inf(inf) => pending_inf = Some(inf),
                hls::Tag::Byterange(range) => pending_byterange = Some(range.into()),
                hls::Tag::Key(key) => current_key = Some(key.into()),
                hls::Tag::Map(map) => {
                    current_map = Some((map, &current_key).into());
                }
                hls::Tag::StreamInf(info) => {
                    is_master = true;
                    pending_stream_inf = Some(info);
                }
                hls::Tag::Media(media) => {
                    is_master = true;
                    alternatives.push(media.into());
                }
                hls::Tag::Endlist(_) => end_list = true,
                _ => {}
            },
            HlsLine::Uri(uri) => {
                if let Some(info) = pending_stream_inf.take() {
                    variants.push((info, uri).into());
                } else if let Some(inf) = pending_inf.take() {
                    segments.push(
                        (
                            inf,
                            uri,
                            pending_byterange.take(),
                            current_key.clone(),
                            current_map.clone(),
                            current_part_index,
                        )
                            .into(),
                    );
                }

                pending_inf = None;
                pending_byterange = None;
                current_key = None;
            }
            _ => {}
        }
    }

    Ok(if is_master {
        Playlist::MasterPlaylist(MasterPlaylist {
            variants,
            alternatives,
        })
    } else {
        Playlist::MediaPlaylist(MediaPlaylist {
            media_sequence,
            discontinuity_sequence,
            segments,
            end_list,
        })
    })
}
