mod constant;
mod error;
pub use error::*;

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use memchr::memmem;
use mpeg2ts::es::StreamType;
use mpeg2ts::pes::PesHeader;
use mpeg2ts::ts::{
    ContinuityCounter, ReadTsPacket, TransportScramblingControl, TsHeader, TsPacket,
    TsPacketReader, TsPacketWriter, TsPayload, WriteTsPacket,
    payload::{Bytes, Pes},
};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

pub struct NALUnit {
    data: Vec<u8>,
    pub r#type: u8,
    length: usize,
    start_code_length: u8,
}

impl NALUnit {
    pub fn get_next(input: &[u8]) -> Result<(Self, &[u8])> {
        let start_code_length = if input.len() > 4 && &input[0..4] == b"\x00\x00\x00\x01" {
            4
        } else if input.len() > 3 && &input[0..3] == b"\x00\x00\x01" {
            3
        } else {
            return Err(Error::InvalidStartCode);
        };

        let next = &input[start_code_length..];
        let next_pos = if let Some(pos) = memmem::find(next, b"\x00\x00\x01") {
            // check pos - 1 for 0x00
            if pos > 0 && next[pos - 1] == 0x00 {
                start_code_length + pos - 1
            } else {
                start_code_length + pos
            }
        } else {
            input.len()
        };
        let next = &input[next_pos..];

        let data = input[start_code_length..next_pos].to_vec();
        Ok((
            Self {
                r#type: data[0] & 0x1f,
                data,
                length: next_pos - start_code_length,
                start_code_length: start_code_length as u8,
            },
            next,
        ))
    }

    fn remove_scep_3_bytes(&mut self) {
        let mut i = 0;
        let mut j = 0;

        while i < self.length {
            if self.length - i > 3 && self.data[i..i + 3] == [0x00, 0x00, 0x03] {
                self.data[j] = 0x00;
                self.data[j + 1] = 0x00;
                i += 3;
                j += 2;
            } else {
                self.data[j] = self.data[i];
                i += 1;
                j += 1;
            }
        }

        self.data.truncate(j);
        self.length = j;
    }

    /// Encrypted_nal_unit () {
    ///     nal_unit_type_byte                // 1 byte
    ///     unencrypted_leader                // 31 bytes
    ///     while (bytes_remaining() > 0) {
    ///         if (bytes_remaining() > 16) {
    ///             encrypted_block           // 16 bytes
    ///         }
    ///         unencrypted_block           // MIN(144, bytes_remaining()) bytes
    ///     }
    /// }
    pub fn decrypt(&mut self, key: &[u8; 16], iv: &[u8; 16]) {
        if self.data.len() <= 48 {
            return;
        }

        self.remove_scep_3_bytes();

        let mut decryptor = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());

        if self.data.len() < 32 {
            return;
        }

        let mut pos = &mut self.data.as_mut_slice()[32..];

        while !pos.is_empty() {
            if pos.len() > 16 {
                let block = &mut pos[..16];
                decryptor.decrypt_block_mut(block.into());
                pos = &mut pos[16..];
            }

            let remaining_len = pos.len();
            pos = &mut pos[144.min(remaining_len)..];
        }
    }

    pub fn write<W: Write>(&self, output: &mut W) -> Result<()> {
        if self.start_code_length == 4 {
            output.write_all(&[0x00, 0x00, 0x00, 0x01])?;
        } else {
            output.write_all(&[0x00, 0x00, 0x01])?;
        }
        output.write_all(&self.data)?;

        Ok(())
    }
}

struct AdtsHeader {
    length: usize,
    crc: bool,
}

impl AdtsHeader {
    fn new(data: &[u8]) -> Self {
        Self {
            length: Self::read_adts_frame_length(data),
            // Protection absence, set to 1 if there is no CRC and 0 if there is CRC.
            crc: data[1] & 0x01 == 0,
        }
    }

    fn data<'a>(&self, input: &'a mut [u8]) -> &'a mut [u8] {
        &mut input[if self.crc { 9 } else { 7 }..self.length]
    }

    fn read_adts_frame_length(header: &[u8]) -> usize {
        // 2
        let byte3 = header[3] as u16;
        // 8
        let byte4 = header[4] as u16;
        // 3
        let byte5 = header[5] as u16;

        // Extract and combine bits
        let length = ((byte3 & 0b11) << 11) | (byte4 << 3) | (byte5 >> 5);
        length as usize
    }
}

struct Ac3Header {
    length: usize,
}

impl Ac3Header {
    fn new(data: &[u8]) -> Self {
        Self {
            length: Self::read_ac3_frame_length(data),
        }
    }

    fn data<'a>(&self, input: &'a mut [u8]) -> &'a mut [u8] {
        &mut input[..self.length]
    }

    fn read_ac3_frame_length(header: &[u8]) -> usize {
        let fscod = (header[4] >> 6) as usize;
        let frmsizcod = (header[4] & 0b111111) as usize;
        // the number of (2-byte) words before the next syncword
        let frame_size = constant::AC3_FRAME_SIZE_CODE_TABLE[frmsizcod][fscod];
        frame_size * 2
    }
}

struct Eac3Header {
    length: usize,
}

impl Eac3Header {
    fn new(data: &[u8]) -> Self {
        Self {
            length: Self::read_eac3_frame_length(data),
        }
    }

    fn data<'a>(&self, input: &'a mut [u8]) -> &'a mut [u8] {
        &mut input[..self.length]
    }

    fn read_eac3_frame_length(header: &[u8]) -> usize {
        let frame_size =
            1 + ((((header[2] as usize) << 8) | header[3] as usize) & 0b0000011111111111);
        frame_size * 2
    }
}

/// Encrypted_AAC_Frame () {
///     ADTS_Header                        // 7 or 9 bytes
///     unencrypted_leader                 // 16 bytes
///     while (bytes_remaining() >= 16) {
///         encrypted_block                // 16 bytes
///     }
///     unencrypted_trailer                // 0-15 bytes
/// }
fn decrypt_aac_frame(input: &mut [u8], key: [u8; 16], iv: [u8; 16]) -> usize {
    let adts = AdtsHeader::new(input);
    let data = adts.data(input);

    decrypt_raw_sample(data, key, iv);
    adts.length
}

/// Encrypted_AC3_Frame () {
///     unencrypted_leader                 // 16 bytes
///     while (bytes_remaining() >= 16) {
///         encrypted_block                // 16 bytes
///     }
///     unencrypted_trailer                // 0-15 bytes
/// }
fn decrypt_ac3_frame(input: &mut [u8], key: [u8; 16], iv: [u8; 16]) -> usize {
    let ac3 = Ac3Header::new(input);
    let data = ac3.data(input);

    decrypt_raw_sample(data, key, iv);
    ac3.length
}

/// Encrypted_Enhanced_AC3_syncframe () {
///     unencrypted_leader                 // 16 bytes
///     while (bytes_remaining() >= 16) {
///         encrypted_block                // 16 bytes
///     }
///     unencrypted_trailer                // 0-15 bytes
/// }
fn decrypt_eac3_frame(input: &mut [u8], key: [u8; 16], iv: [u8; 16]) -> usize {
    let eac3 = Eac3Header::new(input);
    let data = eac3.data(input);

    decrypt_raw_sample(data, key, iv);
    eac3.length
}

fn decrypt_raw_sample(input: &mut [u8], key: [u8; 16], iv: [u8; 16]) {
    let mut decryptor = cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into());

    let mut is_first = true;
    let chunks = input.chunks_mut(16);
    for chunk in chunks {
        if chunk.len() < 16 || is_first {
            is_first = false;
            continue;
        }
        decryptor.decrypt_block_mut(chunk.into());
    }
}

struct PESSegment {
    stream_type: StreamType,

    pes_ts_header: TsHeader,
    pes_header: PesHeader,
    pes_packet_len: u16,
    initial_size: usize,

    data: Vec<u8>,
    data_packet_num: usize,
}

impl PESSegment {
    fn decrypt_and_write<W: Write>(
        mut self,
        key: [u8; 16],
        iv: [u8; 16],
        writer: &mut IoriTsPacketWriter<W>,
    ) -> Result<()> {
        // do decrypt first
        match self.stream_type {
            // avc
            StreamType::H264 | StreamType::H264WithAes128Cbc => self.decrypt_video(key, iv)?,
            // adts
            StreamType::AdtsAac
            | StreamType::AdtsAacWithAes128Cbc
            // ac3
            | StreamType::DolbyDigitalUpToSixChannelAudio
            | StreamType::DolbyDigitalUpToSixChannelAudioWithAes128Cbc
            // eac3
            | StreamType::DolbyDigitalPlusUpTo16ChannelAudio
            | StreamType::DolbyDigitalPlusUpToSixChannelAudioWithAes128Cbc => {
                self.decrypt_audio(key, iv)
            }
            _ => unreachable!("Unsupported stream type: {:?}", self.stream_type),
        }

        let pid = self.pes_ts_header.pid;

        // split data into PES packets and write
        // max TS packet size is 188
        let mut input = self.data.as_slice();
        let initial_size = input.len().min(self.initial_size);
        writer.write_packet(&mut TsPacket {
            header: self.pes_ts_header,
            adaptation_field: None,
            payload: Some(TsPayload::Pes(Pes {
                header: self.pes_header,
                pes_packet_len: self.pes_packet_len,
                data: Bytes::new(&self.data[..initial_size])?,
            })),
        })?;

        input = &input[initial_size..];
        let mut remaining_packets = self.data_packet_num;

        while !input.is_empty() {
            // We need to make sure the total count of packets not change after decryption
            let size = input.len() / remaining_packets;
            let data = &input[..size];
            input = &input[size..];

            let mut packet = TsPacket {
                header: TsHeader {
                    pid,
                    transport_scrambling_control: TransportScramblingControl::NotScrambled,
                    transport_error_indicator: false,
                    transport_priority: false,
                    continuity_counter: ContinuityCounter::new(), // will be set by writer
                },
                adaptation_field: None,
                // SAFETY: unwrap here is safe because we know the data length <= Bytes::MAX_SIZE
                payload: Some(TsPayload::Raw(Bytes::new(data).unwrap())),
            };
            writer.write_packet(&mut packet)?;

            remaining_packets -= 1;
        }

        Ok(())
    }

    fn decrypt_video(&mut self, key: [u8; 16], iv: [u8; 16]) -> Result<()> {
        let mut input = self.data.as_slice();
        let output = Vec::with_capacity(self.data.len() * 2);
        let mut output = BufWriter::new(output);

        loop {
            let (mut nal_unit, data_new) = NALUnit::get_next(input)?;
            input = data_new;

            if nal_unit.r#type == 5 || nal_unit.r#type == 1 {
                nal_unit.decrypt(&key, &iv);
            }

            nal_unit.write(&mut output)?;

            if input.is_empty() {
                break;
            }
        }

        self.data = output.into_inner().map_err(|e| e.into_error())?;

        Ok(())
    }

    fn decrypt_audio(&mut self, key: [u8; 16], iv: [u8; 16]) {
        let mut input = self.data.as_mut_slice();
        while !input.is_empty() {
            match self.stream_type {
                // adts
                StreamType::AdtsAac | StreamType::AdtsAacWithAes128Cbc => {
                    let size = decrypt_aac_frame(input, key, iv);
                    input = &mut input[size..];
                }
                // ac3
                StreamType::DolbyDigitalUpToSixChannelAudio
                | StreamType::DolbyDigitalUpToSixChannelAudioWithAes128Cbc => {
                    let size = decrypt_ac3_frame(input, key, iv);
                    input = &mut input[size..];
                }
                // eac3
                StreamType::DolbyDigitalPlusUpTo16ChannelAudio
                | StreamType::DolbyDigitalPlusUpToSixChannelAudioWithAes128Cbc => {
                    let size = decrypt_eac3_frame(input, key, iv);
                    input = &mut input[size..];
                }
                _ => unimplemented!("Unsupported stream type: {:?}", self.stream_type),
            }
        }
    }
}

struct IoriTsPacketWriter<W> {
    inner: TsPacketWriter<W>,
    counters: HashMap<u16, ContinuityCounter>,
}

impl<W: Write> IoriTsPacketWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner: TsPacketWriter::new(inner),
            counters: HashMap::new(),
        }
    }

    fn get_counter(
        &mut self,
        pid: u16,
        default_counter: ContinuityCounter,
    ) -> &mut ContinuityCounter {
        self.counters.entry(pid).or_insert(default_counter)
    }

    fn write_packet(&mut self, packet: &mut TsPacket) -> mpeg2ts::Result<()> {
        let counter =
            self.get_counter(packet.header.pid.as_u16(), packet.header.continuity_counter);
        packet.header.continuity_counter = *counter;

        if !matches!(packet.payload, None | Some(TsPayload::Null(_))) {
            counter.increment();
        }

        self.inner.write_ts_packet(packet)
    }
}

fn should_decrypt_stream(id_map: &HashMap<u16, StreamType>, pid: u16) -> bool {
    let stream_type = id_map.get(&pid);

    match stream_type {
        Some(
            // avc
            StreamType::H264WithAes128Cbc
            | StreamType::H264
            // adts
            | StreamType::AdtsAacWithAes128Cbc
            | StreamType::AdtsAac
            // ac3
            | StreamType::DolbyDigitalUpToSixChannelAudioWithAes128Cbc
            | StreamType::DolbyDigitalUpToSixChannelAudio
            // eac3
            | StreamType::DolbyDigitalPlusUpToSixChannelAudioWithAes128Cbc
            | StreamType::DolbyDigitalPlusUpTo16ChannelAudio,
        ) => true,
        _ => false,
    }
}

pub fn decrypt_mpegts<R, W>(input: R, output: W, key: [u8; 16], iv: [u8; 16]) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut reader = TsPacketReader::new(input);
    let mut writer = IoriTsPacketWriter::new(output);

    let mut streams = HashMap::new();
    let mut pid_map = HashMap::new();

    while let Ok(Some(TsPacket {
        header,
        adaptation_field,
        payload,
    })) = reader.read_ts_packet()
    {
        if let Some(payload) = payload {
            // do not flush after receiving the following payloads
            let flush = if matches!(
                payload,
                // PES is the start of a new stream
                TsPayload::Pes(_) |
                // RAW is part of the current stream
                TsPayload::Raw(_) |
                // NULL is just placeholder, no need to flush
                TsPayload::Null(_)
            ) {
                None
            } else {
                Some(header.pid)
            };

            match payload {
                TsPayload::Pmt(mut pmt) => {
                    // modify from encrypted to clear stream
                    for es in pmt.es_info.iter_mut() {
                        // save stream type before modify
                        pid_map.insert(es.elementary_pid.as_u16(), es.stream_type);

                        // map stream types to its unencrypted version
                        es.stream_type = match es.stream_type {
                            StreamType::H264WithAes128Cbc => StreamType::H264,
                            StreamType::AdtsAacWithAes128Cbc => StreamType::AdtsAac,
                            StreamType::DolbyDigitalUpToSixChannelAudioWithAes128Cbc => {
                                StreamType::DolbyDigitalUpToSixChannelAudio
                            }
                            StreamType::DolbyDigitalPlusUpToSixChannelAudioWithAes128Cbc => {
                                StreamType::DolbyDigitalPlusUpTo16ChannelAudio
                            }
                            _ => es.stream_type,
                        };
                    }
                    writer.write_packet(&mut TsPacket {
                        header,
                        adaptation_field,
                        payload: Some(TsPayload::Pmt(pmt)),
                    })?;
                }
                // only decrypt stream that should be decrypted
                TsPayload::Pes(pes) if should_decrypt_stream(&pid_map, header.pid.as_u16()) => {
                    let stream_type = pid_map.get(&header.pid.as_u16());

                    let prev_pes = streams.insert(
                        header.pid,
                        PESSegment {
                            // SAFETY: we know the stream type is valid
                            stream_type: *stream_type.unwrap(),

                            pes_ts_header: header,
                            pes_header: pes.header,
                            pes_packet_len: pes.pes_packet_len,
                            initial_size: pes.data.len(),
                            data: pes.data.to_vec(),
                            data_packet_num: 0,
                        },
                    );

                    if let Some(pes) = prev_pes {
                        pes.decrypt_and_write(key, iv, &mut writer)?;
                    }
                }
                TsPayload::Raw(bytes) if streams.contains_key(&header.pid) => {
                    // SAFETY: We've validated the stream exist in streams
                    let pes = streams.get_mut(&header.pid).unwrap();
                    pes.data_packet_num += 1;
                    pes.data.extend_from_slice(&bytes);
                }
                // for other payload, just write it without modification
                _ => writer.write_packet(&mut TsPacket {
                    header,
                    adaptation_field,
                    payload: Some(payload),
                })?,
            }

            if let Some(flush) = flush
                && let Some(pes) = streams.remove(&flush)
            {
                pes.decrypt_and_write(key, iv, &mut writer)?;
            };
        }
    }

    // handle remaining streams
    for pes in streams.into_values() {
        pes.decrypt_and_write(key, iv, &mut writer)?;
    }

    Ok(())
}

enum AudioSetupType {
    /// AAC-LC
    AacLc,
    /// AAC-HEv1
    AacHeV1,
    /// AAC-HEv2
    AacHeV2,
    /// AC-3
    Ac3,
    /// Enhanced AC-3
    EnhancedAc3,
}

pub fn decrypt<R, W>(input: R, mut output: W, key: [u8; 16], iv: [u8; 16]) -> Result<()>
where
    R: Read,
    W: Write,
{
    let mut input = BufReader::new(input);
    let magic = input.fill_buf()?;

    if magic.is_empty() {
        return Ok(());
    }

    // MPEG-TS
    if magic[0] == 0x47 {
        return decrypt_mpegts(input, output, key, iv);
    }

    let mut audio_format = None;
    let mut is_id3 = &magic[0..3] == b"ID3";
    while is_id3 {
        #[allow(deprecated)]
        let tag = id3::Tag::read_from(&mut input)?;
        tag.write_to(&mut output, tag.version())?;

        // In elementary streams the audio setup information is carried inside an ID3 Private Frame, as defined in ID3 tag version 2.4.0.
        // The owner identifier is com.apple.streaming.audioDescription.
        let format = tag.frames().find(|f| f.id() == "PRIV").and_then(|p| {
            if let id3::Content::Private(p) = p.content()
                && p.owner_identifier == "com.apple.streaming.audioDescription"
            {
                // audio_setup_information() {
                //     audio_type               // 4 bytes
                //     priming                  // 2 bytes
                //     version                  // 1 byte
                //     setup_data_length        // 1 byte
                //     setup_data               // setup_data_length
                // }
                let data = &p.private_data;
                if data.len() >= 4 {
                    let format = &data[0..4];
                    return match format {
                        b"zaac" => Some(AudioSetupType::AacLc),
                        b"zach" => Some(AudioSetupType::AacHeV1),
                        b"zacp" => Some(AudioSetupType::AacHeV2),
                        b"zac3" => Some(AudioSetupType::Ac3),
                        b"zec3" => Some(AudioSetupType::EnhancedAc3),
                        _ => None,
                    };
                }
            }

            None
        });

        if let Some(format) = format {
            audio_format = Some(format);
        }

        let magic = input.fill_buf()?;
        is_id3 = magic.len() >= 3 && &magic[0..3] == b"ID3";
    }

    let Some(audio_format) = audio_format else {
        return Ok(());
    };

    let mut buf = Vec::new();
    input.read_to_end(&mut buf)?;

    let mut data = &mut buf[..];
    loop {
        if data.is_empty() {
            break;
        }

        let size = match audio_format {
            AudioSetupType::AacLc | AudioSetupType::AacHeV1 | AudioSetupType::AacHeV2 => {
                decrypt_aac_frame(data, key, iv)
            }
            AudioSetupType::Ac3 => decrypt_ac3_frame(data, key, iv),
            AudioSetupType::EnhancedAc3 => decrypt_eac3_frame(data, key, iv),
        };

        let decrypted = &data[..size];
        output.write_all(decrypted)?;

        data = &mut data[size..];
    }

    Ok(())
}
