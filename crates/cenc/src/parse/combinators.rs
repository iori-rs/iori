//! Winnow parser combinators for MP4 box structures

use shiguredo_mp4::{BoxHeader, BoxSize, BoxType};
use winnow::Parser;
use winnow::binary::{be_u8, be_u32, be_u64};
use winnow::error::{ContextError, ErrMode};
use winnow::stream::Partial;
use winnow::token::take;

/// Parse MP4 box header (8 or 16 bytes)
///
/// Structure:
/// - size: u32 (4 bytes)
/// - type: [u8; 4] (4 bytes)
/// - extended_size: u64 (8 bytes, only if size == 1)
///
/// If size == 0, box extends to end of file (not supported in streaming)
/// If size == 1, use 64-bit extended size
pub fn box_header(input: &mut Partial<&[u8]>) -> Result<BoxHeader, ErrMode<ContextError>> {
    let box_size = be_u32.parse_next(input)?;

    let box_type: [u8; 4] = take(4usize)
        .parse_next(input)?
        .try_into()
        .map_err(|_| ErrMode::Cut(ContextError::new()))?;
    let box_type = if box_type == [b'u', b'u', b'i', b'd'] {
        let uuid: [u8; 16] = take(16usize)
            .parse_next(input)?
            .try_into()
            .map_err(|_| ErrMode::Cut(ContextError::new()))?;
        BoxType::Uuid(uuid)
    } else {
        BoxType::Normal(box_type)
    };

    let box_size = if box_size == 1 {
        // Extended size
        let size = be_u64.parse_next(input)?;
        BoxSize::U64(size)
    } else if box_size == 0 {
        // Box extends to EOF - not supported in streaming mode
        return Err(ErrMode::Cut(ContextError::new()));
    } else {
        BoxSize::U32(box_size)
    };

    Ok(BoxHeader { box_type, box_size })
}

/// Full box header (version + flags)
///
/// Structure:
/// - version: u8 (1 byte)
/// - flags: u24 (3 bytes)
#[derive(Debug, Clone, PartialEq)]
pub struct FullBoxHeader {
    pub version: u8,
    pub flags: u32,
}

/// Parse full box header (version + flags)
pub fn full_box_header(input: &mut Partial<&[u8]>) -> Result<FullBoxHeader, ErrMode<ContextError>> {
    let version = be_u8.parse_next(input)?;
    let flags = be_u24.parse_next(input)?;

    Ok(FullBoxHeader { version, flags })
}

/// Parse 24-bit big-endian unsigned integer
pub fn be_u24(input: &mut Partial<&[u8]>) -> Result<u32, ErrMode<ContextError>> {
    let bytes: [u8; 3] = take(3usize)
        .parse_next(input)?
        .try_into()
        .map_err(|_| ErrMode::Cut(ContextError::new()))?;

    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
}

/// Parse fixed-size byte array
pub fn array<const N: usize>(input: &mut Partial<&[u8]>) -> Result<[u8; N], ErrMode<ContextError>> {
    take(N)
        .parse_next(input)?
        .try_into()
        .map_err(|_| ErrMode::Cut(ContextError::new()))
}

/// Read box payload by skipping header and reading remaining bytes
pub fn box_payload<'a>(
    input: &mut &'a [u8],
    header: &BoxHeader,
) -> Result<&'a [u8], ErrMode<ContextError>> {
    let payload_size = (header.box_size.get() as usize)
        .checked_sub(header.external_size())
        .ok_or_else(|| ErrMode::Cut(ContextError::new()))?;

    take(payload_size).parse_next(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_header_normal() {
        let data = [
            0x00, 0x00, 0x00, 0x20, // size = 32
            b'm', b'd', b'a', b't', // type = mdat
        ];
        let mut input = Partial::new(&data[..]);
        let header = box_header(&mut input).unwrap();

        assert_eq!(header.box_type, BoxType::Normal(*b"mdat"));
        assert_eq!(header.box_size.get(), 32);
        assert_eq!(header.external_size(), 8);
    }

    #[test]
    fn test_box_header_extended() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // size = 1 (extended)
            b'm', b'd', b'a', b't', // type = mdat
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // extended size = 65536
        ];
        let mut input = Partial::new(&data[..]);
        let header = box_header(&mut input).unwrap();

        assert_eq!(header.box_type, BoxType::Normal(*b"mdat"));
        assert_eq!(header.box_size.get(), 65536);
        assert_eq!(header.external_size(), 16);
    }

    #[test]
    fn test_box_header_eof_unsupported() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // size = 0 (extends to EOF)
            b'm', b'd', b'a', b't', // type = mdat
        ];
        let mut input = Partial::new(&data[..]);
        let result = box_header(&mut input);

        assert!(result.is_err());
    }

    #[test]
    fn test_full_box_header() {
        let data = [
            0x01, // version = 1
            0x00, 0x00, 0x04, // flags = 0x000004
        ];
        let mut input = Partial::new(&data[..]);
        let header = full_box_header(&mut input).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.flags, 0x000004);
    }

    #[test]
    fn test_be_u24() {
        let data = [0x12, 0x34, 0x56];
        let mut input = Partial::new(&data[..]);
        let value = be_u24(&mut input).unwrap();

        assert_eq!(value, 0x123456);
    }

    #[test]
    fn test_array() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut input = Partial::new(&data[..]);
        let arr: [u8; 4] = array(&mut input).unwrap();

        assert_eq!(arr, [0x01, 0x02, 0x03, 0x04]);
    }
}
