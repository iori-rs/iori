use shiguredo_mp4::{BoxHeader, Decode};

pub fn read_mdat_payload(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset < data.len() {
        let (header, header_size) = BoxHeader::decode(&data[offset..]).ok()?;
        let mut box_size = usize::try_from(header.box_size.get()).ok()?;
        if box_size == 0 {
            box_size = data.len() - offset;
        }
        if box_size < header_size || offset + box_size > data.len() {
            return None;
        }
        if let shiguredo_mp4::BoxType::Normal(ty) = &header.box_type
            && ty == b"mdat"
        {
            let payload_start = offset + header_size;
            let payload_end = offset + box_size;
            return Some(data[payload_start..payload_end].to_vec());
        }
        offset += box_size;
    }
    None
}
