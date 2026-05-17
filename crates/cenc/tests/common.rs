use shiguredo_mp4::{BoxHeader, Decode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxLayout {
    pub typ: [u8; 4],
    pub start: usize,
    pub size: usize,
    pub header_size: usize,
}

pub fn top_level_box_layout(data: &[u8]) -> Option<Vec<BoxLayout>> {
    let mut boxes = Vec::new();
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
        if let shiguredo_mp4::BoxType::Normal(typ) = header.box_type {
            boxes.push(BoxLayout {
                typ,
                start: offset,
                size: box_size,
                header_size,
            });
        }
        offset += box_size;
    }
    Some(boxes)
}

pub fn find_top_level_box(data: &[u8], target: &[u8; 4]) -> Option<BoxLayout> {
    top_level_box_layout(data)?
        .into_iter()
        .find(|layout| &layout.typ == target)
}

pub fn read_mdat_payload(data: &[u8]) -> Option<Vec<u8>> {
    let mdat = find_top_level_box(data, b"mdat")?;
    let payload_start = mdat.start + mdat.header_size;
    let payload_end = mdat.start + mdat.size;
    Some(data[payload_start..payload_end].to_vec())
}
