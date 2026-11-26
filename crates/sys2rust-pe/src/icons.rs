use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;
use sys2rust_core::binary::{read_u16_le, read_u32_le, sha256_hex};

use crate::resources::{ResourceEntry, ResourceId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IconGroupEntry {
    pub source_file: String,
    pub group_id: String,
    pub icon_count: u16,
    pub dimensions: String,
    pub bit_depth: u16,
    pub format: String,
    pub sha256: String,
    #[serde(skip_serializing)]
    pub ico_bytes: Vec<u8>,
}

pub fn reassemble_icons(source_file: &str, entries: &[ResourceEntry]) -> Vec<IconGroupEntry> {
    let mut rt_icons: BTreeMap<(u32, u32), &[u8]> = BTreeMap::new();
    let mut rt_icons_fallback: BTreeMap<u32, &[u8]> = BTreeMap::new();
    let mut rt_cursors: BTreeMap<(u32, u32), &[u8]> = BTreeMap::new();
    let mut rt_cursors_fallback: BTreeMap<u32, &[u8]> = BTreeMap::new();

    for entry in entries {
        if let ResourceId::Numeric(id) = entry.name_id {
            match entry.type_id {
                ResourceId::Numeric(3) => {
                    rt_icons.entry((id, entry.language_id)).or_insert(entry.data.as_slice());
                    rt_icons_fallback.entry(id).or_insert(entry.data.as_slice());
                }
                ResourceId::Numeric(1) => {
                    rt_cursors
                        .entry((id, entry.language_id))
                        .or_insert(entry.data.as_slice());
                    rt_cursors_fallback.entry(id).or_insert(entry.data.as_slice());
                }
                _ => {}
            }
        }
    }

    let mut groups = Vec::new();
    for entry in entries {
        let is_cursor = match entry.type_id {
            ResourceId::Numeric(14) => false,
            ResourceId::Numeric(12) => true,
            _ => continue,
        };
        if let Some(group) = build_ico_or_cur(
            source_file,
            entry,
            is_cursor,
            &rt_icons,
            &rt_icons_fallback,
            &rt_cursors,
            &rt_cursors_fallback,
        ) {
            groups.push(group);
        }
    }
    groups
}

fn build_ico_or_cur(
    source_file: &str,
    group_entry: &ResourceEntry,
    is_cursor: bool,
    rt_icons: &BTreeMap<(u32, u32), &[u8]>,
    rt_icons_fallback: &BTreeMap<u32, &[u8]>,
    rt_cursors: &BTreeMap<(u32, u32), &[u8]>,
    rt_cursors_fallback: &BTreeMap<u32, &[u8]>,
) -> Option<IconGroupEntry> {
    let buf = &group_entry.data;
    if buf.len() < 6 {
        return None;
    }
    let reserved = read_u16_le(buf, 0)?;
    let id_type = read_u16_le(buf, 2)?;
    let count = read_u16_le(buf, 4)?;
    if reserved != 0 || (id_type != 1 && id_type != 2) || count == 0 {
        return None;
    }

    let max_entries = ((buf.len() - 6) / 14).min(usize::from(count));
    if max_entries == 0 {
        return None;
    }

    struct ResolvedSlice {
        width: u8,
        height: u8,
        color_count: u8,
        reserved: u8,
        field1: u16,
        field2: u16,
        payload: Vec<u8>,
        is_png: bool,
    }

    let mut slices = Vec::with_capacity(max_entries);
    for i in 0..max_entries {
        let off = 6 + i * 14;
        let width = buf[off];
        let height = buf[off + 1];
        let color_count = buf[off + 2];
        let entry_res = buf[off + 3];
        let planes = read_u16_le(buf, off + 4)?;
        let bit_count = read_u16_le(buf, off + 6)?;
        let _bytes_in_res = read_u32_le(buf, off + 8)?;
        let n_id = u32::from(read_u16_le(buf, off + 12)?);

        let raw_payload = if is_cursor {
            rt_cursors
                .get(&(n_id, group_entry.language_id))
                .or_else(|| rt_cursors_fallback.get(&n_id))
                .copied()?
        } else {
            rt_icons
                .get(&(n_id, group_entry.language_id))
                .or_else(|| rt_icons_fallback.get(&n_id))
                .copied()?
        };

        let (field1, field2, payload) = if is_cursor && raw_payload.len() >= 4 {
            let hx = read_u16_le(raw_payload, 0).unwrap_or(0);
            let hy = read_u16_le(raw_payload, 2).unwrap_or(0);
            (hx, hy, raw_payload[4..].to_vec())
        } else {
            (planes, bit_count, raw_payload.to_vec())
        };

        let is_png = payload.starts_with(b"\x89PNG\r\n\x1a\n");
        slices.push(ResolvedSlice {
            width,
            height,
            color_count,
            reserved: entry_res,
            field1,
            field2,
            payload,
            is_png,
        });
    }

    let header_size = 6usize + slices.len() * 16;
    let total_payload: usize = slices.iter().map(|s| s.payload.len()).sum();
    let mut ico = Vec::with_capacity(header_size + total_payload);
    ico.extend_from_slice(&0u16.to_le_bytes());
    ico.extend_from_slice(&(if is_cursor { 2u16 } else { 1u16 }).to_le_bytes());
    ico.extend_from_slice(&(slices.len() as u16).to_le_bytes());

    let mut cur_offset = header_size as u32;
    let mut dims = Vec::new();
    let mut max_bpp = 0u16;
    let mut has_png = false;
    let mut has_dib = false;

    for s in &slices {
        let w_disp = if s.width == 0 { 256 } else { u16::from(s.width) };
        let h_disp = if s.height == 0 { 256 } else { u16::from(s.height) };
        dims.push(format!("{w_disp}x{h_disp}"));
        if !is_cursor {
            max_bpp = max_bpp.max(s.field2);
        } else if s.payload.len() >= 16 {
            let dib_bpp = read_u16_le(&s.payload, 14).unwrap_or(32);
            max_bpp = max_bpp.max(dib_bpp);
        }
        if s.is_png {
            has_png = true;
        } else {
            has_dib = true;
        }

        ico.push(s.width);
        ico.push(s.height);
        ico.push(s.color_count);
        ico.push(s.reserved);
        ico.extend_from_slice(&s.field1.to_le_bytes());
        ico.extend_from_slice(&s.field2.to_le_bytes());
        ico.extend_from_slice(&(s.payload.len() as u32).to_le_bytes());
        ico.extend_from_slice(&cur_offset.to_le_bytes());
        cur_offset = cur_offset.saturating_add(s.payload.len() as u32);
    }

    for s in &slices {
        ico.extend_from_slice(&s.payload);
    }

    let format = match (is_cursor, has_png, has_dib) {
        (true, _, _) => "CUR",
        (false, true, true) => "ICO (PNG+BMP)",
        (false, true, false) => "ICO (PNG)",
        (false, false, _) => "ICO (BMP)",
    }
    .to_string();

    let sha = sha256_hex(&ico);
    Some(IconGroupEntry {
        source_file: source_file.to_string(),
        group_id: group_entry.resource_name_or_id.clone(),
        icon_count: slices.len() as u16,
        dimensions: dims.join(", "),
        bit_depth: max_bpp,
        format,
        sha256: sha,
        ico_bytes: ico,
    })
}

pub fn extract_icons(groups: &[IconGroupEntry], out_dir: &Path) -> Sys2RustResult<Vec<PathBuf>> {
    fs::create_dir_all(out_dir)?;
    let mut written = Vec::new();
    for (idx, g) in groups.iter().enumerate() {
        let ext = if g.format == "CUR" { "cur" } else { "ico" };
        let clean_id: String = g
            .group_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let path = out_dir.join(format!("icon_{idx}_{clean_id}.{ext}"));
        fs::write(&path, &g.ico_bytes)?;
        written.push(path);
    }
    Ok(written)
}
