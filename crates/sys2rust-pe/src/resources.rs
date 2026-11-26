use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;
use sys2rust_core::binary::{decode_utf16le, read_u16_le, read_u32_le, sha256_hex};

use crate::pe::{IMAGE_DIRECTORY_ENTRY_RESOURCE, PeFile};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceId {
    Numeric(u32),
    Name(String),
}

impl ResourceId {
    pub fn display(&self) -> String {
        match self {
            Self::Numeric(n) => format!("#{n}"),
            Self::Name(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub type_id: ResourceId,
    pub resource_type: String,
    pub name_id: ResourceId,
    pub resource_name_or_id: String,
    pub language_id: u32,
    pub rva: u32,
    pub file_offset: Option<u64>,
    pub size_bytes: u32,
    pub detected_mime: String,
    pub sha256: String,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
}

pub fn resource_type_name(id: &ResourceId) -> String {
    match id {
        ResourceId::Name(name) => name.clone(),
        ResourceId::Numeric(n) => match n {
            1 => "RT_CURSOR".to_string(),
            2 => "RT_BITMAP".to_string(),
            3 => "RT_ICON".to_string(),
            4 => "RT_MENU".to_string(),
            5 => "RT_DIALOG".to_string(),
            6 => "RT_STRING".to_string(),
            7 => "RT_FONTDIR".to_string(),
            8 => "RT_FONT".to_string(),
            9 => "RT_ACCELERATOR".to_string(),
            10 => "RT_RCDATA".to_string(),
            11 => "RT_MESSAGETABLE".to_string(),
            12 => "RT_GROUP_CURSOR".to_string(),
            14 => "RT_GROUP_ICON".to_string(),
            16 => "RT_VERSION".to_string(),
            24 => "RT_MANIFEST".to_string(),
            other => format!("RT_{other}"),
        },
    }
}

pub fn detect_resource_mime(type_id: &ResourceId, data: &[u8]) -> &'static str {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png";
    }
    if data.starts_with(b"BM") {
        return "image/bmp";
    }
    if data.starts_with(b"\xFF\xD8\xFF") {
        return "image/jpeg";
    }
    if data.starts_with(b"GIF8") {
        return "image/gif";
    }
    if matches!(type_id, ResourceId::Numeric(24)) || data.trim_ascii_start().starts_with(b"<") {
        return "application/xml";
    }
    if matches!(type_id, ResourceId::Numeric(16)) {
        return "application/x-ms-version";
    }
    if matches!(type_id, ResourceId::Numeric(3 | 14)) {
        return "image/x-icon";
    }
    if data
        .iter()
        .take(128)
        .all(|&b| b.is_ascii() && (b >= 0x20 || matches!(b, b'\t' | b'\r' | b'\n')))
        && !data.is_empty()
    {
        return "text/plain";
    }
    "application/octet-stream"
}

pub fn parse_resources(pe: &PeFile<'_>) -> Sys2RustResult<Vec<ResourceEntry>> {
    let dir = pe.data_dir(IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }
    let Some(rsrc_base) = pe.rva_to_offset(dir.virtual_address) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    walk_dir(pe, rsrc_base, rsrc_base, 0, None, None, &mut visited, &mut out);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    pe: &PeFile<'_>,
    rsrc_base: usize,
    dir_off: usize,
    depth: usize,
    cur_type: Option<ResourceId>,
    cur_name: Option<ResourceId>,
    visited: &mut BTreeSet<usize>,
    out: &mut Vec<ResourceEntry>,
) {
    if depth > 8 || !visited.insert(dir_off) || dir_off + 16 > pe.bytes.len() {
        return;
    }

    let num_named = usize::from(read_u16_le(pe.bytes, dir_off + 12).unwrap_or(0));
    let num_id = usize::from(read_u16_le(pe.bytes, dir_off + 14).unwrap_or(0));
    let total = num_named.saturating_add(num_id).min(4096);

    for i in 0..total {
        let entry_off = dir_off + 16 + i * 8;
        if entry_off + 8 > pe.bytes.len() {
            break;
        }
        let name_or_id = read_u32_le(pe.bytes, entry_off).unwrap_or(0);
        let offset_to_data = read_u32_le(pe.bytes, entry_off + 4).unwrap_or(0);

        let id = if (name_or_id & 0x8000_0000) != 0 {
            let str_rel = (name_or_id & 0x7FFF_FFFF) as usize;
            read_rsrc_string(pe.bytes, rsrc_base, str_rel)
                .map(ResourceId::Name)
                .unwrap_or(ResourceId::Numeric(name_or_id))
        } else {
            ResourceId::Numeric(name_or_id)
        };

        let is_subdir = (offset_to_data & 0x8000_0000) != 0;
        let rel = (offset_to_data & 0x7FFF_FFFF) as usize;
        let Some(target_off) = rsrc_base.checked_add(rel) else {
            continue;
        };

        if is_subdir {
            match depth {
                0 => walk_dir(pe, rsrc_base, target_off, 1, Some(id), None, visited, out),
                1 => walk_dir(pe, rsrc_base, target_off, 2, cur_type.clone(), Some(id), visited, out),
                _ => {}
            }
        } else if target_off + 16 <= pe.bytes.len() {
            let data_rva = read_u32_le(pe.bytes, target_off).unwrap_or(0);
            let data_size = read_u32_le(pe.bytes, target_off + 4).unwrap_or(0);
            let lang_id = match id {
                ResourceId::Numeric(n) => n,
                ResourceId::Name(_) => 0,
            };
            let type_id = cur_type.clone().unwrap_or(ResourceId::Numeric(0));
            let name_id = cur_name.clone().unwrap_or(ResourceId::Numeric(0));
            let data = pe
                .slice_rva(data_rva, data_size.min(64 * 1024 * 1024) as usize)
                .map(|s| s.to_vec())
                .unwrap_or_default();
            let mime = detect_resource_mime(&type_id, &data).to_string();
            let sha = sha256_hex(&data);
            out.push(ResourceEntry {
                resource_type: resource_type_name(&type_id),
                resource_name_or_id: name_id.display(),
                type_id,
                name_id,
                language_id: lang_id,
                rva: data_rva,
                file_offset: pe.rva_to_offset(data_rva).map(|o| o as u64),
                size_bytes: data_size,
                detected_mime: mime,
                sha256: sha,
                data,
            });
        }
    }
}

fn read_rsrc_string(bytes: &[u8], rsrc_base: usize, rel: usize) -> Option<String> {
    let off = rsrc_base.checked_add(rel)?;
    let char_count = usize::from(read_u16_le(bytes, off)?);
    let byte_len = char_count.checked_mul(2)?;
    let slice = bytes.get(off + 2..off + 2 + byte_len)?;
    Some(decode_utf16le(slice))
}

pub fn extract_resources(entries: &[ResourceEntry], out_dir: &Path) -> Sys2RustResult<Vec<PathBuf>> {
    fs::create_dir_all(out_dir)?;
    let mut written = Vec::new();
    let mut seen_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for entry in entries {
        let safe_type = sanitize_filename(&entry.resource_type);
        let safe_name = sanitize_filename(&entry.resource_name_or_id);
        let ext = match entry.detected_mime.as_str() {
            "image/png" => "png",
            "image/bmp" => "bmp",
            "application/xml" => "xml",
            "text/plain" => "txt",
            _ => "bin",
        };
        let stem = format!("{safe_type}_{safe_name}_{}", entry.language_id);
        let count = seen_counts
            .entry((stem.clone(), ext.to_string()))
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let filename = if *count == 1 {
            format!("{stem}.{ext}")
        } else {
            format!("{stem}_{}.{ext}", *count)
        };
        let path = out_dir.join(filename);
        fs::write(&path, &entry.data)?;
        written.push(path);
    }
    Ok(written)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
