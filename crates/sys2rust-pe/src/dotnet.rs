use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sys2rust_core::binary::{read_u16_le, read_u32_le, sha256_hex};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::pe::{IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, PeFile};

pub const BSJB_SIGNATURE: u32 = 0x424A_5342;
pub const DOTNET_RESOURCES_MAGIC: u32 = 0xBEEF_CACE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetResource {
    pub assembly_name: String,
    pub resource_name: String,
    pub offset: u32,
    pub size_bytes: u32,
    pub visibility: String,
    pub embedded_type: String,
    pub sha256: String,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetAssemblyMeta {
    pub assembly_name: String,
    pub version: String,
    pub culture: String,
    pub module_name: String,
    pub runtime_version: String,
    pub resources: Vec<DotNetResource>,
}

#[derive(Debug, Clone)]
struct StreamSlice<'a> {
    name: String,
    data: &'a [u8],
}

pub fn parse_dotnet_metadata(pe: &PeFile<'_>) -> Sys2RustResult<Option<DotNetAssemblyMeta>> {
    let com_dir = pe.data_dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if com_dir.virtual_address == 0 || com_dir.size < 72 {
        return Ok(None);
    }
    let Some(cor_off) = pe.rva_to_offset(com_dir.virtual_address) else {
        return Ok(None);
    };
    if cor_off + 72 > pe.bytes.len() {
        return Err(Sys2RustError::Parse {
            format: "CLR",
            detail: "truncated IMAGE_COR20_HEADER".to_string(),
        });
    }

    let meta_rva = read_u32_le(pe.bytes, cor_off + 8).unwrap_or(0);
    let meta_size = read_u32_le(pe.bytes, cor_off + 12).unwrap_or(0) as usize;
    let res_rva = read_u32_le(pe.bytes, cor_off + 24).unwrap_or(0);
    let res_size = read_u32_le(pe.bytes, cor_off + 28).unwrap_or(0) as usize;

    let Some(meta_bytes) = pe.slice_rva(meta_rva, meta_size) else {
        return Err(Sys2RustError::Parse {
            format: "CLR",
            detail: "invalid MetaData RVA/Size".to_string(),
        });
    };
    if meta_bytes.len() < 16 || read_u32_le(meta_bytes, 0) != Some(BSJB_SIGNATURE) {
        return Err(Sys2RustError::Parse {
            format: "CLR",
            detail: "missing BSJB metadata root signature".to_string(),
        });
    }

    let ver_len = read_u32_le(meta_bytes, 12).unwrap_or(0) as usize;
    let ver_start = 16usize;
    let ver_end = ver_start.saturating_add(ver_len).min(meta_bytes.len());
    let runtime_version = String::from_utf8_lossy(&meta_bytes[ver_start..ver_end])
        .trim_end_matches('\0')
        .to_string();

    let mut pos = align4(ver_start.saturating_add(ver_len));
    if pos + 4 > meta_bytes.len() {
        return Err(Sys2RustError::Parse {
            format: "CLR",
            detail: "truncated BSJB stream header count".to_string(),
        });
    }
    let stream_count = usize::from(read_u16_le(meta_bytes, pos + 2).unwrap_or(0));
    pos += 4;

    let mut streams = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        if pos + 8 > meta_bytes.len() {
            break;
        }
        let s_off = read_u32_le(meta_bytes, pos).unwrap_or(0) as usize;
        let s_sz = read_u32_le(meta_bytes, pos + 4).unwrap_or(0) as usize;
        pos += 8;
        let name_start = pos;
        while pos < meta_bytes.len() && meta_bytes[pos] != 0 {
            pos += 1;
        }
        let name = String::from_utf8_lossy(&meta_bytes[name_start..pos]).to_string();
        if pos < meta_bytes.len() {
            pos += 1;
        }
        pos = align4(pos);
        if let Some(slice) = meta_bytes.get(s_off..s_off.saturating_add(s_sz)) {
            streams.push(StreamSlice { name, data: slice });
        }
    }

    let strings_heap = streams
        .iter()
        .find(|s| s.name == "#Strings")
        .map(|s| s.data)
        .unwrap_or(&[]);
    let tables_stream = streams
        .iter()
        .find(|s| s.name == "#~" || s.name == "#-")
        .map(|s| s.data)
        .ok_or_else(|| Sys2RustError::Parse {
            format: "CLR",
            detail: "missing #~ / #- metadata table stream".to_string(),
        })?;

    if tables_stream.len() < 24 {
        return Err(Sys2RustError::Parse {
            format: "CLR",
            detail: "truncated #~ header".to_string(),
        });
    }

    let heap_sizes = tables_stream[6];
    let str_idx_sz = if (heap_sizes & 0x01) != 0 { 4 } else { 2 };
    let guid_idx_sz = if (heap_sizes & 0x02) != 0 { 4 } else { 2 };
    let blob_idx_sz = if (heap_sizes & 0x04) != 0 { 4 } else { 2 };

    let valid_mask = u64::from_le_bytes(tables_stream[8..16].try_into().unwrap_or([0; 8]));
    let mut tpos = 24usize;
    let mut row_counts = [0u32; 64];
    for (tid, slot) in row_counts.iter_mut().enumerate() {
        if (valid_mask & (1u64 << tid)) != 0 {
            let Some(cnt) = read_u32_le(tables_stream, tpos) else {
                return Err(Sys2RustError::Parse {
                    format: "CLR",
                    detail: "truncated #~ row count table".to_string(),
                });
            };
            *slot = cnt;
            tpos += 4;
        }
    }

    let mut module_name = String::new();
    let mut assembly_name = String::new();
    let mut version = String::new();
    let mut culture = String::new();
    let mut resources = Vec::new();
    let res_blob = if res_rva != 0 && res_size > 0 {
        pe.slice_rva(res_rva, res_size).unwrap_or(&[])
    } else {
        &[]
    };

    for tid in 0..=0x28usize {
        if (valid_mask & (1u64 << tid)) == 0 {
            continue;
        }
        let count = row_counts[tid] as usize;
        let row_sz = table_row_size(tid, str_idx_sz, guid_idx_sz, blob_idx_sz, &row_counts);
        if row_sz == 0 {
            break;
        }
        let table_bytes = count.saturating_mul(row_sz);
        if tpos.saturating_add(table_bytes) > tables_stream.len() {
            break;
        }

        if tid == 0x00 && count > 0 {
            let name_idx = read_heap_idx(tables_stream, tpos + 2, str_idx_sz);
            module_name = read_strings_heap(strings_heap, name_idx);
        } else if tid == 0x20 && count > 0 {
            let maj = read_u16_le(tables_stream, tpos + 4).unwrap_or(0);
            let min = read_u16_le(tables_stream, tpos + 6).unwrap_or(0);
            let bld = read_u16_le(tables_stream, tpos + 8).unwrap_or(0);
            let rev = read_u16_le(tables_stream, tpos + 10).unwrap_or(0);
            version = format!("{maj}.{min}.{bld}.{rev}");
            let name_off = tpos + 16 + blob_idx_sz;
            let cult_off = name_off + str_idx_sz;
            assembly_name = read_strings_heap(strings_heap, read_heap_idx(tables_stream, name_off, str_idx_sz));
            culture = read_strings_heap(strings_heap, read_heap_idx(tables_stream, cult_off, str_idx_sz));
            if culture.is_empty() {
                culture = "neutral".to_string();
            }
        } else if tid == 0x28 {
            for r in 0..count {
                let roff = tpos + r * row_sz;
                let res_off = read_u32_le(tables_stream, roff).unwrap_or(0);
                let flags = read_u32_le(tables_stream, roff + 4).unwrap_or(0);
                let name_idx = read_heap_idx(tables_stream, roff + 8, str_idx_sz);
                let impl_coded = read_heap_idx(
                    tables_stream,
                    roff + 8 + str_idx_sz,
                    coded_index_size(&[0x26, 0x23, 0x27], &row_counts),
                );
                let res_name = read_strings_heap(strings_heap, name_idx);
                let visibility = match flags & 0x0007 {
                    1 => "Public".to_string(),
                    2 => "Private".to_string(),
                    other => format!("Flags({other:#x})"),
                };
                let (data, size_bytes, embedded_type) = if impl_coded == 0 {
                    extract_embedded_resource(res_blob, res_off)
                } else {
                    (Vec::new(), 0, "External/Linked".to_string())
                };
                let sha = sha256_hex(&data);
                resources.push(DotNetResource {
                    assembly_name: if assembly_name.is_empty() {
                        module_name.clone()
                    } else {
                        assembly_name.clone()
                    },
                    resource_name: res_name,
                    offset: res_off,
                    size_bytes,
                    visibility,
                    embedded_type,
                    sha256: sha,
                    data,
                });
            }
        }

        tpos += table_bytes;
    }

    if assembly_name.is_empty() {
        assembly_name = module_name.clone();
    }

    Ok(Some(DotNetAssemblyMeta {
        assembly_name,
        version,
        culture,
        module_name,
        runtime_version,
        resources,
    }))
}

fn extract_embedded_resource(res_blob: &[u8], offset: u32) -> (Vec<u8>, u32, String) {
    let off = offset as usize;
    let Some(len) = read_u32_le(res_blob, off) else {
        return (Vec::new(), 0, "Unavailable".to_string());
    };
    let start = off + 4;
    let Some(end) = start.checked_add(len as usize) else {
        return (Vec::new(), 0, "Truncated/Unavailable".to_string());
    };
    let Some(slice) = res_blob.get(start..end) else {
        return (Vec::new(), 0, "Truncated/Unavailable".to_string());
    };
    let data = slice.to_vec();
    let kind = if read_u32_le(&data, 0) == Some(DOTNET_RESOURCES_MAGIC) {
        "ResourceManager (.resources)".to_string()
    } else {
        "Raw/Binary".to_string()
    };
    (data, len, kind)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn read_heap_idx(buf: &[u8], off: usize, size: usize) -> usize {
    if size == 4 {
        read_u32_le(buf, off).unwrap_or(0) as usize
    } else {
        usize::from(read_u16_le(buf, off).unwrap_or(0))
    }
}

fn read_strings_heap(heap: &[u8], idx: usize) -> String {
    let Some(tail) = heap.get(idx..) else {
        return String::new();
    };
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).to_string()
}

fn tbl_idx_size(tid: usize, counts: &[u32; 64]) -> usize {
    if counts.get(tid).copied().unwrap_or(0) >= 65536 {
        4
    } else {
        2
    }
}

fn coded_index_size(tids: &[usize], counts: &[u32; 64]) -> usize {
    let bits = (tids.len() as u32).next_power_of_two().trailing_zeros();
    let threshold = 1u32 << (16 - bits);
    let max_rows = tids
        .iter()
        .map(|&tid| counts.get(tid).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    if max_rows >= threshold { 4 } else { 2 }
}

fn table_row_size(tid: usize, str_sz: usize, guid_sz: usize, blob_sz: usize, counts: &[u32; 64]) -> usize {
    let type_def_or_ref = coded_index_size(&[0x02, 0x01, 0x1B], counts);
    let has_const = coded_index_size(&[0x04, 0x08, 0x17], counts);
    let has_cust_attr = coded_index_size(
        &[
            0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27,
            0x28, 0x2A, 0x2C, 0x2B,
        ],
        counts,
    );
    let custom_attr_type = coded_index_size(&[0x06, 0x0A, 0x00, 0x00, 0x00], counts);
    let has_field_marshal = coded_index_size(&[0x04, 0x08], counts);
    let has_decl_sec = coded_index_size(&[0x02, 0x06, 0x20], counts);
    let member_ref_parent = coded_index_size(&[0x02, 0x01, 0x1A, 0x06, 0x1B], counts);
    let has_semantics = coded_index_size(&[0x14, 0x17], counts);
    let method_def_or_ref = coded_index_size(&[0x06, 0x0A], counts);
    let member_forwarded = coded_index_size(&[0x04, 0x06], counts);
    let implementation = coded_index_size(&[0x26, 0x23, 0x27], counts);
    let resolution_scope = coded_index_size(&[0x00, 0x1A, 0x23, 0x01], counts);

    match tid {
        0x00 => 2 + str_sz + 3 * guid_sz,      // Module
        0x01 => resolution_scope + 2 * str_sz, // TypeRef
        0x02 => 4 + 2 * str_sz + type_def_or_ref + tbl_idx_size(0x04, counts) + tbl_idx_size(0x06, counts), // TypeDef
        0x04 => 2 + str_sz + blob_sz,          // Field
        0x06 => 4 + 2 + 2 + str_sz + blob_sz + tbl_idx_size(0x08, counts), // MethodDef
        0x08 => 2 + 2 + str_sz,                // Param
        0x09 => tbl_idx_size(0x02, counts) + type_def_or_ref, // InterfaceImpl
        0x0A => member_ref_parent + str_sz + blob_sz, // MemberRef
        0x0B => 2 + has_const + blob_sz,       // Constant
        0x0C => has_cust_attr + custom_attr_type + blob_sz, // CustomAttribute
        0x0D => has_field_marshal + blob_sz,   // FieldMarshal
        0x0E => 2 + has_decl_sec + blob_sz,    // DeclSecurity
        0x0F => 2 + 4 + tbl_idx_size(0x02, counts), // ClassLayout
        0x10 => 4 + tbl_idx_size(0x04, counts), // FieldLayout
        0x11 => blob_sz,                       // StandAloneSig
        0x12 => tbl_idx_size(0x02, counts) + tbl_idx_size(0x14, counts), // EventMap
        0x14 => 2 + str_sz + type_def_or_ref,  // Event
        0x15 => tbl_idx_size(0x02, counts) + tbl_idx_size(0x17, counts), // PropertyMap
        0x17 => 2 + str_sz + blob_sz,          // Property
        0x18 => 2 + tbl_idx_size(0x06, counts) + has_semantics, // MethodSemantics
        0x19 => tbl_idx_size(0x02, counts) + 2 * method_def_or_ref, // MethodImpl
        0x1A => str_sz,                        // ModuleRef
        0x1B => blob_sz,                       // TypeSpec
        0x1C => 2 + member_forwarded + str_sz + tbl_idx_size(0x1A, counts), // ImplMap
        0x1D => 4 + tbl_idx_size(0x04, counts), // FieldRVA
        0x20 => 4 + 8 + 4 + blob_sz + 2 * str_sz, // Assembly
        0x21 => 4,                             // AssemblyProcessor
        0x22 => 12,                            // AssemblyOS
        0x23 => 8 + 4 + 2 * blob_sz + 2 * str_sz, // AssemblyRef
        0x24 => 4 + tbl_idx_size(0x23, counts), // AssemblyRefProcessor
        0x25 => 12 + tbl_idx_size(0x23, counts), // AssemblyRefOS
        0x26 => 4 + str_sz + blob_sz,          // File
        0x27 => 4 + 4 + 2 * str_sz + implementation, // ExportedType
        0x28 => 4 + 4 + str_sz + implementation, // ManifestResource
        _ => 0,
    }
}

pub fn extract_dotnet_resources(resources: &[DotNetResource], out_dir: &Path) -> Sys2RustResult<Vec<PathBuf>> {
    fs::create_dir_all(out_dir)?;
    let mut written = Vec::new();
    for res in resources {
        if res.data.is_empty() {
            continue;
        }
        let clean: String = res
            .resource_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = out_dir.join(clean);
        fs::write(&path, &res.data)?;
        written.push(path);
    }
    Ok(written)
}
