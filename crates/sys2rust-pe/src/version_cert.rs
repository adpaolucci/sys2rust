use serde::{Deserialize, Serialize};
use sys2rust_core::binary::{decode_utf16le_nul, read_u16_le, read_u32_le, sha256_hex};

use crate::pe::{IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_SECURITY, PeFile};
use crate::resources::{ResourceEntry, ResourceId};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionStrings {
    pub file_version: String,
    pub product_name: String,
    pub company_name: String,
    pub file_description: String,
    pub original_filename: String,
    pub internal_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfoSummary {
    pub file_path: String,
    pub machine: String,
    pub subsystem: String,
    pub is_dotnet: bool,
    pub compiler_linker_hint: String,
    pub entry_point_rva: u32,
    pub time_date_stamp: u32,
    pub sections_count: u16,
    pub file_version: String,
    pub product_name: String,
    pub company_name: String,
    pub file_description: String,
    pub signed: bool,
    pub cert_type: Option<u16>,
    pub sha256: String,
    pub manifest_xml: Option<String>,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn read_utf16_nul_and_end(buf: &[u8], start: usize, limit: usize) -> Option<(String, usize)> {
    let mut off = start;
    let mut units = Vec::new();
    let end_limit = limit.min(buf.len());
    while off + 2 <= end_limit {
        let c = read_u16_le(buf, off)?;
        off += 2;
        if c == 0 {
            return Some((String::from_utf16_lossy(&units), off));
        }
        units.push(c);
    }
    Some((String::from_utf16_lossy(&units), off))
}

pub fn parse_version_info(resources: &[ResourceEntry]) -> Option<VersionStrings> {
    let ver_res = resources
        .iter()
        .find(|r| matches!(r.type_id, ResourceId::Numeric(16)))?;
    let buf = &ver_res.data;
    if buf.len() < 40 {
        return None;
    }

    let mut out = VersionStrings::default();
    let total_len = usize::from(read_u16_le(buf, 0)?).min(buf.len());
    let val_len = usize::from(read_u16_le(buf, 2)?);
    let (_root_key, after_key) = read_utf16_nul_and_end(buf, 6, total_len)?;
    let val_off = align4(after_key);

    if val_len >= 52 && val_off + 52 <= total_len && read_u32_le(buf, val_off) == Some(0xFEEF_04BD) {
        let ms = read_u32_le(buf, val_off + 8).unwrap_or(0);
        let ls = read_u32_le(buf, val_off + 12).unwrap_or(0);
        out.file_version = format!("{}.{}.{}.{}", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF);
    }

    let mut child_off = align4(val_off + val_len);
    while child_off + 6 < total_len {
        let c_len = usize::from(read_u16_le(buf, child_off).unwrap_or(0));
        if c_len < 6 || child_off + c_len > total_len {
            break;
        }
        let c_end = child_off + c_len;
        let (c_key, after_c_key) = read_utf16_nul_and_end(buf, child_off + 6, c_end)?;
        if c_key == "StringFileInfo" {
            let mut tbl_off = align4(after_c_key);
            while tbl_off + 6 < c_end {
                let t_len = usize::from(read_u16_le(buf, tbl_off).unwrap_or(0));
                if t_len < 6 || tbl_off + t_len > c_end {
                    break;
                }
                let t_end = tbl_off + t_len;
                let (_cp_key, after_cp) = read_utf16_nul_and_end(buf, tbl_off + 6, t_end)?;
                let mut str_off = align4(after_cp);
                while str_off + 6 < t_end {
                    let s_len = usize::from(read_u16_le(buf, str_off).unwrap_or(0));
                    if s_len < 6 || str_off + s_len > t_end {
                        break;
                    }
                    let s_end = str_off + s_len;
                    let s_val_words = usize::from(read_u16_le(buf, str_off + 2).unwrap_or(0));
                    let (s_key, after_s_key) = read_utf16_nul_and_end(buf, str_off + 6, s_end)?;
                    let val_start = align4(after_s_key);
                    let val_str = if s_val_words > 0 && val_start < s_end {
                        let byte_span = (s_val_words * 2).min(s_end - val_start);
                        decode_utf16le_nul(&buf[val_start..val_start + byte_span])
                    } else if val_start < s_end {
                        decode_utf16le_nul(&buf[val_start..s_end])
                    } else {
                        String::new()
                    };
                    match s_key.as_str() {
                        "FileVersion" if !val_str.is_empty() => out.file_version = val_str,
                        "ProductName" => out.product_name = val_str,
                        "CompanyName" => out.company_name = val_str,
                        "FileDescription" => out.file_description = val_str,
                        "OriginalFilename" => out.original_filename = val_str,
                        "InternalName" => out.internal_name = val_str,
                        _ => {}
                    }
                    str_off = align4(s_end);
                }
                tbl_off = align4(t_end);
            }
        }
        child_off = align4(c_end);
    }

    Some(out)
}

/// Inspect `IMAGE_DIRECTORY_ENTRY_SECURITY` (DataDir[4]) using RAW FILE OFFSET (never RVA!).
pub fn parse_win_certificate(pe: &PeFile<'_>) -> (bool, Option<u16>) {
    let sec_dir = pe.data_dir(IMAGE_DIRECTORY_ENTRY_SECURITY);
    if sec_dir.virtual_address == 0 || sec_dir.size < 8 {
        return (false, None);
    }
    let raw_off = sec_dir.virtual_address as usize;
    if raw_off.checked_add(8).is_none_or(|end| end > pe.bytes.len()) {
        return (false, None);
    }
    let dw_len = read_u32_le(pe.bytes, raw_off).unwrap_or(0) as usize;
    let cert_type = read_u16_le(pe.bytes, raw_off + 6).unwrap_or(0);
    let valid = dw_len >= 8 && raw_off.saturating_add(dw_len) <= pe.bytes.len();
    (valid, if valid { Some(cert_type) } else { None })
}

pub fn infer_compiler_linker_hint(pe: &PeFile<'_>, is_dotnet: bool) -> String {
    if is_dotnet {
        return "Roslyn / .NET CLR".to_string();
    }
    let maj = pe.optional.major_linker_version;
    let min = pe.optional.minor_linker_version;
    let has_gnu_sec = pe
        .sections
        .iter()
        .any(|s| s.name.starts_with(".eh_fram") || s.name == ".CRT" || s.name == "/4");
    if has_gnu_sec || (maj <= 3 && min >= 20) {
        format!("GNU ld / MinGW (Linker {maj}.{min})")
    } else if maj == 14 {
        format!("MSVC / LLD (Linker {maj}.{min})")
    } else {
        format!("PE Linker {maj}.{min}")
    }
}

pub fn summarize_pe_info(file_path: &str, pe: &PeFile<'_>, resources: &[ResourceEntry]) -> PeInfoSummary {
    let com_dir = pe.data_dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    let is_dotnet = com_dir.virtual_address != 0 && com_dir.size >= 72;
    let ver = parse_version_info(resources).unwrap_or_default();
    let (signed, cert_type) = parse_win_certificate(pe);
    let manifest_xml = resources
        .iter()
        .find(|r| matches!(r.type_id, ResourceId::Numeric(24)))
        .map(|r| String::from_utf8_lossy(&r.data).trim_end_matches('\0').to_string());

    PeInfoSummary {
        file_path: file_path.to_string(),
        machine: pe.machine_name().to_string(),
        subsystem: pe.subsystem_name().to_string(),
        is_dotnet,
        compiler_linker_hint: infer_compiler_linker_hint(pe, is_dotnet),
        entry_point_rva: pe.optional.address_of_entry_point,
        time_date_stamp: pe.coff.time_date_stamp,
        sections_count: pe.coff.number_of_sections,
        file_version: ver.file_version,
        product_name: ver.product_name,
        company_name: ver.company_name,
        file_description: ver.file_description,
        signed,
        cert_type,
        sha256: sha256_hex(pe.bytes),
        manifest_xml,
    }
}
