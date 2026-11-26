use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;
use sys2rust_core::binary::{read_u16_le, read_u32_le};

use crate::pe::{IMAGE_DIRECTORY_ENTRY_EXPORT, PeFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub function_name: String,
    pub ordinal: u32,
    pub rva: u32,
    pub file_offset: Option<u64>,
    pub forwarded_to: Option<String>,
    pub dll_name: String,
    pub arch: String,
}

pub fn parse_exports(pe: &PeFile<'_>) -> Sys2RustResult<Vec<ExportEntry>> {
    let dir = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if dir.virtual_address == 0 || dir.size < 40 {
        return Ok(Vec::new());
    }
    let Some(exp_off) = pe.rva_to_offset(dir.virtual_address) else {
        return Ok(Vec::new());
    };
    if exp_off + 40 > pe.bytes.len() {
        return Ok(Vec::new());
    }

    let name_rva = read_u32_le(pe.bytes, exp_off + 12).unwrap_or(0);
    let base = read_u32_le(pe.bytes, exp_off + 16).unwrap_or(1);
    let num_functions = read_u32_le(pe.bytes, exp_off + 20).unwrap_or(0).min(65_536) as usize;
    let num_names = read_u32_le(pe.bytes, exp_off + 24).unwrap_or(0).min(65_536) as usize;
    let addr_funcs_rva = read_u32_le(pe.bytes, exp_off + 28).unwrap_or(0);
    let addr_names_rva = read_u32_le(pe.bytes, exp_off + 32).unwrap_or(0);
    let addr_ords_rva = read_u32_le(pe.bytes, exp_off + 36).unwrap_or(0);

    let dll_name = pe
        .read_cstr_rva(name_rva, 256)
        .unwrap_or_else(|| "<unknown>.dll".to_string());
    let arch = pe.machine_name().to_string();

    let Some(funcs_off) = pe.rva_to_offset(addr_funcs_rva) else {
        return Ok(Vec::new());
    };

    let mut ordinal_to_name: BTreeMap<usize, String> = BTreeMap::new();
    if let (Some(names_off), Some(ords_off)) = (pe.rva_to_offset(addr_names_rva), pe.rva_to_offset(addr_ords_rva)) {
        for i in 0..num_names {
            let Some(name_str_rva) = read_u32_le(pe.bytes, names_off + i * 4) else {
                break;
            };
            let Some(func_idx) = read_u16_le(pe.bytes, ords_off + i * 2) else {
                break;
            };
            let func_name = pe
                .read_cstr_rva(name_str_rva, 512)
                .unwrap_or_else(|| format!("#Name_{i}"));
            ordinal_to_name.entry(usize::from(func_idx)).or_insert(func_name);
        }
    }

    let exp_start = dir.virtual_address;
    let exp_end = dir.virtual_address.saturating_add(dir.size);
    let mut entries = Vec::new();

    for idx in 0..num_functions {
        let Some(func_rva) = read_u32_le(pe.bytes, funcs_off + idx * 4) else {
            break;
        };
        if func_rva == 0 {
            continue;
        }
        let ordinal = base.saturating_add(idx as u32);
        let function_name = ordinal_to_name
            .get(&idx)
            .cloned()
            .unwrap_or_else(|| format!("#Ordinal_{ordinal}"));

        let is_forwarder = func_rva >= exp_start && func_rva < exp_end;
        let (file_offset, forwarded_to) = if is_forwarder {
            (None, pe.read_cstr_rva(func_rva, 512))
        } else {
            (pe.rva_to_offset(func_rva).map(|o| o as u64), None)
        };

        entries.push(ExportEntry {
            function_name,
            ordinal,
            rva: func_rva,
            file_offset,
            forwarded_to,
            dll_name: dll_name.clone(),
            arch: arch.clone(),
        });
    }

    Ok(entries)
}
