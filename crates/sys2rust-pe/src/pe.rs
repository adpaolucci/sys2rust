use sys2rust_core::binary::{read_u16_le, read_u32_le, read_u64_le};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub kind: PeKind,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeFile<'a> {
    pub bytes: &'a [u8],
    pub e_lfanew: usize,
    pub coff: CoffHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<SectionHeader>,
}

impl<'a> PeFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Sys2RustResult<Self> {
        if bytes.len() < 64 {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: "file smaller than 64-byte DOS header".to_string(),
            });
        }
        let dos_magic = read_u16_le(bytes, 0).ok_or_else(|| Sys2RustError::Parse {
            format: "PE",
            detail: "missing DOS header".to_string(),
        })?;
        if dos_magic != IMAGE_DOS_SIGNATURE {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: format!("invalid DOS magic {dos_magic:#06x}, expected 0x5A4D"),
            });
        }
        let e_lfanew = read_u32_le(bytes, 0x3C).ok_or_else(|| Sys2RustError::Parse {
            format: "PE",
            detail: "missing e_lfanew".to_string(),
        })? as usize;

        if e_lfanew.checked_add(24).is_none_or(|end| end > bytes.len()) {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: format!("e_lfanew ({e_lfanew:#x}) out of bounds"),
            });
        }
        let pe_sig = read_u32_le(bytes, e_lfanew).ok_or_else(|| Sys2RustError::Parse {
            format: "PE",
            detail: "missing PE signature".to_string(),
        })?;
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: format!("invalid PE signature {pe_sig:#010x}"),
            });
        }

        let coff_off = e_lfanew + 4;
        let machine = read_u16_le(bytes, coff_off).unwrap_or(0);
        let number_of_sections = read_u16_le(bytes, coff_off + 2).unwrap_or(0);
        let time_date_stamp = read_u32_le(bytes, coff_off + 4).unwrap_or(0);
        let size_of_optional_header = read_u16_le(bytes, coff_off + 16).unwrap_or(0);
        let characteristics = read_u16_le(bytes, coff_off + 18).unwrap_or(0);

        let opt_off = coff_off + 20;
        let opt_end = opt_off
            .checked_add(usize::from(size_of_optional_header))
            .ok_or_else(|| Sys2RustError::Parse {
                format: "PE",
                detail: "optional header overflow".to_string(),
            })?;
        if opt_end > bytes.len() || size_of_optional_header < 96 {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: format!("invalid optional header size {size_of_optional_header}"),
            });
        }

        let magic = read_u16_le(bytes, opt_off).ok_or_else(|| Sys2RustError::Parse {
            format: "PE",
            detail: "missing optional header magic".to_string(),
        })?;

        let major_linker_version = bytes[opt_off + 2];
        let minor_linker_version = bytes[opt_off + 3];
        let address_of_entry_point = read_u32_le(bytes, opt_off + 16).unwrap_or(0);

        let (kind, image_base, subsystem, dll_characteristics, num_rva_off, dd_off) = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let image_base = u64::from(read_u32_le(bytes, opt_off + 28).unwrap_or(0));
                let subsystem = read_u16_le(bytes, opt_off + 68).unwrap_or(0);
                let dll_chars = read_u16_le(bytes, opt_off + 70).unwrap_or(0);
                (
                    PeKind::Pe32,
                    image_base,
                    subsystem,
                    dll_chars,
                    opt_off + 92,
                    opt_off + 96,
                )
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                if size_of_optional_header < 112 {
                    return Err(Sys2RustError::Parse {
                        format: "PE",
                        detail: "truncated PE32+ optional header".to_string(),
                    });
                }
                let image_base = read_u64_le(bytes, opt_off + 24).unwrap_or(0);
                let subsystem = read_u16_le(bytes, opt_off + 68).unwrap_or(0);
                let dll_chars = read_u16_le(bytes, opt_off + 70).unwrap_or(0);
                (
                    PeKind::Pe32Plus,
                    image_base,
                    subsystem,
                    dll_chars,
                    opt_off + 108,
                    opt_off + 112,
                )
            }
            other => {
                return Err(Sys2RustError::Parse {
                    format: "PE",
                    detail: format!("unsupported optional header magic {other:#06x}"),
                });
            }
        };

        let num_dirs = read_u32_le(bytes, num_rva_off).unwrap_or(0).min(16) as usize;
        let mut data_directories = Vec::with_capacity(16);
        for i in 0..16 {
            if i < num_dirs && dd_off + (i + 1) * 8 <= opt_end {
                let va = read_u32_le(bytes, dd_off + i * 8).unwrap_or(0);
                let sz = read_u32_le(bytes, dd_off + i * 8 + 4).unwrap_or(0);
                data_directories.push(DataDirectory {
                    virtual_address: va,
                    size: sz,
                });
            } else {
                data_directories.push(DataDirectory::default());
            }
        }

        let sec_table_off = opt_end;
        let sec_count = usize::from(number_of_sections);
        let sec_end = sec_table_off
            .checked_add(sec_count.saturating_mul(40))
            .ok_or_else(|| Sys2RustError::Parse {
                format: "PE",
                detail: "section table overflow".to_string(),
            })?;
        if sec_end > bytes.len() {
            return Err(Sys2RustError::Parse {
                format: "PE",
                detail: "section table extends past EOF".to_string(),
            });
        }

        let mut sections = Vec::with_capacity(sec_count);
        for i in 0..sec_count {
            let off = sec_table_off + i * 40;
            let raw_name = &bytes[off..off + 8];
            let end_nul = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..end_nul]).to_string();
            sections.push(SectionHeader {
                name,
                virtual_size: read_u32_le(bytes, off + 8).unwrap_or(0),
                virtual_address: read_u32_le(bytes, off + 12).unwrap_or(0),
                size_of_raw_data: read_u32_le(bytes, off + 16).unwrap_or(0),
                pointer_to_raw_data: read_u32_le(bytes, off + 20).unwrap_or(0),
                characteristics: read_u32_le(bytes, off + 36).unwrap_or(0),
            });
        }

        Ok(Self {
            bytes,
            e_lfanew,
            coff: CoffHeader {
                machine,
                number_of_sections,
                time_date_stamp,
                size_of_optional_header,
                characteristics,
            },
            optional: OptionalHeader {
                kind,
                major_linker_version,
                minor_linker_version,
                address_of_entry_point,
                image_base,
                subsystem,
                dll_characteristics,
                data_directories,
            },
            sections,
        })
    }

    pub fn data_dir(&self, index: usize) -> DataDirectory {
        self.optional.data_directories.get(index).copied().unwrap_or_default()
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let span = sec.virtual_size.max(sec.size_of_raw_data);
            if span == 0 {
                continue;
            }
            let end_rva = sec.virtual_address.saturating_add(span);
            if rva >= sec.virtual_address && rva < end_rva {
                let delta = rva - sec.virtual_address;
                if delta < sec.size_of_raw_data {
                    let offset = usize::try_from(sec.pointer_to_raw_data.checked_add(delta)?).ok()?;
                    if offset < self.bytes.len() {
                        return Some(offset);
                    }
                }
            }
        }
        None
    }

    pub fn slice_rva(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        let off = self.rva_to_offset(rva)?;
        let end = off.checked_add(len)?;
        self.bytes.get(off..end)
    }

    pub fn read_cstr_rva(&self, rva: u32, max_len: usize) -> Option<String> {
        let off = self.rva_to_offset(rva)?;
        let tail = self.bytes.get(off..)?;
        let limit = tail.len().min(max_len);
        let end = tail[..limit].iter().position(|&b| b == 0).unwrap_or(limit);
        Some(String::from_utf8_lossy(&tail[..end]).to_string())
    }

    pub fn machine_name(&self) -> &'static str {
        machine_name(self.coff.machine)
    }

    pub fn subsystem_name(&self) -> &'static str {
        subsystem_name(self.optional.subsystem)
    }
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86 (0x014C)",
        0x8664 => "x64 (0x8664)",
        0xAA64 => "ARM64 (0xAA64)",
        0x01C4 => "ARMv7 Thumb-2 (0x01C4)",
        0x0200 => "IA64 (0x0200)",
        _ => "Unknown",
    }
}

pub fn subsystem_name(sub: u16) -> &'static str {
    match sub {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        14 => "Xbox",
        _ => "Unknown",
    }
}
