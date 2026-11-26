use chrono::{DateTime, TimeDelta, Utc};
use sys2rust_core::binary::{
    decode_utf16le, iso8601_to_datetime, read_i32_le, read_u16_le, read_u32_le, read_u64_le, sha256_hex,
};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::backend::{CodecEntry, FirmwareTableEntry, TaskEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTzi {
    pub bias_minutes: i32,
    pub standard_bias: i32,
    pub daylight_bias: i32,
    pub utc_offset_min: i64,
    pub supports_dst: bool,
    pub dst_start_rule: String,
    pub dst_end_rule: String,
}

#[derive(Debug, Clone, Copy)]
struct SystemTimeRule {
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
}

fn parse_systemtime_rule(buf: &[u8], off: usize) -> Option<SystemTimeRule> {
    Some(SystemTimeRule {
        month: read_u16_le(buf, off + 2)?,
        day_of_week: read_u16_le(buf, off + 4)?,
        day: read_u16_le(buf, off + 6)?,
        hour: read_u16_le(buf, off + 8)?,
        minute: read_u16_le(buf, off + 10)?,
    })
}

fn format_dst_rule(rule: SystemTimeRule) -> String {
    if rule.month == 0 {
        return "None".to_string();
    }
    let month_name = match rule.month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "Month?",
    };
    let dow = match rule.day_of_week {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        _ => "Day",
    };
    let nth = match rule.day {
        1 => "1st",
        2 => "2nd",
        3 => "3rd",
        4 => "4th",
        5 => "Last",
        _ => "Nth",
    };
    format!("{month_name} {nth} {dow} {:02}:{:02}", rule.hour, rule.minute)
}

/// Decode a 44-byte `REG_TZI_FORMAT` (`TZI` registry binary value) into UTC offset & DST rules.
pub fn decode_reg_tzi(bytes: &[u8]) -> Sys2RustResult<DecodedTzi> {
    if bytes.len() < 44 {
        return Err(Sys2RustError::Parse {
            format: "REG_TZI_FORMAT",
            detail: format!("expected 44 bytes, got {}", bytes.len()),
        });
    }
    let bias = read_i32_le(bytes, 0).unwrap_or(0);
    let std_bias = read_i32_le(bytes, 4).unwrap_or(0);
    let dst_bias = read_i32_le(bytes, 8).unwrap_or(0);
    let std_date = parse_systemtime_rule(bytes, 12).ok_or_else(|| Sys2RustError::Parse {
        format: "REG_TZI_FORMAT",
        detail: "invalid StandardDate".to_string(),
    })?;
    let dst_date = parse_systemtime_rule(bytes, 28).ok_or_else(|| Sys2RustError::Parse {
        format: "REG_TZI_FORMAT",
        detail: "invalid DaylightDate".to_string(),
    })?;

    let supports_dst = std_date.month != 0 && dst_date.month != 0;
    let _ = dst_bias;
    // Windows Bias is defined as UTC = local + Bias, so local UTC offset in minutes is -(Bias + StandardBias).
    let utc_offset_min = -i64::from(bias.saturating_add(std_bias));

    Ok(DecodedTzi {
        bias_minutes: bias,
        standard_bias: std_bias,
        daylight_bias: dst_bias,
        utc_offset_min,
        supports_dst,
        dst_start_rule: format_dst_rule(dst_date),
        dst_end_rule: format_dst_rule(std_date),
    })
}

pub fn current_local_from_offset(now_utc: DateTime<Utc>, offset_min: i64) -> DateTime<Utc> {
    TimeDelta::try_minutes(offset_min)
        .and_then(|delta| now_utc.checked_add_signed(delta))
        .unwrap_or(now_utc)
}

/// Filter out NULL kernel driver addresses (returned on unprivileged Windows 11 due to KASLR)
/// and deduplicate non-zero addresses while preserving order.
pub fn filter_non_null_driver_addrs(addrs: &[usize]) -> Vec<usize> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for &addr in addrs {
        if addr != 0 && seen.insert(addr) {
            out.push(addr);
        }
    }
    out
}

/// Normalize kernel driver paths returned by `GetDeviceDriverFileNameW` or SCM `QueryServiceConfigW`.
pub fn normalize_driver_path(raw: &str, windir: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return String::new();
    }
    let without_nt = if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case(r"\??\") {
        &trimmed[4..]
    } else {
        trimmed
    };
    let lower = without_nt.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        let orig_rest = &without_nt[r"\systemroot\".len()..];
        let _ = rest;
        format!("{windir}\\{orig_rest}")
    } else if lower.starts_with(r"system32\") {
        format!("{windir}\\{without_nt}")
    } else if lower.starts_with(r"\system32\") {
        format!("{windir}{without_nt}")
    } else {
        without_nt.to_string()
    }
}

/// Parse Windows `SYSTEM.INI` `[drivers32]` section entries (including `;` commented disabled codecs).
pub fn parse_system_ini_drivers32(content: &str) -> Vec<CodecEntry> {
    let mut in_section = false;
    let mut out = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line.eq_ignore_ascii_case("[drivers32]");
            continue;
        }
        if !in_section {
            continue;
        }
        let (disabled, effective) = if let Some(rest) = line.strip_prefix(';') {
            (true, rest.trim())
        } else {
            (false, line)
        };
        if let Some((key, val)) = effective.split_once('=') {
            let name = key.trim();
            let file = val.trim();
            if !name.is_empty() && !file.is_empty() {
                let codec_type = if name.to_ascii_uppercase().starts_with("VIDC") {
                    "VFW Video"
                } else {
                    "ACM Audio"
                };
                out.push(CodecEntry {
                    codec_name: name.to_string(),
                    codec_type: codec_type.to_string(),
                    clsid: String::new(),
                    filename: file.to_string(),
                    merit: 0,
                    disabled,
                    version: String::new(),
                    company: String::new(),
                });
            }
        }
    }
    out
}

/// Parse a Windows Task Scheduler XML file (UTF-8 or UTF-16LE with BOM) via `roxmltree`.
pub fn parse_task_scheduler_xml(folder: &str, task_name: &str, raw_bytes: &[u8]) -> Sys2RustResult<TaskEntry> {
    let xml_text = if raw_bytes.starts_with(&[0xFF, 0xFE]) {
        decode_utf16le(&raw_bytes[2..])
    } else if raw_bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = raw_bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&p| u16::from_be_bytes(p))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw_bytes)
            .trim_start_matches('\u{feff}')
            .to_string()
    };

    let doc = roxmltree::Document::parse(&xml_text).map_err(|e| Sys2RustError::Parse {
        format: "TaskSchedulerXML",
        detail: e.to_string(),
    })?;

    let find_text = |tag: &str| -> Option<String> {
        doc.descendants()
            .find(|n| n.has_tag_name(tag))
            .and_then(|n| n.text())
            .map(|s| s.trim().to_string())
    };

    let enabled = find_text("Enabled")
        .map(|v| !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    let hidden = find_text("Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let wake_to_run = find_text("WakeToRun").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let run_as_user = find_text("UserId").unwrap_or_else(|| "SYSTEM".to_string());
    let start_boundary = find_text("StartBoundary").and_then(|s| iso8601_to_datetime(&s));

    let mut triggers = Vec::new();
    if let Some(t_node) = doc.descendants().find(|n| n.has_tag_name("Triggers")) {
        for ch in t_node.children().filter(|c| c.is_element()) {
            let mut label = ch.tag_name().name().to_string();
            if let Some(sb) = ch
                .descendants()
                .find(|d| d.has_tag_name("StartBoundary"))
                .and_then(|d| d.text())
            {
                label.push_str(&format!("({sb})"));
            }
            triggers.push(label);
        }
    }

    let mut actions = Vec::new();
    if let Some(a_node) = doc.descendants().find(|n| n.has_tag_name("Actions")) {
        for exec in a_node.children().filter(|c| c.is_element()) {
            if exec.has_tag_name("Exec") {
                let cmd = exec
                    .children()
                    .find(|c| c.has_tag_name("Command"))
                    .and_then(|c| c.text())
                    .unwrap_or("");
                let args = exec
                    .children()
                    .find(|c| c.has_tag_name("Arguments"))
                    .and_then(|c| c.text())
                    .unwrap_or("");
                if args.is_empty() {
                    actions.push(cmd.to_string());
                } else {
                    actions.push(format!("{cmd} {args}"));
                }
            } else {
                actions.push(exec.tag_name().name().to_string());
            }
        }
    }

    Ok(TaskEntry {
        task_name: task_name.to_string(),
        folder: folder.to_string(),
        status: if enabled { "Ready" } else { "Disabled" }.to_string(),
        enabled,
        hidden,
        triggers: triggers.join("; "),
        actions: actions.join("; "),
        last_run_time: start_boundary,
        next_run_time: None,
        last_result: 0,
        wake_to_run,
        run_as_user,
    })
}

/// Pure-Rust SMBIOS (`RSMB`) parser supporting Types 0, 1, 2, 3, 4, 16, 17, 19, and 127.
pub fn parse_smbios_raw_data(raw: &[u8]) -> Sys2RustResult<FirmwareTableEntry> {
    if raw.len() < 8 {
        return Err(Sys2RustError::Parse {
            format: "SMBIOS",
            detail: "RawSMBIOSData smaller than 8-byte header".to_string(),
        });
    }
    let major = raw[1];
    let minor = raw[2];
    let table_len = read_u32_le(raw, 4).unwrap_or(0) as usize;
    let stream = raw.get(8..8 + table_len.min(raw.len() - 8)).unwrap_or(&[]);

    let mut pos = 0usize;
    let mut parts = Vec::new();

    while pos + 4 <= stream.len() {
        let stype = stream[pos];
        let slen = usize::from(stream[pos + 1]);
        if slen < 4 || pos + slen > stream.len() {
            return Err(Sys2RustError::Parse {
                format: "SMBIOS",
                detail: format!("invalid structure length {slen} at offset {pos}"),
            });
        }
        let body = &stream[pos..pos + slen];

        // Scan double-NUL terminated string table safely
        let mut str_pos = pos + slen;
        let mut strings = Vec::new();
        while str_pos < stream.len() {
            if stream[str_pos] == 0 {
                if str_pos + 1 < stream.len() && stream[str_pos + 1] == 0 {
                    str_pos += 2;
                    break;
                }
                str_pos += 1;
                if strings.is_empty() {
                    // Empty string table terminated by \0\0
                    if str_pos < stream.len() && stream[str_pos] == 0 {
                        str_pos += 1;
                    }
                    break;
                }
            } else {
                let start = str_pos;
                while str_pos < stream.len() && stream[str_pos] != 0 {
                    str_pos += 1;
                }
                strings.push(String::from_utf8_lossy(&stream[start..str_pos]).to_string());
                if str_pos < stream.len() {
                    str_pos += 1; // consume NUL
                }
                if str_pos < stream.len() && stream[str_pos] == 0 {
                    str_pos += 1; // second NUL terminates table
                    break;
                }
            }
        }
        if str_pos <= pos {
            break;
        }
        pos = str_pos;

        let get_str = |idx_byte: usize| -> String {
            let s_idx = usize::from(*body.get(idx_byte).unwrap_or(&0));
            if s_idx == 0 {
                String::new()
            } else {
                strings.get(s_idx - 1).cloned().unwrap_or_default()
            }
        };

        match stype {
            0 => {
                let vendor = get_str(4);
                let version = get_str(5);
                let date = get_str(8);
                let rom_kb = body.get(9).map(|&b| (usize::from(b) + 1) * 64).unwrap_or(0);
                parts.push(format!("BIOS[{vendor} {version} {date} ROM={rom_kb}KiB]"));
            }
            1 => {
                let mfg = get_str(4);
                let prod = get_str(5);
                let uuid = body.get(8..24).map(format_smbios_uuid).unwrap_or_default();
                parts.push(format!("System[{mfg} {prod} UUID={uuid}]"));
            }
            2 => {
                parts.push(format!("Board[{} {}]", get_str(4), get_str(5)));
            }
            3 => {
                let chassis_type = body.get(5).copied().unwrap_or(0) & 0x7F;
                parts.push(format!("Chassis[{} Type={chassis_type}]", get_str(4)));
            }
            4 => {
                let socket = get_str(4);
                let version = get_str(16);
                let max_mhz = read_u16_le(body, 20).unwrap_or(0);
                let cores = body.get(35).copied().unwrap_or(0);
                parts.push(format!("CPU[{socket}: {version} {max_mhz}MHz {cores}C]"));
            }
            16 => {
                let slots = read_u16_le(body, 13).unwrap_or(0);
                let max_kb = read_u32_le(body, 7).unwrap_or(0);
                parts.push(format!("MemArray[Slots={slots} Max={max_kb}KiB]"));
            }
            17 => {
                let raw_sz = read_u16_le(body, 12).unwrap_or(0);
                let mb = if raw_sz == 0x7FFF {
                    read_u32_le(body, 28).unwrap_or(0)
                } else {
                    u32::from(raw_sz & 0x7FFF)
                };
                let speed = read_u16_le(body, 21).unwrap_or(0);
                let locator = get_str(16);
                let mfg = get_str(23);
                parts.push(format!("DIMM[{locator}: {mb}MiB @{speed}MT/s {mfg}]"));
            }
            19 => {
                let start_kb = read_u32_le(body, 4).unwrap_or(0);
                let end_kb = read_u32_le(body, 8).unwrap_or(0);
                parts.push(format!("MemMap[{start_kb}..{end_kb}KiB]"));
            }
            127 => break,
            _ => {}
        }
    }

    Ok(FirmwareTableEntry {
        provider_signature: "RSMB".to_string(),
        table_id: "SMBIOS".to_string(),
        length: raw.len() as u64,
        oem_id: String::new(),
        oem_table_id: format!("SMBIOS {major}.{minor}"),
        revision: u32::from(major),
        checksum_valid: true,
        decoded_summary: parts.join("; "),
        raw_bytes: raw.to_vec(),
    })
}

fn format_smbios_uuid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

pub fn verify_acpi_checksum(bytes: &[u8]) -> bool {
    if bytes.len() < 36 {
        return false;
    }
    let declared_len = read_u32_le(bytes, 4).unwrap_or(0) as usize;
    if declared_len < 36 || declared_len > bytes.len() {
        return false;
    }
    bytes[..declared_len].iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

pub fn finalize_acpi_checksum(buf: &mut [u8]) {
    if buf.len() < 36 {
        return;
    }
    buf[9] = 0;
    let sum = buf.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    buf[9] = 0u8.wrapping_sub(sum);
}

/// Pure-Rust ACPI SDT table decoder (`RSDT`, `XSDT`, `FACP`, `DSDT`, `MCFG`, `TPM2`, generic SDT).
pub fn parse_acpi_table(raw: &[u8]) -> Sys2RustResult<FirmwareTableEntry> {
    if raw.len() < 36 {
        return Err(Sys2RustError::Parse {
            format: "ACPI",
            detail: "ACPI SDT header smaller than 36 bytes".to_string(),
        });
    }
    let sig = String::from_utf8_lossy(&raw[0..4]).to_string();
    let len = read_u32_le(raw, 4).unwrap_or(raw.len() as u32) as usize;
    let rev = u32::from(raw[8]);
    let checksum_valid = verify_acpi_checksum(raw);
    let oem_id = String::from_utf8_lossy(&raw[10..16])
        .trim_end_matches(['\0', ' '])
        .to_string();
    let oem_table_id = String::from_utf8_lossy(&raw[16..24])
        .trim_end_matches(['\0', ' '])
        .to_string();
    let bounded = &raw[..len.min(raw.len())];

    let summary = match sig.as_str() {
        "RSDT" => {
            let count = bounded.len().saturating_sub(36) / 4;
            format!("RSDT entries={count}")
        }
        "XSDT" => {
            let count = bounded.len().saturating_sub(36) / 8;
            format!("XSDT entries={count}")
        }
        "FACP" => {
            let fw_ctrl = read_u32_le(bounded, 36).unwrap_or(0);
            let dsdt = read_u32_le(bounded, 40).unwrap_or(0);
            let pm_prof = bounded.get(45).copied().unwrap_or(0);
            let sci_int = read_u16_le(bounded, 46).unwrap_or(0);
            format!("FADT: PMProfile={pm_prof}, SCI_INT={sci_int}, FACS={fw_ctrl:#x}, DSDT={dsdt:#x}")
        }
        "DSDT" => {
            let aml_len = bounded.len().saturating_sub(36);
            let hash = sha256_hex(bounded);
            format!("DSDT AML={aml_len} bytes, SHA256={}", &hash[..16])
        }
        "MCFG" => {
            let mut segs = Vec::new();
            let mut off = 44usize;
            while off + 16 <= bounded.len() {
                let base = read_u64_le(bounded, off).unwrap_or(0);
                let seg = read_u16_le(bounded, off + 8).unwrap_or(0);
                let start_bus = bounded[off + 10];
                let end_bus = bounded[off + 11];
                segs.push(format!("seg={seg} base={base:#x} bus={start_bus}..{end_bus}"));
                off += 16;
            }
            format!("MCFG ECAM: {}", segs.join(", "))
        }
        "TPM2" => {
            let pclass = read_u16_le(bounded, 36).unwrap_or(0);
            let ctrl_addr = read_u64_le(bounded, 40).unwrap_or(0);
            let start_method = read_u32_le(bounded, 48).unwrap_or(0);
            let method_name = match start_method {
                6 => "MemoryMappedIO/TIS",
                7 => "CommandResponseBuffer/CRB",
                8 => "CRB+SMC",
                _ => "Other",
            };
            format!("TPM2: Class={pclass}, CtrlArea={ctrl_addr:#x}, StartMethod={start_method} ({method_name})")
        }
        _ => format!("{sig} rev={rev} ({} bytes)", bounded.len()),
    };

    Ok(FirmwareTableEntry {
        provider_signature: "ACPI".to_string(),
        table_id: sig,
        length: bounded.len() as u64,
        oem_id,
        oem_table_id,
        revision: rev,
        checksum_valid,
        decoded_summary: summary,
        raw_bytes: bounded.to_vec(),
    })
}
