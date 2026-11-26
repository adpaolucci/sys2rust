use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sys2rust_core::binary::{decode_utf16le_nul, filetime_to_datetime, format_guid_le, read_u32_le, read_u64_le};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::backend::{AppxPkgItem, DesktopIconItem, TrayIconItem};

/// Decoded `Explorer\StartupApproved` 12-byte REG_BINARY entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupApprovedState {
    pub disabled: bool,
    pub changed_at: Option<DateTime<Utc>>,
}

/// Decode `Explorer\StartupApproved\{Run,Run32,StartupFolder}` binary value.
/// Byte 0: even (`0x02`, `0x06`) = enabled; odd (`0x03`, `0x07`, etc.) = disabled.
/// Bytes `4..12`: little-endian Windows FILETIME.
pub fn decode_startup_approved(bytes: &[u8]) -> Option<StartupApprovedState> {
    if bytes.len() < 12 {
        return None;
    }
    let disabled = (bytes[0] & 0x01) != 0;
    let ft = read_u64_le(bytes, 4).unwrap_or(0);
    Some(StartupApprovedState {
        disabled,
        changed_at: filetime_to_datetime(ft),
    })
}

pub fn encode_startup_approved(disabled: bool, changed_at: Option<DateTime<Utc>>) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = if disabled { 0x03 } else { 0x02 };
    if disabled && let Some(dt) = changed_at {
        let ft = sys2rust_core::binary::datetime_to_filetime(dt);
        out[4..12].copy_from_slice(&ft.to_le_bytes());
    }
    out
}

/// Apply ROT13 transformation to ASCII alphabetic characters (used by Windows TrayNotify streams).
pub fn rot13_str(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            other => other,
        })
        .collect()
}

/// Parse Windows 7–10 `TrayNotify\IconStreams` or `PastIconsStream` binary blobs.
/// 20-byte header followed by 1640-byte records:
/// - `[0..528]`: UTF-16LE NUL-terminated ROT13 executable path
/// - `[528..532]`: `u32` visibility (`0` = OnlyNotifications, `1` = Hide, `2` = Show)
/// - `[532..1044]` (or nearby UTF-16LE): ROT13 tooltip string
/// - `[1044..1060]`: 16-byte GUID (optional)
pub fn parse_tray_notify_stream(stream_name: &str, bytes: &[u8]) -> Vec<TrayIconItem> {
    const HEADER_LEN: usize = 20;
    const RECORD_LEN: usize = 1640;
    if bytes.len() < HEADER_LEN + RECORD_LEN {
        return Vec::new();
    }

    let mut items = Vec::new();
    let mut off = HEADER_LEN;
    while off + RECORD_LEN <= bytes.len() {
        let rec = &bytes[off..off + RECORD_LEN];
        let raw_exe = decode_utf16le_nul(&rec[0..528]);
        let exe = rot13_str(&raw_exe);
        let vis_code = read_u32_le(rec, 528).unwrap_or(0);
        let visibility = match vis_code {
            1 => "Hide".to_string(),
            2 => "Show".to_string(),
            _ => "OnlyNotifications".to_string(),
        };
        let raw_tip = decode_utf16le_nul(&rec[532..1044]);
        let tip = rot13_str(&raw_tip);
        let guid = if let Ok(arr) = <[u8; 16]>::try_from(&rec[1044..1060]) {
            if arr.iter().any(|&b| b != 0) {
                format_guid_le(&arr)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        if !exe.is_empty() {
            items.push(TrayIconItem {
                executable: exe,
                tip_text: tip,
                guid,
                visibility,
                registry_key: format!(
                    r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify\{stream_name}"
                ),
            });
        }
        off += RECORD_LEN;
    }
    items
}

/// Parse `AppxManifest.xml` using `roxmltree`.
pub fn parse_appx_manifest_xml(install_location: &str, family_name: &str, xml: &str) -> Sys2RustResult<AppxPkgItem> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| Sys2RustError::Parse {
        format: "AppxManifest.xml",
        detail: e.to_string(),
    })?;

    let identity = doc.descendants().find(|n| n.has_tag_name("Identity"));
    let package_name = identity
        .and_then(|n| n.attribute("Name"))
        .unwrap_or("UnknownPackage")
        .to_string();
    let version = identity
        .and_then(|n| n.attribute("Version"))
        .unwrap_or("0.0.0.0")
        .to_string();
    let publisher = identity
        .and_then(|n| n.attribute("Publisher"))
        .unwrap_or("")
        .to_string();
    let architecture = identity
        .and_then(|n| n.attribute("ProcessorArchitecture"))
        .unwrap_or("neutral")
        .to_string();

    let is_framework = doc
        .descendants()
        .find(|n| n.has_tag_name("Framework"))
        .and_then(|n| n.text())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("true"));

    let app_id = doc
        .descendants()
        .find(|n| n.has_tag_name("Application"))
        .and_then(|n| n.attribute("Id"))
        .unwrap_or("App");

    let app_user_model_id = if family_name.is_empty() {
        format!("{package_name}!{app_id}")
    } else {
        format!("{family_name}!{app_id}")
    };

    Ok(AppxPkgItem {
        package_name,
        family_name: family_name.to_string(),
        version,
        publisher,
        architecture,
        install_location: install_location.to_string(),
        is_framework,
        non_removable: false,
        app_user_model_id,
    })
}

/// Serialize desktop icon positions to DesktopOK-compatible INI text.
pub fn serialize_desktopok_ini(profile: &str, icons: &[DesktopIconItem]) -> String {
    let mut out = format!("[DesktopOK]\nProfile={profile}\nCount={}\n", icons.len());
    for (idx, icon) in icons.iter().enumerate() {
        out.push_str(&format!(
            "\n[Icon_{idx}]\nName={}\nX={}\nY={}\nMonitor={}\n",
            icon.icon_name, icon.x, icon.y, icon.monitor
        ));
    }
    out
}

/// Parse DesktopOK-compatible INI text into `DesktopIconItem`s.
pub fn parse_desktopok_ini(ini: &str) -> Vec<DesktopIconItem> {
    let mut profile = "Default".to_string();
    let mut icons = Vec::new();
    let mut cur_section = String::new();
    let mut cur_name: Option<String> = None;
    let mut cur_x: i32 = 0;
    let mut cur_y: i32 = 0;
    let mut cur_mon = "Primary".to_string();
    let now = Utc::now();

    let flush = |icons: &mut Vec<DesktopIconItem>,
                 cur_name: &mut Option<String>,
                 cur_x: &mut i32,
                 cur_y: &mut i32,
                 cur_mon: &mut String,
                 profile: &str| {
        if let Some(name) = cur_name.take() {
            icons.push(DesktopIconItem {
                icon_name: name,
                x: *cur_x,
                y: *cur_y,
                monitor: cur_mon.clone(),
                profile_name: profile.to_string(),
                saved_at: now,
            });
        }
        *cur_x = 0;
        *cur_y = 0;
        *cur_mon = "Primary".to_string();
    };

    for raw in ini.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if cur_section.starts_with("Icon_") {
                flush(
                    &mut icons,
                    &mut cur_name,
                    &mut cur_x,
                    &mut cur_y,
                    &mut cur_mon,
                    &profile,
                );
            }
            cur_section = line[1..line.len() - 1].to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if cur_section == "DesktopOK" && key.eq_ignore_ascii_case("Profile") {
                profile = val.to_string();
            } else if cur_section.starts_with("Icon_") {
                match key {
                    "Name" => cur_name = Some(val.to_string()),
                    "X" => cur_x = val.parse().unwrap_or(0),
                    "Y" => cur_y = val.parse().unwrap_or(0),
                    "Monitor" => cur_mon = val.to_string(),
                    _ => {}
                }
            }
        }
    }
    if cur_section.starts_with("Icon_") {
        flush(
            &mut icons,
            &mut cur_name,
            &mut cur_x,
            &mut cur_y,
            &mut cur_mon,
            &profile,
        );
    }
    icons
}

/// Validate `CleanAfterMe` privacy categories (rejects empty or unknown categories).
pub fn validate_privacy_categories(categories: &[String]) -> Sys2RustResult<Vec<&'static str>> {
    if categories.is_empty() {
        return Err(Sys2RustError::InvalidArgument(
            "clean_privacy requires explicit non-empty categories".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(categories.len());
    for cat in categories {
        let canonical = if cat.eq_ignore_ascii_case("RunMRU") {
            "RunMRU"
        } else if cat.eq_ignore_ascii_case("TypedPaths") {
            "TypedPaths"
        } else if cat.eq_ignore_ascii_case("WordWheelQuery") {
            "WordWheelQuery"
        } else if cat.eq_ignore_ascii_case("Temp") {
            "Temp"
        } else {
            return Err(Sys2RustError::InvalidArgument(format!(
                "unknown privacy category '{cat}'; expected one of RunMRU, TypedPaths, WordWheelQuery, Temp"
            )));
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// Resolve a DesktopOK profile argument either as an explicit file path or under
/// `<config_dir>/sys2rust/desktop_profiles/<profile>.ini`.
pub fn resolve_desktop_profile_path(profile: &str) -> PathBuf {
    let trimmed = profile.trim();
    let p = Path::new(trimmed);
    if p.exists()
        || p.is_absolute()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.to_ascii_lowercase().ends_with(".ini")
    {
        return p.to_path_buf();
    }
    let base = dirs::config_dir().unwrap_or_else(std::env::temp_dir);
    base.join("sys2rust")
        .join("desktop_profiles")
        .join(format!("{trimmed}.ini"))
}
