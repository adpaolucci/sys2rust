use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;
use walkdir::WalkDir;

use crate::dotnet::parse_dotnet_metadata;
use crate::pe::PeFile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GacAssemblyEntry {
    pub assembly_name: String,
    pub version: String,
    pub culture: String,
    pub public_key_token: String,
    pub processor_arch: String,
    pub file_path: String,
    pub modified_time: Option<DateTime<Utc>>,
    pub file_size: u64,
}

pub fn default_gac_roots() -> Vec<PathBuf> {
    let windir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    vec![windir.join("Microsoft.NET").join("assembly"), windir.join("assembly")]
}

pub fn scan_gac_roots(roots: &[PathBuf]) -> Sys2RustResult<Vec<GacAssemblyEntry>> {
    let mut entries = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for dent in WalkDir::new(root).min_depth(2).max_depth(5).into_iter().flatten() {
            if !dent.file_type().is_file() {
                continue;
            }
            let path = dent.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("dll") && !ext.eq_ignore_ascii_case("exe") {
                continue;
            }
            if let Some(entry) = parse_gac_file_entry(path) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

fn parse_gac_file_entry(path: &Path) -> Option<GacAssemblyEntry> {
    let meta = fs::metadata(path).ok()?;
    let modified_time = meta.modified().ok().map(DateTime::<Utc>::from);
    let file_size = meta.len();

    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let len = comps.len();
    let ver_dir = len
        .checked_sub(2)
        .and_then(|i| comps.get(i))
        .cloned()
        .unwrap_or_default();
    let name_dir = len
        .checked_sub(3)
        .and_then(|i| comps.get(i))
        .cloned()
        .unwrap_or_default();
    let gac_bucket = len
        .checked_sub(4)
        .and_then(|i| comps.get(i))
        .cloned()
        .unwrap_or_default();

    let (mut version, mut culture, pkt) = parse_gac_ver_folder(&ver_dir);
    let mut assembly_name = if !name_dir.is_empty() {
        name_dir
    } else {
        path.file_stem()?.to_string_lossy().to_string()
    };

    if let Ok(bytes) = fs::read(path)
        && let Ok(pe) = PeFile::parse(&bytes)
        && let Ok(Some(dn)) = parse_dotnet_metadata(&pe)
    {
        if !dn.assembly_name.is_empty() {
            assembly_name = dn.assembly_name;
        }
        if !dn.version.is_empty() {
            version = dn.version;
        }
        if !dn.culture.is_empty() {
            culture = dn.culture;
        }
    }

    let processor_arch = if gac_bucket.contains("64") {
        "AMD64".to_string()
    } else if gac_bucket.contains("32") {
        "x86".to_string()
    } else {
        "MSIL".to_string()
    };

    Some(GacAssemblyEntry {
        assembly_name,
        version,
        culture,
        public_key_token: pkt,
        processor_arch,
        file_path: path.display().to_string(),
        modified_time,
        file_size,
    })
}

fn parse_gac_ver_folder(folder: &str) -> (String, String, String) {
    let stripped = folder.strip_prefix("v4.0_").unwrap_or(folder);
    let parts: Vec<&str> = stripped.split('_').collect();
    match parts.as_slice() {
        [ver, cult, pkt, ..] => (
            (*ver).to_string(),
            if cult.is_empty() {
                "neutral".to_string()
            } else {
                (*cult).to_string()
            },
            (*pkt).to_string(),
        ),
        [ver, pkt] => ((*ver).to_string(), "neutral".to_string(), (*pkt).to_string()),
        _ => (stripped.to_string(), "neutral".to_string(), String::new()),
    }
}
