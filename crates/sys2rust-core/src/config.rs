use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sys2RustConfig {
    pub pid_filter: Option<u32>,
    pub include_system: bool,
    pub max_heap_blocks: usize,
    pub etw_capture_ms: u64,
    pub handle_query_timeout_ms: u64,
    pub wmi_namespace: String,
    pub wmi_query: String,
    pub pe_target: Option<PathBuf>,
    pub extract_dir: Option<PathBuf>,
    pub allow_mutating: bool,
    pub offline_fixture_dir: Option<PathBuf>,
}

impl Default for Sys2RustConfig {
    fn default() -> Self {
        Self {
            pid_filter: None,
            include_system: true,
            max_heap_blocks: 512,
            etw_capture_ms: 250,
            handle_query_timeout_ms: 50,
            wmi_namespace: r"root\cimv2".to_string(),
            wmi_query:
                "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime FROM Win32_OperatingSystem"
                    .to_string(),
            pe_target: None,
            extract_dir: None,
            allow_mutating: false,
            offline_fixture_dir: None,
        }
    }
}
