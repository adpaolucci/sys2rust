use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;
use sys2rust_core::binary::{decode_utf16le, decode_utf16le_nul, read_u32_le, read_u64_le};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub image_path: String,
    pub session_id: u32,
    pub user: String,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub cpu_time_ms: u64,
    pub integrity_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEntry {
    pub tid: u32,
    pub pid: u32,
    pub process_name: String,
    pub start_address: u64,
    pub context_switches: u64,
    pub priority: i32,
    pub base_priority: i32,
    pub state: String,
    pub wait_reason: String,
    pub user_time_ms: u64,
    pub kernel_time_ms: u64,
    pub created_time: Option<DateTime<Utc>>,
    pub suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedDllEntry {
    pub dll_path: String,
    pub dll_name: String,
    pub process_count: u32,
    pub processes: String,
    pub base_address: u64,
    pub size_bytes: u64,
    pub product_name: String,
    pub file_version: String,
    pub company: String,
    pub signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleEntry {
    pub pid: u32,
    pub process_name: String,
    pub handle_value: u64,
    pub object_type: String,
    pub object_name: String,
    pub access_mask: u32,
    pub handle_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFileEntry {
    pub filename: String,
    pub full_path: String,
    pub handle: u64,
    pub pid: u32,
    pub process_name: String,
    pub user_name: String,
    pub access_mask: u32,
    pub sharing_mode: String,
    pub file_offset: u64,
    pub process_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileActivityEntry {
    pub file_path: String,
    pub open_count: u64,
    pub close_count: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub last_activity_time: DateTime<Utc>,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapBlockEntry {
    pub pid: u32,
    pub heap_id: u64,
    pub block_address: u64,
    pub size_bytes: u64,
    pub flags: String,
    pub ascii_preview: String,
    pub hex_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdiProcessEntry {
    pub pid: u32,
    pub process_name: String,
    pub pen: u32,
    pub brush: u32,
    pub font: u32,
    pub bitmap: u32,
    pub region: u32,
    pub dc: u32,
    pub metafile: u32,
    pub other_gdi: u32,
    pub all_gdi: u32,
    pub user_objects: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HungWindowEntry {
    pub pid: u32,
    pub process_name: String,
    pub window_title: String,
    pub hang_duration_ms: u64,
    pub blocked_thread_id: u32,
    pub wait_reason: String,
    pub call_stack: String,
    pub loaded_modules: String,
    pub environment_strings: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEventEntry {
    pub event_time: DateTime<Utc>,
    pub event_type: String,
    pub pid: u32,
    pub tid: u32,
    pub address: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionEntry {
    pub pid: u32,
    pub base_address: u64,
    pub region_size: u64,
    pub state: String,
    pub protect: String,
    pub mem_type: String,
    pub mapped_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEnvEntry {
    pub pid: u32,
    pub process_name: String,
    pub current_dir: String,
    pub env_var_name: String,
    pub env_var_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwLifecycleEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: String,
    pub exit_code: i32,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEtwEvent {
    pub provider_guid: String,
    pub event_id: u16,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub user_data: Vec<u8>,
}

pub trait ProcBackend: Send + Sync {
    fn list_processes(&self) -> Sys2RustResult<Vec<ProcessEntry>>;
    fn list_threads(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ThreadEntry>>;
    fn list_loaded_dlls(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<LoadedDllEntry>>;
    fn list_handles(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HandleEntry>>;
    fn list_open_files(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<OpenFileEntry>>;
    fn collect_file_activity(&self) -> Sys2RustResult<Vec<FileActivityEntry>>;
    fn list_heap_blocks(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HeapBlockEntry>>;
    fn list_gdi_counts(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<GdiProcessEntry>>;
    fn detect_hung_windows(&self) -> Sys2RustResult<Vec<HungWindowEntry>>;
    fn list_debug_events(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<DebugEventEntry>>;
    fn list_memory_regions(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<MemoryRegionEntry>>;
    fn list_process_env(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ProcessEnvEntry>>;
    fn collect_etw_lifecycle(&self) -> Sys2RustResult<Vec<EtwLifecycleEntry>>;

    // Mutating operations (strictly standard Win32, zero DLL injection)
    fn terminate_process(&self, pid: u32, exit_code: u32, dry_run: bool) -> Sys2RustResult<String>;
    fn control_thread(&self, tid: u32, suspend: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn close_remote_handle(&self, pid: u32, handle: u64, dry_run: bool) -> Sys2RustResult<String>;
    fn attach_debugger_probe(&self, pid: u32, timeout_ms: u64, dry_run: bool) -> Sys2RustResult<Vec<DebugEventEntry>>;
}

/// Bounded timeout worker wrapper preventing `NtQueryObject(ObjectNameInformation)` from
/// blocking indefinitely on synchronous named pipe handles.
pub fn query_with_timeout<F>(timeout_ms: u64, stalled_counter: &AtomicUsize, work: F) -> String
where
    F: FnOnce() -> Option<String> + Send + 'static,
{
    const MAX_STALLED_WORKERS: usize = 8;
    if stalled_counter.load(Ordering::Relaxed) >= MAX_STALLED_WORKERS {
        return "<pipe guard active: stalled worker cap reached>".to_string();
    }
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    match rx.recv_timeout(Duration::from_millis(timeout_ms.max(1))) {
        Ok(Some(name)) => name,
        Ok(None) => String::new(),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            stalled_counter.fetch_add(1, Ordering::Relaxed);
            "<query timeout: possible synchronous pipe>".to_string()
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => String::new(),
    }
}

/// Pure-Rust decoder for `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`)
/// synthetic/captured `RawEtwEvent` user_data records.
///
/// Layout supported for `event_id`:
/// - `12` (`Create` / NameCreate): `u64 file_key` + UTF-16LE NUL-terminated path
/// - `14` (`Close`): `u64 file_key` + optional UTF-16LE path
/// - `15` (`Read`): `u64 file_key` + `u32 io_size` + optional UTF-16LE path
/// - `16` (`Write`): `u64 file_key` + `u32 io_size` + optional UTF-16LE path
pub fn decode_kernel_file_events(events: &[RawEtwEvent]) -> Vec<FileActivityEntry> {
    let mut key_to_path: BTreeMap<(u32, u64), String> = BTreeMap::new();
    let mut stats: BTreeMap<(u32, String), FileActivityEntry> = BTreeMap::new();

    for ev in events {
        let file_key = read_u64_le(&ev.user_data, 0).unwrap_or(0);
        let (io_size, path_off) = match ev.event_id {
            15 | 16 => (u64::from(read_u32_le(&ev.user_data, 8).unwrap_or(0)), 12usize),
            _ => (0u64, 8usize),
        };
        let inline_path = ev.user_data.get(path_off..).map(decode_utf16le_nul).unwrap_or_default();

        let resolved_path = if !inline_path.is_empty() {
            if file_key != 0 {
                key_to_path.insert((ev.pid, file_key), inline_path.clone());
            }
            inline_path
        } else if let Some(known) = key_to_path.get(&(ev.pid, file_key)) {
            known.clone()
        } else {
            format!("<FileKey:{file_key:#x}>")
        };

        let entry = stats
            .entry((ev.pid, resolved_path.clone()))
            .or_insert_with(|| FileActivityEntry {
                file_path: resolved_path,
                open_count: 0,
                close_count: 0,
                read_count: 0,
                write_count: 0,
                read_bytes: 0,
                write_bytes: 0,
                last_activity_time: ev.timestamp,
                pid: ev.pid,
            });

        if ev.timestamp > entry.last_activity_time {
            entry.last_activity_time = ev.timestamp;
        }

        match ev.event_id {
            10 | 12 | 30 => entry.open_count += 1,
            14 => entry.close_count += 1,
            15 => {
                entry.read_count += 1;
                entry.read_bytes = entry.read_bytes.saturating_add(io_size);
            }
            16 => {
                entry.write_count += 1;
                entry.write_bytes = entry.write_bytes.saturating_add(io_size);
            }
            _ => {}
        }
    }

    stats.into_values().collect()
}

/// Pure-Rust decoder for `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`).
///
/// Layout supported for `event_id`:
/// - `1` (`ProcessStart`): `u32 pid`, `u32 ppid`, UTF-16LE NUL `image_path`, UTF-16LE NUL `command_line`
/// - `2` (`ProcessStop`): `u32 pid`, `i32 exit_code`, UTF-16LE NUL `image_path`
/// - `5` (`ImageLoad`): `u32 pid`, UTF-16LE NUL `image_path`
pub fn decode_kernel_process_events(events: &[RawEtwEvent]) -> Vec<EtwLifecycleEntry> {
    let mut out = Vec::new();
    for ev in events {
        match ev.event_id {
            1 => {
                let pid = read_u32_le(&ev.user_data, 0).unwrap_or(ev.pid);
                let ppid = read_u32_le(&ev.user_data, 4).unwrap_or(0);
                let rest = ev.user_data.get(8..).unwrap_or(&[]);
                let (img, consumed) = split_utf16_nul(rest);
                let cmd = rest.get(consumed..).map(decode_utf16le_nul).unwrap_or_default();
                out.push(EtwLifecycleEntry {
                    timestamp: ev.timestamp,
                    event_type: "ProcessStart".to_string(),
                    pid,
                    parent_pid: ppid,
                    image_path: img,
                    exit_code: 0,
                    command_line: cmd,
                });
            }
            2 => {
                let pid = read_u32_le(&ev.user_data, 0).unwrap_or(ev.pid);
                let exit_code = read_u32_le(&ev.user_data, 4).unwrap_or(0) as i32;
                let img = ev.user_data.get(8..).map(decode_utf16le_nul).unwrap_or_default();
                out.push(EtwLifecycleEntry {
                    timestamp: ev.timestamp,
                    event_type: "ProcessStop".to_string(),
                    pid,
                    parent_pid: 0,
                    image_path: img,
                    exit_code,
                    command_line: String::new(),
                });
            }
            5 => {
                let pid = read_u32_le(&ev.user_data, 0).unwrap_or(ev.pid);
                let img = ev.user_data.get(4..).map(decode_utf16le_nul).unwrap_or_default();
                out.push(EtwLifecycleEntry {
                    timestamp: ev.timestamp,
                    event_type: "ImageLoad".to_string(),
                    pid,
                    parent_pid: 0,
                    image_path: img,
                    exit_code: 0,
                    command_line: String::new(),
                });
            }
            other => {
                out.push(EtwLifecycleEntry {
                    timestamp: ev.timestamp,
                    event_type: format!("Event_{other}"),
                    pid: ev.pid,
                    parent_pid: 0,
                    image_path: String::new(),
                    exit_code: 0,
                    command_line: String::new(),
                });
            }
        }
    }
    out
}

fn split_utf16_nul(bytes: &[u8]) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

/// Parse a UTF-16LE `\0`-delimited, `\0\0`-terminated Windows PEB environment block.
pub fn parse_peb_environment_block(bytes: &[u8]) -> Vec<(String, String)> {
    let decoded = decode_utf16le(bytes);
    let mut pairs = Vec::new();
    for entry in decoded.split('\0') {
        if entry.is_empty() {
            break;
        }
        // Handle drive-letter special entries like `=C:=C:\work` safely
        let split_pos = if let Some(rest) = entry.strip_prefix('=') {
            rest.find('=').map(|idx| idx + 1)
        } else {
            entry.find('=')
        };
        if let Some(eq) = split_pos {
            let name = entry[..eq].to_string();
            let val = entry[eq + 1..].to_string();
            if !name.is_empty() {
                pairs.push((name, val));
            }
        }
    }
    pairs
}
