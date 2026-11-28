use std::sync::Mutex;

use chrono::{TimeZone, Utc};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::backend::{
    DebugEventEntry, EtwLifecycleEntry, FileActivityEntry, GdiProcessEntry, HandleEntry, HeapBlockEntry,
    HungWindowEntry, LoadedDllEntry, MemoryRegionEntry, OpenFileEntry, ProcBackend, ProcessEntry, ProcessEnvEntry,
    RawEtwEvent, ThreadEntry, decode_kernel_file_events, decode_kernel_process_events, parse_peb_environment_block,
};

#[derive(Debug, Default)]
struct MockProcState {
    processes: Vec<ProcessEntry>,
    threads: Vec<ThreadEntry>,
    handles: Vec<HandleEntry>,
    open_files: Vec<OpenFileEntry>,
    deny_privileged: bool,
}

pub struct MockProcBackend {
    state: Mutex<MockProcState>,
}

impl Default for MockProcBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProcBackend {
    pub fn new() -> Self {
        let ts = Utc.with_ymd_and_hms(2026, 11, 23, 4, 0, 0).unwrap();
        let processes = vec![
            ProcessEntry {
                pid: 1000,
                parent_pid: 4,
                process_name: "explorer.exe".to_string(),
                command_line: r"C:\Windows\explorer.exe".to_string(),
                image_path: r"C:\Windows\explorer.exe".to_string(),
                session_id: 1,
                user: r"WORKSTATION\User".to_string(),
                working_set_bytes: 94_371_840,
                private_bytes: 67_108_864,
                cpu_time_ms: 14_200,
                integrity_level: "Medium".to_string(),
            },
            ProcessEntry {
                pid: 1400,
                parent_pid: 650,
                process_name: "svchost.exe".to_string(),
                command_line: r"C:\Windows\System32\svchost.exe -k netsvcs".to_string(),
                image_path: r"C:\Windows\System32\svchost.exe".to_string(),
                session_id: 0,
                user: r"NT AUTHORITY\SYSTEM".to_string(),
                working_set_bytes: 28_311_552,
                private_bytes: 18_874_368,
                cpu_time_ms: 3_150,
                integrity_level: "System".to_string(),
            },
            ProcessEntry {
                pid: 4200,
                parent_pid: 1000,
                process_name: "notepad.exe".to_string(),
                command_line: r"C:\Windows\System32\notepad.exe C:\work\notes.txt".to_string(),
                image_path: r"C:\Windows\System32\notepad.exe".to_string(),
                session_id: 1,
                user: r"WORKSTATION\User".to_string(),
                working_set_bytes: 19_922_944,
                private_bytes: 12_582_912,
                cpu_time_ms: 420,
                integrity_level: "Medium".to_string(),
            },
        ];

        let threads = vec![
            ThreadEntry {
                tid: 1004,
                pid: 1000,
                process_name: "explorer.exe".to_string(),
                start_address: 0x0000_7FF6_1000_1200,
                context_switches: 4820,
                priority: 8,
                base_priority: 8,
                state: "Waiting".to_string(),
                wait_reason: "WrUserRequest".to_string(),
                user_time_ms: 510,
                kernel_time_ms: 210,
                created_time: Some(ts),
                suspended: false,
            },
            ThreadEntry {
                tid: 4208,
                pid: 4200,
                process_name: "notepad.exe".to_string(),
                start_address: 0x0000_7FF6_2000_0400,
                context_switches: 912,
                priority: 8,
                base_priority: 8,
                state: "Waiting".to_string(),
                wait_reason: "Executive".to_string(),
                user_time_ms: 120,
                kernel_time_ms: 45,
                created_time: Some(ts),
                suspended: false,
            },
        ];

        let handles = vec![
            HandleEntry {
                pid: 4200,
                process_name: "notepad.exe".to_string(),
                handle_value: 0x1A4,
                object_type: "File".to_string(),
                object_name: r"\Device\HarddiskVolume3\work\notes.txt".to_string(),
                access_mask: 0x0012_019F,
                handle_count: 1,
            },
            HandleEntry {
                pid: 4200,
                process_name: "notepad.exe".to_string(),
                handle_value: 0x1F8,
                object_type: "File".to_string(),
                object_name: r"\Device\NamedPipe\sys2rust_sync_pipe (FILE_TYPE_PIPE skipped)".to_string(),
                access_mask: 0x0012_019F,
                handle_count: 1,
            },
            HandleEntry {
                pid: 1000,
                process_name: "explorer.exe".to_string(),
                handle_value: 0x220,
                object_type: "Key".to_string(),
                object_name: r"\REGISTRY\USER\S-1-5-21\Software\Microsoft\Windows".to_string(),
                access_mask: 0x0002_0019,
                handle_count: 2,
            },
        ];

        let open_files = vec![OpenFileEntry {
            filename: "notes.txt".to_string(),
            full_path: r"C:\work\notes.txt".to_string(),
            handle: 0x1A4,
            pid: 4200,
            process_name: "notepad.exe".to_string(),
            user_name: r"WORKSTATION\User".to_string(),
            access_mask: 0x0012_019F,
            sharing_mode: "Read|Write".to_string(),
            file_offset: 128,
            process_path: r"C:\Windows\System32\notepad.exe".to_string(),
        }];

        Self {
            state: Mutex::new(MockProcState {
                processes,
                threads,
                handles,
                open_files,
                deny_privileged: false,
            }),
        }
    }

    pub fn with_deny_privileged(self, deny: bool) -> Self {
        self.state.lock().unwrap().deny_privileged = deny;
        self
    }

    pub fn synthetic_kernel_file_events() -> Vec<RawEtwEvent> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 23, 4, 15, 0).unwrap();
        let utf16_path = |s: &str| -> Vec<u8> {
            let mut b = Vec::new();
            for u in s.encode_utf16() {
                b.extend_from_slice(&u.to_le_bytes());
            }
            b.extend_from_slice(&0u16.to_le_bytes());
            b
        };

        let mut ev1 = 0xCAFE_0001u64.to_le_bytes().to_vec();
        ev1.extend_from_slice(&utf16_path(r"C:\work\data.bin"));

        let mut ev2 = 0xCAFE_0001u64.to_le_bytes().to_vec();
        ev2.extend_from_slice(&4096u32.to_le_bytes());

        let mut ev3 = 0xCAFE_0001u64.to_le_bytes().to_vec();
        ev3.extend_from_slice(&1024u32.to_le_bytes());

        let ev4 = 0xCAFE_0001u64.to_le_bytes().to_vec();

        vec![
            RawEtwEvent {
                provider_guid: "{EDD08927-9CC4-4E65-B970-C2560FB5C289}".to_string(),
                event_id: 12,
                pid: 4200,
                timestamp: ts,
                user_data: ev1,
            },
            RawEtwEvent {
                provider_guid: "{EDD08927-9CC4-4E65-B970-C2560FB5C289}".to_string(),
                event_id: 15,
                pid: 4200,
                timestamp: ts + chrono::Duration::milliseconds(10),
                user_data: ev2,
            },
            RawEtwEvent {
                provider_guid: "{EDD08927-9CC4-4E65-B970-C2560FB5C289}".to_string(),
                event_id: 16,
                pid: 4200,
                timestamp: ts + chrono::Duration::milliseconds(20),
                user_data: ev3,
            },
            RawEtwEvent {
                provider_guid: "{EDD08927-9CC4-4E65-B970-C2560FB5C289}".to_string(),
                event_id: 14,
                pid: 4200,
                timestamp: ts + chrono::Duration::milliseconds(30),
                user_data: ev4,
            },
        ]
    }

    pub fn synthetic_kernel_process_events() -> Vec<RawEtwEvent> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 23, 4, 20, 0).unwrap();
        let push_u16z = |buf: &mut Vec<u8>, s: &str| {
            for u in s.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
        };

        let mut start_data = Vec::new();
        start_data.extend_from_slice(&5500u32.to_le_bytes());
        start_data.extend_from_slice(&1000u32.to_le_bytes());
        push_u16z(&mut start_data, r"C:\Windows\System32\cmd.exe");
        push_u16z(&mut start_data, "cmd.exe /c whoami");

        let mut img_data = Vec::new();
        img_data.extend_from_slice(&5500u32.to_le_bytes());
        push_u16z(&mut img_data, r"C:\Windows\System32\ntdll.dll");

        let mut stop_data = Vec::new();
        stop_data.extend_from_slice(&5500u32.to_le_bytes());
        stop_data.extend_from_slice(&0i32.to_le_bytes());
        push_u16z(&mut stop_data, r"C:\Windows\System32\cmd.exe");

        vec![
            RawEtwEvent {
                provider_guid: "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}".to_string(),
                event_id: 1,
                pid: 5500,
                timestamp: ts,
                user_data: start_data,
            },
            RawEtwEvent {
                provider_guid: "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}".to_string(),
                event_id: 5,
                pid: 5500,
                timestamp: ts + chrono::Duration::milliseconds(5),
                user_data: img_data,
            },
            RawEtwEvent {
                provider_guid: "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}".to_string(),
                event_id: 2,
                pid: 5500,
                timestamp: ts + chrono::Duration::milliseconds(15),
                user_data: stop_data,
            },
        ]
    }
}

impl ProcBackend for MockProcBackend {
    fn list_processes(&self) -> Sys2RustResult<Vec<ProcessEntry>> {
        Ok(self.state.lock().unwrap().processes.clone())
    }

    fn list_threads(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ThreadEntry>> {
        let rows = self.state.lock().unwrap().threads.clone();
        Ok(rows
            .into_iter()
            .filter(|t| pid_filter.is_none_or(|p| t.pid == p))
            .collect())
    }

    fn list_loaded_dlls(&self, _pid_filter: Option<u32>) -> Sys2RustResult<Vec<LoadedDllEntry>> {
        Ok(vec![
            LoadedDllEntry {
                dll_path: r"C:\Windows\System32\ntdll.dll".to_string(),
                dll_name: "ntdll.dll".to_string(),
                process_count: 3,
                processes: "explorer.exe, svchost.exe, notepad.exe".to_string(),
                base_address: 0x0000_7FFD_8000_0000,
                size_bytes: 2_240_512,
                product_name: "Microsoft Windows Operating System".to_string(),
                file_version: "10.0.26300.1".to_string(),
                company: "Microsoft Corporation".to_string(),
                signed: true,
            },
            LoadedDllEntry {
                dll_path: r"C:\work\plugins\custom_ext.dll".to_string(),
                dll_name: "custom_ext.dll".to_string(),
                process_count: 1,
                processes: "notepad.exe".to_string(),
                base_address: 0x0000_7FFD_4000_0000,
                size_bytes: 131_072,
                product_name: "Custom Extension".to_string(),
                file_version: "1.0.0.0".to_string(),
                company: "Fixture Corp".to_string(),
                signed: false,
            },
        ])
    }

    fn list_handles(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HandleEntry>> {
        let rows = self.state.lock().unwrap().handles.clone();
        Ok(rows
            .into_iter()
            .filter(|h| pid_filter.is_none_or(|p| h.pid == p))
            .collect())
    }

    fn list_open_files(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<OpenFileEntry>> {
        let rows = self.state.lock().unwrap().open_files.clone();
        Ok(rows
            .into_iter()
            .filter(|f| pid_filter.is_none_or(|p| f.pid == p))
            .collect())
    }

    fn collect_file_activity(&self) -> Sys2RustResult<Vec<FileActivityEntry>> {
        if self.state.lock().unwrap().deny_privileged {
            return Err(Sys2RustError::PermissionDenied {
                operation: "StartTraceW(Kernel-File)",
                detail: "ETW kernel file trace session requires elevation".to_string(),
                hint: "Run elevated as Administrator or join 'Performance Log Users'".to_string(),
            });
        }
        Ok(decode_kernel_file_events(&Self::synthetic_kernel_file_events()))
    }

    fn list_heap_blocks(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HeapBlockEntry>> {
        let target_pid = pid_filter.unwrap_or(4200);
        Ok(vec![HeapBlockEntry {
            pid: target_pid,
            heap_id: 0x0000_01AA_0001_0000,
            block_address: 0x0000_01AA_0001_4200,
            size_bytes: 256,
            flags: "LF32_FIXED".to_string(),
            ascii_preview: "HELLO_HEAP_PAYLOAD".to_string(),
            hex_preview: "48 45 4C 4C 4F 5F 48 45 41 50 5F 50 41 59 4C 4F 41 44".to_string(),
        }])
    }

    fn list_gdi_counts(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<GdiProcessEntry>> {
        let items = vec![
            GdiProcessEntry {
                pid: 1000,
                process_name: "explorer.exe".to_string(),
                pen: 12,
                brush: 34,
                font: 28,
                bitmap: 64,
                region: 14,
                dc: 18,
                metafile: 0,
                other_gdi: 8,
                all_gdi: 178,
                user_objects: 210,
            },
            GdiProcessEntry {
                pid: 4200,
                process_name: "notepad.exe".to_string(),
                pen: 2,
                brush: 4,
                font: 6,
                bitmap: 3,
                region: 1,
                dc: 2,
                metafile: 0,
                other_gdi: 1,
                all_gdi: 19,
                user_objects: 24,
            },
        ];
        Ok(items
            .into_iter()
            .filter(|g| pid_filter.is_none_or(|p| g.pid == p))
            .collect())
    }

    fn detect_hung_windows(&self) -> Sys2RustResult<Vec<HungWindowEntry>> {
        Ok(vec![HungWindowEntry {
            pid: 4200,
            process_name: "notepad.exe".to_string(),
            window_title: "notes.txt - Notepad".to_string(),
            hang_duration_ms: 5200,
            blocked_thread_id: 4208,
            wait_reason: "CriticalSection (blocked on TID 4212)".to_string(),
            call_stack: "ntdll!NtWaitForSingleObject+0x14 -> kernelbase!WaitForSingleObjectEx+0x92".to_string(),
            loaded_modules: "notepad.exe, ntdll.dll, kernelbase.dll, user32.dll".to_string(),
            environment_strings: "WINDIR=C:\\Windows; TEMP=C:\\Temp".to_string(),
        }])
    }

    fn list_debug_events(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<DebugEventEntry>> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 23, 4, 21, 0).unwrap();
        let evs = vec![DebugEventEntry {
            event_time: ts,
            event_type: "LOAD_DLL_DEBUG_EVENT".to_string(),
            pid: pid_filter.unwrap_or(4200),
            tid: 4208,
            address: 0x0000_7FFD_8000_0000,
            detail: r"Loaded C:\Windows\System32\ntdll.dll".to_string(),
        }];
        Ok(evs)
    }

    fn list_memory_regions(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<MemoryRegionEntry>> {
        Ok(vec![
            MemoryRegionEntry {
                pid: pid_filter.unwrap_or(4200),
                base_address: 0x0000_7FF6_2000_0000,
                region_size: 65_536,
                state: "MEM_COMMIT".to_string(),
                protect: "PAGE_EXECUTE_READ".to_string(),
                mem_type: "MEM_IMAGE".to_string(),
                mapped_file: r"\Device\HarddiskVolume3\Windows\System32\notepad.exe".to_string(),
            },
            MemoryRegionEntry {
                pid: pid_filter.unwrap_or(4200),
                base_address: 0x0000_01AA_0000_0000,
                region_size: 1_048_576,
                state: "MEM_COMMIT".to_string(),
                protect: "PAGE_READWRITE".to_string(),
                mem_type: "MEM_PRIVATE".to_string(),
                mapped_file: String::new(),
            },
        ])
    }

    fn list_process_env(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ProcessEnvEntry>> {
        let raw_env: Vec<u8> = "PATH=C:\\Windows\\System32\0TEMP=C:\\Temp\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let parsed = parse_peb_environment_block(&raw_env);
        let pid = pid_filter.unwrap_or(4200);
        Ok(parsed
            .into_iter()
            .map(|(k, v)| ProcessEnvEntry {
                pid,
                process_name: "notepad.exe".to_string(),
                current_dir: r"C:\work".to_string(),
                env_var_name: k,
                env_var_value: v,
            })
            .collect())
    }

    fn collect_etw_lifecycle(&self) -> Sys2RustResult<Vec<EtwLifecycleEntry>> {
        if self.state.lock().unwrap().deny_privileged {
            return Err(Sys2RustError::PermissionDenied {
                operation: "StartTraceW(Kernel-Process)",
                detail: "ETW kernel process session requires elevation".to_string(),
                hint: "Run elevated as Administrator".to_string(),
            });
        }
        Ok(decode_kernel_process_events(&Self::synthetic_kernel_process_events()))
    }

    fn terminate_process(&self, pid: u32, exit_code: u32, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let exists = st.processes.iter().any(|p| p.pid == pid);
        if !exists {
            return Err(Sys2RustError::NotFound(format!("process PID {pid}")));
        }
        if dry_run {
            return Ok(format!(
                "[dry-run] would terminate PID {pid} with exit_code={exit_code}"
            ));
        }
        st.processes.retain(|p| p.pid != pid);
        Ok(format!("terminated PID {pid} with exit_code={exit_code}"))
    }

    fn control_thread(&self, tid: u32, suspend: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(thread) = st.threads.iter_mut().find(|t| t.tid == tid) else {
            return Err(Sys2RustError::NotFound(format!("thread TID {tid}")));
        };
        let op = if suspend { "suspend" } else { "resume" };
        if dry_run {
            return Ok(format!("[dry-run] would {op} TID {tid}"));
        }
        thread.suspended = suspend;
        thread.state = if suspend {
            "Suspended".to_string()
        } else {
            "Running".to_string()
        };
        Ok(format!("executed {op} on TID {tid}"))
    }

    fn close_remote_handle(&self, pid: u32, handle: u64, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let exists = st.handles.iter().any(|h| h.pid == pid && h.handle_value == handle);
        if !exists {
            return Err(Sys2RustError::NotFound(format!("handle {handle:#x} in PID {pid}")));
        }
        if dry_run {
            return Ok(format!("[dry-run] would close handle {handle:#x} in PID {pid}"));
        }
        st.handles.retain(|h| !(h.pid == pid && h.handle_value == handle));
        st.open_files.retain(|f| !(f.pid == pid && f.handle == handle));
        Ok(format!("closed handle {handle:#x} in PID {pid}"))
    }

    fn attach_debugger_probe(&self, pid: u32, timeout_ms: u64, dry_run: bool) -> Sys2RustResult<Vec<DebugEventEntry>> {
        if dry_run {
            return Ok(vec![DebugEventEntry {
                event_time: Utc::now(),
                event_type: "DRY_RUN_PROBE".to_string(),
                pid,
                tid: 0,
                address: 0,
                detail: format!("[dry-run] would attach DebugActiveProcess to PID {pid} for {timeout_ms}ms"),
            }]);
        }
        self.list_debug_events(Some(pid))
    }
}
