use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use chrono::{DateTime, Utc};
use sys2rust_core::binary::{
    decode_utf16le_nul, encode_hex_lower, filetime_to_datetime, read_i32_le, read_u32_le, read_u64_le,
};
use sys2rust_core::{Sys2RustConfig, Sys2RustError, Sys2RustResult, enable_se_debug_privilege};
use windows::Wdk::Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS, ObjectTypeInformation};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, NtQueryInformationThread, ProcessBasicInformation, ProcessCommandLineInformation,
    THREADINFOCLASS,
};
use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED,
    FILETIME, HANDLE, HWND, LPARAM, MAX_PATH, NTSTATUS, WIN32_ERROR,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY,
    TOKEN_USER, TokenIntegrityLevel, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_TYPE_PIPE, GetFileType, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CloseThreadWaitChainSession, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess, DebugActiveProcessStop,
    GetThreadContext, GetThreadWaitChain, OpenThreadWaitChainSession, ReadProcessMemory, STACKFRAME64, StackWalk64,
    SymFunctionTableAccess64, SymGetModuleBase64, SymInitialize, WAIT_CHAIN_THREAD_OPTIONS, WAITCHAIN_NODE_INFO,
    WCT_OBJECT_TYPE, WaitForDebugEventEx,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    PROPERTY_DATA_DESCRIPTOR, ProcessTrace, PropertyStruct, StartTraceW, TDH_INTYPE_ANSISTRING, TDH_INTYPE_FILETIME,
    TDH_INTYPE_HEXINT32, TDH_INTYPE_HEXINT64, TDH_INTYPE_INT8, TDH_INTYPE_INT16, TDH_INTYPE_INT32, TDH_INTYPE_INT64,
    TDH_INTYPE_POINTER, TDH_INTYPE_SIZET, TDH_INTYPE_UINT8, TDH_INTYPE_UINT16, TDH_INTYPE_UINT32, TDH_INTYPE_UINT64,
    TDH_INTYPE_UNICODESTRING, TRACE_EVENT_INFO, TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, HEAPENTRY32, HEAPLIST32, Heap32First, Heap32ListFirst, Heap32ListNext, Heap32Next,
    MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W, Process32FirstW, Process32NextW,
    TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
    Thread32First, Thread32Next,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::{GetMappedFileNameW, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GR_GDIOBJECTS, GR_USEROBJECTS, GetCurrentProcess, GetGuiResources, GetProcessTimes, OpenProcess, OpenProcessToken,
    OpenThread, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    PROCESS_VM_READ, QueryFullProcessImageNameW, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME, TerminateProcess,
};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsHungAppWindow};
use windows::core::{BOOL, GUID, PWSTR};

use crate::backend::{
    DebugEventEntry, EtwLifecycleEntry, FileActivityEntry, GdiProcessEntry, HandleEntry, HeapBlockEntry,
    HungWindowEntry, LoadedDllEntry, MemoryRegionEntry, OpenFileEntry, ProcBackend, ProcessEntry, ProcessEnvEntry,
    RawEtwEvent, ThreadEntry, decode_kernel_file_events, decode_kernel_process_events, parse_peb_environment_block,
    query_with_timeout,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleTableEntryInfoEx {
    object: usize,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: usize,
}

#[repr(C)]
struct ProcessBasicInfoRaw {
    exit_status: i32,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

pub struct LiveProcBackend {
    cfg: Sys2RustConfig,
    stalled_handle_workers: AtomicUsize,
}

impl LiveProcBackend {
    pub fn new(cfg: Sys2RustConfig) -> Self {
        let _ = enable_se_debug_privilege();
        Self {
            cfg,
            stalled_handle_workers: AtomicUsize::new(0),
        }
    }

    fn effective_pid(&self, pid_filter: Option<u32>) -> Option<u32> {
        pid_filter.or(self.cfg.pid_filter)
    }
}

fn wchar_slice_to_string(slice: &[u16]) -> String {
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..end])
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

fn query_process_image_path(handle: HANDLE) -> String {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe {
        if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }
}

fn query_process_cmdline(handle: HANDLE) -> String {
    unsafe {
        let mut needed = 0u32;
        let _ = NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 || needed > 65_536 {
            return String::new();
        }
        let mut buf = vec![0u8; needed as usize];
        let status = NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        if status.0 < 0 || buf.len() < size_of::<UnicodeString>() {
            return String::new();
        }
        let us = &*(buf.as_ptr().cast::<UnicodeString>());
        let ptr = us.buffer;
        let byte_len = usize::from(us.length);
        if ptr == 0 || byte_len == 0 {
            return String::new();
        }
        let base = buf.as_ptr() as usize;
        if ptr >= base && ptr + byte_len <= base + buf.len() {
            let off = ptr - base;
            decode_utf16le_nul(&buf[off..off + byte_len])
        } else {
            String::new()
        }
    }
}

fn query_process_user_and_il(handle: HANDLE) -> (String, String) {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut tok).is_err() {
            return ("<access denied>".to_string(), "Unknown".to_string());
        }

        let mut user_str = String::new();
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut len);
        if len > 0 {
            let mut buf = vec![0u8; len as usize];
            if GetTokenInformation(tok, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len).is_ok() {
                let tu = &*(buf.as_ptr().cast::<TOKEN_USER>());
                let mut name = [0u16; 128];
                let mut name_len = name.len() as u32;
                let mut domain = [0u16; 128];
                let mut dom_len = domain.len() as u32;
                let mut use_kind = SID_NAME_USE::default();
                if LookupAccountSidW(
                    None,
                    tu.User.Sid,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    Some(PWSTR(domain.as_mut_ptr())),
                    &mut dom_len,
                    &mut use_kind,
                )
                .is_ok()
                {
                    let d = String::from_utf16_lossy(&domain[..dom_len as usize]);
                    let n = String::from_utf16_lossy(&name[..name_len as usize]);
                    user_str = if d.is_empty() { n } else { format!("{d}\\{n}") };
                }
            }
        }

        let mut il_str = "Unknown".to_string();
        let mut il_len = 0u32;
        let _ = GetTokenInformation(tok, TokenIntegrityLevel, None, 0, &mut il_len);
        if il_len > 0 {
            let mut buf = vec![0u8; il_len as usize];
            if GetTokenInformation(
                tok,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr().cast()),
                il_len,
                &mut il_len,
            )
            .is_ok()
            {
                let sid = (*(buf.as_ptr().cast::<windows::Win32::Security::SID_AND_ATTRIBUTES>())).Sid;
                let cnt_ptr = GetSidSubAuthorityCount(sid);
                if !cnt_ptr.is_null() && *cnt_ptr > 0 {
                    let rid = *GetSidSubAuthority(sid, u32::from(*cnt_ptr - 1));
                    il_str = match rid {
                        0x0000 => "Untrusted",
                        0x1000 => "Low",
                        0x2000 => "Medium",
                        0x3000 => "High",
                        0x4000 => "System",
                        _ => "Protected",
                    }
                    .to_string();
                }
            }
        }

        let _ = CloseHandle(tok);
        (user_str, il_str)
    }
}

fn process_name_map() -> BTreeMap<u32, (String, u32, u32)> {
    let mut map = BTreeMap::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return map;
        };
        let mut pe: PROCESSENTRY32W = zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let name = wchar_slice_to_string(&pe.szExeFile);
                map.insert(pe.th32ProcessID, (name, pe.th32ParentProcessID, pe.cntThreads));
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    map
}

fn query_file_version_strings(path: &str) -> (String, String, String) {
    if path.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut handle = 0u32;
        let sz = GetFileVersionInfoSizeW(windows::core::PCWSTR(wide.as_ptr()), Some(&mut handle));
        if sz == 0 {
            return (String::new(), String::new(), String::new());
        }
        let mut buf = vec![0u8; sz as usize];
        if GetFileVersionInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            Some(0),
            sz,
            buf.as_mut_ptr().cast(),
        )
        .is_err()
        {
            return (String::new(), String::new(), String::new());
        }

        let mut trans_ptr: *mut c_void = std::ptr::null_mut();
        let mut trans_len = 0u32;
        let trans_q: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        let (lang, cp) = if VerQueryValueW(
            buf.as_ptr().cast(),
            windows::core::PCWSTR(trans_q.as_ptr()),
            &mut trans_ptr,
            &mut trans_len,
        )
        .as_bool()
            && trans_len >= 4
            && !trans_ptr.is_null()
        {
            let pair = std::slice::from_raw_parts(trans_ptr.cast::<u16>(), 2);
            (pair[0], pair[1])
        } else {
            (0x0409, 0x04B0)
        };

        let fetch = |key: &str| -> String {
            let sub: Vec<u16> = format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\{key}\0")
                .encode_utf16()
                .collect();
            let mut val_ptr: *mut c_void = std::ptr::null_mut();
            let mut val_len = 0u32;
            if VerQueryValueW(
                buf.as_ptr().cast(),
                windows::core::PCWSTR(sub.as_ptr()),
                &mut val_ptr,
                &mut val_len,
            )
            .as_bool()
                && !val_ptr.is_null()
                && val_len > 0
            {
                let sl = std::slice::from_raw_parts(val_ptr.cast::<u16>(), val_len as usize);
                wchar_slice_to_string(sl)
            } else {
                String::new()
            }
        };

        (fetch("ProductName"), fetch("FileVersion"), fetch("CompanyName"))
    }
}

fn query_object_type_name(dup: HANDLE) -> String {
    unsafe {
        let mut buf = vec![0u8; 512];
        let mut ret = 0u32;
        let status = NtQueryObject(
            Some(dup),
            ObjectTypeInformation,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            Some(&mut ret),
        );
        if status.0 < 0 || buf.len() < size_of::<UnicodeString>() {
            return String::new();
        }
        let us = &*(buf.as_ptr().cast::<UnicodeString>());
        let byte_len = usize::from(us.length);
        let ptr = us.buffer;
        let base = buf.as_ptr() as usize;
        if ptr >= base && ptr + byte_len <= base + buf.len() {
            let off = ptr - base;
            decode_utf16le_nul(&buf[off..off + byte_len])
        } else {
            String::new()
        }
    }
}

struct OwnedHandleGuard(HANDLE);
impl Drop for OwnedHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn query_object_name_sync(dup_raw: usize) -> Option<String> {
    let _guard = OwnedHandleGuard(HANDLE(dup_raw as *mut c_void));
    let dup = _guard.0;
    unsafe {
        let mut buf = vec![0u8; 2048];
        let mut ret = 0u32;
        let status = NtQueryObject(
            Some(dup),
            OBJECT_INFORMATION_CLASS(1), // ObjectNameInformation
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            Some(&mut ret),
        );
        if status.0 < 0 || buf.len() < size_of::<UnicodeString>() {
            return None;
        }
        let us = &*(buf.as_ptr().cast::<UnicodeString>());
        let byte_len = usize::from(us.length);
        let ptr = us.buffer;
        let base = buf.as_ptr() as usize;
        if ptr >= base && ptr + byte_len <= base + buf.len() {
            let off = ptr - base;
            Some(decode_utf16le_nul(&buf[off..off + byte_len]))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
enum TdhPropValue {
    Text(String),
    U64(u64),
    I64(i64),
}

impl TdhPropValue {
    fn as_str(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::U64(v) => v.to_string(),
            Self::I64(v) => v.to_string(),
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            Self::I64(v) => u64::try_from(*v).ok(),
            Self::Text(s) => s.parse().ok(),
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            Self::U64(v) => i64::try_from(*v).ok(),
            Self::Text(s) => s.parse().ok(),
        }
    }
}

#[derive(Debug, Clone)]
struct TdhDecodedEvent {
    event_id: u16,
    pid: u32,
    timestamp: DateTime<Utc>,
    task_name: String,
    opcode_name: String,
    props: BTreeMap<String, TdhPropValue>,
}

#[derive(Default)]
struct EtwSessionSink {
    raw_events: Mutex<Vec<RawEtwEvent>>,
    tdh_events: Mutex<Vec<TdhDecodedEvent>>,
}

unsafe fn read_tdh_string_at(buf: &[u8], offset: u32) -> String {
    let off = offset as usize;
    if offset == 0 || off >= buf.len() {
        return String::new();
    }
    decode_utf16le_nul(&buf[off..])
}

unsafe fn extract_tdh_event(
    rec: &EVENT_RECORD,
    event_id: u16,
    pid: u32,
    timestamp: DateTime<Utc>,
) -> Option<TdhDecodedEvent> {
    unsafe {
        let mut info_sz = 0u32;
        let st = TdhGetEventInformation(rec, None, None, &mut info_sz);
        if info_sz == 0 || (st != 0 && st != 122) {
            return None;
        }
        let mut buf = vec![0u8; info_sz as usize];
        let info_ptr = buf.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
        if TdhGetEventInformation(rec, None, Some(info_ptr), &mut info_sz) != 0 {
            return None;
        }
        let info = &*info_ptr;
        let task_name = read_tdh_string_at(&buf, info.TaskNameOffset);
        let opcode_name = read_tdh_string_at(&buf, info.OpcodeNameOffset);
        let count = (info.TopLevelPropertyCount as usize).min(64);
        let prop_arr = info.EventPropertyInfoArray.as_ptr();
        let mut props = BTreeMap::new();

        for i in 0..count {
            let epi = &*prop_arr.add(i);
            if (epi.Flags.0 & PropertyStruct.0) != 0 {
                continue;
            }
            let name_off = epi.NameOffset as usize;
            if name_off >= buf.len() {
                continue;
            }
            let name = decode_utf16le_nul(&buf[name_off..]);
            if name.is_empty() {
                continue;
            }
            let name_ptr = buf.as_ptr().add(name_off).cast::<u16>();
            let desc = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: name_ptr as u64,
                ArrayIndex: u32::MAX,
                Reserved: 0,
            };
            let mut prop_sz = 0u32;
            if TdhGetPropertySize(rec, None, &[desc], &mut prop_sz) != 0 || prop_sz == 0 || prop_sz > 65_536 {
                continue;
            }
            let mut pbuf = vec![0u8; prop_sz as usize];
            if TdhGetProperty(rec, None, &[desc], &mut pbuf) != 0 {
                continue;
            }
            let in_type = i32::from(epi.Anonymous1.nonStructType.InType);
            let val = if in_type == TDH_INTYPE_UNICODESTRING.0 {
                TdhPropValue::Text(decode_utf16le_nul(&pbuf))
            } else if in_type == TDH_INTYPE_ANSISTRING.0 {
                let end = pbuf.iter().position(|&b| b == 0).unwrap_or(pbuf.len());
                TdhPropValue::Text(String::from_utf8_lossy(&pbuf[..end]).to_string())
            } else if in_type == TDH_INTYPE_UINT8.0 {
                TdhPropValue::U64(u64::from(*pbuf.first().unwrap_or(&0)))
            } else if in_type == TDH_INTYPE_INT8.0 {
                TdhPropValue::I64(i64::from(*pbuf.first().unwrap_or(&0) as i8))
            } else if in_type == TDH_INTYPE_UINT16.0 && pbuf.len() >= 2 {
                TdhPropValue::U64(u64::from(u16::from_le_bytes([pbuf[0], pbuf[1]])))
            } else if in_type == TDH_INTYPE_INT16.0 && pbuf.len() >= 2 {
                TdhPropValue::I64(i64::from(i16::from_le_bytes([pbuf[0], pbuf[1]])))
            } else if (in_type == TDH_INTYPE_UINT32.0 || in_type == TDH_INTYPE_HEXINT32.0) && pbuf.len() >= 4 {
                TdhPropValue::U64(u64::from(read_u32_le(&pbuf, 0).unwrap_or(0)))
            } else if in_type == TDH_INTYPE_INT32.0 && pbuf.len() >= 4 {
                TdhPropValue::I64(i64::from(read_i32_le(&pbuf, 0).unwrap_or(0)))
            } else if (in_type == TDH_INTYPE_UINT64.0
                || in_type == TDH_INTYPE_HEXINT64.0
                || in_type == TDH_INTYPE_FILETIME.0)
                && pbuf.len() >= 8
            {
                TdhPropValue::U64(read_u64_le(&pbuf, 0).unwrap_or(0))
            } else if in_type == TDH_INTYPE_INT64.0 && pbuf.len() >= 8 {
                TdhPropValue::I64(read_u64_le(&pbuf, 0).unwrap_or(0) as i64)
            } else if in_type == TDH_INTYPE_POINTER.0 || in_type == TDH_INTYPE_SIZET.0 {
                if pbuf.len() >= 8 {
                    TdhPropValue::U64(read_u64_le(&pbuf, 0).unwrap_or(0))
                } else if pbuf.len() >= 4 {
                    TdhPropValue::U64(u64::from(read_u32_le(&pbuf, 0).unwrap_or(0)))
                } else {
                    continue;
                }
            } else {
                continue;
            };
            props.insert(name, val);
        }

        Some(TdhDecodedEvent {
            event_id,
            pid,
            timestamp,
            task_name,
            opcode_name,
            props,
        })
    }
}

unsafe extern "system" fn etw_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    if rec.UserContext.is_null() {
        return;
    }
    let sink = unsafe { &*(rec.UserContext.cast::<EtwSessionSink>()) };
    let pid = rec.EventHeader.ProcessId;
    let event_id = rec.EventHeader.EventDescriptor.Id;
    let ts_ticks = rec.EventHeader.TimeStamp;
    let timestamp = if ts_ticks > 0 {
        filetime_to_datetime(ts_ticks as u64).unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    };
    let data = if !rec.UserData.is_null() && rec.UserDataLength > 0 {
        unsafe { std::slice::from_raw_parts(rec.UserData.cast::<u8>(), usize::from(rec.UserDataLength)) }.to_vec()
    } else {
        Vec::new()
    };
    let g = rec.EventHeader.ProviderId;
    let guid_str = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    );
    if let Ok(mut guard) = sink.raw_events.lock()
        && guard.len() < 8192
    {
        guard.push(RawEtwEvent {
            provider_guid: guid_str,
            event_id,
            pid,
            timestamp,
            user_data: data,
        });
    }
    if let Some(decoded) = unsafe { extract_tdh_event(rec, event_id, pid, timestamp) }
        && let Ok(mut guard) = sink.tdh_events.lock()
        && guard.len() < 8192
    {
        guard.push(decoded);
    }
}

fn run_etw_capture(
    session_name: &str,
    provider_guid: GUID,
    capture_ms: u64,
) -> Sys2RustResult<(Vec<RawEtwEvent>, Vec<TdhDecodedEvent>)> {
    let sink_ptr = Box::into_raw(Box::new(EtwSessionSink::default()));
    let name_w: Vec<u16> = session_name.encode_utf16().chain(std::iter::once(0)).collect();
    let prop_size = size_of::<EVENT_TRACE_PROPERTIES>() + name_w.len() * 2 + 128;
    let mut prop_buf = vec![0u8; prop_size];

    unsafe {
        let props = &mut *(prop_buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>());
        props.Wnode.BufferSize = prop_size as u32;
        props.Wnode.Flags = 0x0002_0000; // WNODE_FLAG_TRACED_GUID
        props.Wnode.ClientContext = 1; // QPC
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        // Ensure stale session with same name is stopped first
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            windows::core::PCWSTR(name_w.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );

        let mut trace_handle = CONTROLTRACE_HANDLE::default();
        let err = StartTraceW(&mut trace_handle, windows::core::PCWSTR(name_w.as_ptr()), props);
        if err == ERROR_ACCESS_DENIED {
            drop(Box::from_raw(sink_ptr));
            return Err(Sys2RustError::PermissionDenied {
                operation: "StartTraceW",
                detail: format!("Access denied starting ETW session '{session_name}'"),
                hint: "Run elevated as Administrator or add the user to 'Performance Log Users'".to_string(),
            });
        }
        if err != WIN32_ERROR(0) {
            drop(Box::from_raw(sink_ptr));
            return Err(Sys2RustError::SourceUnavailable {
                source_name: "ETW Real-Time Session",
                detail: format!("StartTraceW('{session_name}') returned code {}", err.0),
            });
        }

        let enable_err = EnableTraceEx2(
            trace_handle,
            &provider_guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            4,
            u64::MAX,
            0,
            0,
            None::<*const ENABLE_TRACE_PARAMETERS>,
        );
        if enable_err != WIN32_ERROR(0) {
            let _ = ControlTraceW(
                trace_handle,
                windows::core::PCWSTR(name_w.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            drop(Box::from_raw(sink_ptr));
            return Err(Sys2RustError::SourceUnavailable {
                source_name: "ETW EnableTraceEx2",
                detail: format!("EnableTraceEx2 failed with code {}", enable_err.0),
            });
        }

        let mut log_name_w = name_w.clone();
        let mut logfile: EVENT_TRACE_LOGFILEW = zeroed();
        logfile.LoggerName = PWSTR(log_name_w.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_record_callback);
        logfile.Context = sink_ptr.cast();

        let consumer = OpenTraceW(&mut logfile);
        if consumer.Value == u64::MAX {
            let _ = ControlTraceW(
                trace_handle,
                windows::core::PCWSTR(name_w.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            drop(Box::from_raw(sink_ptr));
            return Err(Sys2RustError::SourceUnavailable {
                source_name: "ETW OpenTraceW",
                detail: format!("OpenTraceW('{session_name}') returned INVALID_PROCESSTRACE_HANDLE"),
            });
        }

        let worker = std::thread::spawn(move || {
            let handles = [consumer];
            let _ = ProcessTrace(&handles, None, None);
        });

        std::thread::sleep(std::time::Duration::from_millis(capture_ms.clamp(50, 2000)));
        let _ = ControlTraceW(
            trace_handle,
            windows::core::PCWSTR(name_w.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
        let _ = CloseTrace(consumer);
        let _ = worker.join();

        let sink = Box::from_raw(sink_ptr);
        let raw = sink.raw_events.into_inner().unwrap_or_default();
        let tdh = sink.tdh_events.into_inner().unwrap_or_default();
        Ok((raw, tdh))
    }
}

fn map_tdh_file_events(events: &[TdhDecodedEvent]) -> Vec<FileActivityEntry> {
    let mut key_to_path: BTreeMap<(u32, u64), String> = BTreeMap::new();
    let mut stats: BTreeMap<(u32, String), FileActivityEntry> = BTreeMap::new();

    for ev in events {
        let file_key = ev
            .props
            .get("FileKey")
            .or_else(|| ev.props.get("FileObject"))
            .and_then(TdhPropValue::as_u64)
            .unwrap_or(0);
        let inline_path = ev
            .props
            .get("OpenPath")
            .or_else(|| ev.props.get("FileName"))
            .map(TdhPropValue::as_str)
            .unwrap_or_default();
        let io_size = ev
            .props
            .get("IoSize")
            .or_else(|| ev.props.get("TransferSize"))
            .and_then(TdhPropValue::as_u64)
            .unwrap_or(0);

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

        let op_lower = ev.opcode_name.to_ascii_lowercase();
        let task_lower = ev.task_name.to_ascii_lowercase();
        if ev.event_id == 10
            || ev.event_id == 12
            || ev.event_id == 30
            || op_lower.contains("create")
            || task_lower.contains("create")
        {
            entry.open_count += 1;
        } else if ev.event_id == 14 || op_lower.contains("close") {
            entry.close_count += 1;
        } else if ev.event_id == 15 || op_lower.contains("read") || task_lower.contains("read") {
            entry.read_count += 1;
            entry.read_bytes = entry.read_bytes.saturating_add(io_size);
        } else if ev.event_id == 16 || op_lower.contains("write") || task_lower.contains("write") {
            entry.write_count += 1;
            entry.write_bytes = entry.write_bytes.saturating_add(io_size);
        }
    }
    stats.into_values().collect()
}

fn map_tdh_process_events(events: &[TdhDecodedEvent]) -> Vec<EtwLifecycleEntry> {
    events
        .iter()
        .map(|ev| {
            let pid = ev
                .props
                .get("ProcessID")
                .or_else(|| ev.props.get("ProcessId"))
                .and_then(TdhPropValue::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(ev.pid);
            let parent_pid = ev
                .props
                .get("ParentProcessID")
                .or_else(|| ev.props.get("ParentProcessId"))
                .and_then(TdhPropValue::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            let image_path = ev
                .props
                .get("ImageName")
                .or_else(|| ev.props.get("FileName"))
                .map(TdhPropValue::as_str)
                .unwrap_or_default();
            let command_line = ev
                .props
                .get("CommandLine")
                .map(TdhPropValue::as_str)
                .unwrap_or_default();
            let exit_code = ev
                .props
                .get("ExitCode")
                .and_then(TdhPropValue::as_i64)
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(0);
            let event_type = match ev.event_id {
                1 => "ProcessStart".to_string(),
                2 => "ProcessStop".to_string(),
                5 => "ImageLoad".to_string(),
                other => {
                    if !ev.task_name.is_empty() {
                        ev.task_name.clone()
                    } else {
                        format!("Event_{other}")
                    }
                }
            };
            EtwLifecycleEntry {
                timestamp: ev.timestamp,
                event_type,
                pid,
                parent_pid,
                image_path,
                exit_code,
                command_line,
            }
        })
        .collect()
}

impl ProcBackend for LiveProcBackend {
    fn list_processes(&self) -> Sys2RustResult<Vec<ProcessEntry>> {
        let mut out = Vec::new();
        let proc_map = process_name_map();
        for (pid, (name, ppid, _threads)) in proc_map {
            if let Some(filter) = self.cfg.pid_filter
                && pid != filter
            {
                continue;
            }
            if !self.cfg.include_system && pid <= 4 {
                continue;
            }

            let mut image_path = String::new();
            let mut cmdline = String::new();
            let mut session_id = 0u32;
            let mut user = "<access denied>".to_string();
            let mut il = "Unknown".to_string();
            let mut ws_bytes = 0u64;
            let mut priv_bytes = 0u64;
            let mut cpu_ms = 0u64;

            unsafe {
                let _ = windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session_id);
                if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid)
                    .or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))
                {
                    image_path = query_process_image_path(h);
                    cmdline = query_process_cmdline(h);
                    (user, il) = query_process_user_and_il(h);

                    let mut pmc: PROCESS_MEMORY_COUNTERS = zeroed();
                    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                    if GetProcessMemoryInfo(h, &mut pmc, pmc.cb).is_ok() {
                        ws_bytes = pmc.WorkingSetSize as u64;
                        priv_bytes = pmc.PagefileUsage as u64;
                    }

                    let (mut create_ft, mut exit_ft, mut kern_ft, mut user_ft) = (
                        FILETIME::default(),
                        FILETIME::default(),
                        FILETIME::default(),
                        FILETIME::default(),
                    );
                    if GetProcessTimes(h, &mut create_ft, &mut exit_ft, &mut kern_ft, &mut user_ft).is_ok() {
                        let ticks = filetime_to_u64(kern_ft).saturating_add(filetime_to_u64(user_ft));
                        cpu_ms = ticks / 10_000;
                    }
                    let _ = CloseHandle(h);
                }
            }

            out.push(ProcessEntry {
                pid,
                parent_pid: ppid,
                process_name: name,
                command_line: cmdline,
                image_path,
                session_id,
                user,
                working_set_bytes: ws_bytes,
                private_bytes: priv_bytes,
                cpu_time_ms: cpu_ms,
                integrity_level: il,
            });
        }
        Ok(out)
    }

    fn list_threads(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ThreadEntry>> {
        let filter = self.effective_pid(pid_filter);
        let pmap = process_name_map();
        let mut out = Vec::new();
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) else {
                return Err(Sys2RustError::SourceUnavailable {
                    source_name: "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)",
                    detail: "Failed to snapshot system threads".to_string(),
                });
            };
            let mut te: THREADENTRY32 = zeroed();
            te.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut te).is_ok() {
                loop {
                    if filter.is_none_or(|p| p == te.th32OwnerProcessID) {
                        let proc_name = pmap
                            .get(&te.th32OwnerProcessID)
                            .map(|v| v.0.clone())
                            .unwrap_or_else(|| format!("PID {}", te.th32OwnerProcessID));

                        let mut start_addr = 0u64;
                        let mut created_time: Option<DateTime<Utc>> = None;
                        let mut user_ms = 0u64;
                        let mut kernel_ms = 0u64;

                        if let Ok(ht) = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID)
                            .or_else(|_| OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID))
                        {
                            let mut ret = 0u32;
                            let mut sa: usize = 0;
                            if NtQueryInformationThread(
                                ht,
                                THREADINFOCLASS(9), // ThreadQuerySetWin32StartAddress
                                (&raw mut sa).cast(),
                                size_of::<usize>() as u32,
                                &mut ret,
                            )
                            .0 >= 0
                            {
                                start_addr = sa as u64;
                            }
                            let mut times = [0u64; 4]; // Create, Exit, Kernel, User
                            if NtQueryInformationThread(
                                ht,
                                THREADINFOCLASS(1), // ThreadTimes
                                times.as_mut_ptr().cast(),
                                size_of::<[u64; 4]>() as u32,
                                &mut ret,
                            )
                            .0 >= 0
                            {
                                created_time = filetime_to_datetime(times[0]);
                                kernel_ms = times[2] / 10_000;
                                user_ms = times[3] / 10_000;
                            }
                            let _ = CloseHandle(ht);
                        }

                        out.push(ThreadEntry {
                            tid: te.th32ThreadID,
                            pid: te.th32OwnerProcessID,
                            process_name: proc_name,
                            start_address: start_addr,
                            context_switches: 0,
                            priority: te.tpBasePri,
                            base_priority: te.tpBasePri,
                            state: "Active".to_string(),
                            wait_reason: "None".to_string(),
                            user_time_ms: user_ms,
                            kernel_time_ms: kernel_ms,
                            created_time,
                            suspended: false,
                        });
                    }
                    if Thread32Next(snap, &mut te).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
        Ok(out)
    }

    fn list_loaded_dlls(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<LoadedDllEntry>> {
        let filter = self.effective_pid(pid_filter);
        let pmap = process_name_map();
        let mut by_path: BTreeMap<String, (LoadedDllEntry, Vec<String>)> = BTreeMap::new();

        for (pid, (proc_name, _, _)) in pmap {
            if filter.is_some_and(|f| f != pid) {
                continue;
            }
            unsafe {
                let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) else {
                    continue;
                };
                let mut me: MODULEENTRY32W = zeroed();
                me.dwSize = size_of::<MODULEENTRY32W>() as u32;
                if Module32FirstW(snap, &mut me).is_ok() {
                    loop {
                        let dll_path = wchar_slice_to_string(&me.szExePath);
                        let dll_name = wchar_slice_to_string(&me.szModule);
                        let key = dll_path.to_ascii_lowercase();
                        let entry = by_path.entry(key).or_insert_with(|| {
                            let (product_name, file_version, company) = query_file_version_strings(&dll_path);
                            (
                                LoadedDllEntry {
                                    dll_path: dll_path.clone(),
                                    dll_name,
                                    process_count: 0,
                                    processes: String::new(),
                                    base_address: me.modBaseAddr as u64,
                                    size_bytes: u64::from(me.modBaseSize),
                                    product_name,
                                    file_version,
                                    company,
                                    signed: false,
                                },
                                Vec::new(),
                            )
                        });
                        if !entry.1.contains(&proc_name) {
                            entry.1.push(proc_name.clone());
                        }
                        if Module32NextW(snap, &mut me).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }

        let mut out: Vec<LoadedDllEntry> = by_path
            .into_values()
            .map(|(mut item, procs)| {
                item.process_count = procs.len() as u32;
                item.processes = procs.join(", ");
                item
            })
            .collect();
        out.sort_by(|a, b| b.process_count.cmp(&a.process_count).then(a.dll_name.cmp(&b.dll_name)));
        Ok(out)
    }

    fn list_handles(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HandleEntry>> {
        let filter = self.effective_pid(pid_filter).unwrap_or_else(std::process::id);
        let pmap = process_name_map();
        let proc_name = pmap
            .get(&filter)
            .map(|v| v.0.clone())
            .unwrap_or_else(|| format!("PID {filter}"));

        let mut out = Vec::new();
        unsafe {
            let mut cap = 128 * 1024usize;
            let mut buf = vec![0u8; cap];
            loop {
                let mut ret = 0u32;
                let st = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS(64), // SystemExtendedHandleInformation
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut ret,
                );
                if st == NTSTATUS(0xC000_0004u32 as i32) && cap < 32 * 1024 * 1024 {
                    cap *= 2;
                    buf.resize(cap, 0);
                    continue;
                }
                if st.0 < 0 {
                    return Err(Sys2RustError::SourceUnavailable {
                        source_name: "NtQuerySystemInformation(SystemExtendedHandleInformation)",
                        detail: format!("NTSTATUS {:#010x}", st.0 as u32),
                    });
                }
                break;
            }

            if buf.len() < 16 {
                return Ok(out);
            }
            let count = *(buf.as_ptr().cast::<usize>());
            let entries_ptr = buf.as_ptr().add(16).cast::<SystemHandleTableEntryInfoEx>();
            let max_entries = (buf.len() - 16) / size_of::<SystemHandleTableEntryInfoEx>();
            let entries = std::slice::from_raw_parts(entries_ptr, count.min(max_entries));

            let Ok(h_proc) = OpenProcess(windows::Win32::System::Threading::PROCESS_DUP_HANDLE, false, filter) else {
                return Err(Sys2RustError::PermissionDenied {
                    operation: "OpenProcess(PROCESS_DUP_HANDLE)",
                    detail: format!("Cannot inspect handles of PID {filter}"),
                    hint: "Run elevated or target a user-owned process".to_string(),
                });
            };
            let me = GetCurrentProcess();

            for entry in entries
                .iter()
                .filter(|e| e.unique_process_id == filter as usize)
                .take(512)
            {
                let mut dup = HANDLE::default();
                if DuplicateHandle(
                    h_proc,
                    HANDLE(entry.handle_value as *mut c_void),
                    me,
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
                .is_err()
                {
                    continue;
                }
                let obj_type = query_object_type_name(dup);
                let obj_name = if obj_type == "File" && GetFileType(dup) == FILE_TYPE_PIPE {
                    let _ = CloseHandle(dup);
                    r"\Device\NamedPipe\<pipe skipped by deadlock guard>".to_string()
                } else {
                    let dup_raw = dup.0 as usize;
                    query_with_timeout(
                        self.cfg.handle_query_timeout_ms,
                        &self.stalled_handle_workers,
                        move || query_object_name_sync(dup_raw),
                    )
                };
                out.push(HandleEntry {
                    pid: filter,
                    process_name: proc_name.clone(),
                    handle_value: entry.handle_value as u64,
                    object_type: obj_type,
                    object_name: obj_name,
                    access_mask: entry.granted_access,
                    handle_count: 1,
                });
            }
            let _ = CloseHandle(h_proc);
        }

        Ok(out)
    }

    fn list_open_files(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<OpenFileEntry>> {
        let handles = self.list_handles(pid_filter)?;
        let out = handles
            .into_iter()
            .filter(|h| h.object_type == "File" && !h.object_name.is_empty())
            .map(|h| {
                let filename = h
                    .object_name
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&h.object_name)
                    .to_string();
                OpenFileEntry {
                    filename,
                    full_path: h.object_name,
                    handle: h.handle_value,
                    pid: h.pid,
                    process_name: h.process_name,
                    user_name: String::new(),
                    access_mask: h.access_mask,
                    sharing_mode: "Shared".to_string(),
                    file_offset: 0,
                    process_path: String::new(),
                }
            })
            .collect();
        Ok(out)
    }

    fn collect_file_activity(&self) -> Sys2RustResult<Vec<FileActivityEntry>> {
        let guid = GUID::from_u128(0xEDD08927_9CC4_4E65_B970_C2560FB5C289);
        let session = format!("sys2rust_kernel_file_{}", std::process::id());
        let (raw, tdh) = run_etw_capture(&session, guid, self.cfg.etw_capture_ms)?;
        if !tdh.is_empty() {
            Ok(map_tdh_file_events(&tdh))
        } else {
            Ok(decode_kernel_file_events(&raw))
        }
    }

    fn list_heap_blocks(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<HeapBlockEntry>> {
        let pid = self.effective_pid(pid_filter).unwrap_or_else(std::process::id);
        let mut out = Vec::new();
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid) else {
                return Err(Sys2RustError::PermissionDenied {
                    operation: "CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST)",
                    detail: format!("Cannot snapshot heaps for PID {pid}"),
                    hint: "Target an accessible process or run elevated".to_string(),
                });
            };
            let h_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok();
            let mut hl: HEAPLIST32 = zeroed();
            hl.dwSize = size_of::<HEAPLIST32>();
            if Heap32ListFirst(snap, &mut hl).is_ok() {
                loop {
                    let mut he: HEAPENTRY32 = zeroed();
                    he.dwSize = size_of::<HEAPENTRY32>();
                    if Heap32First(&mut he, hl.th32ProcessID, hl.th32HeapID).is_ok() {
                        loop {
                            if out.len() >= self.cfg.max_heap_blocks {
                                break;
                            }
                            let mut preview = [0u8; 32];
                            let mut read_len = 0usize;
                            if let Some(hp) = h_proc {
                                let to_read = he.dwBlockSize.min(preview.len());
                                if ReadProcessMemory(
                                    hp,
                                    he.dwAddress as *const c_void,
                                    preview.as_mut_ptr().cast(),
                                    to_read,
                                    Some(&mut read_len),
                                )
                                .is_err()
                                {
                                    read_len = 0;
                                }
                            }
                            let slice = &preview[..read_len];
                            let ascii_preview: String = slice
                                .iter()
                                .map(|&b| {
                                    if b.is_ascii_graphic() || b == b' ' {
                                        b as char
                                    } else {
                                        '.'
                                    }
                                })
                                .collect();
                            out.push(HeapBlockEntry {
                                pid,
                                heap_id: hl.th32HeapID as u64,
                                block_address: he.dwAddress as u64,
                                size_bytes: he.dwBlockSize as u64,
                                flags: format!("{:#x}", he.dwFlags.0),
                                ascii_preview,
                                hex_preview: encode_hex_lower(slice),
                            });
                            if Heap32Next(&mut he).is_err() {
                                break;
                            }
                        }
                    }
                    if out.len() >= self.cfg.max_heap_blocks || Heap32ListNext(snap, &mut hl).is_err() {
                        break;
                    }
                }
            }
            if let Some(hp) = h_proc {
                let _ = CloseHandle(hp);
            }
            let _ = CloseHandle(snap);
        }
        Ok(out)
    }

    fn list_gdi_counts(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<GdiProcessEntry>> {
        let filter = self.effective_pid(pid_filter);
        let pmap = process_name_map();
        let mut out = Vec::new();
        for (pid, (name, _, _)) in pmap {
            if filter.is_some_and(|f| f != pid) || pid == 0 {
                continue;
            }
            unsafe {
                let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                    continue;
                };
                let all_gdi = GetGuiResources(h, GR_GDIOBJECTS);
                let user_objects = GetGuiResources(h, GR_USEROBJECTS);
                let _ = CloseHandle(h);
                if all_gdi > 0 || user_objects > 0 || filter == Some(pid) {
                    out.push(GdiProcessEntry {
                        pid,
                        process_name: name,
                        pen: 0,
                        brush: 0,
                        font: 0,
                        bitmap: 0,
                        region: 0,
                        dc: 0,
                        metafile: 0,
                        other_gdi: all_gdi,
                        all_gdi,
                        user_objects,
                    });
                }
            }
        }
        Ok(out)
    }

    fn detect_hung_windows(&self) -> Sys2RustResult<Vec<HungWindowEntry>> {
        struct EnumCtx {
            hung: Vec<(HWND, u32, u32, String)>,
        }
        unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
            unsafe {
                if IsHungAppWindow(hwnd).as_bool() {
                    let mut pid = 0u32;
                    let tid = GetWindowThreadProcessId(hwnd, Some(&mut pid));
                    let mut title = [0u16; 256];
                    let len = GetWindowTextW(hwnd, &mut title);
                    let title_str = String::from_utf16_lossy(&title[..len as usize]);
                    let ctx = &mut *(lparam.0 as *mut EnumCtx);
                    ctx.hung.push((hwnd, pid, tid, title_str));
                }
                BOOL(1)
            }
        }

        let mut ctx = EnumCtx { hung: Vec::new() };
        unsafe {
            let _ = EnumWindows(Some(enum_cb), LPARAM((&raw mut ctx) as isize));
        }
        let pmap = process_name_map();
        let mut out = Vec::new();

        unsafe extern "system" fn sym_table_access(h: HANDLE, addr: u64) -> *mut c_void {
            unsafe { SymFunctionTableAccess64(h, addr) }
        }
        unsafe extern "system" fn sym_module_base(h: HANDLE, addr: u64) -> u64 {
            unsafe { SymGetModuleBase64(h, addr) }
        }

        unsafe {
            let raw_wct = OpenThreadWaitChainSession(
                windows::Win32::System::Diagnostics::Debug::OPEN_THREAD_WAIT_CHAIN_SESSION_FLAGS(0),
                None,
            );
            let wct = if raw_wct.is_null() { None } else { Some(raw_wct) };
            for (_hwnd, pid, tid, title) in ctx.hung {
                let proc_name = pmap
                    .get(&pid)
                    .map(|v| v.0.clone())
                    .unwrap_or_else(|| format!("PID {pid}"));
                let mut wait_reason = "Window message pump unresponsive".to_string();
                if let Some(session) = wct {
                    let mut nodes = [WAITCHAIN_NODE_INFO::default(); 16];
                    let mut node_count = 16u32;
                    let mut is_cycle = BOOL(0);
                    if GetThreadWaitChain(
                        session,
                        None,
                        WAIT_CHAIN_THREAD_OPTIONS(0),
                        tid,
                        &mut node_count,
                        nodes.as_mut_ptr(),
                        &mut is_cycle,
                    )
                    .is_ok()
                        && node_count > 0
                    {
                        let ty: WCT_OBJECT_TYPE = nodes[0].ObjectType;
                        wait_reason = format!("WCT ObjectType={} (cycle={})", ty.0, is_cycle.as_bool());
                    }
                }

                let mut stack_frames = Vec::new();
                if let (Ok(hp), Ok(ht)) = (
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid),
                    OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid),
                ) {
                    let _ = SymInitialize(hp, None, true);
                    let mut ctx_rec: CONTEXT = zeroed();
                    ctx_rec.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0010_001F); // CONTEXT_FULL on x64
                    if GetThreadContext(ht, &mut ctx_rec).is_ok() {
                        let mut frame: STACKFRAME64 = zeroed();
                        #[cfg(target_arch = "x86_64")]
                        {
                            frame.AddrPC.Offset = ctx_rec.Rip;
                            frame.AddrFrame.Offset = ctx_rec.Rbp;
                            frame.AddrStack.Offset = ctx_rec.Rsp;
                        }
                        frame.AddrPC.Mode = windows::Win32::System::Diagnostics::Debug::AddrModeFlat;
                        frame.AddrFrame.Mode = windows::Win32::System::Diagnostics::Debug::AddrModeFlat;
                        frame.AddrStack.Mode = windows::Win32::System::Diagnostics::Debug::AddrModeFlat;
                        for _ in 0..8 {
                            if !StackWalk64(
                                0x8664,
                                hp,
                                ht,
                                &mut frame,
                                (&raw mut ctx_rec).cast(),
                                None,
                                Some(sym_table_access),
                                Some(sym_module_base),
                                None,
                            )
                            .as_bool()
                            {
                                break;
                            }
                            stack_frames.push(format!("{:#x}", frame.AddrPC.Offset));
                        }
                    }
                    let _ = CloseHandle(ht);
                    let _ = CloseHandle(hp);
                }

                out.push(HungWindowEntry {
                    pid,
                    process_name: proc_name,
                    window_title: title,
                    hang_duration_ms: 5000,
                    blocked_thread_id: tid,
                    wait_reason,
                    call_stack: stack_frames.join(" -> "),
                    loaded_modules: String::new(),
                    environment_strings: String::new(),
                });
            }
            if let Some(session) = wct {
                CloseThreadWaitChainSession(session);
            }
        }
        Ok(out)
    }

    fn list_debug_events(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<DebugEventEntry>> {
        let filter = self.effective_pid(pid_filter);
        let lifecycle = self.collect_etw_lifecycle()?;
        Ok(lifecycle
            .into_iter()
            .filter(|e| filter.is_none_or(|p| p == e.pid))
            .map(|e| DebugEventEntry {
                event_time: e.timestamp,
                event_type: e.event_type,
                pid: e.pid,
                tid: 0,
                address: 0,
                detail: format!(
                    "ppid={} exit={} image={} cmd={}",
                    e.parent_pid, e.exit_code, e.image_path, e.command_line
                ),
            })
            .collect())
    }

    fn list_memory_regions(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<MemoryRegionEntry>> {
        let pid = self.effective_pid(pid_filter).unwrap_or_else(std::process::id);
        let mut out = Vec::new();
        unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else {
                return Err(Sys2RustError::PermissionDenied {
                    operation: "OpenProcess(PROCESS_VM_READ)",
                    detail: format!("Cannot read virtual memory map for PID {pid}"),
                    hint: "Run elevated or target a user-owned process".to_string(),
                });
            };
            let mut addr = 0usize;
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            while VirtualQueryEx(
                h,
                Some(addr as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let state = if mbi.State == MEM_COMMIT {
                    "MEM_COMMIT"
                } else if mbi.State.0 == 0x2000 {
                    "MEM_RESERVE"
                } else {
                    "MEM_FREE"
                }
                .to_string();
                let mem_type = if mbi.Type == MEM_IMAGE {
                    "MEM_IMAGE"
                } else if mbi.Type == MEM_MAPPED {
                    "MEM_MAPPED"
                } else if mbi.Type == MEM_PRIVATE {
                    "MEM_PRIVATE"
                } else {
                    "NONE"
                }
                .to_string();

                let mut mapped = String::new();
                if mbi.State == MEM_COMMIT && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                    let mut buf = [0u16; MAX_PATH as usize];
                    let len = GetMappedFileNameW(h, mbi.BaseAddress, &mut buf);
                    if len > 0 {
                        mapped = String::from_utf16_lossy(&buf[..len as usize]);
                    }
                }

                if mbi.State == MEM_COMMIT {
                    out.push(MemoryRegionEntry {
                        pid,
                        base_address: mbi.BaseAddress as u64,
                        region_size: mbi.RegionSize as u64,
                        state,
                        protect: format!("{:#x}", mbi.Protect.0),
                        mem_type,
                        mapped_file: mapped,
                    });
                }
                let next = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if next <= addr || out.len() >= 2048 {
                    break;
                }
                addr = next;
            }
            let _ = CloseHandle(h);
        }
        Ok(out)
    }

    fn list_process_env(&self, pid_filter: Option<u32>) -> Sys2RustResult<Vec<ProcessEnvEntry>> {
        let pid = self.effective_pid(pid_filter).unwrap_or_else(std::process::id);
        let pmap = process_name_map();
        let proc_name = pmap
            .get(&pid)
            .map(|v| v.0.clone())
            .unwrap_or_else(|| format!("PID {pid}"));

        unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else {
                return Err(Sys2RustError::PermissionDenied {
                    operation: "OpenProcess(PROCESS_VM_READ)",
                    detail: format!("Cannot inspect PEB environment for PID {pid}"),
                    hint: "Run elevated or target a user-owned process".to_string(),
                });
            };
            let mut pbi: ProcessBasicInfoRaw = zeroed();
            let mut ret = 0u32;
            let st = NtQueryInformationProcess(
                h,
                ProcessBasicInformation,
                (&raw mut pbi).cast(),
                size_of::<ProcessBasicInfoRaw>() as u32,
                &mut ret,
            );
            if st.0 < 0 || pbi.peb_base_address == 0 {
                let _ = CloseHandle(h);
                return Err(Sys2RustError::SourceUnavailable {
                    source_name: "NtQueryInformationProcess(ProcessBasicInformation)",
                    detail: format!("NTSTATUS {:#010x}", st.0 as u32),
                });
            }

            // PEB.ProcessParameters pointer is at offset 0x20 on x64
            let mut proc_params_ptr: usize = 0;
            let mut read_n = 0usize;
            if ReadProcessMemory(
                h,
                (pbi.peb_base_address + 0x20) as *const c_void,
                (&raw mut proc_params_ptr).cast(),
                size_of::<usize>(),
                Some(&mut read_n),
            )
            .is_err()
                || proc_params_ptr == 0
            {
                let _ = CloseHandle(h);
                return Ok(Vec::new());
            }

            // RTL_USER_PROCESS_PARAMETERS on x64: CurrentDirectory.DosPath at 0x38 (UNICODE_STRING), Environment at 0x80 (PWSTR)
            let mut cur_dir_us = UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: 0,
            };
            let _ = ReadProcessMemory(
                h,
                (proc_params_ptr + 0x38) as *const c_void,
                (&raw mut cur_dir_us).cast(),
                size_of::<UnicodeString>(),
                Some(&mut read_n),
            );
            let mut current_dir = String::new();
            if cur_dir_us.buffer != 0 && cur_dir_us.length > 0 && cur_dir_us.length <= 4096 {
                let mut cd_buf = vec![0u8; usize::from(cur_dir_us.length)];
                if ReadProcessMemory(
                    h,
                    cur_dir_us.buffer as *const c_void,
                    cd_buf.as_mut_ptr().cast(),
                    cd_buf.len(),
                    Some(&mut read_n),
                )
                .is_ok()
                {
                    current_dir = decode_utf16le_nul(&cd_buf);
                }
            }

            let mut env_ptr: usize = 0;
            let _ = ReadProcessMemory(
                h,
                (proc_params_ptr + 0x80) as *const c_void,
                (&raw mut env_ptr).cast(),
                size_of::<usize>(),
                Some(&mut read_n),
            );
            let mut out = Vec::new();
            if env_ptr != 0 {
                let mut env_buf = vec![0u8; 32 * 1024];
                if ReadProcessMemory(
                    h,
                    env_ptr as *const c_void,
                    env_buf.as_mut_ptr().cast(),
                    env_buf.len(),
                    Some(&mut read_n),
                )
                .is_ok()
                {
                    env_buf.truncate(read_n);
                    for (k, v) in parse_peb_environment_block(&env_buf) {
                        out.push(ProcessEnvEntry {
                            pid,
                            process_name: proc_name.clone(),
                            current_dir: current_dir.clone(),
                            env_var_name: k,
                            env_var_value: v,
                        });
                    }
                }
            }
            let _ = CloseHandle(h);
            Ok(out)
        }
    }

    fn collect_etw_lifecycle(&self) -> Sys2RustResult<Vec<EtwLifecycleEntry>> {
        let guid = GUID::from_u128(0x22FB2CD6_0E7B_422B_A0C7_2FAD1FD0E716);
        let session = format!("sys2rust_kernel_process_{}", std::process::id());
        let (raw, tdh) = run_etw_capture(&session, guid, self.cfg.etw_capture_ms)?;
        if !tdh.is_empty() {
            Ok(map_tdh_process_events(&tdh))
        } else {
            Ok(decode_kernel_process_events(&raw))
        }
    }

    fn terminate_process(&self, pid: u32, exit_code: u32, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would call TerminateProcess on PID {pid} (exit_code={exit_code})"
            ));
        }
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|_| Sys2RustError::PermissionDenied {
                operation: "OpenProcess(PROCESS_TERMINATE)",
                detail: format!("Cannot open PID {pid} for termination"),
                hint: "Run elevated as Administrator".to_string(),
            })?;
            let res = TerminateProcess(h, exit_code);
            let _ = CloseHandle(h);
            res.map_err(|e| Sys2RustError::OsError {
                api: "TerminateProcess",
                code: e.code().0 as u32,
                message: e.message(),
            })?;
        }
        Ok(format!("terminated PID {pid} with exit_code={exit_code}"))
    }

    fn control_thread(&self, tid: u32, suspend: bool, dry_run: bool) -> Sys2RustResult<String> {
        let op = if suspend { "SuspendThread" } else { "ResumeThread" };
        if dry_run {
            return Ok(format!("[dry-run] would call {op} on TID {tid}"));
        }
        unsafe {
            let ht = OpenThread(THREAD_SUSPEND_RESUME, false, tid).map_err(|_| Sys2RustError::PermissionDenied {
                operation: "OpenThread(THREAD_SUSPEND_RESUME)",
                detail: format!("Cannot open TID {tid}"),
                hint: "Run elevated or verify thread ID".to_string(),
            })?;
            let prev = if suspend { SuspendThread(ht) } else { ResumeThread(ht) };
            let _ = CloseHandle(ht);
            if prev == u32::MAX {
                return Err(Sys2RustError::OsError {
                    api: op,
                    code: 0,
                    message: format!("{op} returned -1 for TID {tid}"),
                });
            }
            Ok(format!("{op} succeeded on TID {tid} (prev_suspend_count={prev})"))
        }
    }

    fn close_remote_handle(&self, pid: u32, handle: u64, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would close handle {handle:#x} in PID {pid} via DUPLICATE_CLOSE_SOURCE"
            ));
        }
        unsafe {
            let h_proc =
                OpenProcess(windows::Win32::System::Threading::PROCESS_DUP_HANDLE, false, pid).map_err(|_| {
                    Sys2RustError::PermissionDenied {
                        operation: "OpenProcess(PROCESS_DUP_HANDLE)",
                        detail: format!("Cannot duplicate/close handle in PID {pid}"),
                        hint: "Run elevated as Administrator".to_string(),
                    }
                })?;
            let mut dup = HANDLE::default();
            let res = DuplicateHandle(
                h_proc,
                HANDLE(handle as *mut c_void),
                GetCurrentProcess(),
                &mut dup,
                0,
                false,
                DUPLICATE_CLOSE_SOURCE,
            );
            if !dup.is_invalid() {
                let _ = CloseHandle(dup);
            }
            let _ = CloseHandle(h_proc);
            res.map_err(|e| Sys2RustError::OsError {
                api: "DuplicateHandle(DUPLICATE_CLOSE_SOURCE)",
                code: e.code().0 as u32,
                message: e.message(),
            })?;
        }
        Ok(format!("closed handle {handle:#x} in PID {pid}"))
    }

    fn attach_debugger_probe(&self, pid: u32, timeout_ms: u64, dry_run: bool) -> Sys2RustResult<Vec<DebugEventEntry>> {
        if dry_run {
            return Ok(vec![DebugEventEntry {
                event_time: Utc::now(),
                event_type: "DRY_RUN_ATTACH".to_string(),
                pid,
                tid: 0,
                address: 0,
                detail: format!("[dry-run] would attach DebugActiveProcess to PID {pid} for {timeout_ms}ms"),
            }]);
        }
        if pid == std::process::id() {
            return Err(Sys2RustError::InvalidArgument(
                "cannot attach debugger to self".to_string(),
            ));
        }
        unsafe {
            DebugActiveProcess(pid).map_err(|_| Sys2RustError::PermissionDenied {
                operation: "DebugActiveProcess",
                detail: format!("Cannot attach debugger to PID {pid}"),
                hint: "Run elevated or target a non-protected child process".to_string(),
            })?;
            let mut events = Vec::new();
            let mut ev: DEBUG_EVENT = zeroed();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.clamp(20, 2000));
            while std::time::Instant::now() < deadline && events.len() < 32 {
                if WaitForDebugEventEx(&mut ev, 50).is_err() {
                    break;
                }
                events.push(DebugEventEntry {
                    event_time: Utc::now(),
                    event_type: format!("DEBUG_EVENT_{}", ev.dwDebugEventCode.0),
                    pid: ev.dwProcessId,
                    tid: ev.dwThreadId,
                    address: 0,
                    detail: "Captured via DebugActiveProcess".to_string(),
                });
                let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            }
            let _ = DebugActiveProcessStop(pid);
            Ok(events)
        }
    }
}
