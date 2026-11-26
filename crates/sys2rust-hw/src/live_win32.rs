use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::Path;

use chrono::{DateTime, Utc};
use sys2rust_core::binary::{decode_utf16le_nul, dmtf_to_datetime};
use sys2rust_core::{Sys2RustConfig, Sys2RustError, Sys2RustResult};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DEVNODE_STATUS_FLAGS, CM_Get_DevNode_Status, CM_PROB, CR_SUCCESS, DICS_DISABLE, DICS_ENABLE, DICS_FLAG_GLOBAL,
    DIF_PROPERTYCHANGE, DIGCF_ALLCLASSES, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_CLASSINSTALL_HEADER,
    SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, SP_PROPCHANGE_PARAMS, SPDRP_CLASS,
    SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME, SPDRP_HARDWAREID, SPDRP_MFG, SPDRP_SERVICE, SetupDiCallClassInstaller,
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceInterfaceDetailW, SetupDiGetDeviceRegistryPropertyW,
    SetupDiSetClassInstallParamsW,
};
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS, GENERIC_READ, GENERIC_WRITE, GetLastError};
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, MFT_CATEGORY_AUDIO_DECODER, MFT_CATEGORY_AUDIO_ENCODER, MFT_CATEGORY_VIDEO_DECODER,
    MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_ALL, MFT_FRIENDLY_NAME_Attribute, MFTEnum2,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileVersionInfoSizeW,
    GetFileVersionInfoW, OPEN_EXISTING, VerQueryValueW,
};
use windows::Win32::System::Com::{
    CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoTaskMemFree,
    EOLE_AUTHENTICATION_CAPABILITIES, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ole::{SafeArrayDestroy, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::Power::{
    BATTERY_INFORMATION, BATTERY_QUERY_INFORMATION, BATTERY_STATUS, BatteryInformation, GUID_DEVICE_BATTERY,
    IOCTL_BATTERY_QUERY_INFORMATION, IOCTL_BATTERY_QUERY_STATUS, IOCTL_BATTERY_QUERY_TAG,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE,
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DISABLED,
    SERVICE_DRIVER, SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_PAUSE_CONTINUE, SERVICE_QUERY_CONFIG, SERVICE_START,
    SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STOP, SERVICE_WIN32, StartServiceW,
};
use windows::Win32::System::SystemInformation::{
    EnumSystemFirmwareTables, FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
};
use windows::Win32::System::TaskScheduler::{ITaskFolder, ITaskService, TaskScheduler};
use windows::Win32::System::Time::{DYNAMIC_TIME_ZONE_INFORMATION, EnumDynamicTimeZoneInformation};
use windows::Win32::System::Variant::{
    VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_EMPTY, VT_I4, VT_NULL, VT_UI4, VariantClear,
};
use windows::Win32::System::Wmi::{
    IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
};
use windows::Win32::UI::Shell::{
    FOLDERID_AppDataDesktop, FOLDERID_CommonPrograms, FOLDERID_CommonStartup, FOLDERID_Desktop, FOLDERID_Documents,
    FOLDERID_Downloads, FOLDERID_Favorites, FOLDERID_Fonts, FOLDERID_LocalAppData, FOLDERID_Music, FOLDERID_Pictures,
    FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, FOLDERID_Programs,
    FOLDERID_Public, FOLDERID_PublicDesktop, FOLDERID_PublicDocuments, FOLDERID_Recent, FOLDERID_RoamingAppData,
    FOLDERID_SendTo, FOLDERID_StartMenu, FOLDERID_Startup, FOLDERID_System, FOLDERID_SystemX86, FOLDERID_Templates,
    FOLDERID_Videos, FOLDERID_Windows, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath,
};
use windows::core::{BSTR, GUID, PCWSTR, PWSTR};

use crate::backend::{
    BatteryEntry, CodecEntry, DeviceEntry, DriverEntry, FirmwareTableEntry, HwBackend, ServiceEntry,
    SpecialFolderEntry, TaskEntry, TimeZoneEntry, WmiRowEntry,
};
use crate::parsers::{
    current_local_from_offset, decode_reg_tzi, filter_non_null_driver_addrs, normalize_driver_path, parse_acpi_table,
    parse_smbios_raw_data, parse_system_ini_drivers32, parse_task_scheduler_xml,
};

pub struct LiveHwBackend {
    cfg: Sys2RustConfig,
}

impl LiveHwBackend {
    pub fn new(cfg: Sys2RustConfig) -> Self {
        Self { cfg }
    }
}

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wchar_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn pwstr_to_string(ptr: PWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    unsafe { ptr.to_string().unwrap_or_default() }
}

unsafe fn com_init() {
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
}

fn query_driver_version_info(path: &str) -> (String, String, String) {
    if path.is_empty() || !Path::new(path).exists() {
        return (String::new(), String::new(), String::new());
    }
    let wide = wide_z(path);
    unsafe {
        let mut h = 0u32;
        let sz = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut h));
        if sz == 0 {
            return (String::new(), String::new(), String::new());
        }
        let mut buf = vec![0u8; sz as usize];
        if GetFileVersionInfoW(PCWSTR(wide.as_ptr()), Some(0), sz, buf.as_mut_ptr().cast()).is_err() {
            return (String::new(), String::new(), String::new());
        }

        let mut trans_ptr: *mut c_void = std::ptr::null_mut();
        let mut trans_len = 0u32;
        let trans_q = wide_z(r"\VarFileInfo\Translation");
        let (lang, cp) = if VerQueryValueW(
            buf.as_ptr().cast(),
            PCWSTR(trans_q.as_ptr()),
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
            let sub = wide_z(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\{key}"));
            let mut ptr: *mut c_void = std::ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(buf.as_ptr().cast(), PCWSTR(sub.as_ptr()), &mut ptr, &mut len).as_bool()
                && !ptr.is_null()
                && len > 0
            {
                let sl = std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize);
                wchar_to_string(sl)
            } else {
                String::new()
            }
        };
        (fetch("ProductName"), fetch("FileVersion"), fetch("CompanyName"))
    }
}

pub fn map_win32_error(api: &'static str, err: windows::core::Error) -> Sys2RustError {
    let code = err.code().0 as u32;
    if code == 5 || code == 0x8007_0005 {
        Sys2RustError::PermissionDenied {
            operation: api,
            detail: err.message(),
            hint: "Run elevated as Administrator".to_string(),
        }
    } else {
        Sys2RustError::OsError {
            api,
            code,
            message: err.message(),
        }
    }
}

fn map_reg_io_error(operation: &'static str, err: std::io::Error) -> Sys2RustError {
    if err.kind() == std::io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(5) {
        Sys2RustError::PermissionDenied {
            operation,
            detail: err.to_string(),
            hint: "Run elevated as Administrator".to_string(),
        }
    } else {
        Sys2RustError::Io(err)
    }
}

fn list_drivers_via_scm(windir: &str) -> Sys2RustResult<Vec<DriverEntry>> {
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)
            .map_err(|e| map_win32_error("OpenSCManagerW", e))?;

        let mut bytes_needed = 0u32;
        let mut returned = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut returned,
            Some(&mut resume),
            None,
        );
        let mut buf = vec![0u8; bytes_needed.max(4096) as usize];
        let res = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut bytes_needed,
            &mut returned,
            Some(&mut resume),
            None,
        );
        if res.is_err() {
            let _ = CloseServiceHandle(scm);
            return Err(Sys2RustError::SourceUnavailable {
                source_name: "EnumServicesStatusExW(SERVICE_DRIVER)",
                detail: "Driver service enumeration failed".to_string(),
            });
        }

        let slice = std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), returned as usize);
        let mut out = Vec::with_capacity(slice.len());
        let mut seen_names = BTreeSet::new();

        for item in slice {
            let svc_name = pwstr_to_string(item.lpServiceName);
            let mut raw_bin = String::new();
            let svc_w = wide_z(&svc_name);
            if let Ok(hs) = OpenServiceW(scm, PCWSTR(svc_w.as_ptr()), SERVICE_QUERY_CONFIG) {
                let mut needed = 0u32;
                let _ = QueryServiceConfigW(hs, None, 0, &mut needed);
                if needed > 0 {
                    let mut cbuf = vec![0u8; needed as usize];
                    if QueryServiceConfigW(
                        hs,
                        Some(cbuf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                        needed,
                        &mut needed,
                    )
                    .is_ok()
                    {
                        let qc = &*(cbuf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>());
                        raw_bin = pwstr_to_string(qc.lpBinaryPathName);
                    }
                }
                let _ = CloseServiceHandle(hs);
            }

            let mut path = normalize_driver_path(&raw_bin, windir);
            if path.is_empty() {
                let candidate = format!("{windir}\\System32\\drivers\\{svc_name}.sys");
                if Path::new(&candidate).exists() {
                    path = candidate;
                }
            }
            let driver_name = if !path.is_empty() {
                Path::new(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&svc_name)
                    .to_string()
            } else {
                svc_name.clone()
            };
            if driver_name.is_empty() || !seen_names.insert(driver_name.to_ascii_lowercase()) {
                continue;
            }
            let (file_size, modified_time) = std::fs::metadata(&path)
                .map(|m| (m.len(), m.modified().ok().map(DateTime::<Utc>::from)))
                .unwrap_or((0, None));
            let (product_name, version, company) = query_driver_version_info(&path);
            let is_running = item.ServiceStatusProcess.dwCurrentState.0 == 4;
            let drv_type = if (item.ServiceStatusProcess.dwServiceType.0 & 0x02) != 0 {
                "FileSystem Driver"
            } else {
                "Kernel Driver"
            };
            out.push(DriverEntry {
                driver_name,
                address: 0,
                end_address: 0,
                size_bytes: file_size,
                load_count: if is_running { 1 } else { 0 },
                driver_type: drv_type.to_string(),
                path,
                product_name,
                version,
                company,
                modified_time,
            });
        }

        let _ = CloseServiceHandle(scm);
        Ok(out)
    }
}

fn variant_to_string(v: &VARIANT) -> String {
    unsafe {
        let vt = v.Anonymous.Anonymous.vt;
        if vt == VT_EMPTY || vt == VT_NULL {
            return String::new();
        }
        if vt == VT_BSTR {
            return v.Anonymous.Anonymous.Anonymous.bstrVal.to_string();
        }
        if vt == VT_I4 {
            return v.Anonymous.Anonymous.Anonymous.lVal.to_string();
        }
        if vt == VT_UI4 {
            return v.Anonymous.Anonymous.Anonymous.ulVal.to_string();
        }
        if vt == VT_BOOL {
            return (v.Anonymous.Anonymous.Anonymous.boolVal.0 != 0).to_string();
        }
        if vt.0 & VT_ARRAY.0 != 0 && vt.0 & VT_BSTR.0 != 0 {
            let psa = v.Anonymous.Anonymous.Anonymous.parray;
            if psa.is_null() {
                return String::new();
            }
            let lb = SafeArrayGetLBound(psa, 1).unwrap_or(0);
            let ub = SafeArrayGetUBound(psa, 1).unwrap_or(-1);
            let mut items = Vec::new();
            for idx in lb..=ub {
                let mut elem = BSTR::default();
                if SafeArrayGetElement(psa, &idx, (&raw mut elem).cast()).is_ok() {
                    items.push(elem.to_string());
                }
            }
            return items.join(", ");
        }
        format!("<vt={}>", vt.0)
    }
}

impl HwBackend for LiveHwBackend {
    fn list_services(&self) -> Sys2RustResult<Vec<ServiceEntry>> {
        unsafe {
            let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE).map_err(|_| {
                Sys2RustError::PermissionDenied {
                    operation: "OpenSCManagerW",
                    detail: "Failed to open Service Control Manager".to_string(),
                    hint: "Check SCM permissions".to_string(),
                }
            })?;

            let mut bytes_needed = 0u32;
            let mut returned = 0u32;
            let mut resume = 0u32;
            let _ = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut returned,
                Some(&mut resume),
                None,
            );
            let mut buf = vec![0u8; bytes_needed.max(4096) as usize];
            let res = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut bytes_needed,
                &mut returned,
                Some(&mut resume),
                None,
            );
            if res.is_err() {
                let _ = CloseServiceHandle(scm);
                return Err(Sys2RustError::SourceUnavailable {
                    source_name: "EnumServicesStatusExW",
                    detail: "Service enumeration failed".to_string(),
                });
            }

            let slice =
                std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), returned as usize);
            let mut out = Vec::with_capacity(slice.len());

            for item in slice {
                let name = pwstr_to_string(item.lpServiceName);
                let display = pwstr_to_string(item.lpDisplayName);
                let status = match item.ServiceStatusProcess.dwCurrentState.0 {
                    1 => "Stopped",
                    2 => "StartPending",
                    3 => "StopPending",
                    4 => "Running",
                    5 => "ContinuePending",
                    6 => "PausePending",
                    7 => "Paused",
                    _ => "Unknown",
                }
                .to_string();

                let mut startup_type = "Unknown".to_string();
                let mut binary_path = String::new();
                let mut account = String::new();
                let name_w = wide_z(&name);
                if let Ok(hs) = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_CONFIG) {
                    let mut needed = 0u32;
                    let _ = QueryServiceConfigW(hs, None, 0, &mut needed);
                    if needed > 0 {
                        let mut cbuf = vec![0u8; needed as usize];
                        if QueryServiceConfigW(
                            hs,
                            Some(cbuf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                            needed,
                            &mut needed,
                        )
                        .is_ok()
                        {
                            let qc = &*(cbuf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>());
                            startup_type = match qc.dwStartType.0 {
                                0 => "Boot",
                                1 => "System",
                                2 => "Auto",
                                3 => "Manual",
                                4 => "Disabled",
                                _ => "Other",
                            }
                            .to_string();
                            binary_path = pwstr_to_string(qc.lpBinaryPathName);
                            account = pwstr_to_string(qc.lpServiceStartName);
                        }
                    }
                    let _ = CloseServiceHandle(hs);
                }

                out.push(ServiceEntry {
                    service_name: name,
                    display_name: display,
                    status,
                    startup_type,
                    service_type: format!("{:#x}", item.ServiceStatusProcess.dwServiceType.0),
                    binary_path,
                    account,
                    description: String::new(),
                    pid: item.ServiceStatusProcess.dwProcessId,
                    company: String::new(),
                    signed: false,
                });
            }

            let _ = CloseServiceHandle(scm);
            Ok(out)
        }
    }

    fn list_drivers(&self) -> Sys2RustResult<Vec<DriverEntry>> {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        unsafe {
            let mut needed = 0u32;
            let _ = EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed);
            if needed > 0 {
                let count = (needed as usize) / size_of::<*mut c_void>();
                let mut addrs = vec![std::ptr::null_mut::<c_void>(); count];
                if EnumDeviceDrivers(addrs.as_mut_ptr(), needed, &mut needed).is_ok() {
                    let raw_addrs: Vec<usize> = addrs.into_iter().map(|p| p as usize).collect();
                    let valid_addrs = filter_non_null_driver_addrs(&raw_addrs);
                    if !valid_addrs.is_empty() {
                        let mut seen_paths = BTreeSet::new();
                        let mut out = Vec::with_capacity(valid_addrs.len());
                        for addr_val in valid_addrs {
                            let addr = addr_val as *mut c_void;
                            let mut fbuf = [0u16; 512];
                            let flen = GetDeviceDriverFileNameW(addr, &mut fbuf);
                            if flen == 0 {
                                continue;
                            }
                            let raw_path = String::from_utf16_lossy(&fbuf[..flen as usize]);
                            let path = normalize_driver_path(&raw_path, &windir);
                            if path.is_empty() || !seen_paths.insert(path.to_ascii_lowercase()) {
                                continue;
                            }
                            let name = Path::new(&path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(&path)
                                .to_string();
                            let (file_size, modified_time) = std::fs::metadata(&path)
                                .map(|m| (m.len(), m.modified().ok().map(DateTime::<Utc>::from)))
                                .unwrap_or((0, None));
                            let (product_name, version, company) = query_driver_version_info(&path);
                            out.push(DriverEntry {
                                driver_name: name,
                                address: addr_val as u64,
                                end_address: (addr_val as u64).saturating_add(file_size),
                                size_bytes: file_size,
                                load_count: 1,
                                driver_type: "Kernel".to_string(),
                                path,
                                product_name,
                                version,
                                company,
                                modified_time,
                            });
                        }
                        if !out.is_empty() {
                            return Ok(out);
                        }
                    }
                }
            }
        }
        // Fallback for unprivileged Windows 11 where EnumDeviceDrivers zeroes kernel addresses (KASLR)
        list_drivers_via_scm(&windir)
    }

    fn list_devices(&self) -> Sys2RustResult<Vec<DeviceEntry>> {
        unsafe {
            let Ok(hdev) = SetupDiGetClassDevsW(None, None, None, DIGCF_ALLCLASSES) else {
                return Err(Sys2RustError::SourceUnavailable {
                    source_name: "SetupDiGetClassDevsW",
                    detail: "Failed to open PnP device info set".to_string(),
                });
            };
            let get_prop = |dev_info: &SP_DEVINFO_DATA,
                            prop: windows::Win32::Devices::DeviceAndDriverInstallation::SETUP_DI_REGISTRY_PROPERTY|
             -> String {
                let mut buf = [0u8; 1024];
                let mut req = 0u32;
                if SetupDiGetDeviceRegistryPropertyW(hdev, dev_info, prop, None, Some(&mut buf), Some(&mut req)).is_ok()
                {
                    decode_utf16le_nul(&buf[..req.min(buf.len() as u32) as usize])
                } else {
                    String::new()
                }
            };

            let mut out = Vec::new();
            let mut idx = 0u32;
            loop {
                let mut dev_info = SP_DEVINFO_DATA {
                    cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                    ..zeroed()
                };
                if SetupDiEnumDeviceInfo(hdev, idx, &mut dev_info).is_err() {
                    break;
                }
                idx += 1;

                let friendly = get_prop(&dev_info, SPDRP_FRIENDLYNAME);
                let desc = get_prop(&dev_info, SPDRP_DEVICEDESC);
                let device_name = if !friendly.is_empty() { friendly } else { desc };
                let device_type = get_prop(&dev_info, SPDRP_CLASS);
                let hardware_id = get_prop(&dev_info, SPDRP_HARDWAREID);
                let manufacturer = get_prop(&dev_info, SPDRP_MFG);
                let service_name = get_prop(&dev_info, SPDRP_SERVICE);

                let mut inst_buf = [0u16; 512];
                let mut req = 0u32;
                let instance_id =
                    if SetupDiGetDeviceInstanceIdW(hdev, &dev_info, Some(&mut inst_buf), Some(&mut req)).is_ok() {
                        wchar_to_string(&inst_buf)
                    } else {
                        String::new()
                    };

                let mut status_flags = CM_DEVNODE_STATUS_FLAGS(0);
                let mut problem_code_raw = CM_PROB(0);
                let cm_ok =
                    CM_Get_DevNode_Status(&mut status_flags, &mut problem_code_raw, dev_info.DevInst, 0) == CR_SUCCESS;
                let problem_code = problem_code_raw.0;
                let connected = cm_ok && problem_code == 0;
                let status = if !cm_ok {
                    "Disconnected"
                } else if problem_code == 0 {
                    "OK"
                } else {
                    "Problem"
                }
                .to_string();

                out.push(DeviceEntry {
                    device_name,
                    device_type,
                    status,
                    connected,
                    problem_code,
                    hardware_id,
                    driver_name: String::new(),
                    driver_version: String::new(),
                    manufacturer,
                    instance_id,
                    service_name,
                });
            }

            let _ = SetupDiDestroyDeviceInfoList(hdev);
            Ok(out)
        }
    }

    fn list_tasks(&self) -> Sys2RustResult<Vec<TaskEntry>> {
        // Primary: Task Scheduler COM (ITaskService)
        let mut out = Vec::new();
        unsafe {
            com_init();
            if let Ok(service) = CoCreateInstance::<_, ITaskService>(&TaskScheduler, None, CLSCTX_ALL)
                && service
                    .Connect(
                        &VARIANT::default(),
                        &VARIANT::default(),
                        &VARIANT::default(),
                        &VARIANT::default(),
                    )
                    .is_ok()
                && let Ok(root) = service.GetFolder(&BSTR::from(r"\"))
            {
                fn walk_folder(folder: &ITaskFolder, path: &str, out: &mut Vec<TaskEntry>) {
                    unsafe {
                        if let Ok(tasks) = folder.GetTasks(1)
                            && let Ok(count) = tasks.Count()
                        {
                            for i in 1..=count.min(256) {
                                if let Ok(task) = tasks.get_Item(&VARIANT::from(i)) {
                                    let name = task.Name().map(|b| b.to_string()).unwrap_or_default();
                                    let enabled = task.Enabled().map(|b| b.as_bool()).unwrap_or(false);
                                    let xml_str = task.Xml().map(|b| b.to_string()).unwrap_or_default();
                                    if let Ok(mut parsed) = parse_task_scheduler_xml(path, &name, xml_str.as_bytes()) {
                                        parsed.enabled = enabled;
                                        parsed.last_result = task.LastTaskResult().unwrap_or(0) as u32;
                                        out.push(parsed);
                                    }
                                }
                            }
                        }
                        if let Ok(subfolders) = folder.GetFolders(0)
                            && let Ok(fcount) = subfolders.Count()
                        {
                            for i in 1..=fcount.min(64) {
                                if let Ok(sub) = subfolders.get_Item(&VARIANT::from(i)) {
                                    let sub_path = sub.Path().map(|b| b.to_string()).unwrap_or_default();
                                    walk_folder(&sub, &sub_path, out);
                                }
                            }
                        }
                    }
                }
                walk_folder(&root, r"\", &mut out);
                if !out.is_empty() {
                    return Ok(out);
                }
            }
        }

        // Fallback: Pure-Rust roxmltree scan of %WINDIR%\System32\Tasks
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let tasks_root = Path::new(&windir).join("System32").join("Tasks");
        if tasks_root.exists() {
            for entry in std::fs::read_dir(&tasks_root).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_file()
                    && let Ok(bytes) = std::fs::read(&p)
                    && let Some(name) = p.file_name().and_then(|n| n.to_str())
                    && let Ok(t) = parse_task_scheduler_xml(r"\", name, &bytes)
                {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }

    fn query_wmi(&self, namespace: &str, wql: &str) -> Sys2RustResult<Vec<WmiRowEntry>> {
        let ns = if namespace.is_empty() {
            &self.cfg.wmi_namespace
        } else {
            namespace
        };
        let query = if wql.is_empty() { &self.cfg.wmi_query } else { wql };

        unsafe {
            com_init();
            let locator: IWbemLocator =
                CoCreateInstance(&WbemLocator, None, CLSCTX_ALL).map_err(|e| Sys2RustError::SourceUnavailable {
                    source_name: "WbemLocator",
                    detail: format!("CoCreateInstance failed: {e}"),
                })?;

            let svc = locator
                .ConnectServer(
                    &BSTR::from(ns),
                    &BSTR::new(),
                    &BSTR::new(),
                    &BSTR::new(),
                    0,
                    &BSTR::new(),
                    None,
                )
                .map_err(|e| Sys2RustError::SourceUnavailable {
                    source_name: "IWbemLocator::ConnectServer",
                    detail: format!("ConnectServer('{ns}') failed: {e}"),
                })?;

            let _ = CoSetProxyBlanket(
                &svc,
                RPC_C_AUTHN_WINNT,
                0,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOLE_AUTHENTICATION_CAPABILITIES(0),
            );

            let enumerator = svc
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(query),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
                .map_err(|e| Sys2RustError::InvalidArgument(format!("WQL ExecQuery failed: {e}")))?;

            let mut out = Vec::new();
            let mut objs = [None; 1];
            let mut returned = 0u32;
            while enumerator.Next(WBEM_INFINITE, &mut objs, &mut returned).is_ok() && returned > 0 {
                if let Some(obj) = objs[0].take() {
                    let mut props = BTreeMap::new();
                    let mut class_name = String::new();
                    let mut instance_id = String::new();
                    let mut ts_utc = None;

                    if let Ok(psa) = obj.GetNames(
                        None,
                        windows::Win32::System::Wmi::WBEM_CONDITION_FLAG_TYPE(0),
                        std::ptr::null(),
                    ) {
                        let lb = SafeArrayGetLBound(psa, 1).unwrap_or(0);
                        let ub = SafeArrayGetUBound(psa, 1).unwrap_or(-1);
                        for idx in lb..=ub {
                            let mut prop_bstr = BSTR::default();
                            if SafeArrayGetElement(psa, &idx, (&raw mut prop_bstr).cast()).is_ok() {
                                let key = prop_bstr.to_string();
                                if key.starts_with("__") {
                                    if key == "__CLASS" {
                                        let mut val = VARIANT::default();
                                        if obj.Get(PCWSTR(prop_bstr.as_ptr()), 0, &mut val, None, None).is_ok() {
                                            class_name = variant_to_string(&val);
                                        }
                                        let _ = VariantClear(&mut val);
                                    }
                                    continue;
                                }
                                let mut val = VARIANT::default();
                                if obj.Get(PCWSTR(prop_bstr.as_ptr()), 0, &mut val, None, None).is_ok() {
                                    let s = variant_to_string(&val);
                                    if ts_utc.is_none() && (key.contains("Time") || key.contains("Date")) {
                                        ts_utc = dmtf_to_datetime(&s);
                                    }
                                    if instance_id.is_empty() && !s.is_empty() {
                                        instance_id = s.clone();
                                    }
                                    props.insert(key, s);
                                }
                                let _ = VariantClear(&mut val);
                            }
                        }
                        let _ = SafeArrayDestroy(psa);
                    }

                    out.push(WmiRowEntry {
                        namespace: ns.to_string(),
                        class_name,
                        instance_id,
                        properties: props,
                        timestamp_utc: ts_utc,
                    });
                }
                if out.len() >= 256 {
                    break;
                }
            }
            Ok(out)
        }
    }

    fn list_firmware_tables(&self) -> Sys2RustResult<Vec<FirmwareTableEntry>> {
        let mut out = Vec::new();
        unsafe {
            for (sig_str, sig_u32) in [
                ("RSMB", u32::from_be_bytes(*b"RSMB")),
                ("ACPI", u32::from_be_bytes(*b"ACPI")),
            ] {
                let prov = FIRMWARE_TABLE_PROVIDER(sig_u32);
                let needed = EnumSystemFirmwareTables(prov, None);
                if needed == 0 {
                    continue;
                }
                let mut id_buf = vec![0u8; needed as usize];
                let got = EnumSystemFirmwareTables(prov, Some(&mut id_buf));
                for &chunk in id_buf[..got as usize].as_chunks::<4>().0 {
                    let tid = u32::from_le_bytes(chunk);
                    let t_sz = GetSystemFirmwareTable(prov, tid, None);
                    if t_sz == 0 || t_sz > 16 * 1024 * 1024 {
                        continue;
                    }
                    let mut raw = vec![0u8; t_sz as usize];
                    let actual = GetSystemFirmwareTable(prov, tid, Some(&mut raw));
                    raw.truncate(actual as usize);
                    if sig_str == "RSMB" {
                        if let Ok(entry) = parse_smbios_raw_data(&raw) {
                            out.push(entry);
                        }
                    } else if let Ok(entry) = parse_acpi_table(&raw) {
                        out.push(entry);
                    }
                }
            }
        }
        Ok(out)
    }

    fn list_batteries(&self) -> Sys2RustResult<Vec<BatteryEntry>> {
        unsafe {
            let Ok(hdev) = SetupDiGetClassDevsW(
                Some(&GUID_DEVICE_BATTERY),
                None,
                None,
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
            ) else {
                return Err(Sys2RustError::HardwareNotFound {
                    device: "Battery",
                    detail: "SetupDiGetClassDevsW(GUID_DEVICE_BATTERY) failed".to_string(),
                });
            };

            let mut batteries = Vec::new();
            let mut idx = 0u32;
            loop {
                let mut if_data = SP_DEVICE_INTERFACE_DATA {
                    cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
                    ..zeroed()
                };
                if SetupDiEnumDeviceInterfaces(hdev, None, &GUID_DEVICE_BATTERY, idx, &mut if_data).is_err() {
                    if GetLastError() == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    break;
                }
                idx += 1;

                let mut req_size = 0u32;
                let _ = SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, None, 0, Some(&mut req_size), None);
                if req_size < 8 {
                    continue;
                }
                let mut detail_buf = vec![0u8; req_size as usize];
                let detail = &mut *(detail_buf.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>());
                detail.cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
                if SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, Some(detail), req_size, None, None).is_err() {
                    continue;
                }
                let dev_path_ptr = detail.DevicePath.as_ptr();
                let Ok(h_bat) = CreateFileW(
                    PCWSTR(dev_path_ptr),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                ) else {
                    continue;
                };

                let mut tag = 0u32;
                let wait = 0u32;
                let mut bytes_ret = 0u32;
                if DeviceIoControl(
                    h_bat,
                    IOCTL_BATTERY_QUERY_TAG,
                    Some((&raw const wait).cast()),
                    4,
                    Some((&raw mut tag).cast()),
                    4,
                    Some(&mut bytes_ret),
                    None,
                )
                .is_ok()
                    && tag != 0
                {
                    let bqi = BATTERY_QUERY_INFORMATION {
                        BatteryTag: tag,
                        InformationLevel: BatteryInformation,
                        AtRate: 0,
                    };
                    let mut bi: BATTERY_INFORMATION = zeroed();
                    let _ = DeviceIoControl(
                        h_bat,
                        IOCTL_BATTERY_QUERY_INFORMATION,
                        Some((&raw const bqi).cast()),
                        size_of::<BATTERY_QUERY_INFORMATION>() as u32,
                        Some((&raw mut bi).cast()),
                        size_of::<BATTERY_INFORMATION>() as u32,
                        Some(&mut bytes_ret),
                        None,
                    );

                    let bqs = windows::Win32::System::Power::BATTERY_WAIT_STATUS {
                        BatteryTag: tag,
                        Timeout: 0,
                        PowerState: 0,
                        LowCapacity: 0,
                        HighCapacity: 0,
                    };
                    let mut bs: BATTERY_STATUS = zeroed();
                    let _ = DeviceIoControl(
                        h_bat,
                        IOCTL_BATTERY_QUERY_STATUS,
                        Some((&raw const bqs).cast()),
                        size_of::<windows::Win32::System::Power::BATTERY_WAIT_STATUS>() as u32,
                        Some((&raw mut bs).cast()),
                        size_of::<BATTERY_STATUS>() as u32,
                        Some(&mut bytes_ret),
                        None,
                    );

                    let design = u64::from(bi.DesignedCapacity);
                    let full = u64::from(bi.FullChargedCapacity);
                    let wear = if design > 0 && full <= design {
                        ((design - full) as f64 / design as f64) * 100.0
                    } else {
                        0.0
                    };
                    let chem = String::from_utf8_lossy(&bi.Chemistry)
                        .trim_end_matches('\0')
                        .to_string();
                    batteries.push(BatteryEntry {
                        battery_name: format!("Battery #{idx}"),
                        manufacturer: String::new(),
                        serial: format!("Tag-{tag}"),
                        chemistry: chem,
                        designed_capacity_mwh: design,
                        full_charged_capacity_mwh: full,
                        wear_level_pct: wear,
                        current_capacity_mwh: u64::from(bs.Capacity),
                        voltage_mv: u64::from(bs.Voltage),
                        power_state: format!("{:#x}", bs.PowerState),
                        charge_rate_mw: i64::from(bs.Rate),
                    });
                }
                let _ = CloseHandle(h_bat);
            }
            let _ = SetupDiDestroyDeviceInfoList(hdev);

            if batteries.is_empty() {
                return Err(Sys2RustError::HardwareNotFound {
                    device: "Battery",
                    detail: "No active smart batteries detected on this system".to_string(),
                });
            }
            Ok(batteries)
        }
    }

    fn list_codecs(&self) -> Sys2RustResult<Vec<CodecEntry>> {
        let mut out = Vec::new();
        // 1. Media Foundation Transforms via MFTEnum2
        unsafe {
            com_init();
            for (label, cat) in [
                ("MFT Video Decoder", MFT_CATEGORY_VIDEO_DECODER),
                ("MFT Video Encoder", MFT_CATEGORY_VIDEO_ENCODER),
                ("MFT Audio Decoder", MFT_CATEGORY_AUDIO_DECODER),
                ("MFT Audio Encoder", MFT_CATEGORY_AUDIO_ENCODER),
            ] {
                let mut pp_act: *mut Option<IMFActivate> = std::ptr::null_mut();
                let mut count = 0u32;
                if MFTEnum2(cat, MFT_ENUM_FLAG_ALL, None, None, None, &mut pp_act, &mut count).is_ok()
                    && !pp_act.is_null()
                {
                    let acts = std::slice::from_raw_parts(pp_act, count as usize);
                    for act in acts.iter().flatten() {
                        let mut name_ptr = PWSTR::null();
                        let mut len = 0u32;
                        let name = if act
                            .GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut name_ptr, &mut len)
                            .is_ok()
                        {
                            let s = pwstr_to_string(name_ptr);
                            CoTaskMemFree(Some(name_ptr.0.cast()));
                            s
                        } else {
                            "Unnamed MFT".to_string()
                        };
                        out.push(CodecEntry {
                            codec_name: name,
                            codec_type: label.to_string(),
                            clsid: String::new(),
                            filename: String::new(),
                            merit: 0,
                            disabled: false,
                            version: String::new(),
                            company: String::new(),
                        });
                    }
                    CoTaskMemFree(Some(pp_act.cast()));
                }
            }
        }

        // 2. Registry Drivers32 (+ Drivers32\Disabled)
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(drv32) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32") {
            for (name, val) in drv32.enum_values().flatten() {
                let s = val.to_string();
                if !s.is_empty() {
                    out.push(CodecEntry {
                        codec_name: name,
                        codec_type: "Drivers32 Registry".to_string(),
                        clsid: String::new(),
                        filename: s,
                        merit: 0,
                        disabled: false,
                        version: String::new(),
                        company: String::new(),
                    });
                }
            }
            if let Ok(dis) = drv32.open_subkey("Disabled") {
                for (name, val) in dis.enum_values().flatten() {
                    let s = val.to_string();
                    if !s.is_empty() {
                        out.push(CodecEntry {
                            codec_name: name,
                            codec_type: "Drivers32 Registry".to_string(),
                            clsid: String::new(),
                            filename: s,
                            merit: 0,
                            disabled: true,
                            version: String::new(),
                            company: String::new(),
                        });
                    }
                }
            }
        }

        // 3. SYSTEM.INI [drivers32]
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys_ini = Path::new(&windir).join("system.ini");
        if let Ok(text) = std::fs::read_to_string(sys_ini) {
            out.extend(parse_system_ini_drivers32(&text));
        }

        Ok(out)
    }

    fn list_timezones(&self) -> Sys2RustResult<Vec<TimeZoneEntry>> {
        let mut out = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let tz_root = hklm
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones")
            .ok();
        let now_utc = Utc::now();

        unsafe {
            let mut idx = 0u32;
            loop {
                let mut dtzi: DYNAMIC_TIME_ZONE_INFORMATION = zeroed();
                let rc = EnumDynamicTimeZoneInformation(idx, &mut dtzi);
                if rc != 0 {
                    break;
                }
                idx += 1;
                let id = wchar_to_string(&dtzi.TimeZoneKeyName);
                let std_name = wchar_to_string(&dtzi.StandardName);
                let dst_name = wchar_to_string(&dtzi.DaylightName);
                let mut display_name = id.clone();
                let mut utc_offset_min = -i64::from(dtzi.Bias);
                let mut supports_dst = !dtzi.DynamicDaylightTimeDisabled && dtzi.StandardDate.wMonth != 0;
                let mut dst_start_rule = String::new();
                let mut dst_end_rule = String::new();

                if let Some(ref root) = tz_root
                    && let Ok(sub) = root.open_subkey(&id)
                {
                    if let Ok(disp) = sub.get_value::<String, _>("Display") {
                        display_name = disp;
                    }
                    if let Ok(raw_tzi) = sub.get_raw_value("TZI")
                        && let Ok(decoded) = decode_reg_tzi(&raw_tzi.bytes)
                    {
                        utc_offset_min = decoded.utc_offset_min;
                        supports_dst = decoded.supports_dst;
                        dst_start_rule = decoded.dst_start_rule;
                        dst_end_rule = decoded.dst_end_rule;
                    }
                }

                out.push(TimeZoneEntry {
                    time_zone_id: id,
                    display_name,
                    standard_name: std_name,
                    daylight_name: dst_name,
                    utc_offset_min,
                    supports_dst,
                    current_local_time: current_local_from_offset(now_utc, utc_offset_min),
                    dst_start_rule,
                    dst_end_rule,
                });
            }
        }
        Ok(out)
    }

    fn list_special_folders(&self) -> Sys2RustResult<Vec<SpecialFolderEntry>> {
        let defs: &[(&str, &str, &GUID, &str)] = &[
            (
                "Desktop",
                "CSIDL_DESKTOPDIRECTORY",
                &FOLDERID_Desktop,
                "%USERPROFILE%\\Desktop",
            ),
            (
                "Documents",
                "CSIDL_MYDOCUMENTS",
                &FOLDERID_Documents,
                "%USERPROFILE%\\Documents",
            ),
            ("Downloads", "N/A", &FOLDERID_Downloads, "%USERPROFILE%\\Downloads"),
            (
                "Favorites",
                "CSIDL_FAVORITES",
                &FOLDERID_Favorites,
                "%USERPROFILE%\\Favorites",
            ),
            ("Music", "CSIDL_MYMUSIC", &FOLDERID_Music, "%USERPROFILE%\\Music"),
            (
                "Pictures",
                "CSIDL_MYPICTURES",
                &FOLDERID_Pictures,
                "%USERPROFILE%\\Pictures",
            ),
            ("Videos", "CSIDL_MYVIDEO", &FOLDERID_Videos, "%USERPROFILE%\\Videos"),
            (
                "Recent",
                "CSIDL_RECENT",
                &FOLDERID_Recent,
                "%APPDATA%\\Microsoft\\Windows\\Recent",
            ),
            (
                "SendTo",
                "CSIDL_SENDTO",
                &FOLDERID_SendTo,
                "%APPDATA%\\Microsoft\\Windows\\SendTo",
            ),
            (
                "StartMenu",
                "CSIDL_STARTMENU",
                &FOLDERID_StartMenu,
                "%APPDATA%\\Microsoft\\Windows\\Start Menu",
            ),
            (
                "Programs",
                "CSIDL_PROGRAMS",
                &FOLDERID_Programs,
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
            ),
            (
                "Startup",
                "CSIDL_STARTUP",
                &FOLDERID_Startup,
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            ),
            ("RoamingAppData", "CSIDL_APPDATA", &FOLDERID_RoamingAppData, "%APPDATA%"),
            (
                "LocalAppData",
                "CSIDL_LOCAL_APPDATA",
                &FOLDERID_LocalAppData,
                "%LOCALAPPDATA%",
            ),
            (
                "Templates",
                "CSIDL_TEMPLATES",
                &FOLDERID_Templates,
                "%APPDATA%\\Microsoft\\Windows\\Templates",
            ),
            ("Profile", "CSIDL_PROFILE", &FOLDERID_Profile, "%USERPROFILE%"),
            ("Windows", "CSIDL_WINDOWS", &FOLDERID_Windows, "%WINDIR%"),
            ("System32", "CSIDL_SYSTEM", &FOLDERID_System, "%WINDIR%\\System32"),
            ("SysWOW64", "CSIDL_SYSTEMX86", &FOLDERID_SystemX86, "%WINDIR%\\SysWOW64"),
            ("Fonts", "CSIDL_FONTS", &FOLDERID_Fonts, "%WINDIR%\\Fonts"),
            (
                "ProgramFiles",
                "CSIDL_PROGRAM_FILES",
                &FOLDERID_ProgramFiles,
                "%ProgramFiles%",
            ),
            (
                "ProgramFilesX86",
                "CSIDL_PROGRAM_FILESX86",
                &FOLDERID_ProgramFilesX86,
                "%ProgramFiles(x86)%",
            ),
            (
                "ProgramData",
                "CSIDL_COMMON_APPDATA",
                &FOLDERID_ProgramData,
                "%ProgramData%",
            ),
            (
                "CommonPrograms",
                "CSIDL_COMMON_PROGRAMS",
                &FOLDERID_CommonPrograms,
                "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
            ),
            (
                "CommonStartup",
                "CSIDL_COMMON_STARTUP",
                &FOLDERID_CommonStartup,
                "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            ),
            ("Public", "N/A", &FOLDERID_Public, "%PUBLIC%"),
            (
                "PublicDesktop",
                "CSIDL_COMMON_DESKTOPDIRECTORY",
                &FOLDERID_PublicDesktop,
                "%PUBLIC%\\Desktop",
            ),
            (
                "PublicDocuments",
                "CSIDL_COMMON_DOCUMENTS",
                &FOLDERID_PublicDocuments,
                "%PUBLIC%\\Documents",
            ),
            ("AppDataDesktop", "N/A", &FOLDERID_AppDataDesktop, "%LOCALAPPDATA%"),
        ];

        let mut out = Vec::with_capacity(defs.len());
        unsafe {
            for &(name, csidl, guid, env_var) in defs {
                let resolved = if let Ok(pw) = SHGetKnownFolderPath(guid, KNOWN_FOLDER_FLAG(0), None) {
                    let s = pwstr_to_string(pw);
                    CoTaskMemFree(Some(pw.0.cast()));
                    s
                } else {
                    String::new()
                };
                let exists = !resolved.is_empty() && Path::new(&resolved).exists();
                let g = *guid;
                out.push(SpecialFolderEntry {
                    folder_name: name.to_string(),
                    csidl: csidl.to_string(),
                    known_folder_guid: format!(
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
                    ),
                    resolved_path: resolved,
                    exists,
                    env_variable: env_var.to_string(),
                });
            }
        }
        Ok(out)
    }

    fn control_service(
        &self,
        service_name: &str,
        action: &str,
        startup_type: Option<&str>,
        dry_run: bool,
    ) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would execute '{action}' on service '{service_name}'"
            ));
        }
        unsafe {
            let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).map_err(|_| Sys2RustError::PermissionDenied {
                operation: "OpenSCManagerW",
                detail: "Cannot connect to SCM".to_string(),
                hint: "Run elevated as Administrator".to_string(),
            })?;
            let access = SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_CHANGE_CONFIG;
            let name_w = wide_z(service_name);
            let hs = OpenServiceW(scm, PCWSTR(name_w.as_ptr()), access).map_err(|_| {
                let _ = CloseServiceHandle(scm);
                Sys2RustError::PermissionDenied {
                    operation: "OpenServiceW",
                    detail: format!("Cannot open service '{service_name}' for control"),
                    hint: "Run elevated as Administrator".to_string(),
                }
            })?;

            let mut status = SERVICE_STATUS::default();
            let res = match action {
                "start" => StartServiceW(hs, None),
                "stop" => ControlService(hs, SERVICE_CONTROL_STOP, &mut status),
                "pause" => ControlService(hs, SERVICE_CONTROL_PAUSE, &mut status),
                "resume" => ControlService(hs, SERVICE_CONTROL_CONTINUE, &mut status),
                "set_startup" => {
                    let st = match startup_type.unwrap_or("Manual") {
                        "Auto" => SERVICE_AUTO_START,
                        "Disabled" => SERVICE_DISABLED,
                        _ => SERVICE_DEMAND_START,
                    };
                    ChangeServiceConfigW(
                        hs,
                        ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                        st,
                        SERVICE_ERROR(SERVICE_NO_CHANGE),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                }
                other => {
                    let _ = CloseServiceHandle(hs);
                    let _ = CloseServiceHandle(scm);
                    return Err(Sys2RustError::InvalidArgument(format!("unknown action '{other}'")));
                }
            };
            let _ = CloseServiceHandle(hs);
            let _ = CloseServiceHandle(scm);
            res.map_err(|e| Sys2RustError::OsError {
                api: "ServiceControl",
                code: e.code().0 as u32,
                message: e.message(),
            })?;
        }
        Ok(format!("service '{service_name}' {action} succeeded"))
    }

    fn control_device(&self, instance_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let verb = if enable { "enable" } else { "disable" };
        if dry_run {
            return Ok(format!("[dry-run] would {verb} PnP device '{instance_id}'"));
        }
        unsafe {
            let hdev = SetupDiGetClassDevsW(None, None, None, DIGCF_ALLCLASSES)
                .map_err(|e| map_win32_error("SetupDiGetClassDevsW", e))?;
            let mut idx = 0u32;
            let mut found = false;
            let mut op_result: Sys2RustResult<()> = Ok(());
            loop {
                let mut dev_info = SP_DEVINFO_DATA {
                    cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                    ..zeroed()
                };
                if SetupDiEnumDeviceInfo(hdev, idx, &mut dev_info).is_err() {
                    break;
                }
                idx += 1;
                let mut ibuf = [0u16; 512];
                let mut req = 0u32;
                if SetupDiGetDeviceInstanceIdW(hdev, &dev_info, Some(&mut ibuf), Some(&mut req)).is_ok()
                    && wchar_to_string(&ibuf).eq_ignore_ascii_case(instance_id)
                {
                    let params = SP_PROPCHANGE_PARAMS {
                        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                            cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                            InstallFunction: DIF_PROPERTYCHANGE,
                        },
                        StateChange: if enable { DICS_ENABLE } else { DICS_DISABLE },
                        Scope: DICS_FLAG_GLOBAL,
                        HwProfile: 0,
                    };
                    if let Err(e) = SetupDiSetClassInstallParamsW(
                        hdev,
                        Some(&dev_info),
                        Some((&raw const params).cast()),
                        size_of::<SP_PROPCHANGE_PARAMS>() as u32,
                    ) {
                        op_result = Err(map_win32_error("SetupDiSetClassInstallParamsW", e));
                    } else if let Err(e) = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hdev, Some(&dev_info)) {
                        op_result = Err(map_win32_error("SetupDiCallClassInstaller", e));
                    }
                    found = true;
                    break;
                }
            }
            let _ = SetupDiDestroyDeviceInfoList(hdev);
            op_result?;
            if !found {
                return Err(Sys2RustError::NotFound(format!("device '{instance_id}'")));
            }
        }
        Ok(format!("device '{instance_id}' {verb} succeeded"))
    }

    fn control_task(&self, task_path: &str, action: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would {action} scheduled task '{task_path}'"));
        }
        unsafe {
            com_init();
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_ALL).map_err(|e| Sys2RustError::SourceUnavailable {
                    source_name: "TaskScheduler",
                    detail: e.to_string(),
                })?;
            service
                .Connect(
                    &VARIANT::default(),
                    &VARIANT::default(),
                    &VARIANT::default(),
                    &VARIANT::default(),
                )
                .map_err(|e| Sys2RustError::PermissionDenied {
                    operation: "ITaskService::Connect",
                    detail: e.to_string(),
                    hint: "Run elevated".to_string(),
                })?;
            let root = service
                .GetFolder(&BSTR::from(r"\"))
                .map_err(|e| Sys2RustError::NotFound(e.to_string()))?;
            let task = root
                .GetTask(&BSTR::from(task_path))
                .map_err(|_| Sys2RustError::NotFound(format!("task '{task_path}'")))?;
            match action {
                "enable" => task
                    .SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(-1))
                    .map_err(|e| Sys2RustError::OsError {
                        api: "IRegisteredTask::SetEnabled",
                        code: e.code().0 as u32,
                        message: e.message(),
                    })?,
                "disable" => task
                    .SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(0))
                    .map_err(|e| Sys2RustError::OsError {
                        api: "IRegisteredTask::SetEnabled",
                        code: e.code().0 as u32,
                        message: e.message(),
                    })?,
                "run" => {
                    let _ = task.Run(&VARIANT::default()).map_err(|e| Sys2RustError::OsError {
                        api: "IRegisteredTask::Run",
                        code: e.code().0 as u32,
                        message: e.message(),
                    })?;
                }
                other => return Err(Sys2RustError::InvalidArgument(format!("unknown task action '{other}'"))),
            }
        }
        Ok(format!("task '{task_path}' {action} succeeded"))
    }

    fn control_codec(&self, codec_id: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let verb = if enable { "enable" } else { "disable" };
        if dry_run {
            return Ok(format!("[dry-run] would {verb} codec '{codec_id}'"));
        }
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let drv32_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32";
        let drv32 = hklm
            .open_subkey_with_flags(drv32_path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_io_error("RegOpenKey(Drivers32)", e))?;

        if enable {
            if let Ok(dis) = drv32.open_subkey_with_flags("Disabled", KEY_READ | KEY_WRITE)
                && let Ok(val) = dis.get_raw_value(codec_id)
            {
                drv32
                    .set_raw_value(codec_id, &val)
                    .map_err(|e| map_reg_io_error("RegSetValue(Drivers32)", e))?;
                let _ = dis.delete_value(codec_id);
                return Ok(format!("enabled Drivers32 codec '{codec_id}'"));
            }
            if drv32.get_raw_value(codec_id).is_ok() {
                return Ok(format!("Drivers32 codec '{codec_id}' is already enabled"));
            }
        } else if let Ok(val) = drv32.get_raw_value(codec_id) {
            let (dis, _) = drv32
                .create_subkey_with_flags("Disabled", KEY_READ | KEY_WRITE)
                .map_err(|e| map_reg_io_error("RegCreateKey(Drivers32\\Disabled)", e))?;
            dis.set_raw_value(codec_id, &val)
                .map_err(|e| map_reg_io_error("RegSetValue(Drivers32\\Disabled)", e))?;
            drv32
                .delete_value(codec_id)
                .map_err(|e| map_reg_io_error("RegDeleteValue(Drivers32)", e))?;
            return Ok(format!("disabled Drivers32 codec '{codec_id}'"));
        }

        // DirectShow CLSID merit/disable toggle
        if codec_id.starts_with('{') && codec_id.ends_with('}') {
            let clsid_path = format!(r"SOFTWARE\Classes\CLSID\{codec_id}");
            let ck = hklm
                .open_subkey_with_flags(&clsid_path, KEY_READ | KEY_WRITE)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => Sys2RustError::NotFound(format!("codec CLSID '{codec_id}'")),
                    _ => map_reg_io_error("RegOpenKey(CLSID)", e),
                })?;
            if enable {
                let _ = ck.delete_value("Disabled");
            } else {
                ck.set_value("Disabled", &1u32)
                    .map_err(|e| map_reg_io_error("RegSetValue(CLSID\\Disabled)", e))?;
            }
            return Ok(format!("{verb}d DirectShow codec CLSID '{codec_id}'"));
        }

        // SYSTEM.INI [drivers32] fallback
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys_ini = Path::new(&windir).join("system.ini");
        if let Ok(content) = std::fs::read_to_string(&sys_ini) {
            let mut in_section = false;
            let mut changed = false;
            let mut lines_out = Vec::new();
            for raw in content.lines() {
                let trimmed = raw.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_section = trimmed.eq_ignore_ascii_case("[drivers32]");
                    lines_out.push(raw.to_string());
                    continue;
                }
                if in_section {
                    let effective = trimmed.strip_prefix(';').map(str::trim).unwrap_or(trimmed);
                    if let Some((k, _)) = effective.split_once('=')
                        && k.trim().eq_ignore_ascii_case(codec_id)
                    {
                        changed = true;
                        if enable {
                            lines_out.push(effective.to_string());
                        } else {
                            lines_out.push(format!(";{effective}"));
                        }
                        continue;
                    }
                }
                lines_out.push(raw.to_string());
            }
            if changed {
                let updated = format!("{}\r\n", lines_out.join("\r\n"));
                std::fs::write(&sys_ini, updated).map_err(|e| map_reg_io_error("Write(system.ini)", e))?;
                return Ok(format!("{verb}d system.ini codec '{codec_id}'"));
            }
        }

        Err(Sys2RustError::NotFound(format!("codec '{codec_id}'")))
    }
}
