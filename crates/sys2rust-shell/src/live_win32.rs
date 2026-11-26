use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;

use chrono::Utc;
use sys2rust_core::{Sys2RustConfig, Sys2RustError, Sys2RustResult};
use winreg::RegKey;
use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};

use windows::Management::Deployment::PackageManager;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, POINT, WPARAM};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MSIINSTALLCONTEXT, MSIINSTALLCONTEXT_ALL, MsiEnumProductsExW, MsiGetProductInfoExW,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, OpenProcess, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, STARTUPINFOW,
};
use windows::Win32::UI::Controls::{LVM_GETITEMCOUNT, LVM_GETITEMPOSITION, LVM_SETITEMPOSITION};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, FindWindowExW, FindWindowW, GetClassNameW, GetWindowThreadProcessId, SendMessageW,
};
use windows::core::{BOOL, HSTRING, PCWSTR, PWSTR};

use crate::backend::{
    AppCompatItem, AppxPkgItem, ComRegItem, DesktopIconItem, EnvVarItem, ExplorerExtItem, FileTypeItem,
    LegacyUninstallItem, MsiPackageItem, MuiVerItem, OpenWithItem, PrivacyAuditItem, ShellBackend, ShellExtItem,
    ShellMenuItem, ShellMenuNewItem, StartupItem, TrayIconItem, UninstallItem, UrlProtoItem,
};
use crate::parsers::{
    decode_startup_approved, encode_startup_approved, parse_desktopok_ini, parse_tray_notify_stream,
    resolve_desktop_profile_path, validate_privacy_categories,
};

pub struct LiveWin32ShellBackend {
    _cfg: Sys2RustConfig,
}

impl LiveWin32ShellBackend {
    pub fn new(cfg: Sys2RustConfig) -> Self {
        Self { _cfg: cfg }
    }
}

fn wchar_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn query_file_ver(path: &str) -> (String, String, String, String, String, String) {
    if path.is_empty() || !Path::new(path).exists() {
        return (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
    }
    let wide = wide_z(path);
    unsafe {
        let mut h = 0u32;
        let sz = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut h));
        if sz == 0 {
            return Default::default();
        }
        let mut buf = vec![0u8; sz as usize];
        if GetFileVersionInfoW(PCWSTR(wide.as_ptr()), Some(0), sz, buf.as_mut_ptr().cast()).is_err() {
            return Default::default();
        }
        let fetch = |key: &str| -> String {
            let sub = wide_z(&format!(r"\StringFileInfo\040904b0\{key}"));
            let mut ptr: *mut c_void = std::ptr::null_mut();
            let mut len = 0u32;
            if VerQueryValueW(buf.as_ptr().cast(), PCWSTR(sub.as_ptr()), &mut ptr, &mut len).as_bool()
                && !ptr.is_null()
                && len > 0
            {
                let sl = std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize);
                wchar_z_to_string(sl)
            } else {
                String::new()
            }
        };
        (
            fetch("FileDescription"),
            fetch("ProductName"),
            fetch("FileVersion"),
            fetch("CompanyName"),
            fetch("OriginalFilename"),
            fetch("InternalName"),
        )
    }
}

fn extract_exe_from_cmdline(cmd: &str) -> String {
    let t = cmd.trim();
    if let Some(rest) = t.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        t.split_whitespace().next().unwrap_or("").to_string()
    }
}

fn map_reg_err(operation: &'static str, err: std::io::Error) -> Sys2RustError {
    if err.kind() == std::io::ErrorKind::PermissionDenied || err.raw_os_error() == Some(5) {
        Sys2RustError::PermissionDenied {
            operation,
            detail: err.to_string(),
            hint: "Run elevated as Administrator".to_string(),
        }
    } else if err.kind() == std::io::ErrorKind::NotFound {
        Sys2RustError::NotFound(format!("{operation}: {err}"))
    } else {
        Sys2RustError::Io(err)
    }
}

fn verify_authenticode_status(path: &str, company_hint: &str) -> String {
    if path.is_empty() || !Path::new(path).exists() {
        return String::new();
    }
    let wide = wide_z(path);
    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: Default::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut wt_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..std::mem::zeroed()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(HWND::default(), &mut action, (&raw mut wt_data).cast());
        wt_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, (&raw mut wt_data).cast());

        if status == 0 {
            if !company_hint.is_empty() {
                format!("Verified ({company_hint})")
            } else {
                "Verified (Authenticode)".to_string()
            }
        } else if status as u32 == 0x800B_0100 {
            "Unsigned".to_string()
        } else {
            format!("Untrusted ({:#010x})", status as u32)
        }
    }
}

fn find_desktop_listview() -> Option<HWND> {
    unsafe {
        let progman_w = wide_z("Progman");
        let defview_w = wide_z("SHELLDLL_DefView");
        let listview_w = wide_z("SysListView32");

        if let Ok(progman) = FindWindowW(PCWSTR(progman_w.as_ptr()), None)
            && let Ok(defview) = FindWindowExW(Some(progman), None, PCWSTR(defview_w.as_ptr()), None)
            && let Ok(listview) = FindWindowExW(Some(defview), None, PCWSTR(listview_w.as_ptr()), None)
        {
            return Some(listview);
        }

        struct WorkerSearch {
            found: Option<HWND>,
            defview_w: Vec<u16>,
            listview_w: Vec<u16>,
        }

        unsafe extern "system" fn enum_workerw_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
            unsafe {
                let state = &mut *(lparam.0 as *mut WorkerSearch);
                let mut cls = [0u16; 64];
                let len = GetClassNameW(hwnd, &mut cls);
                let cls_name = String::from_utf16_lossy(&cls[..len.max(0) as usize]);
                if cls_name == "WorkerW"
                    && let Ok(defview) = FindWindowExW(Some(hwnd), None, PCWSTR(state.defview_w.as_ptr()), None)
                    && let Ok(listview) = FindWindowExW(Some(defview), None, PCWSTR(state.listview_w.as_ptr()), None)
                {
                    state.found = Some(listview);
                    return BOOL(0);
                }
                BOOL(1)
            }
        }

        let mut search = WorkerSearch {
            found: None,
            defview_w,
            listview_w,
        };
        let _ = EnumWindows(Some(enum_workerw_cb), LPARAM((&raw mut search) as isize));
        search.found
    }
}

impl ShellBackend for LiveWin32ShellBackend {
    fn list_startup(&self) -> Sys2RustResult<Vec<StartupItem>> {
        let mut out = Vec::new();
        let sources = [
            (
                HKEY_CURRENT_USER,
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "Current User",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "All Users",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM32",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                "All Users (WOW64)",
            ),
        ];

        for (hive, hive_label, run_path, app_path, user_label) in sources {
            let root = RegKey::predef(hive);
            let approved_key = root.open_subkey(app_path).ok();
            if let Ok(rk) = root.open_subkey(run_path) {
                for (name, val) in rk.enum_values().flatten() {
                    let cmd = val.to_string();
                    let exe = extract_exe_from_cmdline(&cmd);
                    let (disabled, changed_at) = approved_key
                        .as_ref()
                        .and_then(|ak| ak.get_raw_value(&name).ok())
                        .and_then(|rv| decode_startup_approved(&rv.bytes))
                        .map(|s| (s.disabled, s.changed_at))
                        .unwrap_or((false, None));
                    out.push(StartupItem {
                        entry_name: name,
                        item_type: format!("{hive_label} Run"),
                        command_line: cmd,
                        exe_path: exe,
                        location: format!("{hive_label}\\{run_path}"),
                        disabled,
                        user: user_label.to_string(),
                        product_name: String::new(),
                        signed: false,
                        file_time: changed_at,
                    });
                }
            }
        }
        Ok(out)
    }

    fn list_uninstall(&self) -> Sys2RustResult<Vec<UninstallItem>> {
        let mut out = Vec::new();
        let sources = [
            (
                HKEY_LOCAL_MACHINE,
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "x64",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "x86",
            ),
            (
                HKEY_CURRENT_USER,
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "User",
            ),
        ];
        for (hive, label, path, arch) in sources {
            let root = RegKey::predef(hive);
            if let Ok(uk) = root.open_subkey(path) {
                for sub_name in uk.enum_keys().flatten() {
                    if let Ok(sk) = uk.open_subkey(&sub_name) {
                        let display_name: String = sk.get_value("DisplayName").unwrap_or_default();
                        if display_name.is_empty() {
                            continue;
                        }
                        out.push(UninstallItem {
                            display_name,
                            version: sk.get_value("DisplayVersion").unwrap_or_default(),
                            publisher: sk.get_value("Publisher").unwrap_or_default(),
                            install_date: sk.get_value("InstallDate").unwrap_or_default(),
                            estimated_size_kb: u64::from(sk.get_value::<u32, _>("EstimatedSize").unwrap_or(0)),
                            install_location: sk.get_value("InstallLocation").unwrap_or_default(),
                            uninstall_string: sk.get_value("UninstallString").unwrap_or_default(),
                            quiet_uninstall_string: sk.get_value("QuietUninstallString").unwrap_or_default(),
                            registry_key: format!("{label}\\{path}\\{sub_name}"),
                            arch: arch.to_string(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    fn list_msi(&self) -> Sys2RustResult<Vec<MsiPackageItem>> {
        let mut out = Vec::new();
        unsafe {
            let mut idx = 0u32;
            loop {
                let mut code_buf = [0u16; 39];
                let mut ctx = MSIINSTALLCONTEXT::default();
                let rc = MsiEnumProductsExW(
                    None,
                    None,
                    MSIINSTALLCONTEXT_ALL.0 as u32,
                    idx,
                    Some(&mut code_buf),
                    Some(&mut ctx),
                    None,
                    None,
                );
                if rc != 0 {
                    break;
                }
                idx += 1;
                let prod_code = wchar_z_to_string(&code_buf);
                let get_prop = |prop: &str| -> String {
                    let prop_w = wide_z(prop);
                    let mut buf = [0u16; 512];
                    let mut len = buf.len() as u32;
                    let r = MsiGetProductInfoExW(
                        PCWSTR(code_buf.as_ptr()),
                        None,
                        ctx,
                        PCWSTR(prop_w.as_ptr()),
                        Some(PWSTR(buf.as_mut_ptr())),
                        Some(&mut len),
                    );
                    if r == 0 {
                        String::from_utf16_lossy(&buf[..len as usize])
                    } else {
                        String::new()
                    }
                };
                out.push(MsiPackageItem {
                    package_name: get_prop("InstalledProductName"),
                    product_code: prod_code,
                    version: get_prop("VersionString"),
                    vendor: get_prop("Publisher"),
                    install_date: get_prop("InstallDate"),
                    local_package_msi: get_prop("LocalPackage"),
                    install_source: get_prop("InstallSource"),
                    files_count: 0,
                    registry_entries_count: 0,
                });
                if out.len() >= 512 {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn list_appx(&self) -> Sys2RustResult<Vec<AppxPkgItem>> {
        let mut out = Vec::new();
        let Ok(pm) = PackageManager::new() else {
            return Ok(out);
        };
        let Ok(iter) = pm.FindPackagesByUserSecurityId(&HSTRING::new()) else {
            return Ok(out);
        };
        for pkg in iter {
            let Ok(id) = pkg.Id() else { continue };
            let name = id.Name().map(|h| h.to_string()).unwrap_or_default();
            let family = id.FamilyName().map(|h| h.to_string()).unwrap_or_default();
            let publisher = id.Publisher().map(|h| h.to_string()).unwrap_or_default();
            let ver = id
                .Version()
                .map(|v| format!("{}.{}.{}.{}", v.Major, v.Minor, v.Build, v.Revision))
                .unwrap_or_default();
            let arch = id.Architecture().map(|a| format!("{a:?}")).unwrap_or_default();
            let loc = pkg
                .InstalledLocation()
                .and_then(|sf| sf.Path())
                .map(|p| p.to_string())
                .unwrap_or_default();
            let is_framework = pkg.IsFramework().unwrap_or(false);
            out.push(AppxPkgItem {
                package_name: name,
                family_name: family.clone(),
                version: ver,
                publisher,
                architecture: arch,
                install_location: loc,
                is_framework,
                non_removable: false,
                app_user_model_id: format!("{family}!App"),
            });
            if out.len() >= 512 {
                break;
            }
        }
        Ok(out)
    }

    fn list_legacy_uninst(&self) -> Sys2RustResult<Vec<LegacyUninstallItem>> {
        Ok(self
            .list_uninstall()?
            .into_iter()
            .map(|u| LegacyUninstallItem {
                program_name: u.display_name,
                version: u.version,
                publisher: u.publisher,
                install_date: u.install_date,
                uninstall_command: u.uninstall_string,
                registry_path: u.registry_key,
            })
            .collect())
    }

    fn list_shellex(&self) -> Sys2RustResult<Vec<ShellExtItem>> {
        let mut out = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        if let Ok(approved) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved") {
            let blocked = hklm
                .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")
                .ok();
            for (clsid, desc) in approved.enum_values().flatten().take(512) {
                let dll = hkcr
                    .open_subkey(format!(r"CLSID\{clsid}\InprocServer32"))
                    .and_then(|k| k.get_value::<String, _>(""))
                    .unwrap_or_default();
                let is_disabled = blocked.as_ref().is_some_and(|b| b.get_raw_value(&clsid).is_ok());
                out.push(ShellExtItem {
                    extension_name: desc.to_string(),
                    disabled: is_disabled,
                    ext_type: "Approved ShellEx".to_string(),
                    clsid,
                    filename: dll,
                    file_extensions: "*".to_string(),
                    company: String::new(),
                    microsoft: false,
                });
            }
        }
        Ok(out)
    }

    fn list_menus(&self) -> Sys2RustResult<Vec<ShellMenuItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        for ftype in ["*", "Directory", "Folder"] {
            if let Ok(sk) = hkcr.open_subkey(format!(r"{ftype}\shell")) {
                for verb in sk.enum_keys().flatten() {
                    if let Ok(vk) = sk.open_subkey(&verb) {
                        let menu_name: String = vk.get_value("").unwrap_or_else(|_| verb.clone());
                        let icon: String = vk.get_value("Icon").unwrap_or_default();
                        let disabled = vk.get_raw_value("LegacyDisable").is_ok();
                        let cmd = vk
                            .open_subkey("command")
                            .and_then(|ck| ck.get_value::<String, _>(""))
                            .unwrap_or_default();
                        out.push(ShellMenuItem {
                            menu_name,
                            menu_key: verb.clone(),
                            file_type: ftype.to_string(),
                            extension: ftype.to_string(),
                            command_line: cmd,
                            disabled,
                            icon,
                            registry_key: format!(r"HKCR\{ftype}\shell\{verb}"),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    fn list_menu_new(&self) -> Sys2RustResult<Vec<ShellMenuNewItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        for ext in hkcr.enum_keys().flatten().filter(|k| k.starts_with('.')) {
            if let Ok(ek) = hkcr.open_subkey(&ext)
                && let Ok(sn) = ek.open_subkey("ShellNew")
            {
                let ftype: String = ek.get_value("").unwrap_or_default();
                let ttype = if sn.get_raw_value("NullFile").is_ok() {
                    "NullFile"
                } else if sn.get_raw_value("FileName").is_ok() {
                    "FileName"
                } else if sn.get_raw_value("Command").is_ok() {
                    "Command"
                } else if sn.get_raw_value("Data").is_ok() {
                    "Data"
                } else {
                    "Other"
                };
                let disabled = sn.get_raw_value("LegacyDisable").is_ok();
                out.push(ShellMenuNewItem {
                    extension: ext.clone(),
                    file_type: ftype.clone(),
                    menu_text: ftype,
                    template_type: ttype.to_string(),
                    disabled,
                    registry_key: format!(r"HKCR\{ext}\ShellNew"),
                });
            }
        }
        Ok(out)
    }

    fn list_filetypes(&self) -> Sys2RustResult<Vec<FileTypeItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        for ext in hkcr.enum_keys().flatten().filter(|k| k.starts_with('.')) {
            if let Ok(ek) = hkcr.open_subkey(&ext) {
                let type_name: String = ek.get_value("").unwrap_or_default();
                let mime: String = ek.get_value("Content Type").unwrap_or_default();
                let perceived: String = ek.get_value("PerceivedType").unwrap_or_default();
                let (desc, icon, cmd) = if !type_name.is_empty()
                    && let Ok(tk) = hkcr.open_subkey(&type_name)
                {
                    let d = tk.get_value("").unwrap_or_default();
                    let ic = tk
                        .open_subkey("DefaultIcon")
                        .and_then(|k| k.get_value::<String, _>(""))
                        .unwrap_or_default();
                    let oc = tk
                        .open_subkey(r"shell\open\command")
                        .and_then(|k| k.get_value::<String, _>(""))
                        .unwrap_or_default();
                    (d, ic, oc)
                } else {
                    Default::default()
                };
                out.push(FileTypeItem {
                    extension: ext,
                    type_name,
                    description: desc,
                    mime_type: mime,
                    perceived_type: perceived,
                    default_icon: icon,
                    open_command: cmd,
                    flags: 0,
                    modified_time: None,
                });
            }
        }
        Ok(out)
    }

    fn list_openwith(&self) -> Sys2RustResult<Vec<OpenWithItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        if let Ok(apps) = hkcr.open_subkey("Applications") {
            for app in apps.enum_keys().flatten().take(256) {
                if let Ok(ak) = apps.open_subkey(&app) {
                    let disabled = ak.get_raw_value("NoOpenWith").is_ok();
                    let cmd = ak
                        .open_subkey(r"shell\open\command")
                        .and_then(|k| k.get_value::<String, _>(""))
                        .unwrap_or_default();
                    let exe = extract_exe_from_cmdline(&cmd);
                    out.push(OpenWithItem {
                        application_name: app.clone(),
                        exe_path: exe,
                        disabled,
                        company: String::new(),
                        description: ak.get_value("FriendlyAppName").unwrap_or_default(),
                        registry_key: format!(r"HKCR\Applications\{app}"),
                    });
                }
            }
        }
        Ok(out)
    }

    fn list_com(&self) -> Sys2RustResult<Vec<ComRegItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        if let Ok(clsids) = hkcr.open_subkey("CLSID") {
            for clsid in clsids.enum_keys().flatten().take(300) {
                if let Ok(ck) = clsids.open_subkey(&clsid)
                    && let Ok(inproc) = ck.open_subkey("InprocServer32")
                {
                    let dll: String = inproc.get_value("").unwrap_or_default();
                    if dll.is_empty() {
                        continue;
                    }
                    let prog_id = ck
                        .open_subkey("ProgID")
                        .and_then(|k| k.get_value::<String, _>(""))
                        .unwrap_or_default();
                    let tlib = ck
                        .open_subkey("TypeLib")
                        .and_then(|k| k.get_value::<String, _>(""))
                        .unwrap_or_default();
                    let exists = Path::new(&dll).exists() || !dll.contains('\\');
                    out.push(ComRegItem {
                        dll_path: dll,
                        clsid_count: 1,
                        prog_ids: prog_id,
                        type_lib: tlib,
                        last_registered: None,
                        file_exists: exists,
                        company: String::new(),
                        arch: "x64".to_string(),
                    });
                }
            }
        }
        Ok(out)
    }

    fn list_url_proto(&self) -> Sys2RustResult<Vec<UrlProtoItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        for key_name in hkcr
            .enum_keys()
            .flatten()
            .filter(|k| !k.starts_with('.') && k != "CLSID")
        {
            if let Ok(pk) = hkcr.open_subkey(&key_name)
                && pk.get_raw_value("URL Protocol").is_ok()
            {
                let desc: String = pk.get_value("").unwrap_or_default();
                let cmd = pk
                    .open_subkey(r"shell\open\command")
                    .and_then(|k| k.get_value::<String, _>(""))
                    .unwrap_or_default();
                let disabled = pk.get_raw_value("LegacyDisable").is_ok();
                out.push(UrlProtoItem {
                    protocol_name: key_name.clone(),
                    description: desc,
                    command_line: cmd,
                    disabled,
                    registry_key: format!(r"HKCR\{key_name}"),
                    modified_time: None,
                });
            }
        }
        Ok(out)
    }

    fn list_appcompat(&self) -> Sys2RustResult<Vec<AppCompatItem>> {
        let mut out = Vec::new();
        let path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
        for (hive, scope) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            if let Ok(lk) = RegKey::predef(hive).open_subkey(path) {
                for (exe, val) in lk.enum_values().flatten() {
                    out.push(AppCompatItem {
                        file_exists: Path::new(&exe).exists(),
                        exe_path: exe,
                        layers: val.to_string(),
                        scope: scope.to_string(),
                        modified_time: None,
                    });
                }
            }
        }
        Ok(out)
    }

    fn list_mui_ver(&self) -> Sys2RustResult<Vec<MuiVerItem>> {
        let mut out = Vec::new();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mui_path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        if let Ok(mk) = hkcu.open_subkey(mui_path) {
            for (name, val) in mk.enum_values().flatten().take(200) {
                let exe = name.split(".FriendlyAppName").next().unwrap_or(&name).to_string();
                let (desc, prod, ver, comp, orig, internal) = query_file_ver(&exe);
                let signer = verify_authenticode_status(&exe, &comp);
                out.push(MuiVerItem {
                    exe_path: exe,
                    file_description: if desc.is_empty() { val.to_string() } else { desc },
                    product_name: prod,
                    file_version: ver,
                    company: comp,
                    original_filename: orig,
                    internal_name: internal,
                    signer,
                });
            }
        }
        Ok(out)
    }

    fn list_ext_view(&self) -> Sys2RustResult<Vec<ExplorerExtItem>> {
        let mut out = Vec::new();
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let blocked = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")
            .ok();
        for ext in hkcr.enum_keys().flatten().filter(|k| k.starts_with('.')) {
            if let Ok(shellex) = hkcr.open_subkey(format!(r"{ext}\ShellEx")) {
                for kind in shellex.enum_keys().flatten() {
                    if let Ok(hk) = shellex.open_subkey(&kind) {
                        let clsid: String = hk.get_value("").unwrap_or_default();
                        let dll = if !clsid.is_empty() {
                            hkcr.open_subkey(format!(r"CLSID\{clsid}\InprocServer32"))
                                .and_then(|k| k.get_value::<String, _>(""))
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        let enabled = blocked.as_ref().is_none_or(|b| b.get_raw_value(&clsid).is_err());
                        out.push(ExplorerExtItem {
                            extension: ext.clone(),
                            handler_kind: kind,
                            clsid,
                            target_dll: dll,
                            enabled,
                            description: String::new(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    fn list_env_vars(&self) -> Sys2RustResult<Vec<EnvVarItem>> {
        let mut out = Vec::new();
        for (hive, scope, path) in [
            (HKEY_CURRENT_USER, "User", r"Environment"),
            (
                HKEY_LOCAL_MACHINE,
                "System",
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ),
        ] {
            if let Ok(ek) = RegKey::predef(hive).open_subkey(path) {
                for (name, val) in ek.enum_values().flatten() {
                    let raw = val.to_string();
                    let expanded = std::env::var(&name).unwrap_or_else(|_| raw.clone());
                    out.push(EnvVarItem {
                        scope: scope.to_string(),
                        name,
                        value: raw,
                        expanded_value: expanded,
                        registry_key: format!("{scope}\\{path}"),
                    });
                }
            }
        }
        Ok(out)
    }

    fn list_desktop_icons(&self) -> Sys2RustResult<Vec<DesktopIconItem>> {
        // Strictly NO cross-process memory write: uses VirtualAllocEx + LVM_GETITEMPOSITION + ReadProcessMemory!
        let mut out = Vec::new();
        unsafe {
            let Some(listview) = find_desktop_listview() else {
                return Ok(out);
            };

            let count = SendMessageW(listview, LVM_GETITEMCOUNT, Some(WPARAM(0)), Some(LPARAM(0)))
                .0
                .max(0) as usize;
            let mut pid = 0u32;
            GetWindowThreadProcessId(listview, Some(&mut pid));
            if pid == 0 || count == 0 {
                return Ok(out);
            }

            let Ok(h_proc) = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, false, pid) else {
                return Ok(out);
            };
            let remote_pt = VirtualAllocEx(
                h_proc,
                None,
                size_of::<POINT>(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if !remote_pt.is_null() {
                let now = Utc::now();
                for idx in 0..count.min(256) {
                    let ok = SendMessageW(
                        listview,
                        LVM_GETITEMPOSITION,
                        Some(WPARAM(idx)),
                        Some(LPARAM(remote_pt as isize)),
                    );
                    if ok.0 != 0 {
                        let mut pt = POINT::default();
                        let mut read_n = 0usize;
                        if ReadProcessMemory(
                            h_proc,
                            remote_pt,
                            (&raw mut pt).cast(),
                            size_of::<POINT>(),
                            Some(&mut read_n),
                        )
                        .is_ok()
                        {
                            out.push(DesktopIconItem {
                                icon_name: format!("DesktopIcon_{idx}"),
                                x: pt.x,
                                y: pt.y,
                                monitor: "Primary".to_string(),
                                profile_name: "LiveExplorer".to_string(),
                                saved_at: now,
                            });
                        }
                    }
                }
                let _ = VirtualFreeEx(h_proc, remote_pt, 0, MEM_RELEASE);
            }
            let _ = CloseHandle(h_proc);
        }
        Ok(out)
    }

    fn list_tray_icons(&self) -> Sys2RustResult<Vec<TrayIconItem>> {
        let mut out = Vec::new();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(tn) =
            hkcu.open_subkey(r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify")
        {
            for name in ["IconStreams", "PastIconsStream"] {
                if let Ok(rv) = tn.get_raw_value(name) {
                    out.extend(parse_tray_notify_stream(name, &rv.bytes));
                }
            }
        }
        if let Ok(nis) = hkcu.open_subkey(r"Control Panel\NotifyIconSettings") {
            for sub in nis.enum_keys().flatten() {
                if let Ok(sk) = nis.open_subkey(&sub) {
                    let exe: String = sk.get_value("ExecutablePath").unwrap_or_default();
                    if exe.is_empty() {
                        continue;
                    }
                    let tip: String = sk.get_value("InitialTooltip").unwrap_or_default();
                    let promoted: u32 = sk.get_value("IsPromoted").unwrap_or(0);
                    out.push(TrayIconItem {
                        executable: exe,
                        tip_text: tip,
                        guid: sk.get_value("UID").unwrap_or_default(),
                        visibility: if promoted == 1 { "Show" } else { "OnlyNotifications" }.to_string(),
                        registry_key: format!(r"HKCU\Control Panel\NotifyIconSettings\{sub}"),
                    });
                }
            }
        }
        Ok(out)
    }

    fn audit_privacy(&self) -> Sys2RustResult<Vec<PrivacyAuditItem>> {
        let mut out = Vec::new();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for (cat, path) in [
            ("RunMRU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            (
                "TypedPaths",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            ),
            (
                "WordWheelQuery",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
            ),
        ] {
            if let Ok(k) = hkcu.open_subkey(path) {
                let vals: Vec<(String, String)> = k
                    .enum_values()
                    .flatten()
                    .filter(|(n, _)| n != "MRUList" && n != "MRUListEx")
                    .map(|(n, v)| (n, v.to_string()))
                    .collect();
                out.push(PrivacyAuditItem {
                    category: cat.to_string(),
                    location: format!("HKCU\\{path}"),
                    item_count: vals.len() as u64,
                    total_bytes: vals.iter().map(|(_, v)| v.len() as u64).sum(),
                    sample_entry: vals.first().map(|(_, v)| v.clone()).unwrap_or_default(),
                });
            }
        }

        let temp_dir = std::env::temp_dir();
        let mut count = 0u64;
        let mut total_bytes = 0u64;
        let mut sample = String::new();
        for dent in std::fs::read_dir(&temp_dir).into_iter().flatten().flatten().take(500) {
            if let Ok(m) = dent.metadata()
                && m.is_file()
            {
                count += 1;
                total_bytes += m.len();
                if sample.is_empty() {
                    sample = dent.file_name().to_string_lossy().to_string();
                }
            }
        }
        out.push(PrivacyAuditItem {
            category: "Temp".to_string(),
            location: temp_dir.display().to_string(),
            item_count: count,
            total_bytes,
            sample_entry: sample,
        });
        Ok(out)
    }

    fn toggle_startup(&self, entry_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would set StartupApproved '{entry_name}' enabled={enable}"
            ));
        }
        let sources = [
            (
                HKEY_CURRENT_USER,
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM32",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
            ),
        ];

        for (hive, label, run_path, app_path) in sources {
            let root = RegKey::predef(hive);
            let in_run = root
                .open_subkey(run_path)
                .is_ok_and(|k| k.get_raw_value(entry_name).is_ok());
            let in_app = root
                .open_subkey(app_path)
                .is_ok_and(|k| k.get_raw_value(entry_name).is_ok());
            if in_run || in_app {
                let (key, _) = root
                    .create_subkey_with_flags(app_path, KEY_READ | KEY_WRITE)
                    .map_err(|e| map_reg_err("RegOpenKey(StartupApproved)", e))?;
                let blob = encode_startup_approved(!enable, Some(Utc::now()));
                key.set_raw_value(
                    entry_name,
                    &winreg::RegValue {
                        vtype: winreg::enums::REG_BINARY,
                        bytes: blob.to_vec().into(),
                    },
                )
                .map_err(|e| map_reg_err("RegSetValue(StartupApproved)", e))?;
                return Ok(format!("set {label} StartupApproved '{entry_name}' enabled={enable}"));
            }
        }
        Err(Sys2RustError::NotFound(format!("startup entry '{entry_name}'")))
    }

    fn delete_startup(&self, entry_name: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would delete startup Run '{entry_name}'"));
        }
        let sources = [
            (
                HKEY_CURRENT_USER,
                "HKCU",
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            ),
            (
                HKEY_LOCAL_MACHINE,
                "HKLM32",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
            ),
        ];

        for (hive, label, run_path, app_path) in sources {
            let root = RegKey::predef(hive);
            if root
                .open_subkey(run_path)
                .is_ok_and(|k| k.get_raw_value(entry_name).is_ok())
            {
                let key = root
                    .open_subkey_with_flags(run_path, KEY_READ | KEY_WRITE)
                    .map_err(|e| map_reg_err("RegOpenKey(Run)", e))?;
                key.delete_value(entry_name)
                    .map_err(|e| map_reg_err("RegDeleteValue(Run)", e))?;
                if let Ok(ak) = root.open_subkey_with_flags(app_path, KEY_READ | KEY_WRITE) {
                    let _ = ak.delete_value(entry_name);
                }
                return Ok(format!("deleted {label} Run value '{entry_name}'"));
            }
        }
        Err(Sys2RustError::NotFound(format!("startup entry '{entry_name}'")))
    }

    fn run_uninstall(&self, display_name: &str, quiet: bool, dry_run: bool) -> Sys2RustResult<String> {
        let items = self.list_uninstall()?;
        let Some(target) = items
            .into_iter()
            .find(|u| u.display_name.eq_ignore_ascii_case(display_name))
        else {
            return Err(Sys2RustError::NotFound(format!("installed program '{display_name}'")));
        };
        let cmd = if quiet && !target.quiet_uninstall_string.is_empty() {
            target.quiet_uninstall_string
        } else {
            target.uninstall_string
        };
        if cmd.trim().is_empty() {
            return Err(Sys2RustError::InvalidArgument(format!(
                "installed program '{display_name}' has empty uninstall command"
            )));
        }
        if dry_run {
            return Ok(format!("[dry-run] would execute uninstaller: {cmd}"));
        }

        let mut cmd_w = wide_z(&cmd);
        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let flags = if quiet {
                CREATE_NO_WINDOW
            } else {
                PROCESS_CREATION_FLAGS(0)
            };
            if let Err(e) = CreateProcessW(
                None,
                Some(PWSTR(cmd_w.as_mut_ptr())),
                None,
                None,
                false,
                flags,
                None,
                None,
                &si,
                &mut pi,
            ) {
                let code = e.code().0 as u32;
                if code == 5 || code == 0x8007_0005 || code == 740 || code == 0x8007_02E4 {
                    return Err(Sys2RustError::PermissionDenied {
                        operation: "CreateProcessW(RunUninstall)",
                        detail: e.message(),
                        hint: "Run elevated as Administrator".to_string(),
                    });
                }
                return Err(Sys2RustError::OsError {
                    api: "CreateProcessW(RunUninstall)",
                    code,
                    message: e.message(),
                });
            }
            let pid = pi.dwProcessId;
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            Ok(format!("launched uninstaller for '{display_name}' (pid={pid})"))
        }
    }

    fn toggle_shellex(&self, clsid: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set ShellEx '{clsid}' enabled={enable}"));
        }
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let blocked_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
        let (key, _) = hklm
            .create_subkey_with_flags(blocked_path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegCreateKey(Shell Extensions\\Blocked)", e))?;
        if enable {
            match key.delete_value(clsid) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_reg_err("RegDeleteValue(Shell Extensions\\Blocked)", e)),
            }
        } else {
            key.set_value(clsid, &"Blocked by sys2rust")
                .map_err(|e| map_reg_err("RegSetValue(Shell Extensions\\Blocked)", e))?;
        }
        Ok(format!("set ShellEx '{clsid}' enabled={enable}"))
    }

    fn toggle_menu(&self, menu_key: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set shell menu '{menu_key}' enabled={enable}"));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let candidates: Vec<String> = if let Some(stripped) = menu_key.strip_prefix(r"HKCR\") {
            vec![stripped.to_string()]
        } else if menu_key.contains('\\') {
            vec![menu_key.to_string()]
        } else {
            ["*", "Directory", "Folder"]
                .into_iter()
                .map(|ft| format!(r"{ft}\shell\{menu_key}"))
                .collect()
        };

        let target_path = candidates
            .into_iter()
            .find(|p| hkcr.open_subkey(p).is_ok())
            .ok_or_else(|| Sys2RustError::NotFound(format!("shell menu '{menu_key}'")))?;

        let key = hkcr
            .open_subkey_with_flags(&target_path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\...\\shell)", e))?;
        if enable {
            match key.delete_value("LegacyDisable") {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_reg_err("RegDeleteValue(LegacyDisable)", e)),
            }
        } else {
            key.set_value("LegacyDisable", &"")
                .map_err(|e| map_reg_err("RegSetValue(LegacyDisable)", e))?;
        }
        Ok(format!("set shell menu '{target_path}' enabled={enable}"))
    }

    fn toggle_menu_new(&self, extension: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set ShellNew '{extension}' enabled={enable}"));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let path = format!(r"{extension}\ShellNew");
        let key = hkcr
            .open_subkey_with_flags(&path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(ShellNew)", e))?;
        if enable {
            match key.delete_value("LegacyDisable") {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_reg_err("RegDeleteValue(ShellNew\\LegacyDisable)", e)),
            }
        } else {
            key.set_value("LegacyDisable", &"")
                .map_err(|e| map_reg_err("RegSetValue(ShellNew\\LegacyDisable)", e))?;
        }
        Ok(format!("set ShellNew '{extension}' enabled={enable}"))
    }

    fn edit_filetype(&self, extension: &str, description: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set '{extension}' description='{description}'"));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let ext_key = hkcr
            .open_subkey_with_flags(extension, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\ext)", e))?;
        let type_name: String = ext_key.get_value("").unwrap_or_default();
        if !type_name.is_empty()
            && let Ok(tk) = hkcr.open_subkey_with_flags(&type_name, KEY_READ | KEY_WRITE)
        {
            tk.set_value("", &description)
                .map_err(|e| map_reg_err("RegSetValue(ProgID)", e))?;
            return Ok(format!("updated '{type_name}' ({extension}) description"));
        }
        ext_key
            .set_value("", &description)
            .map_err(|e| map_reg_err("RegSetValue(HKCR\\ext)", e))?;
        Ok(format!("updated '{extension}' description"))
    }

    fn toggle_openwith(&self, app_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set OpenWith '{app_name}' enabled={enable}"));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let path = format!(r"Applications\{app_name}");
        let key = hkcr
            .open_subkey_with_flags(&path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\Applications)", e))?;
        if enable {
            match key.delete_value("NoOpenWith") {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_reg_err("RegDeleteValue(NoOpenWith)", e)),
            }
        } else {
            key.set_value("NoOpenWith", &"")
                .map_err(|e| map_reg_err("RegSetValue(NoOpenWith)", e))?;
        }
        Ok(format!("set OpenWith '{app_name}' enabled={enable}"))
    }

    fn clean_com_orphan(&self, dll_path: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would clean orphan COM registration '{dll_path}'"));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let clsids = hkcr
            .open_subkey("CLSID")
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\CLSID)", e))?;

        let mut matched_clsids = Vec::new();
        for clsid in clsids.enum_keys().flatten() {
            if let Ok(ck) = clsids.open_subkey(&clsid)
                && let Ok(inproc) = ck.open_subkey("InprocServer32")
            {
                let dll: String = inproc.get_value("").unwrap_or_default();
                if dll.eq_ignore_ascii_case(dll_path) {
                    if Path::new(&dll).exists() || !dll.contains('\\') {
                        return Err(Sys2RustError::InvalidArgument(format!(
                            "COM target '{dll}' exists or is not an orphaned path"
                        )));
                    }
                    matched_clsids.push(clsid);
                }
            }
        }
        if matched_clsids.is_empty() {
            return Err(Sys2RustError::NotFound(format!(
                "orphaned COM registration for '{dll_path}'"
            )));
        }
        let clsids_rw = hkcr
            .open_subkey_with_flags("CLSID", KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\CLSID write)", e))?;
        for clsid in &matched_clsids {
            clsids_rw
                .delete_subkey_all(clsid)
                .map_err(|e| map_reg_err("RegDeleteTree(HKCR\\CLSID)", e))?;
        }
        Ok(format!(
            "cleaned {} orphaned COM registration(s) for '{dll_path}'",
            matched_clsids.len()
        ))
    }

    fn toggle_url_proto(&self, protocol: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would set URL protocol '{protocol}' enabled={enable}"
            ));
        }
        let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
        let key = hkcr
            .open_subkey_with_flags(protocol, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(HKCR\\protocol)", e))?;
        if key.get_raw_value("URL Protocol").is_err() && key.get_raw_value("LegacyDisable").is_err() {
            return Err(Sys2RustError::NotFound(format!("URL protocol '{protocol}'")));
        }
        if enable {
            match key.delete_value("LegacyDisable") {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(map_reg_err("RegDeleteValue(LegacyDisable)", e)),
            }
        } else {
            key.set_value("LegacyDisable", &"")
                .map_err(|e| map_reg_err("RegSetValue(LegacyDisable)", e))?;
        }
        Ok(format!("set URL protocol '{protocol}' enabled={enable}"))
    }

    fn set_appcompat(&self, exe_path: &str, layers: &str, scope: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would set AppCompat '{layers}' on '{exe_path}' ({scope})"
            ));
        }
        let hive = if scope.eq_ignore_ascii_case("HKLM") {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let root = RegKey::predef(hive);
        let (key, _) = root
            .create_subkey_with_flags(
                r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
                KEY_READ | KEY_WRITE,
            )
            .map_err(|e| map_reg_err("RegCreateKey(AppCompatFlags)", e))?;
        key.set_value(exe_path, &layers)
            .map_err(|e| map_reg_err("RegSetValue(AppCompatFlags)", e))?;
        Ok(format!("set AppCompat '{layers}' on '{exe_path}' ({scope})"))
    }

    fn set_env_var(&self, scope: &str, name: &str, value: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set {scope} env var {name}={value}"));
        }
        let (hive, path) = if scope.eq_ignore_ascii_case("User") {
            (HKEY_CURRENT_USER, "Environment")
        } else if scope.eq_ignore_ascii_case("System") {
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            )
        } else {
            return Err(Sys2RustError::InvalidArgument(format!(
                "unknown env scope '{scope}'; expected User or System"
            )));
        };
        let key = RegKey::predef(hive)
            .open_subkey_with_flags(path, KEY_READ | KEY_WRITE)
            .map_err(|e| map_reg_err("RegOpenKey(Environment)", e))?;
        key.set_value(name, &value)
            .map_err(|e| map_reg_err("RegSetValue(Environment)", e))?;
        Ok(format!("set {scope} env var '{name}'"))
    }

    fn restore_desktop_icons(&self, profile: &str, dry_run: bool) -> Sys2RustResult<String> {
        let profile_path = resolve_desktop_profile_path(profile);
        if dry_run {
            return Ok(format!(
                "[dry-run] would restore desktop icons for profile '{}' ({}) via LVM_SETITEMPOSITION (MAKELPARAM)",
                profile,
                profile_path.display()
            ));
        }
        if !profile_path.is_file() {
            return Err(Sys2RustError::NotFound(format!(
                "desktop icon profile '{}' not found at '{}'",
                profile,
                profile_path.display()
            )));
        }
        let ini_text = std::fs::read_to_string(&profile_path)?;
        let icons = parse_desktopok_ini(&ini_text);
        if icons.is_empty() {
            return Err(Sys2RustError::Parse {
                format: "DesktopOK INI",
                detail: format!("no icon coordinates found in '{}'", profile_path.display()),
            });
        }
        let Some(listview) = find_desktop_listview() else {
            return Err(Sys2RustError::SourceUnavailable {
                source_name: "Desktop SysListView32",
                detail: "Could not locate desktop SysListView32 under Progman or WorkerW".to_string(),
            });
        };

        // Zero cross-process memory write — LVM_SETITEMPOSITION packs (x, y) directly into LPARAM!
        let mut applied = 0usize;
        unsafe {
            let item_count = SendMessageW(listview, LVM_GETITEMCOUNT, Some(WPARAM(0)), Some(LPARAM(0)))
                .0
                .max(0) as usize;
            let limit = if item_count > 0 {
                icons.len().min(item_count)
            } else {
                icons.len()
            };
            for (idx, icon) in icons.iter().take(limit).enumerate() {
                let x = (icon.x as i16) as u16 as isize;
                let y = (icon.y as i16) as u16 as isize;
                let lparam = (y << 16) | (x & 0xFFFF);
                let res = SendMessageW(listview, LVM_SETITEMPOSITION, Some(WPARAM(idx)), Some(LPARAM(lparam)));
                if res.0 != 0 {
                    applied += 1;
                }
            }
        }
        Ok(format!(
            "restored {applied} of {} desktop icon(s) for profile '{}' from '{}'",
            icons.len(),
            profile,
            profile_path.display()
        ))
    }

    fn clean_privacy(&self, categories: &[String], dry_run: bool) -> Sys2RustResult<String> {
        let canonical = validate_privacy_categories(categories)?;
        if dry_run {
            return Ok(format!(
                "[dry-run] would clean privacy categories: {}",
                canonical.join(", ")
            ));
        }

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut deleted = 0usize;
        let mut skipped = 0usize;

        for cat in &canonical {
            match *cat {
                "RunMRU" | "TypedPaths" | "WordWheelQuery" => {
                    let reg_path = format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\{cat}");
                    match hkcu.open_subkey_with_flags(&reg_path, KEY_READ | KEY_WRITE) {
                        Ok(k) => {
                            let names: Vec<String> = k.enum_values().flatten().map(|(n, _)| n).collect();
                            for n in names {
                                match k.delete_value(&n) {
                                    Ok(()) => deleted += 1,
                                    Err(_) => skipped += 1,
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(map_reg_err("RegOpenKey(Privacy)", e)),
                    }
                }
                "Temp" => {
                    let temp_dir = std::env::temp_dir();
                    for dent in std::fs::read_dir(&temp_dir)?.flatten() {
                        let p = dent.path();
                        if let Ok(meta) = dent.metadata() {
                            if meta.is_file() {
                                match std::fs::remove_file(&p) {
                                    Ok(()) => deleted += 1,
                                    Err(_) => skipped += 1,
                                }
                            } else if meta.is_dir() {
                                match std::fs::remove_dir(&p) {
                                    Ok(()) => deleted += 1,
                                    Err(_) => skipped += 1,
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(format!(
            "cleaned categories [{}]: deleted={deleted}, skipped={skipped}",
            canonical.join(", ")
        ))
    }
}
