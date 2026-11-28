use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{TimeZone, Utc};
use sys2rust_core::{Sys2RustError, Sys2RustResult};

use crate::backend::{
    AppCompatItem, AppxPkgItem, ComRegItem, DesktopIconItem, EnvVarItem, ExplorerExtItem, FileTypeItem,
    LegacyUninstallItem, MsiPackageItem, MuiVerItem, OpenWithItem, PrivacyAuditItem, ShellBackend, ShellExtItem,
    ShellMenuItem, ShellNewItem, StartupItem, TrayIconItem, UninstallItem, UrlProtoItem,
};
use crate::parsers::{
    decode_startup_approved, encode_startup_approved, parse_appx_manifest_xml, parse_desktop_icons_ini,
    parse_tray_notify_stream, rot13_str, serialize_desktop_icons_ini, validate_privacy_categories,
};

#[derive(Debug, Default)]
struct MockShellState {
    startup: Vec<StartupItem>,
    uninstall: Vec<UninstallItem>,
    shellex: Vec<ShellExtItem>,
    menus: Vec<ShellMenuItem>,
    menu_new: Vec<ShellNewItem>,
    filetypes: Vec<FileTypeItem>,
    openwith: Vec<OpenWithItem>,
    com: Vec<ComRegItem>,
    url_proto: Vec<UrlProtoItem>,
    appcompat: Vec<AppCompatItem>,
    env_vars: Vec<EnvVarItem>,
    desktop_icons: Vec<DesktopIconItem>,
    privacy_items: Vec<PrivacyAuditItem>,
    privacy_temp_dir: Option<PathBuf>,
}

pub struct SyntheticShellBackend {
    state: Mutex<MockShellState>,
}

impl Default for SyntheticShellBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntheticShellBackend {
    pub fn new() -> Self {
        let ts = Utc.with_ymd_and_hms(2026, 11, 23, 3, 0, 0).unwrap();
        let enabled_blob = encode_startup_approved(false, None);
        let disabled_blob = encode_startup_approved(true, Some(ts));
        let st_en = decode_startup_approved(&enabled_blob).unwrap();
        let st_dis = decode_startup_approved(&disabled_blob).unwrap();

        let startup = vec![
            StartupItem {
                entry_name: "SecurityHealth".to_string(),
                item_type: "HKLM Run".to_string(),
                command_line: r"C:\Windows\System32\SecurityHealthSystray.exe".to_string(),
                exe_path: r"C:\Windows\System32\SecurityHealthSystray.exe".to_string(),
                location: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                disabled: st_en.disabled,
                user: "All Users".to_string(),
                product_name: "Windows Security".to_string(),
                signed: true,
                file_time: st_en.changed_at,
            },
            StartupItem {
                entry_name: "CustomUpdater".to_string(),
                item_type: "HKCU Run".to_string(),
                command_line: r"C:\Tools\updater.exe --tray".to_string(),
                exe_path: r"C:\Tools\updater.exe".to_string(),
                location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                disabled: st_dis.disabled,
                user: "Current User".to_string(),
                product_name: "Updater".to_string(),
                signed: false,
                file_time: st_dis.changed_at,
            },
        ];

        let uninstall = vec![UninstallItem {
            display_name: "Git for Windows".to_string(),
            version: "2.47.0".to_string(),
            publisher: "The Git Development Community".to_string(),
            install_date: "20261101".to_string(),
            estimated_size_kb: 320_000,
            install_location: r"C:\Program Files\Git".to_string(),
            uninstall_string: r"C:\Program Files\Git\unins000.exe".to_string(),
            quiet_uninstall_string: r"C:\Program Files\Git\unins000.exe /VERYSILENT".to_string(),
            registry_key: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1".to_string(),
            arch: "x64".to_string(),
        }];

        let shellex = vec![ShellExtItem {
            extension_name: "7-Zip Shell Extension".to_string(),
            disabled: false,
            ext_type: "Context Menu".to_string(),
            clsid: "{23170F69-40C1-278A-1000-000100020000}".to_string(),
            filename: r"C:\Program Files\7-Zip\7-zip.dll".to_string(),
            file_extensions: "*".to_string(),
            company: "Igor Pavlov".to_string(),
            microsoft: false,
        }];

        let menus = vec![ShellMenuItem {
            menu_name: "Open with Code".to_string(),
            menu_key: "VSCode".to_string(),
            file_type: "*".to_string(),
            extension: "*".to_string(),
            command_line: r"C:\Program Files\Microsoft VS Code\Code.exe %1".to_string(),
            disabled: false,
            icon: r"C:\Program Files\Microsoft VS Code\Code.exe".to_string(),
            registry_key: r"HKCR\*\shell\VSCode".to_string(),
        }];

        let menu_new = vec![ShellNewItem {
            extension: ".txt".to_string(),
            file_type: "txtfile".to_string(),
            menu_text: "Text Document".to_string(),
            template_type: "NullFile".to_string(),
            disabled: false,
            registry_key: r"HKCR\.txt\ShellNew".to_string(),
        }];

        let filetypes = vec![FileTypeItem {
            extension: ".rs".to_string(),
            type_name: "RustSourceFile".to_string(),
            description: "Rust Source File".to_string(),
            mime_type: "text/rust".to_string(),
            perceived_type: "text".to_string(),
            default_icon: r"C:\Tools\rust.ico,0".to_string(),
            open_command: r"C:\Tools\editor.exe %1".to_string(),
            flags: 0,
            modified_time: Some(ts),
        }];

        let openwith = vec![OpenWithItem {
            application_name: "notepad.exe".to_string(),
            exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
            disabled: false,
            company: "Microsoft Corporation".to_string(),
            description: "Notepad".to_string(),
            registry_key: r"HKCR\Applications\notepad.exe".to_string(),
        }];

        let com = vec![
            ComRegItem {
                dll_path: r"C:\Windows\System32\shell32.dll".to_string(),
                clsid_count: 14,
                prog_ids: "Shell.Application".to_string(),
                type_lib: "{50A7E9B0-70EF-11D1-B75A-00A0C90564FE}".to_string(),
                last_registered: Some(ts),
                file_exists: true,
                company: "Microsoft Corporation".to_string(),
                arch: "x64".to_string(),
            },
            ComRegItem {
                dll_path: r"C:\Missing\orphan_com.dll".to_string(),
                clsid_count: 1,
                prog_ids: "Orphan.Ctrl".to_string(),
                type_lib: String::new(),
                last_registered: None,
                file_exists: false,
                company: String::new(),
                arch: "x64".to_string(),
            },
        ];

        let url_proto = vec![UrlProtoItem {
            protocol_name: "customproto".to_string(),
            description: "URL:Custom Protocol".to_string(),
            command_line: r"C:\Tools\handler.exe %1".to_string(),
            disabled: false,
            registry_key: r"HKCR\customproto".to_string(),
            modified_time: Some(ts),
        }];

        let appcompat = vec![AppCompatItem {
            exe_path: r"C:\Tools\legacy_app.exe".to_string(),
            layers: "WIN8RTM RUNASADMIN".to_string(),
            scope: "HKCU".to_string(),
            file_exists: false,
            modified_time: Some(ts),
        }];

        let env_vars = vec![EnvVarItem {
            scope: "User".to_string(),
            name: "RUSTUP_HOME".to_string(),
            value: r"%USERPROFILE%\.rustup".to_string(),
            expanded_value: r"C:\Users\User\.rustup".to_string(),
            registry_key: r"HKCU\Environment".to_string(),
        }];

        let desktop_icons = parse_desktop_icons_ini(
            "[DesktopIcons]\nProfile=Workstation\nCount=2\n\n[Icon_0]\nName=Recycle Bin\nX=24\nY=24\nMonitor=Primary\n\n[Icon_1]\nName=sys2rust\nX=24\nY=120\nMonitor=Primary\n",
        );

        let privacy_items = vec![
            PrivacyAuditItem {
                category: "RunMRU".to_string(),
                location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU".to_string(),
                item_count: 3,
                total_bytes: 128,
                sample_entry: "cmd.exe".to_string(),
            },
            PrivacyAuditItem {
                category: "Temp".to_string(),
                location: r"C:\Temp".to_string(),
                item_count: 2,
                total_bytes: 4096,
                sample_entry: "stale_cache.tmp".to_string(),
            },
        ];

        Self {
            state: Mutex::new(MockShellState {
                startup,
                uninstall,
                shellex,
                menus,
                menu_new,
                filetypes,
                openwith,
                com,
                url_proto,
                appcompat,
                env_vars,
                desktop_icons,
                privacy_items,
                privacy_temp_dir: None,
            }),
        }
    }

    pub fn with_privacy_temp_dir(self, dir: PathBuf) -> Self {
        {
            let mut st = self.state.lock().unwrap();
            st.privacy_temp_dir = Some(dir.clone());
            let count = std::fs::read_dir(&dir).map(|d| d.count() as u64).unwrap_or(0);
            if let Some(p) = st.privacy_items.iter_mut().find(|i| i.category == "Temp") {
                p.location = dir.display().to_string();
                p.item_count = count;
            }
        }
        self
    }

    pub fn synthetic_tray_notify_blob() -> Vec<u8> {
        let mut blob = vec![0u8; 20 + 1640];
        blob[0..4].copy_from_slice(&20u32.to_le_bytes());
        let encoded_path = rot13_str(r"C:\Windows\System32\app.exe");
        let encoded_tip = rot13_str("System Tray Monitor");
        let rec = &mut blob[20..20 + 1640];
        for (i, u) in encoded_path.encode_utf16().enumerate() {
            rec[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        rec[528..532].copy_from_slice(&2u32.to_le_bytes()); // Show
        for (i, u) in encoded_tip.encode_utf16().enumerate() {
            rec[532 + i * 2..532 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        blob
    }
}

impl ShellBackend for SyntheticShellBackend {
    fn list_startup(&self) -> Sys2RustResult<Vec<StartupItem>> {
        Ok(self.state.lock().unwrap().startup.clone())
    }
    fn list_uninstall(&self) -> Sys2RustResult<Vec<UninstallItem>> {
        Ok(self.state.lock().unwrap().uninstall.clone())
    }
    fn list_msi(&self) -> Sys2RustResult<Vec<MsiPackageItem>> {
        Ok(vec![MsiPackageItem {
            package_name: "Rust Toolchain MSI Fixture".to_string(),
            product_code: "{11111111-2222-3333-4444-555555555555}".to_string(),
            version: "1.88.0".to_string(),
            vendor: "Rust Foundation".to_string(),
            install_date: "20261115".to_string(),
            local_package_msi: r"C:\Windows\Installer\1234.msi".to_string(),
            install_source: r"C:\Downloads".to_string(),
            files_count: 142,
            registry_entries_count: 18,
        }])
    }
    fn list_appx(&self) -> Sys2RustResult<Vec<AppxPkgItem>> {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Microsoft.WindowsTerminal" Publisher="CN=Microsoft Corporation" Version="1.21.2911.0" ProcessorArchitecture="x64" />
  <Properties><Framework>false</Framework></Properties>
  <Applications><Application Id="App" /></Applications>
</Package>"#;
        Ok(vec![parse_appx_manifest_xml(
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.2911.0_x64__8wekyb3d8bbwe",
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
            xml,
        )?])
    }
    fn list_legacy_uninst(&self) -> Sys2RustResult<Vec<LegacyUninstallItem>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .uninstall
            .iter()
            .map(|u| LegacyUninstallItem {
                program_name: u.display_name.clone(),
                version: u.version.clone(),
                publisher: u.publisher.clone(),
                install_date: u.install_date.clone(),
                uninstall_command: u.uninstall_string.clone(),
                registry_path: u.registry_key.clone(),
            })
            .collect())
    }
    fn list_shellex(&self) -> Sys2RustResult<Vec<ShellExtItem>> {
        Ok(self.state.lock().unwrap().shellex.clone())
    }
    fn list_menus(&self) -> Sys2RustResult<Vec<ShellMenuItem>> {
        Ok(self.state.lock().unwrap().menus.clone())
    }
    fn list_menu_new(&self) -> Sys2RustResult<Vec<ShellNewItem>> {
        Ok(self.state.lock().unwrap().menu_new.clone())
    }
    fn list_filetypes(&self) -> Sys2RustResult<Vec<FileTypeItem>> {
        Ok(self.state.lock().unwrap().filetypes.clone())
    }
    fn list_openwith(&self) -> Sys2RustResult<Vec<OpenWithItem>> {
        Ok(self.state.lock().unwrap().openwith.clone())
    }
    fn list_com(&self) -> Sys2RustResult<Vec<ComRegItem>> {
        Ok(self.state.lock().unwrap().com.clone())
    }
    fn list_url_proto(&self) -> Sys2RustResult<Vec<UrlProtoItem>> {
        Ok(self.state.lock().unwrap().url_proto.clone())
    }
    fn list_appcompat(&self) -> Sys2RustResult<Vec<AppCompatItem>> {
        Ok(self.state.lock().unwrap().appcompat.clone())
    }
    fn list_mui_ver(&self) -> Sys2RustResult<Vec<MuiVerItem>> {
        Ok(vec![MuiVerItem {
            exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
            file_description: "Notepad".to_string(),
            product_name: "Microsoft Windows Operating System".to_string(),
            file_version: "10.0.26300.1".to_string(),
            company: "Microsoft Corporation".to_string(),
            original_filename: "NOTEPAD.EXE".to_string(),
            internal_name: "Notepad".to_string(),
            signer: "Microsoft Windows".to_string(),
        }])
    }
    fn list_ext_view(&self) -> Sys2RustResult<Vec<ExplorerExtItem>> {
        Ok(vec![ExplorerExtItem {
            extension: ".png".to_string(),
            handler_kind: "Thumbnail Handler".to_string(),
            clsid: "{E357FCCD-A995-4576-B01F-234630154E96}".to_string(),
            target_dll: r"C:\Windows\System32\thumbcache.dll".to_string(),
            enabled: true,
            description: "Windows Thumbnail Provider".to_string(),
        }])
    }
    fn list_env_vars(&self) -> Sys2RustResult<Vec<EnvVarItem>> {
        Ok(self.state.lock().unwrap().env_vars.clone())
    }
    fn list_desktop_icons(&self) -> Sys2RustResult<Vec<DesktopIconItem>> {
        Ok(self.state.lock().unwrap().desktop_icons.clone())
    }
    fn list_tray_icons(&self) -> Sys2RustResult<Vec<TrayIconItem>> {
        let mut items = parse_tray_notify_stream("IconStreams", &Self::synthetic_tray_notify_blob());
        items.push(TrayIconItem {
            executable: r"C:\Windows\System32\SecurityHealthSystray.exe".to_string(),
            tip_text: "Windows Security".to_string(),
            guid: String::new(),
            visibility: "Show".to_string(),
            registry_key: r"HKCU\Control Panel\NotifyIconSettings\1001".to_string(),
        });
        Ok(items)
    }
    fn audit_privacy(&self) -> Sys2RustResult<Vec<PrivacyAuditItem>> {
        Ok(self.state.lock().unwrap().privacy_items.clone())
    }

    fn toggle_startup(&self, entry_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st
            .startup
            .iter_mut()
            .find(|i| i.entry_name.eq_ignore_ascii_case(entry_name))
        else {
            return Err(Sys2RustError::NotFound(format!("startup item '{entry_name}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would set startup '{entry_name}' enabled={enable}"));
        }
        item.disabled = !enable;
        Ok(format!("startup '{entry_name}' enabled={enable}"))
    }

    fn delete_startup(&self, entry_name: &str, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        if !st.startup.iter().any(|i| i.entry_name.eq_ignore_ascii_case(entry_name)) {
            return Err(Sys2RustError::NotFound(format!("startup item '{entry_name}'")));
        }
        if dry_run {
            return Ok(format!("[dry-run] would delete startup '{entry_name}'"));
        }
        st.startup.retain(|i| !i.entry_name.eq_ignore_ascii_case(entry_name));
        Ok(format!("deleted startup '{entry_name}'"))
    }

    fn run_uninstall(&self, display_name: &str, quiet: bool, dry_run: bool) -> Sys2RustResult<String> {
        let st = self.state.lock().unwrap();
        let Some(item) = st
            .uninstall
            .iter()
            .find(|u| u.display_name.eq_ignore_ascii_case(display_name))
        else {
            return Err(Sys2RustError::NotFound(format!("program '{display_name}'")));
        };
        let cmd = if quiet && !item.quiet_uninstall_string.is_empty() {
            &item.quiet_uninstall_string
        } else {
            &item.uninstall_string
        };
        if dry_run {
            return Ok(format!("[dry-run] would run uninstaller: {cmd}"));
        }
        Ok(format!("executed uninstaller: {cmd}"))
    }

    fn toggle_shellex(&self, clsid: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st.shellex.iter_mut().find(|s| s.clsid.eq_ignore_ascii_case(clsid)) else {
            return Err(Sys2RustError::NotFound(format!("shell extension '{clsid}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would set shellex '{clsid}' enabled={enable}"));
        }
        item.disabled = !enable;
        Ok(format!("shellex '{clsid}' enabled={enable}"))
    }

    fn toggle_menu(&self, menu_key: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st.menus.iter_mut().find(|m| m.menu_key.eq_ignore_ascii_case(menu_key)) else {
            return Err(Sys2RustError::NotFound(format!("menu '{menu_key}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would set menu '{menu_key}' enabled={enable}"));
        }
        item.disabled = !enable;
        Ok(format!("menu '{menu_key}' enabled={enable}"))
    }

    fn toggle_menu_new(&self, extension: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st
            .menu_new
            .iter_mut()
            .find(|m| m.extension.eq_ignore_ascii_case(extension))
        else {
            return Err(Sys2RustError::NotFound(format!("ShellNew '{extension}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would set ShellNew '{extension}' enabled={enable}"));
        }
        item.disabled = !enable;
        Ok(format!("ShellNew '{extension}' enabled={enable}"))
    }

    fn edit_filetype(&self, extension: &str, description: &str, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st
            .filetypes
            .iter_mut()
            .find(|f| f.extension.eq_ignore_ascii_case(extension))
        else {
            return Err(Sys2RustError::NotFound(format!("file type '{extension}'")));
        };
        if dry_run {
            return Ok(format!(
                "[dry-run] would set description of '{extension}' to '{description}'"
            ));
        }
        item.description = description.to_string();
        Ok(format!("updated file type '{extension}'"))
    }

    fn toggle_openwith(&self, app_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st
            .openwith
            .iter_mut()
            .find(|o| o.application_name.eq_ignore_ascii_case(app_name))
        else {
            return Err(Sys2RustError::NotFound(format!("OpenWith app '{app_name}'")));
        };
        if dry_run {
            return Ok(format!("[dry-run] would set OpenWith '{app_name}' enabled={enable}"));
        }
        item.disabled = !enable;
        Ok(format!("OpenWith '{app_name}' enabled={enable}"))
    }

    fn clean_com_orphan(&self, dll_path: &str, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st.com.iter().find(|c| c.dll_path.eq_ignore_ascii_case(dll_path)) else {
            return Err(Sys2RustError::NotFound(format!("COM DLL '{dll_path}'")));
        };
        if item.file_exists {
            return Err(Sys2RustError::InvalidArgument(format!(
                "refusing to clean non-orphan COM DLL '{dll_path}'"
            )));
        }
        if dry_run {
            return Ok(format!("[dry-run] would remove orphan COM registration '{dll_path}'"));
        }
        st.com.retain(|c| !c.dll_path.eq_ignore_ascii_case(dll_path));
        Ok(format!("cleaned orphan COM registration '{dll_path}'"))
    }

    fn toggle_url_proto(&self, protocol: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String> {
        let mut st = self.state.lock().unwrap();
        let Some(item) = st
            .url_proto
            .iter_mut()
            .find(|u| u.protocol_name.eq_ignore_ascii_case(protocol))
        else {
            return Err(Sys2RustError::NotFound(format!("URL protocol '{protocol}'")));
        };
        if dry_run {
            return Ok(format!(
                "[dry-run] would set URL protocol '{protocol}' enabled={enable}"
            ));
        }
        item.disabled = !enable;
        Ok(format!("URL protocol '{protocol}' enabled={enable}"))
    }

    fn set_appcompat(&self, exe_path: &str, layers: &str, scope: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!(
                "[dry-run] would set AppCompat '{layers}' for '{exe_path}' ({scope})"
            ));
        }
        let mut st = self.state.lock().unwrap();
        if let Some(existing) = st
            .appcompat
            .iter_mut()
            .find(|a| a.exe_path.eq_ignore_ascii_case(exe_path))
        {
            existing.layers = layers.to_string();
        } else {
            st.appcompat.push(AppCompatItem {
                exe_path: exe_path.to_string(),
                layers: layers.to_string(),
                scope: scope.to_string(),
                file_exists: false,
                modified_time: Some(Utc::now()),
            });
        }
        Ok(format!("set AppCompat '{layers}' on '{exe_path}'"))
    }

    fn set_env_var(&self, scope: &str, name: &str, value: &str, dry_run: bool) -> Sys2RustResult<String> {
        if dry_run {
            return Ok(format!("[dry-run] would set {scope} env var {name}={value}"));
        }
        let mut st = self.state.lock().unwrap();
        if let Some(ev) = st
            .env_vars
            .iter_mut()
            .find(|e| e.scope.eq_ignore_ascii_case(scope) && e.name.eq_ignore_ascii_case(name))
        {
            ev.value = value.to_string();
            ev.expanded_value = value.to_string();
        } else {
            st.env_vars.push(EnvVarItem {
                scope: scope.to_string(),
                name: name.to_string(),
                value: value.to_string(),
                expanded_value: value.to_string(),
                registry_key: r"HKCU\Environment".to_string(),
            });
        }
        Ok(format!("set {scope} env var {name}"))
    }

    fn restore_desktop_icons(&self, profile: &str, dry_run: bool) -> Sys2RustResult<String> {
        let icons = self.state.lock().unwrap().desktop_icons.clone();
        let ini = serialize_desktop_icons_ini(profile, &icons);
        if dry_run {
            return Ok(format!(
                "[dry-run] would restore {} desktop icons for profile '{profile}' ({} bytes INI)",
                icons.len(),
                ini.len()
            ));
        }
        Ok(format!(
            "restored {} desktop icons for profile '{profile}'",
            icons.len()
        ))
    }

    fn clean_privacy(&self, categories: &[String], dry_run: bool) -> Sys2RustResult<String> {
        let canonical = validate_privacy_categories(categories)?;
        let mut st = self.state.lock().unwrap();
        if dry_run {
            return Ok(format!(
                "[dry-run] would clean privacy categories: {}",
                canonical.join(", ")
            ));
        }
        let mut removed_items = 0u64;
        if categories.iter().any(|c| c.eq_ignore_ascii_case("Temp"))
            && let Some(dir) = st.privacy_temp_dir.clone()
            && dir.exists()
        {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_file() && std::fs::remove_file(&p).is_ok() {
                    removed_items += 1;
                }
            }
        }
        for item in &mut st.privacy_items {
            if categories.iter().any(|c| c.eq_ignore_ascii_case(&item.category)) {
                removed_items = removed_items.max(item.item_count);
                item.item_count = 0;
                item.total_bytes = 0;
            }
        }
        Ok(format!(
            "cleaned {} items across [{}]",
            removed_items,
            categories.join(", ")
        ))
    }
}
