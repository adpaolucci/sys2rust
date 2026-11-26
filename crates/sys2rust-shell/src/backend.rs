use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sys2rust_core::Sys2RustResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub entry_name: String,
    pub item_type: String,
    pub command_line: String,
    pub exe_path: String,
    pub location: String,
    pub disabled: bool,
    pub user: String,
    pub product_name: String,
    pub signed: bool,
    pub file_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallItem {
    pub display_name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
    pub estimated_size_kb: u64,
    pub install_location: String,
    pub uninstall_string: String,
    pub quiet_uninstall_string: String,
    pub registry_key: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsiPackageItem {
    pub package_name: String,
    pub product_code: String,
    pub version: String,
    pub vendor: String,
    pub install_date: String,
    pub local_package_msi: String,
    pub install_source: String,
    pub files_count: u64,
    pub registry_entries_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppxPkgItem {
    pub package_name: String,
    pub family_name: String,
    pub version: String,
    pub publisher: String,
    pub architecture: String,
    pub install_location: String,
    pub is_framework: bool,
    pub non_removable: bool,
    pub app_user_model_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyUninstallItem {
    pub program_name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
    pub uninstall_command: String,
    pub registry_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellExtItem {
    pub extension_name: String,
    pub disabled: bool,
    pub ext_type: String,
    pub clsid: String,
    pub filename: String,
    pub file_extensions: String,
    pub company: String,
    pub microsoft: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellMenuItem {
    pub menu_name: String,
    pub menu_key: String,
    pub file_type: String,
    pub extension: String,
    pub command_line: String,
    pub disabled: bool,
    pub icon: String,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellNewItem {
    pub extension: String,
    pub file_type: String,
    pub menu_text: String,
    pub template_type: String,
    pub disabled: bool,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeItem {
    pub extension: String,
    pub type_name: String,
    pub description: String,
    pub mime_type: String,
    pub perceived_type: String,
    pub default_icon: String,
    pub open_command: String,
    pub flags: u32,
    pub modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenWithItem {
    pub application_name: String,
    pub exe_path: String,
    pub disabled: bool,
    pub company: String,
    pub description: String,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComRegItem {
    pub dll_path: String,
    pub clsid_count: u32,
    pub prog_ids: String,
    pub type_lib: String,
    pub last_registered: Option<DateTime<Utc>>,
    pub file_exists: bool,
    pub company: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlProtoItem {
    pub protocol_name: String,
    pub description: String,
    pub command_line: String,
    pub disabled: bool,
    pub registry_key: String,
    pub modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCompatItem {
    pub exe_path: String,
    pub layers: String,
    pub scope: String,
    pub file_exists: bool,
    pub modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuiVerItem {
    pub exe_path: String,
    pub file_description: String,
    pub product_name: String,
    pub file_version: String,
    pub company: String,
    pub original_filename: String,
    pub internal_name: String,
    pub signer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerExtItem {
    pub extension: String,
    pub handler_kind: String,
    pub clsid: String,
    pub target_dll: String,
    pub enabled: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarItem {
    pub scope: String,
    pub name: String,
    pub value: String,
    pub expanded_value: String,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopIconItem {
    pub icon_name: String,
    pub x: i32,
    pub y: i32,
    pub monitor: String,
    pub profile_name: String,
    pub saved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayIconItem {
    pub executable: String,
    pub tip_text: String,
    pub guid: String,
    pub visibility: String,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditItem {
    pub category: String,
    pub location: String,
    pub item_count: u64,
    pub total_bytes: u64,
    pub sample_entry: String,
}

pub trait ShellBackend: Send + Sync {
    fn list_startup(&self) -> Sys2RustResult<Vec<StartupItem>>;
    fn list_uninstall(&self) -> Sys2RustResult<Vec<UninstallItem>>;
    fn list_msi(&self) -> Sys2RustResult<Vec<MsiPackageItem>>;
    fn list_appx(&self) -> Sys2RustResult<Vec<AppxPkgItem>>;
    fn list_legacy_uninst(&self) -> Sys2RustResult<Vec<LegacyUninstallItem>>;
    fn list_shellex(&self) -> Sys2RustResult<Vec<ShellExtItem>>;
    fn list_menus(&self) -> Sys2RustResult<Vec<ShellMenuItem>>;
    fn list_menu_new(&self) -> Sys2RustResult<Vec<ShellNewItem>>;
    fn list_filetypes(&self) -> Sys2RustResult<Vec<FileTypeItem>>;
    fn list_openwith(&self) -> Sys2RustResult<Vec<OpenWithItem>>;
    fn list_com(&self) -> Sys2RustResult<Vec<ComRegItem>>;
    fn list_url_proto(&self) -> Sys2RustResult<Vec<UrlProtoItem>>;
    fn list_appcompat(&self) -> Sys2RustResult<Vec<AppCompatItem>>;
    fn list_mui_ver(&self) -> Sys2RustResult<Vec<MuiVerItem>>;
    fn list_ext_view(&self) -> Sys2RustResult<Vec<ExplorerExtItem>>;
    fn list_env_vars(&self) -> Sys2RustResult<Vec<EnvVarItem>>;
    fn list_desktop_icons(&self) -> Sys2RustResult<Vec<DesktopIconItem>>;
    fn list_tray_icons(&self) -> Sys2RustResult<Vec<TrayIconItem>>;
    fn audit_privacy(&self) -> Sys2RustResult<Vec<PrivacyAuditItem>>;

    // Mutating operations
    fn toggle_startup(&self, entry_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn delete_startup(&self, entry_name: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn run_uninstall(&self, display_name: &str, quiet: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn toggle_shellex(&self, clsid: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn toggle_menu(&self, menu_key: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn toggle_menu_new(&self, extension: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn edit_filetype(&self, extension: &str, description: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn toggle_openwith(&self, app_name: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn clean_com_orphan(&self, dll_path: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn toggle_url_proto(&self, protocol: &str, enable: bool, dry_run: bool) -> Sys2RustResult<String>;
    fn set_appcompat(&self, exe_path: &str, layers: &str, scope: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn set_env_var(&self, scope: &str, name: &str, value: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn restore_desktop_icons(&self, profile: &str, dry_run: bool) -> Sys2RustResult<String>;
    fn clean_privacy(&self, categories: &[String], dry_run: bool) -> Sys2RustResult<String>;
}
