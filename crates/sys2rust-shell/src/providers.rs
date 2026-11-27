use std::sync::Arc;

use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde_json::{Value, json};

use crate::backend::ShellBackend;

pub fn all_shell_providers(backend: Arc<dyn ShellBackend>) -> Vec<Arc<dyn TableProvider>> {
    vec![
        Arc::new(ShellStartupProvider::new(Arc::clone(&backend))),
        Arc::new(ShellUninstallProvider::new(Arc::clone(&backend))),
        Arc::new(ShellMsiProvider::new(Arc::clone(&backend))),
        Arc::new(ShellAppxProvider::new(Arc::clone(&backend))),
        Arc::new(ShellLegacyUninstProvider::new(Arc::clone(&backend))),
        Arc::new(ShellShellexProvider::new(Arc::clone(&backend))),
        Arc::new(ShellMenuProvider::new(Arc::clone(&backend))),
        Arc::new(ShellNewMenuProvider::new(Arc::clone(&backend))),
        Arc::new(ShellFiletypesProvider::new(Arc::clone(&backend))),
        Arc::new(ShellOpenwithProvider::new(Arc::clone(&backend))),
        Arc::new(ShellComProvider::new(Arc::clone(&backend))),
        Arc::new(ShellUrlProtoProvider::new(Arc::clone(&backend))),
        Arc::new(ShellAppcompatProvider::new(Arc::clone(&backend))),
        Arc::new(ShellMuiVerProvider::new(Arc::clone(&backend))),
        Arc::new(ShellExtViewProvider::new(Arc::clone(&backend))),
        Arc::new(ShellEnvVarsProvider::new(Arc::clone(&backend))),
        Arc::new(ShellDesktopIconsProvider::new(Arc::clone(&backend))),
        Arc::new(ShellTaskmgrExtProvider::new(Arc::clone(&backend))),
        Arc::new(ShellPrivacyAuditProvider::new(backend)),
    ]
}

pub fn all_shell_actions(backend: Arc<dyn ShellBackend>) -> Vec<Arc<dyn ActionCommand>> {
    vec![
        Arc::new(ShellStartupToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellStartupDeleteAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellUninstallRunAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellShellexToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellMenuToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellNewToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellFiletypesEditAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellOpenwithToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellComCleanOrphanAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellUrlProtoToggleAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellAppcompatSetAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellEnvVarsSetAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellDesktopIconsRestoreAction {
            backend: Arc::clone(&backend),
        }),
        Arc::new(ShellPrivacyAuditCleanAction { backend }),
    ]
}

macro_rules! simple_shell_provider {
    ($struct_name:ident, $tool_id:expr, $title:expr, $desc:expr, $cols:expr, $fetch:ident, $map_row:expr) => {
        pub struct $struct_name {
            backend: Arc<dyn ShellBackend>,
        }
        impl $struct_name {
            pub fn new(backend: Arc<dyn ShellBackend>) -> Self {
                Self { backend }
            }
        }
        impl TableProvider for $struct_name {
            fn tool_id(&self) -> &'static str {
                $tool_id
            }
            fn description(&self) -> &'static str {
                $desc
            }
            fn schema(&self) -> TableSchema {
                TableSchema::new(self.tool_id(), $title, $cols)
            }
            fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
                let items = self.backend.$fetch()?;
                let mapper = $map_row;
                let rows: Vec<Row> = items
                    .into_iter()
                    .enumerate()
                    .map(|(idx, item)| mapper((idx + 1) as u64, item))
                    .collect();
                apply_query(&self.schema(), &rows, req)
            }
        }
    };
}

// 1. shell_startup
simple_shell_provider!(
    ShellStartupProvider,
    "shell_startup",
    "Windows Startup Items",
    "Inspect Run keys, StartupApproved binary states, and Startup folders",
    vec![
        ColumnDef::new("entry_name", "Entry Name", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("type", "Type", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("command_line", "Command Line", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("exe_path", "Exe Path", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("location", "Location", ColumnType::Text).with_width_hint(210),
        ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("user", "User", ColumnType::Text).with_width_hint(110),
        ColumnDef::new("product_name", "Product", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("signed", "Signed", ColumnType::Bool).with_width_hint(70),
        ColumnDef::new("file_time", "Changed Time", ColumnType::Timestamp).with_width_hint(170),
    ],
    list_startup,
    |id, s: crate::backend::StartupItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(s.entry_name.clone()),
                CellValue::Text(s.item_type.clone()),
                CellValue::Text(s.command_line.clone()),
                CellValue::Text(s.exe_path.clone()),
                CellValue::Text(s.location.clone()),
                CellValue::Bool(s.disabled),
                CellValue::Text(s.user.clone()),
                CellValue::Text(s.product_name.clone()),
                CellValue::Bool(s.signed),
                s.file_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
            ],
        )
        .with_detail_json(json!(s))
    }
);

// 2. shell_uninstall
simple_shell_provider!(
    ShellUninstallProvider,
    "shell_uninstall",
    "Installed Programs",
    "Inspect installed programs across HKLM/WOW6432Node/HKCU Uninstall keys",
    vec![
        ColumnDef::new("display_name", "Display Name", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("publisher", "Publisher", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("install_date", "Install Date", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("estimated_size_kb", "Size (KB)", ColumnType::Uint).with_width_hint(90),
        ColumnDef::new("install_location", "Location", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("uninstall_string", "Uninstall String", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("quiet_uninstall_string", "Quiet Uninstall", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("arch", "Arch", ColumnType::Text).with_width_hint(70),
    ],
    list_uninstall,
    |id, u: crate::backend::UninstallItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(u.display_name.clone()),
                CellValue::Text(u.version.clone()),
                CellValue::Text(u.publisher.clone()),
                CellValue::Text(u.install_date.clone()),
                CellValue::Uint(u.estimated_size_kb),
                CellValue::Text(u.install_location.clone()),
                CellValue::Text(u.uninstall_string.clone()),
                CellValue::Text(u.quiet_uninstall_string.clone()),
                CellValue::Text(u.registry_key.clone()),
                CellValue::Text(u.arch.clone()),
            ],
        )
        .with_detail_json(json!(u))
    }
);

// 3. shell_msi
simple_shell_provider!(
    ShellMsiProvider,
    "shell_msi",
    "Windows Installer Packages",
    "Inspect MSI products via MsiEnumProductsExW / MsiGetProductInfoExW",
    vec![
        ColumnDef::new("package_name", "Package Name", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("product_code", "Product Code", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("vendor", "Vendor", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("install_date", "Install Date", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("local_package_msi", "Local MSI", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("install_source", "Source", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("files_count", "Files", ColumnType::Uint).with_width_hint(75),
        ColumnDef::new("registry_entries_count", "Reg Entries", ColumnType::Uint).with_width_hint(90),
    ],
    list_msi,
    |id, m: crate::backend::MsiPackageItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(m.package_name.clone()),
                CellValue::Text(m.product_code.clone()),
                CellValue::Text(m.version.clone()),
                CellValue::Text(m.vendor.clone()),
                CellValue::Text(m.install_date.clone()),
                CellValue::Text(m.local_package_msi.clone()),
                CellValue::Text(m.install_source.clone()),
                CellValue::Uint(m.files_count),
                CellValue::Uint(m.registry_entries_count),
            ],
        )
        .with_detail_json(json!(m))
    }
);

// 4. shell_appx
simple_shell_provider!(
    ShellAppxProvider,
    "shell_appx",
    "Microsoft Store / Appx Packages",
    "Inspect UWP/MSIX Appx packages via WinRT PackageManager & AppxManifest.xml",
    vec![
        ColumnDef::new("package_name", "Package Name", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("family_name", "Family Name", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(110),
        ColumnDef::new("publisher", "Publisher", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("architecture", "Arch", ColumnType::Text).with_width_hint(80),
        ColumnDef::new("install_location", "Install Location", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("is_framework", "Framework", ColumnType::Bool).with_width_hint(80),
        ColumnDef::new("non_removable", "Non-Removable", ColumnType::Bool).with_width_hint(95),
        ColumnDef::new("app_user_model_id", "AUMID", ColumnType::Text).with_width_hint(220),
    ],
    list_appx,
    |id, a: crate::backend::AppxPkgItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(a.package_name.clone()),
                CellValue::Text(a.family_name.clone()),
                CellValue::Text(a.version.clone()),
                CellValue::Text(a.publisher.clone()),
                CellValue::Text(a.architecture.clone()),
                CellValue::Text(a.install_location.clone()),
                CellValue::Bool(a.is_framework),
                CellValue::Bool(a.non_removable),
                CellValue::Text(a.app_user_model_id.clone()),
            ],
        )
        .with_detail_json(json!(a))
    }
);

// 5. shell_legacy_uninst
simple_shell_provider!(
    ShellLegacyUninstProvider,
    "shell_legacy_uninst",
    "Uninstaller Entries",
    "Compact installed software uninstaller inventory",
    vec![
        ColumnDef::new("program_name", "Program Name", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("publisher", "Publisher", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("install_date", "Install Date", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("uninstall_command", "Uninstall Command", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("registry_path", "Registry Path", ColumnType::Text).with_width_hint(230),
    ],
    list_legacy_uninst,
    |id, l: crate::backend::LegacyUninstallItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(l.program_name.clone()),
                CellValue::Text(l.version.clone()),
                CellValue::Text(l.publisher.clone()),
                CellValue::Text(l.install_date.clone()),
                CellValue::Text(l.uninstall_command.clone()),
                CellValue::Text(l.registry_path.clone()),
            ],
        )
        .with_detail_json(json!(l))
    }
);

// 6. shell_shellex
simple_shell_provider!(
    ShellShellexProvider,
    "shell_shellex",
    "Shell Extensions",
    "Inspect registered Explorer Shell Extensions and Approved/Blocked status",
    vec![
        ColumnDef::new("extension_name", "Extension Name", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("type", "Type", ColumnType::Text).with_width_hint(120),
        ColumnDef::new("clsid", "CLSID", ColumnType::Text).with_width_hint(230),
        ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("file_extensions", "Extensions", ColumnType::Text).with_width_hint(90),
        ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("microsoft", "Microsoft", ColumnType::Bool).with_width_hint(80),
    ],
    list_shellex,
    |id, s: crate::backend::ShellExtItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(s.extension_name.clone()),
                CellValue::Bool(s.disabled),
                CellValue::Text(s.ext_type.clone()),
                CellValue::Text(s.clsid.clone()),
                CellValue::Text(s.filename.clone()),
                CellValue::Text(s.file_extensions.clone()),
                CellValue::Text(s.company.clone()),
                CellValue::Bool(s.microsoft),
            ],
        )
        .with_detail_json(json!(s))
    }
);

// 7. shell_menu
simple_shell_provider!(
    ShellMenuProvider,
    "shell_menu",
    "Explorer Context Menus",
    "Inspect static Explorer context menu verbs under HKCR",
    vec![
        ColumnDef::new("menu_name", "Menu Text", ColumnType::Text).with_width_hint(170),
        ColumnDef::new("menu_key", "Key", ColumnType::Text).with_width_hint(120),
        ColumnDef::new("file_type", "File Type", ColumnType::Text).with_width_hint(110),
        ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(90),
        ColumnDef::new("command_line", "Command", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("icon", "Icon", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(200),
    ],
    list_menus,
    |id, m: crate::backend::ShellMenuItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(m.menu_name.clone()),
                CellValue::Text(m.menu_key.clone()),
                CellValue::Text(m.file_type.clone()),
                CellValue::Text(m.extension.clone()),
                CellValue::Text(m.command_line.clone()),
                CellValue::Bool(m.disabled),
                CellValue::Text(m.icon.clone()),
                CellValue::Text(m.registry_key.clone()),
            ],
        )
        .with_detail_json(json!(m))
    }
);

// 8. shell_menu_new
simple_shell_provider!(
    ShellNewMenuProvider,
    "shell_menu_new",
    "Explorer 'New' Context Menu",
    "Inspect Explorer 'New' submenu ShellNew templates",
    vec![
        ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(90),
        ColumnDef::new("file_type", "File Type", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("menu_text", "Menu Text", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("template_type", "Template Type", ColumnType::Text).with_width_hint(110),
        ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(200),
    ],
    list_menu_new,
    |id, m: crate::backend::ShellNewItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(m.extension.clone()),
                CellValue::Text(m.file_type.clone()),
                CellValue::Text(m.menu_text.clone()),
                CellValue::Text(m.template_type.clone()),
                CellValue::Bool(m.disabled),
                CellValue::Text(m.registry_key.clone()),
            ],
        )
        .with_detail_json(json!(m))
    }
);

// 9. shell_filetypes
simple_shell_provider!(
    ShellFiletypesProvider,
    "shell_filetypes",
    "Registered File Types",
    "Inspect registered file extensions, ProgIDs, MIME types, icons, and open commands",
    vec![
        ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(90),
        ColumnDef::new("type_name", "Type Name", ColumnType::Text).with_width_hint(150),
        ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(190),
        ColumnDef::new("mime_type", "MIME Type", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("perceived_type", "Perceived", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("default_icon", "Default Icon", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("open_command", "Open Command", ColumnType::Text).with_width_hint(230),
        ColumnDef::new("flags", "Flags", ColumnType::Uint).with_width_hint(75),
        ColumnDef::new("modified_time", "Modified", ColumnType::Timestamp).with_width_hint(170),
    ],
    list_filetypes,
    |id, f: crate::backend::FileTypeItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(f.extension.clone()),
                CellValue::Text(f.type_name.clone()),
                CellValue::Text(f.description.clone()),
                CellValue::Text(f.mime_type.clone()),
                CellValue::Text(f.perceived_type.clone()),
                CellValue::Text(f.default_icon.clone()),
                CellValue::Text(f.open_command.clone()),
                CellValue::Uint(u64::from(f.flags)),
                f.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
            ],
        )
        .with_detail_json(json!(f))
    }
);

// 10. shell_openwith
simple_shell_provider!(
    ShellOpenwithProvider,
    "shell_openwith",
    "'Open With' Applications",
    "Inspect applications registered in the Explorer 'Open With' dialog",
    vec![
        ColumnDef::new("application_name", "Application", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("exe_path", "Executable", ColumnType::Text).with_width_hint(230),
        ColumnDef::new("disabled", "NoOpenWith", ColumnType::Bool).with_width_hint(85),
        ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(170),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(210),
    ],
    list_openwith,
    |id, o: crate::backend::OpenWithItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(o.application_name.clone()),
                CellValue::Text(o.exe_path.clone()),
                CellValue::Bool(o.disabled),
                CellValue::Text(o.company.clone()),
                CellValue::Text(o.description.clone()),
                CellValue::Text(o.registry_key.clone()),
            ],
        )
        .with_detail_json(json!(o))
    }
);

// 11. shell_com
simple_shell_provider!(
    ShellComProvider,
    "shell_com",
    "Registered COM / ActiveX DLLs",
    "Inspect registered COM/OLE DLLs and missing orphan registrations",
    vec![
        ColumnDef::new("dll_path", "DLL Path", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("clsid_count", "CLSIDs", ColumnType::Uint).with_width_hint(75),
        ColumnDef::new("prog_ids", "ProgIDs", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("type_lib", "TypeLib", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("last_registered", "Last Registered", ColumnType::Timestamp).with_width_hint(170),
        ColumnDef::new("file_exists", "Exists", ColumnType::Bool).with_width_hint(70),
        ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("arch", "Arch", ColumnType::Text).with_width_hint(70),
    ],
    list_com,
    |id, c: crate::backend::ComRegItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(c.dll_path.clone()),
                CellValue::Uint(u64::from(c.clsid_count)),
                CellValue::Text(c.prog_ids.clone()),
                CellValue::Text(c.type_lib.clone()),
                c.last_registered.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
                CellValue::Bool(c.file_exists),
                CellValue::Text(c.company.clone()),
                CellValue::Text(c.arch.clone()),
            ],
        )
        .with_detail_json(json!(c))
    }
);

// 12. shell_url_proto
simple_shell_provider!(
    ShellUrlProtoProvider,
    "shell_url_proto",
    "URL Protocol Handlers",
    "Inspect custom Windows URI/URL protocol handlers",
    vec![
        ColumnDef::new("protocol_name", "Protocol", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(190),
        ColumnDef::new("command_line", "Command", ColumnType::Text).with_width_hint(260),
        ColumnDef::new("disabled", "Disabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(190),
        ColumnDef::new("modified_time", "Modified", ColumnType::Timestamp).with_width_hint(170),
    ],
    list_url_proto,
    |id, u: crate::backend::UrlProtoItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(u.protocol_name.clone()),
                CellValue::Text(u.description.clone()),
                CellValue::Text(u.command_line.clone()),
                CellValue::Bool(u.disabled),
                CellValue::Text(u.registry_key.clone()),
                u.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
            ],
        )
        .with_detail_json(json!(u))
    }
);

// 13. shell_appcompat
simple_shell_provider!(
    ShellAppcompatProvider,
    "shell_appcompat",
    "App Compatibility Flags",
    "Inspect AppCompatFlags\\Layers compatibility shims per executable",
    vec![
        ColumnDef::new("exe_path", "Executable Path", ColumnType::Text).with_width_hint(260),
        ColumnDef::new("layers", "Compatibility Layers", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("scope", "Scope", ColumnType::Text).with_width_hint(80),
        ColumnDef::new("file_exists", "Exists", ColumnType::Bool).with_width_hint(70),
        ColumnDef::new("modified_time", "Modified", ColumnType::Timestamp).with_width_hint(170),
    ],
    list_appcompat,
    |id, a: crate::backend::AppCompatItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(a.exe_path.clone()),
                CellValue::Text(a.layers.clone()),
                CellValue::Text(a.scope.clone()),
                CellValue::Bool(a.file_exists),
                a.modified_time.map(CellValue::Timestamp).unwrap_or(CellValue::Null),
            ],
        )
        .with_detail_json(json!(a))
    }
);

// 14. shell_mui_ver
simple_shell_provider!(
    ShellMuiVerProvider,
    "shell_mui_ver",
    "MUICache & File Version Info",
    "Inspect Shell MuiCache entries enriched with executable VS_VERSION_INFO metadata",
    vec![
        ColumnDef::new("exe_path", "Executable Path", ColumnType::Text).with_width_hint(250),
        ColumnDef::new("file_description", "Description", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("product_name", "Product Name", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("file_version", "Version", ColumnType::Text).with_width_hint(100),
        ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(150),
        ColumnDef::new("original_filename", "Original Name", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("internal_name", "Internal Name", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("signer", "Signer", ColumnType::Text).with_width_hint(140),
    ],
    list_mui_ver,
    |id, m: crate::backend::MuiVerItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(m.exe_path.clone()),
                CellValue::Text(m.file_description.clone()),
                CellValue::Text(m.product_name.clone()),
                CellValue::Text(m.file_version.clone()),
                CellValue::Text(m.company.clone()),
                CellValue::Text(m.original_filename.clone()),
                CellValue::Text(m.internal_name.clone()),
                CellValue::Text(m.signer.clone()),
            ],
        )
        .with_detail_json(json!(m))
    }
);

// 15. shell_ext_view
simple_shell_provider!(
    ShellExtViewProvider,
    "shell_ext_view",
    "Per-Extension Explorer Handlers",
    "Inspect per-extension ShellEx handlers such as Thumbnail and Preview providers",
    vec![
        ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(90),
        ColumnDef::new("handler_kind", "Handler Kind", ColumnType::Text).with_width_hint(170),
        ColumnDef::new("clsid", "CLSID", ColumnType::Text).with_width_hint(230),
        ColumnDef::new("target_dll", "Target DLL", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("enabled", "Enabled", ColumnType::Bool).with_width_hint(75),
        ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(180),
    ],
    list_ext_view,
    |id, e: crate::backend::ExplorerExtItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(e.extension.clone()),
                CellValue::Text(e.handler_kind.clone()),
                CellValue::Text(e.clsid.clone()),
                CellValue::Text(e.target_dll.clone()),
                CellValue::Bool(e.enabled),
                CellValue::Text(e.description.clone()),
            ],
        )
        .with_detail_json(json!(e))
    }
);

// 16. shell_env_vars
simple_shell_provider!(
    ShellEnvVarsProvider,
    "shell_env_vars",
    "Environment Variables View",
    "Inspect User and System environment variables with expanded values",
    vec![
        ColumnDef::new("scope", "Scope", ColumnType::Text).with_width_hint(85),
        ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(160),
        ColumnDef::new("value", "Raw Value", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("expanded_value", "Expanded Value", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(200),
    ],
    list_env_vars,
    |id, e: crate::backend::EnvVarItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(e.scope.clone()),
                CellValue::Text(e.name.clone()),
                CellValue::Text(e.value.clone()),
                CellValue::Text(e.expanded_value.clone()),
                CellValue::Text(e.registry_key.clone()),
            ],
        )
        .with_detail_json(json!(e))
    }
);

// 17. shell_desktop_icons
simple_shell_provider!(
    ShellDesktopIconsProvider,
    "shell_desktop_icons",
    "Desktop Icon Layout",
    "Inspect desktop SysListView32 icon coordinates via VirtualAllocEx+ReadProcessMemory & icon profile INI",
    vec![
        ColumnDef::new("icon_name", "Icon Name", ColumnType::Text).with_width_hint(180),
        ColumnDef::new("x", "X", ColumnType::Int).with_width_hint(70),
        ColumnDef::new("y", "Y", ColumnType::Int).with_width_hint(70),
        ColumnDef::new("monitor", "Monitor", ColumnType::Text).with_width_hint(110),
        ColumnDef::new("profile_name", "Profile", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("saved_at", "Saved At", ColumnType::Timestamp).with_width_hint(170),
    ],
    list_desktop_icons,
    |id, d: crate::backend::DesktopIconItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(d.icon_name.clone()),
                CellValue::Int(i64::from(d.x)),
                CellValue::Int(i64::from(d.y)),
                CellValue::Text(d.monitor.clone()),
                CellValue::Text(d.profile_name.clone()),
                CellValue::Timestamp(d.saved_at),
            ],
        )
        .with_detail_json(json!(d))
    }
);

// 18. shell_taskmgr_ext (Shell Tray Icons)
simple_shell_provider!(
    ShellTaskmgrExtProvider,
    "shell_taskmgr_ext",
    "Shell Notification / Tray Icons",
    "Inspect TrayNotify ROT13 IconStreams/PastIconsStream and Win11 NotifyIconSettings",
    vec![
        ColumnDef::new("executable", "Executable", ColumnType::Text).with_width_hint(240),
        ColumnDef::new("tip_text", "Tooltip", ColumnType::Text).with_width_hint(200),
        ColumnDef::new("guid", "GUID", ColumnType::Text).with_width_hint(220),
        ColumnDef::new("visibility", "Visibility", ColumnType::Text).with_width_hint(130),
        ColumnDef::new("registry_key", "Registry Key", ColumnType::Text).with_width_hint(240),
    ],
    list_tray_icons,
    |id, t: crate::backend::TrayIconItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(t.executable.clone()),
                CellValue::Text(t.tip_text.clone()),
                CellValue::Text(t.guid.clone()),
                CellValue::Text(t.visibility.clone()),
                CellValue::Text(t.registry_key.clone()),
            ],
        )
        .with_detail_json(json!(t))
    }
);

// 19. shell_privacy_audit (read-only audit default)
simple_shell_provider!(
    ShellPrivacyAuditProvider,
    "shell_privacy_audit",
    "Shell Privacy Audit",
    "Read-only audit of RunMRU, TypedPaths, WordWheelQuery, Recent, and Temp artifacts",
    vec![
        ColumnDef::new("category", "Category", ColumnType::Text).with_width_hint(140),
        ColumnDef::new("location", "Location", ColumnType::Text).with_width_hint(260),
        ColumnDef::new("item_count", "Items", ColumnType::Uint).with_width_hint(85),
        ColumnDef::new("total_bytes", "Total Bytes", ColumnType::BytesSize).with_width_hint(110),
        ColumnDef::new("sample_entry", "Sample Entry", ColumnType::Text).with_width_hint(200),
    ],
    audit_privacy,
    |id, p: crate::backend::PrivacyAuditItem| {
        Row::new(
            id,
            vec![
                CellValue::Text(p.category.clone()),
                CellValue::Text(p.location.clone()),
                CellValue::Uint(p.item_count),
                CellValue::Bytes(p.total_bytes),
                CellValue::Text(p.sample_entry.clone()),
            ],
        )
        .with_detail_json(json!(p))
    }
);

// --- Mutating ActionCommands ---

pub struct ShellStartupToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellStartupToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_startup_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable a Windows startup entry via StartupApproved"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "entry_name": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["entry_name", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let name = args
            .get("entry_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'entry_name'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_startup(name, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellStartupDeleteAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellStartupDeleteAction {
    fn command_id(&self) -> &'static str {
        "shell_startup_delete"
    }
    fn description(&self) -> &'static str {
        "Delete a Windows startup entry from Run registry key"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "entry_name": { "type": "string" } },
            "required": ["entry_name"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let name = args
            .get("entry_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'entry_name'".to_string()))?;
        let msg = self.backend.delete_startup(name, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellUninstallRunAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellUninstallRunAction {
    fn command_id(&self) -> &'static str {
        "shell_uninstall_run"
    }
    fn description(&self) -> &'static str {
        "Invoke an installed program's uninstaller"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "display_name": { "type": "string" }, "quiet": { "type": "boolean", "default": true } },
            "required": ["display_name"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let name = args
            .get("display_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'display_name'".to_string()))?;
        let quiet = args.get("quiet").and_then(Value::as_bool).unwrap_or(true);
        let msg = self.backend.run_uninstall(name, quiet, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellShellexToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellShellexToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_shellex_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable an Explorer shell extension by CLSID"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "clsid": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["clsid", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let clsid = args
            .get("clsid")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'clsid'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_shellex(clsid, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellMenuToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellMenuToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_menu_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable an Explorer context menu verb"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "menu_key": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["menu_key", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let key = args
            .get("menu_key")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'menu_key'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_menu(key, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellNewToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellNewToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_menu_new_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable an Explorer 'New' submenu item"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "extension": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["extension", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let ext = args
            .get("extension")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'extension'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_menu_new(ext, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellFiletypesEditAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellFiletypesEditAction {
    fn command_id(&self) -> &'static str {
        "shell_filetypes_edit"
    }
    fn description(&self) -> &'static str {
        "Update description for a registered file extension"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "extension": { "type": "string" }, "description": { "type": "string" } },
            "required": ["extension", "description"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let ext = args
            .get("extension")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'extension'".to_string()))?;
        let desc = args
            .get("description")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'description'".to_string()))?;
        let msg = self.backend.edit_filetype(ext, desc, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellOpenwithToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellOpenwithToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_openwith_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable an application in Explorer's 'Open With' list"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "application_name": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["application_name", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let app = args
            .get("application_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'application_name'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_openwith(app, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellComCleanOrphanAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellComCleanOrphanAction {
    fn command_id(&self) -> &'static str {
        "shell_com_clean_orphan"
    }
    fn description(&self) -> &'static str {
        "Remove an orphaned COM DLL registration whose target DLL no longer exists on disk"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "dll_path": { "type": "string" } },
            "required": ["dll_path"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let dll = args
            .get("dll_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'dll_path'".to_string()))?;
        let msg = self.backend.clean_com_orphan(dll, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellUrlProtoToggleAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellUrlProtoToggleAction {
    fn command_id(&self) -> &'static str {
        "shell_url_proto_toggle"
    }
    fn description(&self) -> &'static str {
        "Enable or disable a custom URL protocol handler"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "protocol_name": { "type": "string" }, "enable": { "type": "boolean" } },
            "required": ["protocol_name", "enable"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let proto = args
            .get("protocol_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'protocol_name'".to_string()))?;
        let enable = args
            .get("enable")
            .and_then(Value::as_bool)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'enable'".to_string()))?;
        let msg = self.backend.toggle_url_proto(proto, enable, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellAppcompatSetAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellAppcompatSetAction {
    fn command_id(&self) -> &'static str {
        "shell_appcompat_set"
    }
    fn description(&self) -> &'static str {
        "Set AppCompatFlags compatibility layers for an executable"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "exe_path": { "type": "string" },
                "layers": { "type": "string" },
                "scope": { "type": "string", "default": "HKCU" }
            },
            "required": ["exe_path", "layers"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let exe = args
            .get("exe_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'exe_path'".to_string()))?;
        let layers = args
            .get("layers")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'layers'".to_string()))?;
        let scope = args.get("scope").and_then(Value::as_str).unwrap_or("HKCU");
        let msg = self.backend.set_appcompat(exe, layers, scope, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellEnvVarsSetAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellEnvVarsSetAction {
    fn command_id(&self) -> &'static str {
        "shell_env_vars_set"
    }
    fn description(&self) -> &'static str {
        "Set a User or System environment variable"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "scope": { "type": "string", "enum": ["User", "System"] },
                "name": { "type": "string" },
                "value": { "type": "string" }
            },
            "required": ["scope", "name", "value"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let scope = args
            .get("scope")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'scope'".to_string()))?;
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'name'".to_string()))?;
        let val = args
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'value'".to_string()))?;
        let msg = self.backend.set_env_var(scope, name, val, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellDesktopIconsRestoreAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellDesktopIconsRestoreAction {
    fn command_id(&self) -> &'static str {
        "shell_desktop_icons_restore"
    }
    fn description(&self) -> &'static str {
        "Restore saved desktop icon coordinates via LVM_SETITEMPOSITION (MAKELPARAM)"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "profile": { "type": "string", "default": "Workstation" } },
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let profile = args.get("profile").and_then(Value::as_str).unwrap_or("Workstation");
        let msg = self.backend.restore_desktop_icons(profile, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

pub struct ShellPrivacyAuditCleanAction {
    backend: Arc<dyn ShellBackend>,
}
impl ActionCommand for ShellPrivacyAuditCleanAction {
    fn command_id(&self) -> &'static str {
        "shell_privacy_audit_clean"
    }
    fn description(&self) -> &'static str {
        "Clean explicitly selected shell privacy categories (requires AllowMutating + confirm_destructive=true)"
    }
    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "categories": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "required": ["categories"],
            "additionalProperties": false
        })
    }
    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let cats: Vec<String> = args
            .get("categories")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if cats.is_empty() {
            return Err(McpToolError::InvalidParams(
                "missing non-empty 'categories' array".to_string(),
            ));
        }
        let msg = self.backend.clean_privacy(&cats, dry_run)?;
        Ok(json!({ "status": "ok", "dry_run": dry_run, "message": msg }))
    }
}

#[cfg(test)]
mod tests {
    use guap_mcp::{McpServerRegistry, PolicyMode};

    use super::*;
    use crate::mock::SyntheticShellBackend;
    use crate::parsers::{
        decode_startup_approved, encode_startup_approved, parse_desktop_icons_ini, parse_tray_notify_stream, rot13_str,
        serialize_desktop_icons_ini,
    };

    #[test]
    fn all_19_shell_providers_work_offline() {
        let backend: Arc<dyn ShellBackend> = Arc::new(SyntheticShellBackend::new());
        let providers = all_shell_providers(backend);
        assert_eq!(providers.len(), 19);
        for p in &providers {
            let data = p.query(&TableQuery::default()).unwrap();
            assert!(!data.rows.is_empty(), "provider {} empty", p.tool_id());
        }
    }

    #[test]
    fn startup_approved_tray_rot13_and_desktop_icons_roundtrip() {
        let blob = encode_startup_approved(true, Some(chrono::Utc::now()));
        let decoded = decode_startup_approved(&blob).unwrap();
        assert!(decoded.disabled);
        assert!(decoded.changed_at.is_some());

        let rot = rot13_str(r"C:\Windows\System32\app.exe");
        assert_eq!(rot13_str(&rot), r"C:\Windows\System32\app.exe");

        let tray = parse_tray_notify_stream("IconStreams", &SyntheticShellBackend::synthetic_tray_notify_blob());
        assert_eq!(tray.len(), 1);
        assert_eq!(tray[0].executable, r"C:\Windows\System32\app.exe");
        assert_eq!(tray[0].tip_text, "System Tray Monitor");
        assert_eq!(tray[0].visibility, "Show");

        let icons = parse_desktop_icons_ini(
            "[DesktopIcons]\nProfile=Test\n\n[Icon_0]\nName=MyPC\nX=10\nY=20\nMonitor=Primary\n",
        );
        assert_eq!(icons.len(), 1);
        let ser = serialize_desktop_icons_ini("Test", &icons);
        let round = parse_desktop_icons_ini(&ser);
        assert_eq!(round[0].icon_name, "MyPC");
        assert_eq!(round[0].x, 10);
        assert_eq!(round[0].y, 20);
    }

    #[test]
    fn privacy_audit_and_startup_mutations_enforce_policy_gates() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_file = tmp.path().join("junk.tmp");
        std::fs::write(&tmp_file, b"temp_bytes").unwrap();

        let backend: Arc<dyn ShellBackend> =
            Arc::new(SyntheticShellBackend::new().with_privacy_temp_dir(tmp.path().to_path_buf()));
        let mut reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
        for p in all_shell_providers(Arc::clone(&backend)) {
            reg.register_table(p);
        }
        for a in all_shell_actions(Arc::clone(&backend)) {
            reg.register_action(a);
        }

        // Denied under ReadOnlyOnly
        let denied = reg
            .dispatch(
                "shell_privacy_audit_clean",
                &json!({ "categories": ["Temp"], "confirm_destructive": true }),
            )
            .unwrap_err();
        assert_eq!(denied.code, -32003);
        assert!(tmp_file.exists());

        // Denied without confirm_destructive
        reg.set_policy(PolicyMode::AllowMutating);
        let unconfirmed = reg
            .dispatch("shell_privacy_audit_clean", &json!({ "categories": ["Temp"] }))
            .unwrap_err();
        assert_eq!(unconfirmed.code, -32003);
        assert!(tmp_file.exists());

        // Dry run preserves file
        let dry = reg
            .dispatch(
                "shell_privacy_audit_clean",
                &json!({ "categories": ["Temp"], "confirm_destructive": true, "dry_run": true }),
            )
            .unwrap();
        assert_eq!(dry["dry_run"], json!(true));
        assert!(tmp_file.exists());

        // Real execution deletes file
        let ok = reg
            .dispatch(
                "shell_privacy_audit_clean",
                &json!({ "categories": ["Temp"], "confirm_destructive": true, "dry_run": false }),
            )
            .unwrap();
        assert_eq!(ok["status"], json!("ok"));
        assert!(!tmp_file.exists());

        // Startup toggle mutation updates provider state
        let _ = reg
            .dispatch(
                "shell_startup_toggle",
                &json!({ "entry_name": "SecurityHealth", "enable": false, "confirm_destructive": true }),
            )
            .unwrap();
        let st = backend.list_startup().unwrap();
        assert!(st.iter().find(|i| i.entry_name == "SecurityHealth").unwrap().disabled);
    }

    #[test]
    fn regression_clean_privacy_validation_and_missing_desktop_profile() {
        use crate::parsers::{resolve_desktop_profile_path, validate_privacy_categories};

        // 1. Unknown privacy categories must be rejected with InvalidArgument
        let err_unknown = validate_privacy_categories(&["UnknownCat".to_string()]).unwrap_err();
        assert!(matches!(err_unknown, sys2rust_core::Sys2RustError::InvalidArgument(_)));
        let err_empty = validate_privacy_categories(&[]).unwrap_err();
        assert!(matches!(err_empty, sys2rust_core::Sys2RustError::InvalidArgument(_)));
        let valid = validate_privacy_categories(&[
            "runmru".to_string(),
            "TypedPaths".to_string(),
            "wordwheelquery".to_string(),
            "TEMP".to_string(),
        ])
        .unwrap();
        assert_eq!(valid, vec!["RunMRU", "TypedPaths", "WordWheelQuery", "Temp"]);

        // 2. Profile path resolution
        let named = resolve_desktop_profile_path("Workstation");
        assert!(named.ends_with(std::path::Path::new("desktop_profiles").join("Workstation.ini")));

        // 3. LiveWin32ShellBackend checks (safe non-mutating error paths)
        #[cfg(windows)]
        {
            use crate::live_win32::LiveWin32ShellBackend;
            let live = LiveWin32ShellBackend::new(sys2rust_core::Sys2RustConfig::default());

            // Unknown category rejected even in dry_run and live mode
            let clean_err = live.clean_privacy(&["BogusCategory".to_string()], false).unwrap_err();
            assert!(matches!(clean_err, sys2rust_core::Sys2RustError::InvalidArgument(_)));

            // Non-existent desktop icon profile returns NotFound
            let missing_ini = std::env::temp_dir().join("sys2rust_nonexistent_desktop_profile_99999.ini");
            let restore_err = live
                .restore_desktop_icons(&missing_ini.display().to_string(), false)
                .unwrap_err();
            assert!(matches!(restore_err, sys2rust_core::Sys2RustError::NotFound(_)));
        }
    }
}
