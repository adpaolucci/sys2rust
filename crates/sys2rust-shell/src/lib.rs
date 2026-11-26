pub mod backend;
#[cfg(windows)]
pub mod live_win32;
pub mod mock;
pub mod parsers;
pub mod providers;

use std::sync::Arc;

use sys2rust_core::Sys2RustConfig;

pub use backend::{
    AppCompatItem, AppxPkgItem, ComRegItem, DesktopIconItem, EnvVarItem, ExplorerExtItem, FileTypeItem,
    LegacyUninstallItem, MsiPackageItem, MuiVerItem, OpenWithItem, PrivacyAuditItem, ShellBackend, ShellExtItem,
    ShellMenuItem, ShellMenuNewItem, StartupItem, TrayIconItem, UninstallItem, UrlProtoItem,
};
pub use mock::SyntheticShellBackend;
pub use providers::{all_shell_actions, all_shell_providers};

pub fn default_shell_backend(cfg: Sys2RustConfig) -> Arc<dyn ShellBackend> {
    if cfg.offline_fixture_dir.is_some() {
        return Arc::new(SyntheticShellBackend::new());
    }
    #[cfg(windows)]
    {
        Arc::new(live_win32::LiveWin32ShellBackend::new(cfg))
    }
    #[cfg(not(windows))]
    {
        Arc::new(SyntheticShellBackend::new())
    }
}
