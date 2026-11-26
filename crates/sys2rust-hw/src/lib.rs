pub mod backend;
#[cfg(windows)]
pub mod live_win32;
pub mod mock;
pub mod parsers;
pub mod providers;

use std::sync::Arc;

use sys2rust_core::Sys2RustConfig;

pub use backend::{
    BatteryEntry, CodecEntry, DeviceEntry, DriverEntry, FirmwareTableEntry, HwBackend, ServiceEntry,
    SpecialFolderEntry, TaskEntry, TimeZoneEntry, WmiRowEntry,
};
pub use mock::MockHwBackend;
pub use providers::{all_hw_actions, all_hw_providers};

pub fn default_hw_backend(cfg: Sys2RustConfig) -> Arc<dyn HwBackend> {
    if cfg.offline_fixture_dir.is_some() {
        return Arc::new(MockHwBackend::new());
    }
    #[cfg(windows)]
    {
        Arc::new(live_win32::LiveHwBackend::new(cfg))
    }
    #[cfg(not(windows))]
    {
        Arc::new(MockHwBackend::new())
    }
}
