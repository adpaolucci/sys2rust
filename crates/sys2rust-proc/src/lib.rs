pub mod backend;
#[cfg(windows)]
pub mod live_win32;
pub mod mock;
pub mod providers;

use std::sync::Arc;

use sys2rust_core::Sys2RustConfig;

pub use backend::{
    DebugEventEntry, EtwLifecycleEntry, FileActivityEntry, GdiProcessEntry, HandleEntry, HeapBlockEntry,
    HungWindowEntry, LoadedDllEntry, MemoryRegionEntry, OpenFileEntry, ProcBackend, ProcessEntry, ProcessEnvEntry,
    RawEtwEvent, ThreadEntry, decode_kernel_file_events, decode_kernel_process_events, parse_peb_environment_block,
    query_with_timeout,
};
pub use mock::MockProcBackend;
pub use providers::{all_proc_actions, all_proc_providers};

pub fn default_proc_backend(cfg: Sys2RustConfig) -> Arc<dyn ProcBackend> {
    if cfg.offline_fixture_dir.is_some() {
        return Arc::new(MockProcBackend::new());
    }
    #[cfg(windows)]
    {
        Arc::new(live_win32::LiveProcBackend::new(cfg))
    }
    #[cfg(not(windows))]
    {
        Arc::new(MockProcBackend::new())
    }
}
