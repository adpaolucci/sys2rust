use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;

static LOG_INIT: OnceLock<()> = OnceLock::new();

/// Initialize `tracing` subscriber writing exclusively to `stderr` so MCP `stdout` stays clean.
pub fn init_logging(verbose: bool) {
    LOG_INIT.get_or_init(|| {
        let default_level = if verbose { "debug" } else { "warn" };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init();
    });
}
