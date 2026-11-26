pub mod binary;
pub mod config;
pub mod diag;
pub mod error;
pub mod logging;
pub mod traits;

pub use config::Sys2RustConfig;
pub use diag::{
    AvailabilityReport, ElevationStatus, PrivilegeInfo, check_availability, check_elevation, enable_se_debug_privilege,
};
pub use error::{Sys2RustError, Sys2RustResult};
pub use logging::init_logging;
pub use traits::{ToolCatalogEntry, ToolDomain};
