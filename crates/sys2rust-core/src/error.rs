use guap_mcp::McpToolError;
use guap_table::TableError;
use thiserror::Error;

pub type Sys2RustResult<T> = Result<T, Sys2RustError>;

#[derive(Debug, Error)]
pub enum Sys2RustError {
    #[error("[PERMISSION_DENIED] {operation}: {detail}. Hint: {hint}")]
    PermissionDenied {
        operation: &'static str,
        detail: String,
        hint: String,
    },

    #[error("[SOURCE_UNAVAILABLE] {source_name}: {detail}")]
    SourceUnavailable { source_name: &'static str, detail: String },

    #[error("[HARDWARE_NOT_FOUND] {device}: {detail}")]
    HardwareNotFound { device: &'static str, detail: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("timeout after {timeout_ms}ms in {operation}")]
    Timeout { operation: &'static str, timeout_ms: u64 },

    #[error("parse error ({format}): {detail}")]
    Parse { format: &'static str, detail: String },

    #[error("win32/os error ({api}, code={code:#010x}): {message}")]
    OsError {
        api: &'static str,
        code: u32,
        message: String,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<Sys2RustError> for TableError {
    fn from(err: Sys2RustError) -> Self {
        match err {
            Sys2RustError::InvalidArgument(msg) => TableError::QueryParse(msg),
            other => TableError::Provider(other.to_string()),
        }
    }
}

impl From<Sys2RustError> for McpToolError {
    fn from(err: Sys2RustError) -> Self {
        match err {
            Sys2RustError::InvalidArgument(msg) => McpToolError::InvalidParams(msg),
            Sys2RustError::NotFound(msg) => McpToolError::NotFound(msg),
            other => McpToolError::ExecutionFailed(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping_preserves_structured_tags() {
        let perm = Sys2RustError::PermissionDenied {
            operation: "OpenProcess",
            detail: "Access denied for PID 4".to_string(),
            hint: "Run elevated or enable SeDebugPrivilege".to_string(),
        };
        let te: TableError = perm.into();
        assert!(te.to_string().contains("[PERMISSION_DENIED]"));

        let hw = Sys2RustError::HardwareNotFound {
            device: "Battery",
            detail: "No smart battery interface present".to_string(),
        };
        let te_hw: TableError = hw.into();
        assert!(te_hw.to_string().contains("[HARDWARE_NOT_FOUND]"));

        let src = Sys2RustError::SourceUnavailable {
            source_name: "ETW Kernel-File",
            detail: "Session requires Administrator or Performance Log Users".to_string(),
        };
        let te_src: TableError = src.into();
        assert!(te_src.to_string().contains("[SOURCE_UNAVAILABLE]"));
    }
}
