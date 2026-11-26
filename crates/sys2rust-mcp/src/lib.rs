#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use guap_mcp::{ActionCommand, McpServerRegistry, PolicyMode};
use guap_table::TableProvider;
use sys2rust_core::Sys2RustConfig;
use sys2rust_hw::{MockHwBackend, all_hw_actions, all_hw_providers, default_hw_backend};
use sys2rust_pe::{PeTargetSource, all_pe_providers, default_pe_source};
use sys2rust_proc::{MockProcBackend, all_proc_actions, all_proc_providers, default_proc_backend};
use sys2rust_shell::{SyntheticShellBackend, all_shell_actions, all_shell_providers, default_shell_backend};

static SYNTHETIC_GAC_ROOT: OnceLock<PathBuf> = OnceLock::new();

pub fn synthetic_gac_root() -> PathBuf {
    SYNTHETIC_GAC_ROOT
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("sys2rust_synthetic_gac_root");
            let _ = sys2rust_pe::fixture::create_synthetic_gac_tree(&dir);
            dir
        })
        .clone()
}

#[derive(Clone)]
pub struct SuiteWiring {
    pub providers: Vec<Arc<dyn TableProvider>>,
    pub actions: Vec<Arc<dyn ActionCommand>>,
}

pub fn build_suite_wiring(cfg: &Sys2RustConfig) -> SuiteWiring {
    let mut providers = Vec::with_capacity(48);
    let mut actions = Vec::with_capacity(22);

    let proc_backend = default_proc_backend(cfg.clone());
    providers.extend(all_proc_providers(Arc::clone(&proc_backend)));
    actions.extend(all_proc_actions(proc_backend));

    let hw_backend = default_hw_backend(cfg.clone());
    providers.extend(all_hw_providers(Arc::clone(&hw_backend), cfg.clone()));
    actions.extend(all_hw_actions(hw_backend));

    let shell_backend = default_shell_backend(cfg.clone());
    providers.extend(all_shell_providers(Arc::clone(&shell_backend)));
    actions.extend(all_shell_actions(shell_backend));

    let pe_source = if let Some(ref offline_dir) = cfg.offline_fixture_dir {
        let gac_root = if offline_dir.join("gac").exists() {
            offline_dir.join("gac")
        } else if offline_dir != Path::new(".") && offline_dir.exists() {
            offline_dir.clone()
        } else {
            synthetic_gac_root()
        };
        if let Some(ref target) = cfg.pe_target {
            default_pe_source(Some(target.clone()), Some(gac_root))
        } else {
            Arc::new(PeTargetSource::Bytes {
                label: "synthetic_fixture.dll".to_string(),
                bytes: sys2rust_pe::fixture::build_synthetic_pe32_dll(),
                gac_root: Some(gac_root),
            })
        }
    } else {
        default_pe_source(cfg.pe_target.clone(), None)
    };
    providers.extend(all_pe_providers(pe_source));

    SuiteWiring { providers, actions }
}

pub fn build_synthetic_suite_wiring(pe_bytes: Option<Vec<u8>>) -> SuiteWiring {
    let mut providers = Vec::with_capacity(48);
    let mut actions = Vec::with_capacity(22);

    let proc_backend = Arc::new(MockProcBackend::new());
    providers.extend(all_proc_providers(proc_backend.clone()));
    actions.extend(all_proc_actions(proc_backend));

    let hw_backend = Arc::new(MockHwBackend::new());
    providers.extend(all_hw_providers(hw_backend.clone(), Sys2RustConfig::default()));
    actions.extend(all_hw_actions(hw_backend));

    let shell_backend = Arc::new(SyntheticShellBackend::new());
    providers.extend(all_shell_providers(shell_backend.clone()));
    actions.extend(all_shell_actions(shell_backend));

    let pe_src = Arc::new(PeTargetSource::Bytes {
        label: "synthetic_fixture.dll".to_string(),
        bytes: pe_bytes.unwrap_or_else(sys2rust_pe::fixture::build_synthetic_pe32_dll),
        gac_root: Some(synthetic_gac_root()),
    });
    providers.extend(all_pe_providers(pe_src));

    SuiteWiring { providers, actions }
}

pub fn build_sys2rust_registry(policy: PolicyMode, cfg: &Sys2RustConfig) -> McpServerRegistry {
    let wiring = build_suite_wiring(cfg);
    registry_from_wiring(policy, wiring)
}

pub fn registry_from_wiring(policy: PolicyMode, wiring: SuiteWiring) -> McpServerRegistry {
    let mut reg = McpServerRegistry::new(policy).with_server_info("sys2rust", env!("CARGO_PKG_VERSION"));
    for provider in wiring.providers {
        reg.register_table(provider);
    }
    for action in wiring.actions {
        reg.register_action(action);
    }
    reg
}

pub fn print_tools_manifest_json(policy: PolicyMode, cfg: &Sys2RustConfig) -> anyhow::Result<String> {
    let reg = build_sys2rust_registry(policy, cfg);
    Ok(serde_json::to_string_pretty(&reg.list_tools())?)
}

pub fn serve_mcp_stdio(policy: PolicyMode, cfg: &Sys2RustConfig) -> anyhow::Result<()> {
    let reg = build_sys2rust_registry(policy, cfg);
    reg.serve_stdio()
}

#[cfg(test)]
mod tests {
    use guap_mcp::MCP_PROTOCOL_VERSION;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn registers_all_48_tables_and_enforces_32003_policy_gates() {
        let wiring = build_synthetic_suite_wiring(None);
        assert_eq!(wiring.providers.len(), 48, "expected exactly 48 TableProviders");
        assert_eq!(wiring.actions.len(), 22, "expected 22 ActionCommands");

        let mut reg = registry_from_wiring(PolicyMode::ReadOnlyOnly, wiring);

        // Verify initialize handshake (2024-11-05)
        let init_resp = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": MCP_PROTOCOL_VERSION }
            }))
            .unwrap();
        assert_eq!(init_resp["result"]["protocolVersion"], json!(MCP_PROTOCOL_VERSION));

        // Verify tools/list returns all 48 tables + 22 actions = 70 MCP tools
        let list_resp = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }))
            .unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 70);

        // Verify ReadOnlyOnly blocks mutating tools with -32003 even if confirm_destructive=true
        let blocked_ro = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "shell_privacy_audit_clean",
                    "arguments": { "categories": ["Temp"], "confirm_destructive": true }
                }
            }))
            .unwrap();
        assert_eq!(blocked_ro["error"]["code"], json!(-32003));

        // Verify AllowMutating still blocks without confirm_destructive=true
        reg.set_policy(PolicyMode::AllowMutating);
        let blocked_unconfirmed = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "proc_terminate",
                    "arguments": { "pid": 4200 }
                }
            }))
            .unwrap();
        assert_eq!(blocked_unconfirmed["error"]["code"], json!(-32003));

        // Verify AllowMutating + confirm_destructive=true + dry_run=true succeeds
        let dry_ok = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "hw_service_control",
                    "arguments": {
                        "service_name": "Spooler",
                        "action": "stop",
                        "confirm_destructive": true,
                        "dry_run": true
                    }
                }
            }))
            .unwrap();
        assert!(dry_ok.get("error").is_none());
        let text = dry_ok["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["dry_run"], json!(true));

        // Verify ReadOnly table query via tools/call
        let pe_ok = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "pe_info",
                    "arguments": {}
                }
            }))
            .unwrap();
        assert!(pe_ok.get("error").is_none());
    }
}
