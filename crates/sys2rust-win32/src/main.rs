use guap_gui_win32::{Win32TableHostConfig, run_win32_suite};
use sys2rust_core::{Sys2RustConfig, init_logging};
use sys2rust_mcp::build_suite_wiring;

fn main() -> anyhow::Result<()> {
    init_logging(false);
    let cfg = Sys2RustConfig::default();
    let wiring = build_suite_wiring(&cfg);
    let host_cfg = Win32TableHostConfig {
        app_title: "sys2rust — Windows System, Shell & PE Console".to_string(),
        dark_mode: true,
        show_hex_pane: true,
        default_export_dir: None,
    };
    run_win32_suite(host_cfg, wiring.providers, wiring.actions)
}

#[cfg(test)]
mod tests {
    use guap_export::ExportFormat;
    use guap_gui_win32::{Win32GridState, Win32TableHostConfig};
    use sys2rust_mcp::build_synthetic_suite_wiring;

    #[test]
    fn win32_grid_state_drives_all_48_tools_offline() {
        let wiring = build_synthetic_suite_wiring(None);
        assert_eq!(wiring.providers.len(), 48);

        let host_cfg = Win32TableHostConfig {
            app_title: "sys2rust Test".to_string(),
            dark_mode: true,
            show_hex_pane: true,
            default_export_dir: None,
        };
        let mut grid = Win32GridState::new(host_cfg, wiring.providers, wiring.actions);

        for idx in 0..48 {
            assert!(grid.select_tool(idx), "failed to select tool index {idx}");
            assert!(!grid.columns().is_empty(), "tool index {idx} has empty columns");
            if grid.row_count() > 0 {
                let _ = grid.cell_text(0, 0);
                let _ = grid.format_inspector_crlf();
            }
        }

        // Verify filter, sort, and export on pe_exports
        assert!(grid.select_tool_by_id("pe_exports"));
        assert_eq!(grid.row_count(), 4);
        grid.set_filter("FooInit".to_string());
        assert_eq!(grid.row_count(), 1);
        grid.set_filter(String::new());
        assert!(grid.toggle_sort(0));

        let tmp = tempfile::tempdir().unwrap();
        let exp_path = tmp.path().join("win32_export.csv");
        grid.export_to_path(&exp_path, ExportFormat::Csv).unwrap();
        assert!(exp_path.is_file());
    }
}
