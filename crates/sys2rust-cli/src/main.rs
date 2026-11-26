#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use guap_export::{ExportFormat, write_custody_manifest_json};
use guap_mcp::PolicyMode;
use guap_table::{GetNirQuery, TableProvider, TableQuery};
use sys2rust_core::{Sys2RustConfig, check_availability, init_logging};
use sys2rust_hw::{all_hw_providers, default_hw_backend};
use sys2rust_mcp::{build_sys2rust_registry, print_tools_manifest_json, serve_mcp_stdio, synthetic_gac_root};
use sys2rust_pe::{
    PeTargetSource, all_pe_providers,
    dotnet::{extract_dotnet_resources, parse_dotnet_metadata},
    icons::{extract_icons, reassemble_icons},
    pe::PeFile,
    resources::{extract_resources, parse_resources},
};
use sys2rust_proc::{all_proc_providers, default_proc_backend};
use sys2rust_report::{default_export_options, render_table_report, write_table_report};
use sys2rust_shell::{all_shell_providers, default_shell_backend};

#[derive(Parser, Debug)]
#[command(
    name = "sys2rust",
    version,
    about = "48-tool Windows process/ETW, hardware/SMBIOS/ACPI, shell/registry, and pure-Rust PE32/PE32+/.NET inspection suite"
)]
struct Cli {
    /// Allow mutating ActionCommands (required with --confirm-destructive)
    #[arg(short = 'y', long, global = true)]
    allow_mutating: bool,

    /// Explicit destructive confirmation required by MCP/action policy gates
    #[arg(long, global = true)]
    confirm_destructive: bool,

    /// Preview mutating actions without modifying system state
    #[arg(long, global = true)]
    dry_run: bool,

    /// Output format: csv, tsv, json, jsonl, html, html-vertical, markdown (md)
    #[arg(long, global = true, default_value = "markdown")]
    format: String,

    /// Write table output to file and compute custody hashes
    #[arg(long, global = true)]
    export: Option<PathBuf>,

    /// Write SHA-256/SHA-512 Merkle CustodyManifest JSON to path
    #[arg(long, global = true)]
    custody: Option<PathBuf>,

    /// GetNir filter expression (e.g. "name ~ svchost" or "pid > 100")
    #[arg(long, global = true)]
    filter: Option<String>,

    /// Sort column specification (e.g. "pid:desc" or "~working_set_bytes")
    #[arg(long, global = true)]
    sort: Option<String>,

    /// Maximum rows to display/export
    #[arg(long, global = true)]
    limit: Option<usize>,

    /// Use offline synthetic backends
    #[arg(long, global = true)]
    offline: bool,

    /// Optional offline synthetic fixture directory
    #[arg(long, global = true)]
    offline_dir: Option<PathBuf>,

    /// Filter live process tools by PID
    #[arg(long, global = true)]
    pid: Option<u32>,

    /// Verbose stderr logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Process, thread, DLL, handle, heap, GDI, hang, and passive ETW tools (13)
    Proc {
        #[command(subcommand)]
        sub: ProcSub,
    },
    /// Hardware, services, drivers, devices, Task Scheduler, WMI, SMBIOS/ACPI, battery, codecs, timezones (10)
    Hw {
        #[command(subcommand)]
        sub: HwSub,
    },
    /// Shell, startup, uninstall, MSI/Appx, shell extensions, menus, filetypes, COM, DesktopOK, TrayNotify, privacy audit (19)
    Shell {
        #[command(subcommand)]
        sub: ShellSub,
    },
    /// Pure-Rust PE32/PE32+, exports, .rsrc, ICO, ECMA-335 .NET, and GAC tools (6)
    Pe {
        #[command(subcommand)]
        sub: PeSub,
    },
    /// Run or inspect the JSON-RPC 2.0 (2024-11-05) stdio MCP server
    Mcp(McpArgs),
    /// Launch the desktop GUI (Win32 native by default, or --iced)
    Gui(GuiArgs),
    /// Execute a registered ActionCommand under policy gates
    Action(ActionArgs),
    /// List all 48 tools across proc, hw, shell, and pe
    List,
    /// Print host elevation, privilege, and ETW availability diagnostics
    Diag,
}

#[derive(Subcommand, Debug)]
enum ProcSub {
    Threads,
    Dlls,
    Handles,
    OpenFiles,
    Activity,
    Heap,
    Gdi,
    Hang,
    Debug,
    List,
    Mem,
    Env,
    EtwLife,
}

impl ProcSub {
    fn tool_id(&self) -> &'static str {
        match self {
            Self::Threads => "proc_threads",
            Self::Dlls => "proc_dlls",
            Self::Handles => "proc_handles",
            Self::OpenFiles => "proc_open_files",
            Self::Activity => "proc_activity",
            Self::Heap => "proc_heap",
            Self::Gdi => "proc_gdi",
            Self::Hang => "proc_hang",
            Self::Debug => "proc_debug",
            Self::List => "proc_list",
            Self::Mem => "proc_mem",
            Self::Env => "proc_env",
            Self::EtwLife => "proc_etw_life",
        }
    }
}

#[derive(Subcommand, Debug)]
enum HwSub {
    Services,
    Drivers,
    Devices,
    Tasks,
    Wmi,
    Firmware,
    Battery,
    Codecs,
    Timezones,
    SpecialFolders,
}

impl HwSub {
    fn tool_id(&self) -> &'static str {
        match self {
            Self::Services => "hw_services",
            Self::Drivers => "hw_drivers",
            Self::Devices => "hw_devices",
            Self::Tasks => "hw_tasks",
            Self::Wmi => "hw_wmi",
            Self::Firmware => "hw_firmware",
            Self::Battery => "hw_battery",
            Self::Codecs => "hw_codecs",
            Self::Timezones => "hw_timezones",
            Self::SpecialFolders => "hw_special_folders",
        }
    }
}

#[derive(Subcommand, Debug)]
enum ShellSub {
    Startup,
    Uninstall,
    Msi,
    Appx,
    LegacyUninst,
    Shellex,
    Menu,
    MenuNew,
    Filetypes,
    Openwith,
    Com,
    UrlProto,
    Appcompat,
    MuiVer,
    ExtView,
    EnvVars,
    DesktopIcons,
    TaskmgrExt,
    PrivacyAudit,
}

impl ShellSub {
    fn tool_id(&self) -> &'static str {
        match self {
            Self::Startup => "shell_startup",
            Self::Uninstall => "shell_uninstall",
            Self::Msi => "shell_msi",
            Self::Appx => "shell_appx",
            Self::LegacyUninst => "shell_legacy_uninst",
            Self::Shellex => "shell_shellex",
            Self::Menu => "shell_menu",
            Self::MenuNew => "shell_menu_new",
            Self::Filetypes => "shell_filetypes",
            Self::Openwith => "shell_openwith",
            Self::Com => "shell_com",
            Self::UrlProto => "shell_url_proto",
            Self::Appcompat => "shell_appcompat",
            Self::MuiVer => "shell_mui_ver",
            Self::ExtView => "shell_ext_view",
            Self::EnvVars => "shell_env_vars",
            Self::DesktopIcons => "shell_desktop_icons",
            Self::TaskmgrExt => "shell_taskmgr_ext",
            Self::PrivacyAudit => "shell_privacy_audit",
        }
    }
}

#[derive(Args, Debug)]
struct PeTargetArgs {
    /// Target PE file (.exe/.dll/.sys) or directory to inspect
    #[arg(long)]
    path: Option<PathBuf>,
    /// Extract matched resources, icons, or .NET payloads into directory
    #[arg(long)]
    extract_dir: Option<PathBuf>,
    /// Custom GAC root directory (for `pe gac`)
    #[arg(long)]
    gac_root: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum PeSub {
    Exports(PeTargetArgs),
    Resources(PeTargetArgs),
    Icons(PeTargetArgs),
    Dotnet(PeTargetArgs),
    Info(PeTargetArgs),
    Gac(PeTargetArgs),
}

impl PeSub {
    fn tool_id(&self) -> &'static str {
        match self {
            Self::Exports(_) => "pe_exports",
            Self::Resources(_) => "pe_resources",
            Self::Icons(_) => "pe_icons",
            Self::Dotnet(_) => "pe_dotnet",
            Self::Info(_) => "pe_info",
            Self::Gac(_) => "pe_gac",
        }
    }

    fn target_args(&self) -> &PeTargetArgs {
        match self {
            Self::Exports(a) | Self::Resources(a) | Self::Icons(a) | Self::Dotnet(a) | Self::Info(a) | Self::Gac(a) => {
                a
            }
        }
    }
}

#[derive(Args, Debug)]
struct McpArgs {
    /// Print MCP tool/action definitions as JSON and exit
    #[arg(long)]
    tools: bool,
    /// Enable mutating actions (still requires confirm_destructive=true per call)
    #[arg(long)]
    allow_mutating: bool,
}

#[derive(Args, Debug)]
struct GuiArgs {
    /// Launch cross-platform Iced 0.14 GUI instead of native Win32 GUI
    #[arg(long)]
    iced: bool,
}

#[derive(Args, Debug)]
struct ActionArgs {
    /// Registered ActionCommand ID (e.g. shell_startup_toggle)
    #[arg(long)]
    id: String,
    /// JSON object of arguments for the action
    #[arg(long, default_value = "{}")]
    args: String,
}

fn build_config(cli: &Cli) -> Sys2RustConfig {
    let offline_fixture_dir = if let Some(ref dir) = cli.offline_dir {
        Some(dir.clone())
    } else if cli.offline {
        Some(PathBuf::from("."))
    } else {
        None
    };
    Sys2RustConfig {
        pid_filter: cli.pid,
        allow_mutating: cli.allow_mutating,
        offline_fixture_dir,
        ..Sys2RustConfig::default()
    }
}

fn build_table_query(cli: &Cli, provider: &dyn TableProvider) -> Result<TableQuery> {
    let schema = provider.schema();
    let mut gq = GetNirQuery::new();
    if let Some(ref f) = cli.filter {
        gq.filter_expr = Some(f.clone());
    }
    if let Some(ref s) = cli.sort {
        let normalized = if let Some(col) = s.strip_prefix('~') {
            format!("-{col}")
        } else {
            s.clone()
        };
        gq.sort = GetNirQuery::parse_sort(&normalized).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    gq.limit = cli.limit;
    gq.to_table_query(&schema).map_err(|e| anyhow::anyhow!("{e}"))
}

fn emit_provider_output(cli: &Cli, provider: &dyn TableProvider) -> Result<()> {
    let req = build_table_query(cli, provider)?;
    let data = provider.query(&req)?;
    let fmt = ExportFormat::parse(&cli.format)?;
    let opts = default_export_options(None);

    if let Some(ref export_path) = cli.export {
        let manifest = write_table_report(&data, export_path, fmt, &opts)?;
        if let Some(ref custody_path) = cli.custody {
            write_custody_manifest_json(&manifest, custody_path)?;
        }
        eprintln!(
            "Exported {} rows to {} (merkle_sha256={})",
            data.rows.len(),
            export_path.display(),
            manifest.merkle_root_sha256
        );
    } else {
        let bytes = render_table_report(&data, fmt, &opts)?;
        let text = String::from_utf8(bytes)?;
        print!("{text}");
    }
    Ok(())
}

fn maybe_extract_pe(sub: &PeSub, target: &Path) -> Result<()> {
    let Some(out_dir) = &sub.target_args().extract_dir else {
        return Ok(());
    };
    if !target.is_file() {
        bail!("--extract-dir requires --path to point to a single PE file");
    }
    let bytes = std::fs::read(target).with_context(|| format!("reading {}", target.display()))?;
    let pe = PeFile::parse(&bytes)?;
    match sub {
        PeSub::Resources(_) => {
            let res = parse_resources(&pe)?;
            let paths = extract_resources(&res, out_dir)?;
            eprintln!("Extracted {} Win32 resources to {}", paths.len(), out_dir.display());
        }
        PeSub::Icons(_) => {
            let res = parse_resources(&pe)?;
            let groups = reassemble_icons(&target.display().to_string(), &res);
            let paths = extract_icons(&groups, out_dir)?;
            eprintln!("Extracted {} icon groups to {}", paths.len(), out_dir.display());
        }
        PeSub::Dotnet(_) => {
            if let Some(meta) = parse_dotnet_metadata(&pe)? {
                let paths = extract_dotnet_resources(&meta.resources, out_dir)?;
                eprintln!("Extracted {} .NET resources to {}", paths.len(), out_dir.display());
            }
        }
        _ => {}
    }
    Ok(())
}

fn launch_sibling_gui(iced: bool) -> Result<()> {
    let exe_name = if iced {
        if cfg!(windows) {
            "sys2rust-iced.exe"
        } else {
            "sys2rust-iced"
        }
    } else if cfg!(windows) {
        "sys2rust-win32.exe"
    } else {
        "sys2rust-iced"
    };
    let current = std::env::current_exe().context("resolve current executable path")?;
    let sibling = current
        .parent()
        .map(|p| p.join(exe_name))
        .unwrap_or_else(|| PathBuf::from(exe_name));

    let target = if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(exe_name)
    };
    let mut child = Command::new(&target)
        .spawn()
        .with_context(|| format!("failed to launch GUI executable '{}'", target.display()))?;
    let status = child.wait()?;
    if !status.success() {
        bail!("GUI exited with status {status}");
    }
    Ok(())
}

fn run_cli(cli: Cli) -> Result<()> {
    let cfg = build_config(&cli);

    let Some(command) = cli.command.as_ref() else {
        return launch_sibling_gui(false);
    };

    match command {
        Commands::Proc { sub } => {
            let backend = default_proc_backend(cfg);
            let providers = all_proc_providers(backend);
            let p = providers
                .iter()
                .find(|p| p.tool_id() == sub.tool_id())
                .with_context(|| format!("missing provider {}", sub.tool_id()))?;
            emit_provider_output(&cli, p.as_ref())
        }
        Commands::Hw { sub } => {
            let backend = default_hw_backend(cfg.clone());
            let providers = all_hw_providers(backend, cfg);
            let p = providers
                .iter()
                .find(|p| p.tool_id() == sub.tool_id())
                .with_context(|| format!("missing provider {}", sub.tool_id()))?;
            emit_provider_output(&cli, p.as_ref())
        }
        Commands::Shell { sub } => {
            let backend = default_shell_backend(cfg);
            let providers = all_shell_providers(backend);
            let p = providers
                .iter()
                .find(|p| p.tool_id() == sub.tool_id())
                .with_context(|| format!("missing provider {}", sub.tool_id()))?;
            emit_provider_output(&cli, p.as_ref())
        }
        Commands::Pe { sub } => {
            let ta = sub.target_args();
            let gac_root = ta.gac_root.clone().or_else(|| {
                if let Some(ref dir) = cli.offline_dir {
                    let gac_sub = dir.join("gac");
                    Some(if gac_sub.exists() { gac_sub } else { dir.clone() })
                } else if cli.offline {
                    Some(synthetic_gac_root())
                } else {
                    None
                }
            });
            let src = if let Some(ref p) = ta.path {
                maybe_extract_pe(sub, p)?;
                Arc::new(PeTargetSource::FileOrDir {
                    target: Some(p.clone()),
                    gac_root,
                })
            } else if let Some(ref dir) = cli.offline_dir {
                let pe_cand = ["sample.dll", "fixture.dll", "pe"]
                    .into_iter()
                    .map(|n| dir.join(n))
                    .find(|p| p.exists());
                if let Some(p) = pe_cand {
                    Arc::new(PeTargetSource::FileOrDir {
                        target: Some(p),
                        gac_root,
                    })
                } else {
                    Arc::new(PeTargetSource::Bytes {
                        label: "synthetic_fixture.dll".to_string(),
                        bytes: sys2rust_pe::fixture::build_synthetic_pe32_dll(),
                        gac_root,
                    })
                }
            } else if cli.offline {
                Arc::new(PeTargetSource::Bytes {
                    label: "synthetic_fixture.dll".to_string(),
                    bytes: sys2rust_pe::fixture::build_synthetic_pe32_dll(),
                    gac_root,
                })
            } else {
                let target = std::env::current_exe().ok();
                if let Some(ref p) = target {
                    maybe_extract_pe(sub, p)?;
                }
                Arc::new(PeTargetSource::FileOrDir { target, gac_root })
            };
            let providers = all_pe_providers(src);
            let p = providers
                .iter()
                .find(|p| p.tool_id() == sub.tool_id())
                .with_context(|| format!("missing provider {}", sub.tool_id()))?;
            emit_provider_output(&cli, p.as_ref())
        }
        Commands::Mcp(args) => {
            let allow = cli.allow_mutating || args.allow_mutating;
            let policy = if allow {
                PolicyMode::AllowMutating
            } else {
                PolicyMode::ReadOnlyOnly
            };
            if args.tools {
                println!("{}", print_tools_manifest_json(policy, &cfg)?);
                return Ok(());
            }
            serve_mcp_stdio(policy, &cfg)
        }
        Commands::Gui(args) => launch_sibling_gui(args.iced),
        Commands::Action(args) => {
            let policy = if cli.allow_mutating {
                PolicyMode::AllowMutating
            } else {
                PolicyMode::ReadOnlyOnly
            };
            let reg = build_sys2rust_registry(policy, &cfg);
            let mut val: serde_json::Value =
                serde_json::from_str(&args.args).context("invalid JSON passed to --args")?;
            if let Some(obj) = val.as_object_mut() {
                if cli.confirm_destructive {
                    obj.insert("confirm_destructive".to_string(), serde_json::Value::Bool(true));
                }
                if cli.dry_run {
                    obj.insert("dry_run".to_string(), serde_json::Value::Bool(true));
                }
            }
            match reg.dispatch(&args.id, &val) {
                Ok(res) => {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                    Ok(())
                }
                Err(err) => bail!("policy/action error ({}): {}", err.code, err.message),
            }
        }
        Commands::List => {
            let wiring = sys2rust_mcp::build_suite_wiring(&cfg);
            for (idx, p) in wiring.providers.iter().enumerate() {
                println!("{:>2}. {:<24} {}", idx + 1, p.tool_id(), p.description());
            }
            println!(
                "\nTotal tools: {}, mutating actions: {}",
                wiring.providers.len(),
                wiring.actions.len()
            );
            Ok(())
        }
        Commands::Diag => {
            let report = check_availability();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let _ = ctrlc::set_handler(|| {
        std::process::exit(130);
    });
    run_cli(cli)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn clap_definition_is_valid_and_parses_core_subcommands() {
        Cli::command().debug_assert();

        let p1 = Cli::try_parse_from(["sys2rust", "proc", "list", "--offline", "--format", "json"]).unwrap();
        assert!(p1.offline);

        let p2 = Cli::try_parse_from([
            "sys2rust",
            "shell",
            "privacy-audit",
            "--offline",
            "--filter",
            "category ~ Temp",
            "--sort",
            "item_count:desc",
            "--limit",
            "5",
        ])
        .unwrap();
        assert_eq!(p2.limit, Some(5));

        let p3 = Cli::try_parse_from(["sys2rust", "mcp", "--tools", "--allow-mutating"]).unwrap();
        assert!(matches!(
            p3.command,
            Some(Commands::Mcp(McpArgs {
                tools: true,
                allow_mutating: true
            }))
        ));
    }

    #[test]
    fn cli_executes_pe_info_and_report_export_with_custody_offline() {
        let tmp = tempfile::tempdir().unwrap();
        let pe_path = tmp.path().join("sample.dll");
        std::fs::write(&pe_path, sys2rust_pe::fixture::build_synthetic_pe32_dll()).unwrap();

        let export_path = tmp.path().join("pe_info.json");
        let custody_path = tmp.path().join("custody.json");

        let cli = Cli::try_parse_from([
            "sys2rust",
            "pe",
            "info",
            "--path",
            &pe_path.display().to_string(),
            "--format",
            "json",
            "--export",
            &export_path.display().to_string(),
            "--custody",
            &custody_path.display().to_string(),
        ])
        .unwrap();

        run_cli(cli).unwrap();
        assert!(export_path.is_file());
        assert!(custody_path.is_file());
        let json_txt = std::fs::read_to_string(&export_path).unwrap();
        assert!(json_txt.contains("Sys2RustFixture"));
    }

    #[test]
    fn cli_action_enforces_policy_gates_offline() {
        let blocked = Cli::try_parse_from([
            "sys2rust",
            "action",
            "--id",
            "shell_startup_toggle",
            "--args",
            r#"{"entry_name":"SecurityHealth","enable":false}"#,
            "--offline",
        ])
        .unwrap();
        let err = run_cli(blocked).unwrap_err();
        assert!(err.to_string().contains("-32003"));

        let allowed = Cli::try_parse_from([
            "sys2rust",
            "-y",
            "--confirm-destructive",
            "--dry-run",
            "--offline",
            "action",
            "--id",
            "shell_startup_toggle",
            "--args",
            r#"{"entry_name":"SecurityHealth","enable":false}"#,
        ])
        .unwrap();
        run_cli(allowed).unwrap();
    }
}
