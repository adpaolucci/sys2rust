#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use guap_mcp::PolicyMode;
use sys2rust_core::{Sys2RustConfig, init_logging};
use sys2rust_mcp::{print_tools_manifest_json, serve_mcp_stdio};

#[derive(Parser, Debug)]
#[command(name = "sys2rust-mcp", version, about = "sys2rust MCP JSON-RPC 2.0 stdio server")]
struct Args {
    /// Print tool schemas as JSON and exit
    #[arg(long)]
    tools: bool,
    /// Enable mutating ActionCommands (still requires confirm_destructive=true)
    #[arg(long)]
    allow_mutating: bool,
    /// Use offline synthetic backends
    #[arg(long)]
    offline: Option<PathBuf>,
    /// Verbose stderr logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(args.verbose);
    let cfg = Sys2RustConfig {
        allow_mutating: args.allow_mutating,
        offline_fixture_dir: args.offline,
        ..Sys2RustConfig::default()
    };
    let policy = if args.allow_mutating {
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
