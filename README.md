# `sys2rust`

48-tool Windows process/ETW, hardware/firmware, shell/registry, and pure-Rust PE32/PE32+/.NET inspection suite built on `guap-kit` (Rust Edition 2024, Apache-2.0).

## Workspace Crates (10)
- `crates/sys2rust-core`: Shared errors (`PermissionDenied` / `HardwareNotFound` / `SourceUnavailable` diagnostics), config, elevation checks, binary/timestamp decoders, backend traits, and stderr logging.
- `crates/sys2rust-proc`: 13 process, thread, DLL, handle/open-file (with named-pipe deadlock timeout guard), heap, GDI, hang, debugger, memory map, PEB environment, and passive ETW monitors (`Kernel-File`, `Kernel-Process`) with zero DLL injection.
- `crates/sys2rust-hw`: 10 tools covering services, drivers, devices, Task Scheduler (COM + `roxmltree` XML), WMI, pure-Rust SMBIOS/ACPI firmware tables, battery IOCTL, codecs, timezones (`REG_TZI_FORMAT`), and known folders.
- `crates/sys2rust-shell`: 19 tools covering startup (`StartupApproved`), uninstall, MSI, Appx (`roxmltree`), legacy uninstall, shell extensions, context menus, ShellNew, file types, OpenWith, COM registration, URL protocols, appcompat, MUI/version info, explorer extensions, environment variables, DesktopOK icon layout, TrayNotify (ROT13 + Win11 `NotifyIconSettings`), and read-only `CleanAfterMe` privacy audit (+ gated clean).
- `crates/sys2rust-pe`: 6 `#![forbid(unsafe_code)]` pure-Rust PE32/PE32+ & ECMA-335 `.NET` tools (`pe_exports`, `pe_resources`, `pe_icons`, `pe_dotnet`, `pe_info`, `pe_gac`).
- `crates/sys2rust-report`: `guap-export` integration across 7 formats (`csv`, `tsv`, `json`, `jsonl`, `html`, `html-vertical`, `markdown`) + SHA-256/512 Merkle custody manifests.
- `crates/sys2rust-mcp`: Policy-gated JSON-RPC 2.0 (`2024-11-05`) stdio MCP server (`ReadOnlyOnly` default, `-32003` enforcement).
- `crates/sys2rust-cli`: `clap` 4.6 derive CLI (`sys2rust`).
- `crates/sys2rust-win32`: Native Win32 (`winsafe`) desktop console (`sys2rust-win32`).
- `crates/sys2rust-iced`: Cross-platform Iced `0.14` desktop console (`sys2rust-iced`).

## Quick Usage
```powershell
sys2rust --help
sys2rust pe info --path target\debug\sys2rust.exe --format json
sys2rust mcp --tools
```
