# Contributing to `sys2rust`

Thank you for your interest in contributing to `sys2rust`!

## Code Architecture
The workspace consists of 10 modular crates under `crates/`:
- `sys2rust-core`: Shared errors, privilege/hardware diagnostics, binary/timestamp decoders, backend traits, and logging.
- `sys2rust-proc`: 13 process, thread, DLL, handle/open-file (with named-pipe timeout guard), heap, GDI, hang, debug, memory, environment, and ETW monitors.
- `sys2rust-hw`: 10 hardware, service, driver, device, Task Scheduler (COM + XML), WMI, pure-Rust SMBIOS/ACPI firmware, battery, codec, and timezone tools.
- `sys2rust-shell`: 19 startup, uninstall, MSI/Appx, shell extension, context menu, file association, COM, URL protocol, appcompat, MUI/version, environment, desktop icon layout, tray notify, and privacy audit tools.
- `sys2rust-pe`: 6 `#![forbid(unsafe_code)]` pure-Rust PE32/PE32+ & ECMA-335 .NET inspection tools.
- `sys2rust-report`: Multi-format reporting and SHA-256/512 Merkle chain-of-custody manifests.
- `sys2rust-mcp`: Policy-gated JSON-RPC 2.0 stdio MCP server (`ReadOnlyOnly` default).
- `sys2rust-cli`: `clap` 4.6 derive CLI (`sys2rust`).
- `sys2rust-win32` & `sys2rust-iced`: Dual desktop GUI hosts built on `guap-gui-win32` and `guap-gui-iced`.

## Safety & Scope Rules
- **No DLL Injection / API Hooking**: Never introduce `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetWindowsHookExW`, or `WriteProcessMemory` code injection.
- **No Credential Extraction**: `sys2rust` strictly excludes password/credential extraction, DPAPI/Vault/LSA secret dumping, or legacy retired tools.
- **Mutating Policy Gates**: Every mutating operation must implement `guap_mcp::ActionCommand` with `dry_run` support and explicit confirmation flags.

## Verification Commands
```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --offline
```
