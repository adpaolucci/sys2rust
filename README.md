# `sys2rust` — 48-Tool Pure-Rust Windows Process, Hardware, Shell & PE/.NET Inspection Suite

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://sys2rust.guap.ca**](https://sys2rust.guap.ca) • [**Project Wiki**](https://github.com/adpaolucci/sys2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 10 Crates](https://img.shields.io/badge/Workspace-10%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/sys2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/sys2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`sys2rust`** is a 100% pure-Rust 48-tool Windows process/ETW, hardware/SMBIOS/ACPI firmware, shell/registry extension, and PE32/PE32+/ECMA-335 `.NET` inspection suite built on [`guap-kit`](https://github.com/adpaolucci/guap-kit):
1. **`sys2rust-win32`** (**WinSafe `0.0.29`**) — Native zero-GPU Win32 virtual list console (`LVS_OWNERDATA`, ComCtl v6, Per-Monitor DPI v2).
2. **`sys2rust-iced`** (**Iced `0.14`**) — Cross-platform retained-mode GUI (`wgpu` + `tiny-skia` CPU fallback).
3. **`sys2rust`** — Unified `clap 4.6` CLI (`proc`, `hw`, `shell`, `pe`, `mcp`, `gui`, `action`, `list`, `diag`) with `--offline` fixtures, `GetNir` filtering, and `guap-export` Merkle custody reports.
4. **`sys2rust-mcp`** — Policy-gated JSON-RPC 2.0 (`2024-11-05`) `stdio` MCP server exposing **70 tools** (**48** read-only `TableProvider`s + **22** policy-gated mutating `ActionCommand`s).

---

## Comparison: `sys2rust` vs. Legacy System Utilities

| Capability | `sys2rust` | Legacy System Utilities | Ad-Hoc PowerShell / WMI |
|---|---|---|---|
| **Unified Suite Coverage** | **48 tools across `proc`, `hw`, `shell`, and `pe` in 1 suite** | 48+ disparate binaries | Slow WMI/COM scripting |
| **Pure-Rust Binary Parsers** | **`sys2rust-pe` (`#![forbid(unsafe_code)]` PE32/PE32+/ECMA-335 `.NET`), SMBIOS/ACPI, Appx XML** | Mixed Windows-only GUIs | No raw binary parsers |
| **Deadlock & Non-Admin Safety** | **Named-pipe timeout guard on `NtQueryObject`, `PERMISSION_DENIED` fallbacks, passive ETW** | Can hang on synchronous named pipes | Partial error handling |
| **Policy & R4 Boundary** | **`--dry-run` + `ReadOnlyOnly` `-32003` MCP gate; zero DLL injection or hooking** | Immediate unguarded edits | Manual `-WhatIf` |
| **Chain-of-Custody Exports** | **7 `guap-export` formats + CSV formula neutralization + SHA-256/512 Merkle `CustodyManifest`** | Manual text/CSV dumps | No Merkle verification |

---

## Workspace Architecture (10 Crates)

```text
sys2rust/
├── Cargo.toml                  # 10-crate workspace (Edition 2024, MSRV 1.88, Apache-2.0)
├── deny.toml                   # cargo-deny license & advisory policy
├── mcp.json / smithery.yaml    # Standard MCP & Smithery manifests (70 endpoints)
├── metadata.json               # Machine-readable 48-tool suite manifest
├── packaging/                  # WinGet & Homebrew manifests
└── crates/
    ├── sys2rust-core/          # `#![forbid(unsafe_code)]` SysError, privilege diagnostics, binary/timestamp decoders
    ├── sys2rust-proc/          # 13 process, thread, DLL, handle, heap, GDI, hang, debug & passive ETW tools + 4 actions
    ├── sys2rust-hw/            # 10 service, driver, device, Task Scheduler, WMI, SMBIOS/ACPI, battery, codec, timezone tools + 4 actions
    ├── sys2rust-shell/         # 19 startup, uninstall, MSI/Appx, shell extension, menu, filetype, COM, DesktopOK, TrayNotify, privacy tools + 14 actions
    ├── sys2rust-pe/            # `#![forbid(unsafe_code)]` 6 pure-Rust PE32/PE32+, .rsrc, ICO, ECMA-335 .NET & GAC tools
    ├── sys2rust-report/        # guap-export integration across 7 formats + SHA-256/512 Merkle CustodyManifest
    ├── sys2rust-mcp/           # Policy-gated MCP JSON-RPC 2.0 stdio server (`sys2rust-mcp`, 70 endpoints)
    ├── sys2rust-cli/           # Unified CLI (`sys2rust`)
    ├── sys2rust-win32/         # Native Win32 GUI (`sys2rust-win32`, ComCtl v6)
    └── sys2rust-iced/          # Cross-platform Iced 0.14 GUI (`sys2rust-iced`)
```

---

## 48-Tool Matrix & 70 MCP Endpoints

### `sys2rust-proc` (13 Tools + 4 Mutating Actions)
| CLI Subcommand | NirSoft / Diagnostic Equivalent | Scope / Mechanism | MCP Tool ID |
|---|---|---|---|
| `proc threads` | `ProcessThreadsView` | Toolhelp/NT thread stack, start address & priority | `proc_threads` |
| `proc dlls` | `LoadedDllsView` | `EnumProcessModulesEx` / Toolhelp32 module list | `proc_dlls` |
| `proc handles` | `HandleView` | `NtQuerySystemInformation` handles (timeout-guarded) | `proc_handles` |
| `proc open-files` | `OpenFilesView` | Locked file handle resolution | `proc_open_files` |
| `proc activity` | `ProcessActivityView` | Passive ETW `Microsoft-Windows-Kernel-File` I/O | `proc_activity` |
| `proc heap` | `HeapMemView` | `Heap32ListFirst` / `Heap32First` heap blocks | `proc_heap` |
| `proc gdi` | `GDIView` | `GetGuiResources` & GDI object table telemetry | `proc_gdi` |
| `proc hang` | `WhatIsHang` | Unresponsive window/thread wait-chain inspector | `proc_hang` |
| `proc debug` | `SimpleProgramDebugger` | Read-only debug summary (+ gated `proc_debug_attach`) | `proc_debug` |
| `proc list` | *Process Snapshot* | Process PID, PPID, memory, user & elevation | `proc_list` |
| `proc mem` | *Virtual Memory Map* | `VirtualQueryEx` region & protection table | `proc_mem` |
| `proc env` | *Process Environment* | PEB environment variables (read-only) | `proc_env` |
| `proc etw-life` | *ETW Process Lifecycle* | Passive ETW `Microsoft-Windows-Kernel-Process` stream | `proc_etw_life` |

> **Policy-Gated `proc` Actions (4 `[MUT]`)**: `proc_terminate`, `proc_thread_control`, `proc_close_handle`, `proc_debug_attach`.

### `sys2rust-hw` (10 Tools + 4 Mutating Actions)
| CLI Subcommand | NirSoft / Diagnostic Equivalent | Scope / Mechanism | MCP Tool ID |
|---|---|---|---|
| `hw services` | `ServiWin` | Service Control Manager service & binary inventory | `hw_services` |
| `hw drivers` | `DriverView` | `EnumDeviceDrivers` & signed kernel module metadata | `hw_drivers` |
| `hw devices` | `DevManView` | `SetupDiGetClassDevsW` PnP device tree & status | `hw_devices` |
| `hw tasks` | `TaskSchedulerView` | Task Scheduler COM v2 & offline `roxmltree` XML parser | `hw_tasks` |
| `hw wmi` | `SimpleWMIView` | COM WMI / offline `wmi_posture.json` query provider | `hw_wmi` |
| `hw firmware` | `FirmwareTablesView` | `GetSystemFirmwareTable` raw SMBIOS/ACPI RSDP/FADT/MCFG | `hw_firmware` |
| `hw battery` | `BatteryInfoView` | `IOCTL_BATTERY_QUERY_INFORMATION` health & capacity | `hw_battery` |
| `hw codecs` | `InstalledCodec` | DirectShow/ACM/DMO codec registry enumerator | `hw_codecs` |
| `hw timezones` | `TimeZonesView` | `REG_TZI_FORMAT` timezone & DST rule decoder | `hw_timezones` |
| `hw special-folders` | `SpecialFoldersView` | Known Folder GUID & shell path inventory | `hw_special_folders` |

> **Policy-Gated `hw` Actions (4 `[MUT]`)**: `hw_service_control`, `hw_device_control`, `hw_task_control`, `hw_codec_control`.

### `sys2rust-shell` (19 Tools + 14 Mutating Actions)
| CLI Subcommand | NirSoft / Diagnostic Equivalent | Scope | MCP Tool ID |
|---|---|---|---|
| `shell startup` | `WhatInStartup` | Run/RunOnce, `StartupApproved`, Startup folder & services | `shell_startup` |
| `shell uninstall` | `UninstallView` | MSI, Win32, NSIS & store uninstaller inventory | `shell_uninstall` |
| `shell msi` | `InstalledPackagesView` | Windows Installer `MsiEnumProductsExW` database | `shell_msi` |
| `shell appx` | `InstalledAppView` | UWP / MSIX Appx `AppxManifest.xml` (`roxmltree`) | `shell_appx` |
| `shell legacy-uninst` | `MyUninstaller` | Classic ARP registry uninstall entries | `shell_legacy_uninst` |
| `shell shellex` | `ShellExView` | ContextMenu, PropertySheet & IconOverlay shell extensions | `shell_shellex` |
| `shell menu` | `ShellMenuView` | Static shell context-menu verbs | `shell_menu` |
| `shell menu-new` | `ShellMenuNew` | Explorer `ShellNew` file creation templates | `shell_menu_new` |
| `shell filetypes` | `FileTypesMan` | File extensions, ProgIDs & MIME associations | `shell_filetypes` |
| `shell openwith` | `OpenWithView` | `OpenWithProgids` / `OpenWithList` handler map | `shell_openwith` |
| `shell com` | `RegDllView` | Registered COM/ActiveX CLSIDs & InprocServer32 paths | `shell_com` |
| `shell url-proto` | `URLProtocolView` | Custom URI schemes & command handlers | `shell_url_proto` |
| `shell appcompat` | `AppCompatibilityView` | Compatibility Assistant layers & shims | `shell_appcompat` |
| `shell mui-ver` | *MUI / Version Info* | `VS_VERSIONINFO` string tables & language tags | `shell_mui_ver` |
| `shell ext-view` | `ExtensionView` | Unified browser/explorer/shell extension registry view | `shell_ext_view` |
| `shell env-vars` | *Environment Variables* | User, Machine & Process environment variables | `shell_env_vars` |
| `shell desktop-icons` | `DesktopOK` | Desktop icon positions + Win11 `NotifyIconSettings` / ROT13 TrayNotify | `shell_desktop_icons` |
| `shell taskmgr-ext` | *Task Manager Startup/Ext* | Startup impact & Explorer Shell/Taskbar extensions | `shell_taskmgr_ext` |
| `shell privacy-audit` | `CleanAfterMe` | Read-only MRU, RecentDocs, Temp & cache footprint audit | `shell_privacy_audit` |

> **Policy-Gated `shell` Actions (14 `[MUT]`)**: `shell_startup_toggle`, `shell_startup_delete`, `shell_uninstall_run`, `shell_shellex_toggle`, `shell_menu_toggle`, `shell_menu_new_toggle`, `shell_filetypes_edit`, `shell_openwith_toggle`, `shell_com_clean_orphan`, `shell_url_proto_toggle`, `shell_appcompat_set`, `shell_env_vars_set`, `shell_desktop_icons_restore`, `shell_privacy_audit_clean`.

### `sys2rust-pe` (6 Pure-Rust `#![forbid(unsafe_code)]` Tools)
| CLI Subcommand | NirSoft / Diagnostic Equivalent | Scope / Binary Parser | MCP Tool ID |
|---|---|---|---|
| `pe exports` | `DLLExportViewer` | PE32/PE32+ Export Directory (`IMAGE_EXPORT_DIRECTORY`), ordinals & forwarders | `pe_exports` |
| `pe resources` | `ResourcesExtract` | 3-level `.rsrc` tree (`RT_VERSION`, `RT_MANIFEST`, `RT_STRING`, etc.) | `pe_resources` |
| `pe icons` | `IconsExtract` | `RT_GROUP_ICON` + `RT_ICON` & `.ico` directory extraction | `pe_icons` |
| `pe dotnet` | `DotNetResourcesExtract` | CLR header, `BSJB` metadata root, `#~` streams & `.resources` | `pe_dotnet` |
| `pe info` | `ExeInfo` | COFF/Optional header, subsystem, sections, characteristics & Authenticode | `pe_info` |
| `pe gac` | `GACView` | `.NET` GAC assembly version, public key token & processor architecture | `pe_gac` |

---

## R4 Compliance & Non-Admin Fallbacks

- **Graceful Non-Privileged Fallback**: Protected system handles, ETW sessions, and hardware IOCTLs degrade cleanly with explicit `PermissionDenied` / `HardwareNotFound` diagnostics or deterministic `--offline` synthetic backends.
- **Strict R4 Exclusions**: Excludes `cred2rust`, password/DPAPI extraction, `RunAsDate`, DLL injection, API hooking, and all 39 retired legacy NirSoft utilities.

---

## Usage Examples (CLI, Dual GUI & MCP)

```powershell
# Inspect catalog & host privilege readiness
sys2rust list
sys2rust diag

# Pure-Rust PE32 / PE32+ / .NET inspection (works offline on Windows, Linux, macOS)
sys2rust pe info --path target\debug\sys2rust.exe --format json
sys2rust pe exports --path C:\Windows\System32\kernel32.dll --limit 25 --format markdown
sys2rust --offline --format csv --export pe.csv --custody pe.custody.json pe info --path sample.exe

# Process, hardware & shell diagnostics with GetNir filtering
sys2rust --filter "pid > 100" --sort "working_set_bytes:desc" --limit 20 proc list
sys2rust --offline hw firmware --format json
sys2rust --offline shell privacy-audit --format json

# Dry-run vs policy-gated action execution
sys2rust --dry-run action shell_privacy_audit_clean --args '{"categories":["Temp"]}'

# Launch GUIs or MCP server
sys2rust gui              # Native Win32 GUI (sys2rust-win32)
sys2rust gui --iced       # Cross-platform Iced 0.14 GUI (sys2rust-iced)
sys2rust mcp --tools      # Dump all 70 MCP schemas (48 read-only + 22 mutating)
sys2rust mcp              # Start ReadOnlyOnly JSON-RPC 2.0 stdio server (see mcp.json)
```

---

## Building & Testing

```powershell
cargo test --workspace --offline
cargo build --workspace --release --offline
```

---

## Wiki Documentation

Browse the full [`sys2rust` Project Wiki](https://github.com/adpaolucci/sys2rust/wiki):
- [Architecture](https://github.com/adpaolucci/sys2rust/wiki/Architecture)
- [System Diagnostics, PE & 48-Tool Matrix](https://github.com/adpaolucci/sys2rust/wiki/System-Diagnostics-PE-and-48-Tool-Matrix)
- [CLI Reference](https://github.com/adpaolucci/sys2rust/wiki/CLI-Reference)
- [Dual-GUI Guide (Win32 & Iced)](https://github.com/adpaolucci/sys2rust/wiki/Dual-GUI-Guide)
- [GUI Framework Decision & Comparison](https://github.com/adpaolucci/sys2rust/wiki/GUI-Framework-Decision-and-Comparison)
- [MCP Server Guide](https://github.com/adpaolucci/sys2rust/wiki/MCP-Server-Guide)
- [Reports & Forensic Exports](https://github.com/adpaolucci/sys2rust/wiki/Reports-and-Forensic-Exports)
- [Validation Rules & Status Codes](https://github.com/adpaolucci/sys2rust/wiki/Validation-Rules-and-Status-Codes)
- [Building, Testing & CI/CD](https://github.com/adpaolucci/sys2rust/wiki/Building-Testing-and-CI-CD)
- [Security & Stability](https://github.com/adpaolucci/sys2rust/wiki/Security-and-Stability)

## License

Licensed under the [**Apache License, Version 2.0**](LICENSE). See [`NOTICE`](NOTICE) for attribution.
