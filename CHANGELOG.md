# Changelog

All notable changes to `sys2rust` will be documented in this file.

## [0.1.0] - 2026-11-23
### Added
- Initial 10-crate workspace release covering all 48 tools across `sys2rust-proc` (13), `sys2rust-hw` (10), `sys2rust-shell` (19), and `sys2rust-pe` (6).
- `sys2rust-core`: Shared errors with privilege/hardware diagnostics, `Binary` decoders (FILETIME, DMTF, UTF-16LE, NTSTATUS, GUID, SHA-256, access masks), backend traits, and stderr `tracing` setup.
- `sys2rust-report`: `guap-export` integration across all 7 formats plus SHA-256/512 Merkle chain-of-custody manifests.
- `sys2rust-mcp`: JSON-RPC 2.0 (`2024-11-05`) stdio server registering all 48 `TableProvider`s and mutating `ActionCommand`s with `-32003` policy gates.
- `sys2rust-cli`, `sys2rust-win32`, and `sys2rust-iced`: Unified CLI (`sys2rust`) and dual native Win32 (`winsafe`) / cross-platform Iced (`0.14`) desktop consoles.
