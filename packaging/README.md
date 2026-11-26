# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores ready-to-submit package manager manifests matching published GitHub Releases for **`sys2rust`**.

## 1. Windows Package Manager (`winget`)

```powershell
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\sys2rust\0.1.0
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\sys2rust\0.1.0
```

Installed portable command aliases: `sys2rust`, `sys2rust-win32`, `sys2rust-iced`, `sys2rust-mcp`.

## 2. Homebrew (`macOS` & `Linux`)

```bash
brew install adpaolucci/tap/sys2rust
brew install --formula ./packaging/homebrew/sys2rust.rb
brew test sys2rust
```
