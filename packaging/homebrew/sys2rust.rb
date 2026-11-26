class Sys2rust < Formula
  desc "48-tool Windows process/ETW, hardware/firmware, shell/registry, and pure-Rust PE/.NET inspection suite"
  homepage "https://sys2rust.guap.ca"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/sys2rust/releases/download/v0.1.0/sys2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/sys2rust/releases/download/v0.1.0/sys2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/sys2rust/releases/download/v0.1.0/sys2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "sys2rust"
    bin.install "sys2rust-iced"
    bin.install "sys2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "sys2rust", shell_output("#{bin}/sys2rust --help")
    assert_match "pe_info", shell_output("#{bin}/sys2rust mcp --tools")
  end
end
