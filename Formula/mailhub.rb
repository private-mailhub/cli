class Mailhub < Formula
  desc "Manage Mailhub relay addresses from the terminal"
  homepage "https://private-mailhub.com"
  url "https://github.com/private-mailhub/cli/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "896a1e9d7e9a091583e3e6499092bc9647c6ef911d13e43398cb83d041412077"
  license "AGPL-3.0-or-later"

  depends_on "go" => :build
  depends_on :macos

  deny_network_access!

  def fetch
    system "go", "mod", "download"
  end

  def install
    ldflags = "-X github.com/private-mailhub/mailhub-cli/internal/cli.Version=#{version}"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/mailhub"
  end

  test do
    assert_equal "mailhub #{version}", shell_output("#{bin}/mailhub version").strip
  end
end
