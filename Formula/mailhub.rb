class Mailhub < Formula
  desc "Manage Mailhub relay addresses from the terminal"
  homepage "https://private-mailhub.com"
  url "https://github.com/private-mailhub/cli/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "6d16ec66130ecc2822d414aa86c454d8950dbd8390e0a1d4c5b7c362409274d9"
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
