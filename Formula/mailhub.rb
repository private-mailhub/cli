class Mailhub < Formula
  desc "Manage Mailhub relay addresses from the terminal"
  homepage "https://private-mailhub.com"
  url "https://github.com/private-mailhub/cli/archive/refs/tags/v0.1.2.tar.gz"
  sha256 "0578c771aed7744354e53af8c19b7e0c9284bf5283442f2da9882fd64743582d"
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
