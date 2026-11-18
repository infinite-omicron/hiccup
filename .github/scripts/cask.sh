#!/usr/bin/env bash
# Prints the Homebrew cask for a release, using the SHA-256 sums from the
# release's checksums.txt.
# Usage: cask.sh <version without v> <checksums.txt> [download base URL]
set -euo pipefail

version="${1:?usage: cask.sh <version> <checksums.txt> [base-url]}"
sums="${2:?usage: cask.sh <version> <checksums.txt> [base-url]}"
base="${3:-https://github.com/infinite-omicron/hiccup/releases/download/v#{version\}}"

sum() {
  local file="hiccup_${version}_$1.tar.gz" s
  s=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$sums")
  [[ -n "$s" ]] || { echo "no checksum for $file in $sums" >&2; exit 1; }
  echo "$s"
}

cat <<CASK
cask "hiccup" do
  arch arm: "arm64", intel: "amd64"
  os macos: "darwin", linux: "linux"

  version "${version}"
  sha256 arm:          "$(sum darwin_arm64)",
         intel:        "$(sum darwin_amd64)",
         arm64_linux:  "$(sum linux_arm64)",
         x86_64_linux: "$(sum linux_amd64)"

  url "${base}/hiccup_#{version}_#{os}_#{arch}.tar.gz"
  name "hiccup"
  desc "Drive Burp Suite, ZAP or mitmproxy from scripts and agents"
  homepage "https://github.com/infinite-omicron/hiccup"

  livecheck do
    url :url
    strategy :github_latest
  end

  # hiccup finds hiccup-burp.jar next to its binary, so it stays in the staged folder.
  binary "hiccup_#{version}_#{os}_#{arch}/hiccup"

  postflight_steps do
    on_macos do
      # The binaries are not notarized; clear the quarantine flag so macOS runs them.
      run "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "."], chdir: "."
    end
  end

  zap trash: "~/.hiccup"
end
CASK
