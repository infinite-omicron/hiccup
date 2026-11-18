#!/usr/bin/env bash
# Records each release asset on the organization's linked artifacts page
# (https://github.com/orgs/<org>/artifacts) via the artifact metadata API.
# Usage: storage-records.sh <tag> <checksums.txt>
# Needs GH_TOKEN with artifact-metadata: write, and GITHUB_REPOSITORY (owner/repo).
set -euo pipefail

tag="${1:?usage: storage-records.sh <tag> <checksums.txt>}"
sums="${2:?usage: storage-records.sh <tag> <checksums.txt>}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
org="${repo%%/*}"
releases="https://github.com/${repo}/releases"

while read -r digest name; do
  name="${name#\*}" # sha256sum marks binary-mode files with "*"
  [[ -n "$name" ]] || continue
  gh api --method POST "orgs/${org}/artifacts/metadata/storage-record" \
    -f name="$name" \
    -f digest="sha256:${digest}" \
    -f version="${tag#v}" \
    -f registry_url="$releases" \
    -f artifact_url="${releases}/download/${tag}/${name}" \
    -f repository="$repo" \
    -f github_repository="${repo#*/}" \
    -f status=active \
    -F return_records=false >/dev/null
  echo "recorded $name"
done < "$sums"
