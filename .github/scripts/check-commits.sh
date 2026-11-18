#!/usr/bin/env bash
# Fails if any commit subject in the given range is not a Conventional Commit:
#   <type>(<optional scope>)<optional !>: <description>
# Usage: check-commits.sh <base>..<head>
set -euo pipefail

range="${1:?usage: check-commits.sh <base>..<head>}"
pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: [^ ].*'
bad=0
while IFS=$'\t' read -r sha subject; do
  # Merge commits and git's own reverts are generated, not authored.
  [[ "$subject" =~ ^(Merge|Revert\ \") ]] && continue
  if [[ ! "$subject" =~ $pattern ]]; then
    echo "::error::${sha:0:7} is not a Conventional Commit: $subject"
    bad=1
  fi
done < <(git log --format='%H%x09%s' "$range")
if [[ $bad -ne 0 ]]; then
  echo "Use <type>(<scope>): <description>, e.g. 'feat(matrix): add csv export'. See https://www.conventionalcommits.org"
  exit 1
fi
echo "All commits in $range follow Conventional Commits."
