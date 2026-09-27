#!/usr/bin/env bash
# Block large or binary files from being staged.
#
# Why this exists: during development, `git add -A` swept a downloaded ffmpeg
# static build (76 MB), a second 76 MB binary, ~170 VMAF model files, fonts, and
# a rendered MP4 into this repository. It was pushed to a public cryptography
# repository before it was noticed. Rewriting history fixed the size, but the
# cause was committing build artifacts, and that must not be able to recur
# silently.
#
# A cryptography repository should contain source, tests, and documentation. It
# should not contain downloaded toolchains, virtualenvs, or rendered media.
#
# Install:  cp scripts/pre-commit-guard.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Exists in the repository as a normal script so it can also be run manually
# against the index, and so reviewers can see the policy.

set -uo pipefail

# Any staged blob at or above this size is refused. The largest legitimate file
# in this repository is a few kilobytes, so this is generous by two orders of
# magnitude.
readonly MAX_BYTES=$(( 1024 * 1024 ))
readonly MAX_MB=$(( MAX_BYTES / 1024 / 1024 ))

# Directory names that are never source, whatever the parent path is. Matched
# against the first path component rather than as a string prefix, so `venv`,
# `.venv`, and `src/target` are all caught. An earlier version of this guard
# listed `.venv/` and let a bare `venv/` through, which a test caught.
#
# These are deliberately narrow. A name like `tools` or `check` is too generic
# to ban globally, because a legitimate source directory could use it, so
# those are handled by FORBIDDEN_PREFIXES below instead.
readonly FORBIDDEN_DIRS=(
  "venv"
  ".venv"
  "node_modules"
  "target"
  "__pycache__"
)

# Exact path prefixes that are never source in this repository.
readonly FORBIDDEN_PREFIXES=(
  "video/tools/"
  "video/venv/"
  "video/check/"
  "video/tools"
)

status=0
offenders=()

while read -r -d '' path; do
  [ -z "$path" ] && continue

  first_component="${path%%/*}"
  blocked=""

  case "$first_component" in
    venv|.venv|node_modules|target|__pycache__) blocked="build artifact directory" ;;
  esac

  if [ -z "$blocked" ]; then
    case "$path" in
      video/tools|video/tools/*|video/venv/*|video/check/*)
        blocked="build artifact directory"
        ;;
    esac
  fi

  if [ -n "$blocked" ]; then
    offenders+=("$path ($blocked)")
    continue
  fi

  sha="$(git ls-files -s -- "$path" | awk '{print $2}')"
  size=0
  [ -n "$sha" ] && size="$(git cat-file -s "$sha" 2>/dev/null || echo 0)"
  if [ "${size:-0}" -ge "$MAX_BYTES" ]; then
    offenders+=("$path ($(( size / 1024 / 1024 )) MB)")
  fi
done < <(git diff --cached --name-only -z --diff-filter=ACMR)

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "pre-commit guard: refusing the commit." >&2
  echo "" >&2
  echo "The following staged paths are build artifacts or are too large:" >&2
  for offender in "${offenders[@]}"; do
    echo "  - $offender" >&2
  done
  echo "" >&2
  echo "Limit is ${MAX_MB} MB per file, and directories listed in" >&2
  echo "FORBIDDEN_PREFIXES are never source. Unstage them with:" >&2
  echo "  git reset HEAD -- <path>" >&2
  echo "" >&2
  echo "If a large file is genuinely intended, it belongs in a release" >&2
  echo "artifact or Git LFS, not in this repository's history." >&2
  status=1
fi

exit "$status"
