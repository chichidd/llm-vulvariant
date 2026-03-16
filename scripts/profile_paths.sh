#!/usr/bin/env bash

_PROFILE_PATHS_LAUNCH_DIR="${_PROFILE_PATHS_LAUNCH_DIR:-$(pwd -P)}"

# Resolve profile directories from base path + dirname and optional explicit override.
resolve_profile_dir() {
  local base_path="$1"
  local dirname="$2"
  local override_dir="$3"

  if [[ -n "$override_dir" ]]; then
    printf '%s\n' "$(_profile_realpath "$override_dir")"
    return
  fi

  if [[ -z "$base_path" ]]; then
    printf '%s\n' "$(_profile_realpath "$dirname")"
  else
    printf '%s\n' "$(_profile_realpath "$base_path/$dirname")"
  fi
}


_profile_realpath() {
  local raw_path="$1"
  if [[ "$raw_path" != /* ]]; then
    raw_path="$_PROFILE_PATHS_LAUNCH_DIR/$raw_path"
  fi
  if command -v realpath >/dev/null 2>&1; then
    realpath -m "$raw_path"
  else
    printf '%s\n' "$raw_path"
  fi
}
