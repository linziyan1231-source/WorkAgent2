#!/usr/bin/env bash
set -euo pipefail

umask 0077
export LC_ALL=C

fail() {
  echo "release tree mode: $*" >&2
  exit 1
}

if (( $# < 5 )); then
  echo "usage: scripts/freeze-release-tree-modes.sh <freeze|verify> PROFILE ABSOLUTE_TREE_ROOT ABSOLUTE_MANIFEST RELATIVE_EXECUTABLE [...]" >&2
  exit 2
fi

operation=$1
profile=$2
tree_root=$3
manifest_path=$4
shift 4
executable_paths=("$@")

case "$operation" in
  freeze|verify) ;;
  *) fail "operation must be freeze or verify" ;;
esac

case "$profile" in
  public)
    directory_mode=0555
    regular_mode=0444
    executable_mode=0555
    ;;
  root-only)
    directory_mode=0500
    regular_mode=0400
    executable_mode=0500
    ;;
  *) fail "unsupported profile: $profile" ;;
esac

for command in chmod cmp dirname find mktemp mv realpath rm sort stat; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

if [[ $tree_root != /* || $tree_root == / || ! -d $tree_root || -L $tree_root ]]; then
  fail "tree root must be an absolute non-root real directory"
fi
if [[ $(realpath -e -- "$tree_root") != "$tree_root" ]]; then
  fail "tree root must be canonical and symlink-free"
fi
tree_root_mode=$(stat -c '%a' -- "$tree_root")
if (( (8#$tree_root_mode & 8#7000) != 0 )); then
  fail "tree root has setuid, setgid, or sticky mode bits"
fi
if [[ $manifest_path != /* || $(realpath -m -- "$manifest_path") != "$manifest_path" ]]; then
  fail "mode manifest path must be absolute and canonical"
fi
case "$manifest_path/" in
  "$tree_root/"*) fail "mode manifest must remain outside the frozen tree" ;;
esac
manifest_parent=$(dirname -- "$manifest_path")
if [[ ! -d $manifest_parent || -L $manifest_parent || $(realpath -e -- "$manifest_parent") != "$manifest_parent" ]]; then
  fail "mode manifest parent must be a canonical real directory"
fi
manifest_parent_mode=$(stat -c '%a' -- "$manifest_parent")
if (( (8#$manifest_parent_mode & 8#022) != 0 )); then
  fail "mode manifest parent is writable by group or other users"
fi
if [[ $operation == freeze ]]; then
  if [[ -e $manifest_path || -L $manifest_path ]]; then
    fail "mode manifest destination already exists"
  fi
else
  if [[ ! -f $manifest_path || -L $manifest_path ||
        $(realpath -e -- "$manifest_path") != "$manifest_path" ]]; then
    fail "mode manifest is missing or unsafe"
  fi
  manifest_mode=$(stat -c '%a' -- "$manifest_path")
  if (( (8#$manifest_mode & 8#7000) != 0 || 8#$manifest_mode != 8#0400 )); then
    fail "mode manifest has a non-canonical mode"
  fi
fi

validate_relative_path() {
  local relative=$1
  if [[ -z $relative || $relative == . || $relative == /* ||
        $relative == *$'\n'* || $relative == *$'\r'* || $relative == *$'\t'* ||
        $(realpath -m -- "$tree_root/$relative") != "$tree_root/$relative" ]]; then
    fail "non-canonical relative path"
  fi
}

if (( ${#executable_paths[@]} == 0 || ${#executable_paths[@]} > 1024 )); then
  fail "executable allowlist must contain 1..1024 paths"
fi
declare -A allowed_executables=()
for relative in "${executable_paths[@]}"; do
  validate_relative_path "$relative"
  if [[ -n ${allowed_executables[$relative]+present} ]]; then
    fail "duplicate executable allowlist path: $relative"
  fi
  allowed_executables[$relative]=true
done

if IFS= read -r -d '' _unsafe_entry < <(
  find "$tree_root" -mindepth 1 ! -type d ! -type f -print0 -quit
); then
  fail "tree contains a symlink or special entry"
fi

declare -A observed_executables=()
while IFS= read -r -d '' path; do
  relative=${path#"$tree_root"/}
  validate_relative_path "$relative"
  mode=$(stat -c '%a' -- "$path")
  if (( (8#$mode & 8#7000) != 0 )); then
    fail "tree entry has setuid, setgid, or sticky mode bits: $relative"
  fi
  if [[ -f $path ]]; then
    link_count=$(stat -c '%h' -- "$path")
    (( link_count == 1 )) || fail "tree contains a multiply-linked file: $relative"
    if (( (8#$mode & 8#111) != 0 )); then
      if [[ -z ${allowed_executables[$relative]+present} ]]; then
        fail "tree contains an executable outside the allowlist: $relative"
      fi
      observed_executables[$relative]=true
    fi
  fi
done < <(find "$tree_root" -mindepth 1 -print0)

for relative in "${executable_paths[@]}"; do
  path=$tree_root/$relative
  if [[ ! -f $path || -L $path || -z ${observed_executables[$relative]+present} ]]; then
    fail "allowlisted executable is missing, unsafe, or not executable: $relative"
  fi
done

# Freeze validates the complete input before its first mutation. Verify is
# deliberately non-mutating, so it can be repeated after scanners and just
# before evidence publication.
if [[ $operation == freeze ]]; then
  find "$tree_root" -type f -exec chmod "$regular_mode" -- {} +
  for relative in "${executable_paths[@]}"; do
    chmod "$executable_mode" -- "$tree_root/$relative"
  done
  find "$tree_root" -depth -type d -exec chmod "$directory_mode" -- {} +
fi

temporary_manifest=$(mktemp "$manifest_parent/.workagent-tree-modes.XXXXXX")
cleanup() {
  if [[ -n ${temporary_manifest:-} && -e $temporary_manifest ]]; then
    rm -f -- "$temporary_manifest"
  fi
}
trap cleanup EXIT INT TERM
records=$(mktemp "$manifest_parent/.workagent-tree-mode-records.XXXXXX")
cleanup_records() {
  if [[ -n ${records:-} && -e $records ]]; then
    rm -f -- "$records"
  fi
  cleanup
}
trap cleanup_records EXIT INT TERM

printf 'd\t%s\t.\n' "$directory_mode" > "$records"
root_mode=$(stat -c '%a' -- "$tree_root")
if (( (8#$root_mode & 8#7000) != 0 )); then
  fail "frozen tree root has a prohibited special mode"
fi
if (( 8#$root_mode != 8#$directory_mode )); then
  fail "frozen mode mismatch for ."
fi
if IFS= read -r -d '' _unsafe_entry < <(
  find "$tree_root" -mindepth 1 ! -type d ! -type f -print0 -quit
); then
  fail "frozen tree contains a symlink or special entry"
fi
while IFS= read -r -d '' path; do
  relative=${path#"$tree_root"/}
  validate_relative_path "$relative"
  actual_mode=$(stat -c '%a' -- "$path")
  if [[ -d $path ]]; then
    expected_mode=$directory_mode
    entry_type=d
  else
    link_count=$(stat -c '%h' -- "$path")
    (( link_count == 1 )) || fail "frozen tree contains a multiply-linked file: $relative"
    if [[ -n ${allowed_executables[$relative]+present} ]]; then
      expected_mode=$executable_mode
    else
      expected_mode=$regular_mode
    fi
    entry_type=f
  fi
  if (( 8#$actual_mode != 8#$expected_mode )); then
    fail "frozen mode mismatch for $relative"
  fi
  printf '%s\t%s\t%s\n' "$entry_type" "$expected_mode" "$relative" >> "$records"
done < <(find "$tree_root" -mindepth 1 -print0)

{
  printf '# workagent-release-tree-modes-v1 profile=%s\n' "$profile"
  sort -- "$records"
} > "$temporary_manifest"
if [[ $operation == freeze ]]; then
  chmod 0400 -- "$temporary_manifest"
  mv -T --no-clobber -- "$temporary_manifest" "$manifest_path"
  if [[ -e $temporary_manifest || ! -f $manifest_path || -L $manifest_path ]]; then
    fail "mode manifest could not be published without replacement"
  fi
  temporary_manifest=
else
  if ! cmp -s -- "$manifest_path" "$temporary_manifest"; then
    fail "mode manifest does not exactly match the current tree"
  fi
  rm -f -- "$temporary_manifest"
  temporary_manifest=
fi
rm -f -- "$records"
records=
trap - EXIT INT TERM

echo "release tree mode $operation: PASS ($profile)"
