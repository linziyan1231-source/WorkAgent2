#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

fail() {
  printf 'assemble-shared-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

verify_protected_input_path() {
  local name=$1 path=$2 expected_type=$3 current=/ component metadata uid gid mode
  local -a components
  [[ $path == /* && $(realpath -m -- "$path") == "$path" ]] || fail "$name trusted input path must be absolute and canonical"
  IFS=/ read -r -a components <<< "${path#/}"

  for component in / "${components[@]}"; do
    if [[ $component != / ]]; then
      current="${current%/}/$component"
    fi
    [[ ! -L $current ]] || fail "$name trusted input path contains a symbolic link: $current"
    if ! metadata=$(stat -c '%u %g %a' -- "$current"); then
      fail "$name trusted input path is unavailable: $current"
    fi
    read -r uid gid mode <<< "$metadata"
    [[ $uid == 0 && $gid == 0 ]] || fail "$name trusted input path is not owned by UID/GID 0: $current"
    (( (8#$mode & 8#022) == 0 )) || fail "$name trusted input path is group/other-writable: $current"
    if [[ $current != "$path" ]]; then
      [[ -d $current ]] || fail "$name trusted input ancestor is not a directory: $current"
    fi
  done

  case "$expected_type" in
    directory) [[ -d $path ]] || fail "$name trusted input is not a directory" ;;
    file) [[ -f $path ]] || fail "$name trusted input is not a regular file" ;;
    *) fail "$name trusted input type contract is invalid" ;;
  esac
}

verify_protected_input_file() {
  verify_protected_input_path "$1" "$2" file
}

verify_protected_input_tree() {
  local name=$1 root=$2 unsafe
  verify_protected_input_path "$name" "$root" directory
  unsafe=$(find "$root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) || fail "$name trusted input tree could not be inspected"
  [[ -z $unsafe ]] || fail "$name trusted input tree contains a link or special entry: $unsafe"
  unsafe=$(find "$root" \( ! -uid 0 -o ! -gid 0 \) -print -quit) || fail "$name trusted input ownership could not be inspected"
  [[ -z $unsafe ]] || fail "$name trusted input tree contains an entry not owned by UID/GID 0: $unsafe"
  unsafe=$(find "$root" -perm /022 -print -quit) || fail "$name trusted input modes could not be inspected"
  [[ -z $unsafe ]] || fail "$name trusted input tree contains a group/other-writable entry: $unsafe"
}

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" . | sha256sum | cut -d' ' -f1
}

verify_complete_artifact_manifest() {
  local name=$1 root=$2 manifest=$3 external_pin=$4 dialect=$5 external_tree_pin=$6 expected expected_tree manifest_files actual_files
  [[ -f $external_pin && ! -L $external_pin ]] || fail "$name external artifact-manifest pin is missing or unsafe"
  verify_protected_input_file "$name external artifact-manifest pin" "$external_pin"
  if ! expected=$(awk -v required_path="$manifest" '
    NR == 1 && NF == 2 && $1 ~ /^[0-9a-f]{64}$/ && $2 == required_path { digest = $1 }
    END { if (NR != 1 || digest == "") exit 1; print digest }
  ' "$external_pin"); then
    fail "$name external artifact-manifest pin is malformed"
  fi
  [[ -f $root/$manifest && ! -L $root/$manifest ]] || fail "$name artifact manifest is missing or unsafe"
  [[ $(hash_of "$root/$manifest") == "$expected" ]] || fail "$name artifact manifest checksum mismatch"
  [[ -f $external_tree_pin && ! -L $external_tree_pin ]] || fail "$name external artifact-tree pin is missing or unsafe"
  verify_protected_input_file "$name external artifact-tree pin" "$external_tree_pin"
  if ! expected_tree=$(awk '
    NR == 1 && NF == 2 && $1 ~ /^[0-9a-f]{64}$/ && $2 == "canonical-tree" { digest = $1 }
    END { if (NR != 1 || digest == "") exit 1; print digest }
  ' "$external_tree_pin"); then
    fail "$name external artifact-tree pin is malformed"
  fi
  [[ $(canonical_tree_hash "$root") == "$expected_tree" ]] || fail "$name canonical artifact tree checksum mismatch"
  if ! manifest_files=$(awk -v required_dialect="$dialect" -v manifest_path="$manifest" '
    function valid_path(value, count, parts, item) {
      if (value == "" || value ~ /^\// || value ~ /[\\\r]/ || value ~ /[[:cntrl:]]/) return 0
      count = split(value, parts, "/")
      for (item = 1; item <= count; item++) {
        if (parts[item] == "" || parts[item] == "." || parts[item] == "..") return 0
      }
      return 1
    }
    {
      if (length($0) < 67 || substr($0, 1, 64) !~ /^[0-9a-f]{64}$/ ||
          (substr($0, 65, 2) != "  " && substr($0, 65, 2) != " *")) exit 1
      raw = substr($0, 67)
      if (required_dialect == "dot") {
        if (substr(raw, 1, 2) != "./") exit 1
        normalized = substr(raw, 3)
      } else if (required_dialect == "plain") {
        if (substr(raw, 1, 2) == "./") exit 1
        normalized = raw
      } else exit 1
      if (!valid_path(normalized) || normalized == manifest_path || seen[normalized]++) exit 1
      print normalized
    }
    END { if (NR == 0) exit 1 }
  ' "$root/$manifest" | sort); then
    fail "$name artifact manifest paths are malformed, duplicated, or noncanonical"
  fi
  if ! actual_files=$(cd "$root" && find . -type f ! -path "./$manifest" -printf '%P\n' | sort); then
    fail "$name artifact file inventory could not be read"
  fi
  [[ $manifest_files == "$actual_files" ]] || fail "$name artifact manifest does not cover its exact file set"
  (cd "$root" && sha256sum --strict --check "$manifest") >/dev/null || fail "$name component checksums failed"
}

if (( $# != 3 )); then
  echo "usage: scripts/assemble-shared-linux.sh ABSOLUTE_CLIPROXY_ARTIFACT_DIRECTORY ABSOLUTE_CHATFORWARD_ARCHIVE ABSOLUTE_NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
cliproxy_root=$1
chatforward_archive=$2
output_directory=$3

for path in "$cliproxy_root" "$chatforward_archive" "$output_directory"; do
  case "$path" in
    /*) ;;
    *) echo "all shared assembly paths must be absolute" >&2; exit 2 ;;
  esac
done
if [[ ! -d $cliproxy_root || -L $cliproxy_root || $(realpath -m -- "$cliproxy_root") != "$cliproxy_root" ]]; then
  echo "CLIProxy artifact root must be a canonical real directory" >&2
  exit 1
fi
if [[ ! -f $chatforward_archive || -L $chatforward_archive || $(realpath -m -- "$chatforward_archive") != "$chatforward_archive" ]]; then
  echo "ChatForward artifact must be a canonical regular file" >&2
  exit 1
fi
if [[ $(realpath -m -- "$output_directory") != "$output_directory" || -e $output_directory || -L $output_directory ]]; then
  echo "shared output must be a canonical path that does not exist" >&2
  exit 1
fi
for command in awk chmod cut dirname find grep install mkdir mktemp mv readelf realpath sha256sum sort stat tar wc xargs; do
  command -v -- "$command" >/dev/null || { echo "required shared assembly command is missing: $command" >&2; exit 1; }
done
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "shared release target must be Linux x86_64" >&2
  exit 1
fi
output_parent=$(dirname -- "$output_directory")
verify_protected_input_path "shared output parent" "$output_parent" directory

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cliproxy_manifest=$repo_root/components/cliproxyapi/LINUX-ARTIFACTS.sha256
chatforward_manifest=$repo_root/components/chatforward/LINUX-ARTIFACT.sha256
components_json=$repo_root/components/shared/components.json
chatforward_archive_name=workagent-chatforward-zombie-reap-20260725-2329-linux-x64.tar.gz
verify_protected_input_tree "CLIProxy artifact" "$cliproxy_root"
verify_protected_input_file "ChatForward artifact" "$chatforward_archive"
verify_protected_input_file "CLIProxy legacy manifest" "$cliproxy_manifest"
verify_protected_input_file "ChatForward legacy manifest" "$chatforward_manifest"
verify_protected_input_file "shared components inventory" "$components_json"
verify_protected_input_file "shared assembler" "$repo_root/scripts/assemble-shared-linux.sh"
if [[ ${chatforward_archive##*/} != "$chatforward_archive_name" ]]; then
  fail "ChatForward artifact basename must be $chatforward_archive_name"
fi
if ! expected_chatforward_hash=$(awk -v required_name="$chatforward_archive_name" '
  NR == 1 && NF == 2 && $1 ~ /^[0-9a-f]{64}$/ && $2 == required_name { digest = $1 }
  END { if (NR != 1 || digest == "") exit 1; print digest }
' "$chatforward_manifest"); then
  fail "ChatForward legacy manifest is malformed"
fi
[[ $(hash_of "$chatforward_archive") == "$expected_chatforward_hash" ]] || fail "ChatForward artifact checksum mismatch"
(cd "$cliproxy_root" && sha256sum --strict --check "$cliproxy_manifest") >/dev/null
(cd "$(dirname -- "$chatforward_archive")" && sha256sum --strict --check "$chatforward_manifest") >/dev/null
verify_complete_artifact_manifest CLIProxy "$cliproxy_root" share/workagent-components/cliproxyapi/SHA256SUMS \
  "$repo_root/components/cliproxyapi/LINUX-ARTIFACT-MANIFEST.sha256" dot \
  "$repo_root/components/cliproxyapi/LINUX-ARTIFACT-TREE.sha256"
if ! readelf -h "$cliproxy_root/bin/cli-proxy-api" | grep -Fq 'Machine:                           Advanced Micro Devices X86-64'; then
  echo "CLIProxy artifact is not Linux x86-64 ELF" >&2
  exit 1
fi
if ! readelf -h "$cliproxy_root/plugins/cpa-key-policy-v0.4.5.so" | grep -Fq 'Type:                              DYN'; then
  echo "CLIProxy policy plugin is not a shared object" >&2
  exit 1
fi

work_parent=$repo_root/.tools/build
mkdir -p "$work_parent"
verify_protected_input_path "shared work parent" "$work_parent" directory
work_directory=$(mktemp -d "$work_parent/shared.XXXXXX")
cleanup() {
  case "$work_directory" in
    "$repo_root"/.tools/build/shared.*) rm -rf -- "$work_directory" ;;
    *) echo "refusing unsafe shared assembly cleanup" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM
verify_protected_input_path "shared work directory" "$work_directory" directory
[[ $(stat -c '%d' -- "$work_directory") == $(stat -c '%d' -- "$output_parent") ]] || fail 'shared work directory and output parent must be on the same filesystem'
chat_extract=$work_directory/chatforward-extract
stage=$work_directory/stage
mkdir -p "$chat_extract" "$stage/cliproxyapi" "$stage/chatforward" "$stage/share/workagent-components/shared"

release_name=workagent-chatforward-zombie-reap-20260725-2329
if tar -tzf "$chatforward_archive" | grep -Ev "^$release_name(/|$)" >/dev/null; then
  echo "ChatForward archive contains an unexpected top-level path" >&2
  exit 1
fi
tar --extract --gzip --file "$chatforward_archive" --directory "$chat_extract" --no-same-owner --no-same-permissions
chatforward_root=$chat_extract/$release_name
if [[ ! -d $chatforward_root || -L $chatforward_root || -n $(find "$chatforward_root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) ]]; then
  echo "ChatForward archive expanded to an unsafe tree" >&2
  exit 1
fi

(cd "$cliproxy_root" && tar -cf - .) | (cd "$stage/cliproxyapi" && tar -xf - --no-same-owner --no-same-permissions)
(cd "$chatforward_root" && tar -cf - .) | (cd "$stage/chatforward" && tar -xf - --no-same-owner --no-same-permissions)
install -m 0444 "$components_json" "$stage/components.shared.json"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "scope": "shared",' \
  '  "target": "linux-amd64",' \
  '  "component_count": 7,' \
  '  "signed_release_required": true' \
  '}' > "$stage/share/workagent-components/shared/BUILD-INFO.json"

cliproxy_help=$("$stage/cliproxyapi/bin/cli-proxy-api" -h 2>&1)
if [[ ${cliproxy_help%%$'\n'*} != "CLIProxyAPI Version: 7.2.81, Commit: per-key-models.4, BuiltAt: 2026-07-16T14:32:00Z" ]]; then
  echo "assembled CLIProxy version probe failed" >&2
  exit 1
fi
if [[ $("$stage/chatforward/node/bin/node" --version) != v24.15.0 ]]; then
  echo "assembled ChatForward Node.js version probe failed" >&2
  exit 1
fi
if ! grep -Fq '"version": "0.16.0"' "$stage/chatforward/app/extension/manifest.json"; then
  echo "assembled ChatForward extension version probe failed" >&2
  exit 1
fi

executable_list=$work_directory/executables
find "$stage" -type f -perm /111 -printf '%P\0' | sort -z > "$executable_list"
find "$stage" -type f -exec chmod 0444 {} +
(cd "$stage" && xargs -0 -r chmod 0555 -- < "$executable_list")
find "$stage" -type d -exec chmod 0555 {} +
if [[ -n $(find "$stage" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) || -n $(find "$stage" -perm /022 -print -quit) ]]; then
  echo "assembled shared payload is unsafe" >&2
  exit 1
fi
file_count=$(find "$stage" -type f | wc -l)
if (( file_count > 9997 )); then
  echo "assembled shared payload leaves no room for signed-release metadata" >&2
  exit 1
fi

publication_status=0
mv -T --no-clobber -- "$stage" "$output_directory" || publication_status=$?
[[ ! -e $stage && ! -L $stage ]] || fail 'shared output publication did not consume the staging directory'
(( publication_status == 0 )) || fail 'shared output could not be published with an atomic no-clobber rename'
[[ -d $output_directory && ! -L $output_directory ]] || fail 'shared output publication did not create a real directory'
printf 'WorkAgent Linux shared payload: %s\n' "$output_directory"
printf 'Files covered before signed metadata: %s\n' "$file_count"
