#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_component_root="$repo_root/components/runtime"
aionui_dir="${AIONUI_ARTIFACT_DIR:-$repo_root/.tools/artifacts/aionui-2.1.0-beta.editfork.21-linux-x64}"
aioncore_dir="${AIONCORE_ARTIFACT_DIR:-$repo_root/.tools/artifacts/aioncore-v0.1.42-editfork.10-linux-x64}"
codex_dir="${CODEX_ARTIFACT_DIR:-$repo_root/.tools/artifacts/codex-0.144.4-linux-x64}"
kimi_dir="${KIMI_CODE_ARTIFACT_DIR:-$repo_root/.tools/artifacts/kimi-code-0.29.1-fork-steer.1-linux-x64}"
python_dir="${PYTHON_ARTIFACT_DIR:-$repo_root/.tools/artifacts/python-3.13.13-linux-x64}"
output_dir="${RUNTIME_OUTPUT_DIR:-$repo_root/.tools/artifacts/workagent-runtime-linux-x64}"

fail() {
  printf 'assemble-runtime-linux: %s\n' "$*" >&2
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
  [[ $(canonical_tree_hash "$root" .) == "$expected_tree" ]] || fail "$name canonical artifact tree checksum mismatch"
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

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" "${@:2}" | sha256sum | cut -d' ' -f1
}

verify_artifact_root() {
  local name="$1"
  local root="$2"
  [[ "$root" == /* && -d "$root" && ! -L "$root" ]] || fail "$name artifact must be an absolute real directory"
  [[ "$(realpath -m -- "$root")" == "$root" ]] || fail "$name artifact path must be canonical"
  verify_protected_input_tree "$name artifact" "$root"
}

merge_tree() {
  local name="$1"
  local source="$2"
  local relative
  while IFS= read -r -d '' relative; do
    relative="${relative#./}"
    [[ ! -e "$stage/$relative" && ! -L "$stage/$relative" ]] || fail "$name collides with existing runtime file: $relative"
  done < <(cd "$source" && find . -type f -print0 | LC_ALL=C sort -z)
  (cd "$source" && tar -cf - .) | (cd "$stage" && tar -xf - --no-same-owner --no-same-permissions)
  find "$stage" -type d -exec chmod 0755 {} +
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
for command in awk chmod cmp cut dirname find flock grep install mkdir mktemp mv readelf realpath rm sed sha256sum sort stat tar wc xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"
output_parent="$(dirname -- "$output_dir")"
verify_protected_input_path "runtime output parent" "$output_parent" directory

verify_artifact_root AionUi "$aionui_dir"
verify_artifact_root AionCore "$aioncore_dir"
verify_artifact_root Codex "$codex_dir"
verify_artifact_root Kimi-Code "$kimi_dir"
verify_artifact_root Python "$python_dir"

for repo_input in \
  "$repo_root/scripts/assemble-runtime-linux.sh" \
  "$repo_root/components/aioncore/BINARY.sha256" \
  "$repo_root/components/kimi-code/VERSION" \
  "$repo_root/components/kimi-code/SOURCE" \
  "$repo_root/components/kimi-code/SOURCE.sha256" \
  "$repo_root/components/kimi-code/NODE.sha256" \
  "$repo_root/components/kimi-code/PATCH.sha256" \
  "$repo_root/components/kimi-code/RESP-PATCH.sha256" \
  "$repo_root/components/kimi-code/LICENSE.sha256" \
  "$repo_root/components/kimi-code/kimi-code-0.29.1-acp-session-fork-steer.patch" \
  "$repo_root/components/kimi-code/kimi-code-0.29.1-minidb-resp-recovery.patch" \
  "$runtime_component_root/components.json" \
  "$repo_root/scripts/smoke-runtime-linux.sh"; do
  verify_protected_input_file "repository assembly input" "$repo_input"
done

verify_complete_artifact_manifest AionUi "$aionui_dir" share/workagent-components/aionui/SHA256SUMS \
  "$repo_root/components/aionui/LINUX-ARTIFACT-MANIFEST.sha256" dot \
  "$repo_root/components/aionui/LINUX-ARTIFACT-TREE.sha256"
verify_complete_artifact_manifest AionCore "$aioncore_dir" share/workagent-components/aioncore/SHA256SUMS \
  "$repo_root/components/aioncore/LINUX-ARTIFACT-MANIFEST.sha256" dot \
  "$repo_root/components/aioncore/LINUX-ARTIFACT-TREE.sha256"
verify_complete_artifact_manifest Codex "$codex_dir" share/workagent-components/codex/SHA256SUMS \
  "$repo_root/components/codex/LINUX-ARTIFACT-MANIFEST.sha256" dot \
  "$repo_root/components/codex/LINUX-ARTIFACT-TREE.sha256"
verify_complete_artifact_manifest Kimi-Code "$kimi_dir" SHA256SUMS \
  "$repo_root/components/kimi-code/LINUX-ARTIFACT-MANIFEST.sha256" plain \
  "$repo_root/components/kimi-code/LINUX-ARTIFACT-TREE.sha256"
verify_complete_artifact_manifest Python "$python_dir" share/workagent-components/python/SHA256SUMS \
  "$repo_root/components/python/LINUX-ARTIFACT-MANIFEST.sha256" dot \
  "$repo_root/components/python/LINUX-ARTIFACT-TREE.sha256"
(cd "$aionui_dir/share/workagent-components/aionui" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'AionUi license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'AionCore license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore/managed-licenses/node" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'managed Node license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore/managed-licenses/codex-acp" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'managed Codex ACP license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore/managed-licenses/openai-codex" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'managed OpenAI Codex license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore/managed-licenses/claude-agent-acp" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'managed Claude ACP license checksum failed'
(cd "$aioncore_dir/share/workagent-components/aioncore/managed-licenses/claude-agent-sdk" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'managed Claude SDK license checksum failed'
(cd "$codex_dir/share/workagent-components/codex" && sha256sum --strict --check LICENSE.sha256) >/dev/null || fail 'Codex license checksum failed'
[[ "$(hash_of "$kimi_dir/LICENSE")" == "$(cut -d' ' -f1 < "$repo_root/components/kimi-code/LICENSE.sha256")" ]] || fail 'Kimi Code license checksum failed'

[[ "$(hash_of "$aionui_dir/bin/aionui-web")" == 9edd87cdadb47d9d8398d8a708e636b8c595800bf0e495cb0a65e110c6e4e387 ]] || fail 'AionUi binary checksum mismatch'
[[ "$(find "$aionui_dir/static" -type f | wc -l)" == 548 ]] || fail 'AionUi static file count mismatch'
[[ "$(find "$aionui_dir/workagent-builtin-assistants" -type f | wc -l)" == 83 ]] || fail 'WorkAgent assistant file count mismatch'
[[ "$(cut -d' ' -f1 < "$aionui_dir/share/workagent-components/noble-hashes/SOURCE.sha256")" == b74fceb0006b617ed388254677b3d3847aeceb7e3f57db0cc9acc54644dabba6 ]] || fail '@noble/hashes evidence mismatch'

expected_aioncore="$(cut -d' ' -f1 < "$repo_root/components/aioncore/BINARY.sha256")"
[[ "$(hash_of "$aioncore_dir/bin/aioncore")" == "$expected_aioncore" ]] || fail 'AionCore binary checksum mismatch'
[[ "$(canonical_tree_hash "$aioncore_dir/bin/managed-resources" .)" == 4131c117b99b83d1c36980417ba4f9f1d860500e711ad54fea9ae007d7c9d567 ]] || fail 'AionCore managed-resource checksum mismatch'
(cd "$aioncore_dir/bin/managed-resources" && sha256sum --strict --check "$aioncore_dir/share/workagent-components/aioncore/MANAGED-CONTENTS.sha256") >/dev/null || fail 'AionCore managed-resource content checks failed'
managed_node="$aioncore_dir/bin/managed-resources/node/node-v24.11.0-linux-x64/bin/node"
managed_codex="$aioncore_dir/bin/managed-resources/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64"
managed_codex_entrypoint="$managed_codex/node_modules/@agentclientprotocol/codex-acp/dist/index.js"
[[ "$(hash_of "$managed_codex_entrypoint")" == 53db7dc43339e67ecfff817c35c822c35637695a119e77199b92e4d8ad08bdf9 ]] || fail 'managed Codex ACP patch checksum mismatch'
[[ "$("$managed_node" -p "require('$managed_codex/node_modules/@agentclientprotocol/codex-acp/package.json').version")" == 1.1.2 ]] || fail 'managed Codex ACP version mismatch'
[[ "$("$managed_node" -p "require('$managed_codex/node_modules/@openai/codex/package.json').version")" == 0.144.4 ]] || fail 'managed OpenAI Codex version mismatch'
(cd "$managed_codex" && sha256sum --strict --check "$aioncore_dir/share/workagent-components/aioncore/CODEX-ACP-LICENSES.sha256") >/dev/null || fail 'managed Codex license evidence mismatch'
"$managed_node" "$aioncore_dir/share/workagent-components/aioncore/tests/codex-acp-wire-smoke.mjs" "$managed_node" "$managed_codex"
grep -F '"workspace_test_suite": "passed"' "$aioncore_dir/share/workagent-components/aioncore/BUILD-INFO.json" >/dev/null || fail 'AionCore artifact lacks full-test evidence'
grep -F '"managed_codex_acp_protocol_gate": "passed"' "$aioncore_dir/share/workagent-components/aioncore/BUILD-INFO.json" >/dev/null || fail 'AionCore artifact lacks managed Codex protocol evidence'

[[ "$(hash_of "$codex_dir/libexec/codex/bin/codex")" == 2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a ]] || fail 'Codex native binary checksum mismatch'
[[ "$(hash_of "$kimi_dir/bin/kimi")" == 430c9f9b8ac74d1bee5186f151b6c45c85b414604c92f9b76b96220f741f6da0 ]] || fail 'Kimi Code binary checksum mismatch'
[[ "$(canonical_tree_hash "$python_dir" bin libexec)" == 3a3bc7c278954dca6c2a76e18df2428174de6730dd40f4db7da4873e6152885d ]] || fail 'Python runtime checksum mismatch'
grep -F '"regression_suite": "passed-45233-tests"' "$python_dir/share/workagent-components/python/BUILD-INFO.json" >/dev/null || fail 'Python artifact lacks full-test evidence'

work_parent="$repo_root/.tools/build"
mkdir -p -- "$work_parent"
verify_protected_input_path "runtime work parent" "$work_parent" directory
work_dir="$(mktemp -d "$work_parent/runtime.XXXXXX")"
cleanup() {
  case "$work_dir" in
    "$repo_root"/.tools/build/runtime.*) rm -rf -- "$work_dir" ;;
    *) printf 'assemble-runtime-linux: refusing unsafe cleanup path: %s\n' "$work_dir" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM
verify_protected_input_path "runtime work directory" "$work_dir" directory
[[ $(stat -c '%d' -- "$work_dir") == $(stat -c '%d' -- "$output_parent") ]] || fail 'runtime work directory and output parent must be on the same filesystem'
stage="$work_dir/artifact"
mkdir -m 0755 -- "$stage"

merge_tree AionUi "$aionui_dir"
merge_tree AionCore "$aioncore_dir"
merge_tree Codex "$codex_dir"
merge_tree Python "$python_dir"

install -d -m 0755 "$stage/share/workagent-components/kimi-code" "$stage/share/workagent-components/runtime"
install -m 0555 "$kimi_dir/bin/kimi" "$stage/bin/kimi"
install -m 0444 "$repo_root/components/kimi-code/VERSION" "$repo_root/components/kimi-code/SOURCE" \
  "$repo_root/components/kimi-code/SOURCE.sha256" "$repo_root/components/kimi-code/NODE.sha256" \
  "$repo_root/components/kimi-code/PATCH.sha256" "$repo_root/components/kimi-code/RESP-PATCH.sha256" \
  "$repo_root/components/kimi-code/LICENSE.sha256" \
  "$repo_root/components/kimi-code/kimi-code-0.29.1-acp-session-fork-steer.patch" \
  "$repo_root/components/kimi-code/kimi-code-0.29.1-minidb-resp-recovery.patch" \
  "$stage/share/workagent-components/kimi-code/"
install -m 0444 "$kimi_dir/LICENSE" "$stage/share/workagent-components/kimi-code/LICENSE"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "kimi-code",' \
  '  "version": "0.29.1-fork-steer.1",' \
  '  "upstream_version": "0.29.1",' \
  '  "binary_sha256": "430c9f9b8ac74d1bee5186f151b6c45c85b414604c92f9b76b96220f741f6da0"' \
  '}' > "$stage/share/workagent-components/kimi-code/BUILD-INFO.json"
(cd "$stage" && sha256sum bin/kimi \
  share/workagent-components/kimi-code/VERSION \
  share/workagent-components/kimi-code/SOURCE \
  share/workagent-components/kimi-code/SOURCE.sha256 \
  share/workagent-components/kimi-code/NODE.sha256 \
  share/workagent-components/kimi-code/PATCH.sha256 \
  share/workagent-components/kimi-code/RESP-PATCH.sha256 \
  share/workagent-components/kimi-code/LICENSE \
  share/workagent-components/kimi-code/LICENSE.sha256 \
  share/workagent-components/kimi-code/kimi-code-0.29.1-acp-session-fork-steer.patch \
  share/workagent-components/kimi-code/kimi-code-0.29.1-minidb-resp-recovery.patch \
  share/workagent-components/kimi-code/BUILD-INFO.json > share/workagent-components/kimi-code/SHA256SUMS)

for component in aioncore aionui codex kimi-code noble-hashes; do
  [[ -f "$stage/share/workagent-components/$component/LICENSE" ]] || fail "$component license file is missing"
done
[[ -f "$stage/libexec/python/3.13.13/lib/python3.13/LICENSE.txt" ]] || fail 'Python license file is missing'
for managed_license in \
  "$stage/bin/managed-resources/node/node-v24.11.0-linux-x64/LICENSE" \
  "$stage/bin/managed-resources/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64/LICENSE" \
  "$stage/bin/managed-resources/acp/codex-acp/0.16.0-aion-fork-steer.6/linux-x64/LICENSE.openai-codex" \
  "$stage/bin/managed-resources/acp/claude-agent-acp/0.39.0/linux-x64/node_modules/@agentclientprotocol/claude-agent-acp/LICENSE" \
  "$stage/bin/managed-resources/acp/claude-agent-acp/0.39.0/linux-x64/node_modules/@anthropic-ai/claude-agent-sdk/LICENSE.md"; do
  [[ -f "$managed_license" ]] || fail "managed component license file is missing: $managed_license"
done
[[ -f "$stage/share/workagent-components/aioncore/MANAGED-COMPONENTS.json" ]] || fail 'managed component inventory is missing'

install -m 0444 "$runtime_component_root/components.json" "$stage/components.runtime.json"
install -m 0555 "$repo_root/scripts/smoke-runtime-linux.sh" \
  "$stage/share/workagent-components/runtime/smoke-runtime-linux.sh"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "scope": "runtime",' \
  '  "target": "linux-amd64",' \
  '  "component_count": 6,' \
  '  "signed_release_required": true' \
  '}' > "$stage/share/workagent-components/runtime/BUILD-INFO.json"

[[ "$("$stage/bin/aionui-web" version)" == 2.1.0-beta.editfork.21 ]] || fail 'assembled AionUi version probe failed'
[[ "$("$stage/bin/aioncore" --version)" == 'aioncore 0.1.42-editfork.10' ]] || fail 'assembled AionCore version probe failed'
[[ "$("$stage/bin/codex" --version)" == 'codex-cli 0.144.4' ]] || fail 'assembled Codex version probe failed'
kimi_home="$work_dir/kimi-home"
mkdir -m 0700 -- "$kimi_home"
[[ "$(env HOME="$kimi_home" KIMI_CODE_HOME="$kimi_home/.kimi-code" NO_COLOR=1 "$stage/bin/kimi" --version)" == 0.29.1 ]] || fail 'assembled Kimi version probe failed'
[[ "$("$stage/bin/python3" --version)" == 'Python 3.13.13' ]] || fail 'assembled Python version probe failed'

executable_list="$work_dir/executables"
find "$stage" -type f -perm /111 -printf '%P\0' | LC_ALL=C sort -z > "$executable_list"
find "$stage" -type f -exec chmod 0444 {} +
(cd "$stage" && xargs -0 -r chmod 0555 -- < "$executable_list")

(cd "$stage" && find . -type f ! -path './share/workagent-components/runtime/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/runtime/SHA256SUMS)
chmod 0444 "$stage/share/workagent-components/runtime/SHA256SUMS"
find "$stage" -type d -exec chmod 0555 {} +
[[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'assembled runtime contains a symbolic link'
[[ -z "$(find "$stage" ! -type d ! -type f -print -quit)" ]] || fail 'assembled runtime contains a special file'
[[ -z "$(find "$stage" -perm /022 -print -quit)" ]] || fail 'assembled runtime contains a group/other-writable entry'
file_count="$(find "$stage" -type f | wc -l)"
[[ "$file_count" -le 9997 ]] || fail "assembled runtime leaves no room for the three required signed-release metadata files: $file_count files"
verify_complete_artifact_manifest Runtime-Payload "$stage" share/workagent-components/runtime/SHA256SUMS \
  "$runtime_component_root/LINUX-PAYLOAD-MANIFEST.sha256" dot \
  "$runtime_component_root/LINUX-PAYLOAD-TREE.sha256"

publication_status=0
mv -T --no-clobber -- "$stage" "$output_dir" || publication_status=$?
[[ ! -e $stage && ! -L $stage ]] || fail 'runtime output publication did not consume the staging directory'
(( publication_status == 0 )) || fail 'runtime output could not be published with an atomic no-clobber rename'
[[ -d $output_dir && ! -L $output_dir ]] || fail 'runtime output publication did not create a real directory'
printf 'WorkAgent Linux runtime payload: %s\n' "$output_dir"
printf 'Files covered before signed metadata: %s\n' "$file_count"
