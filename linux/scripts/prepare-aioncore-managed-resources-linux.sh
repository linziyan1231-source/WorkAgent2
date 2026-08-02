#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/aioncore"
node_archive="${AIONCORE_NODE_ARCHIVE:-$repo_root/.tools/downloads/node-v24.11.0/node-v24.11.0-linux-x64.tar.gz}"
prepare_binary="${AIONCORE_PREPARE_BINARY:-}"
raw_dir="${AIONCORE_MANAGED_RAW_DIR:-}"
codex_raw_dir="${AIONCORE_CODEX_ACP_RAW_DIR:-$repo_root/.tools/materials/aioncore-managed-codex-acp-1.1.2-linux-x64-raw}"
codex_archive="${AIONCORE_CODEX_ACP_ARCHIVE:-$repo_root/.tools/downloads/codex-acp-1.1.2-windows-reference/original.tgz}"
codex_acp_license="${AIONCORE_CODEX_ACP_LICENSE:-$repo_root/.tools/downloads/aioncore-managed-licenses/codex-acp-v1.1.2-LICENSE}"
codex_cli_license="${AIONCORE_CODEX_LICENSE:-$repo_root/.tools/downloads/codex-0.144.4/LICENSE.rust-v0.144.4}"
codex_patch="$component_root/codex-acp-1.1.2-aionui-fork-steer.6.patch"
output_dir="${AIONCORE_MANAGED_OUTPUT_DIR:-$repo_root/.tools/materials/aioncore-managed-resources-0.1.42-editfork.10-linux-x64}"
accept_unpinned="${AIONCORE_MANAGED_ACCEPT_UNPINNED:-0}"
build_root="/tmp/workagent-aioncore-managed-resources-prepare-v1"
data_root="$build_root/data"
home_root="$build_root/home"
stage="$build_root/material"
executable_list="$build_root/executables"

expected_node_archive="b3c071cdf47aab867c3b2aa287257df12ec5d7c962bf922b32fd33226c4295fd"
expected_codex_raw="805ed9096853e3a9a389dcd4d8e867a8760c953b2f79b1a5a9c0e67dc7d3f6f8"
expected_codex_archive="fb5892908471f1cd63e970817e4df1b821a54ffc45759516201c26ce8b4fd24c"
expected_codex_lock="72f3794a5c60c41d3bfb80073e5cc5e192b9f333aa667c44111e8ae2f3fa4c6e"
expected_codex_modules_lock="cbf94c493984264893a3ee698e969e11c749f672c319476df2a7f59980510867"
expected_codex_base="d05351bc8c47367969a340ac92b013f6fdce538cdf89f38ec046847bd6c2ef84"
expected_codex_patch="f52e4ab6d6616df1572282ade8280465c26f842be0d6f8c86b13173e73942879"
expected_codex_patched="53db7dc43339e67ecfff817c35c822c35637695a119e77199b92e4d8ad08bdf9"
expected_codex_binary="2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a"
expected_codex_acp_license="72ea310b40e1ee2c4aa61935d22065155c50bfde288b114c9cfd3e1fa34f8049"
expected_codex_cli_license="d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc"

fail() {
  printf 'prepare-aioncore-managed-resources-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" . | sha256sum | cut -d' ' -f1
}

cleanup() {
  for path in "$data_root" "$home_root" "$stage" "$executable_list"; do
    case "$path" in
      "$build_root"/*) [[ ! -e "$path" && ! -L "$path" ]] || rm -rf -- "$path" ;;
      *) printf 'prepare-aioncore-managed-resources-linux: refusing unsafe cleanup path: %s\n' "$path" >&2 ;;
    esac
  done
}

remove_pruned_path() {
  local path="$1"
  case "$path" in
    "$stage"/*) [[ ! -e "$path" && ! -L "$path" ]] || rm -rf -- "$path" ;;
    *) fail "refusing unsafe prune path: $path" ;;
  esac
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
[[ "$accept_unpinned" == 0 || "$accept_unpinned" == 1 ]] || fail 'AIONCORE_MANAGED_ACCEPT_UNPINNED must be 0 or 1'
for command in awk chmod cmp cut dirname find flock grep install mkdir mv patch readelf readlink realpath rm sha256sum sort tar tr unlink wc xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ "$node_archive" == /* && -f "$node_archive" && ! -L "$node_archive" ]] || fail 'Node archive must be an absolute regular file'
[[ "$(hash_of "$node_archive")" == "$expected_node_archive" ]] || fail 'official Node archive checksum mismatch'
[[ "$codex_raw_dir" == /* && -d "$codex_raw_dir" && ! -L "$codex_raw_dir" ]] || fail 'Codex ACP raw material must be an absolute real directory'
[[ "$(realpath -m -- "$codex_raw_dir")" == "$codex_raw_dir" ]] || fail 'Codex ACP raw material must be canonical'
[[ -z "$(find "$codex_raw_dir" ! -type d ! -type f ! -type l -print -quit)" ]] || fail 'Codex ACP raw material contains a special file'
[[ "$(canonical_tree_hash "$codex_raw_dir")" == "$expected_codex_raw" ]] || fail 'Codex ACP raw material checksum mismatch'
[[ "$codex_archive" == /* && -f "$codex_archive" && ! -L "$codex_archive" ]] || fail 'Codex ACP archive must be an absolute regular file'
[[ "$(hash_of "$codex_archive")" == "$expected_codex_archive" ]] || fail 'Codex ACP Windows-reference archive checksum mismatch'
[[ "$codex_acp_license" == /* && -f "$codex_acp_license" && ! -L "$codex_acp_license" ]] || fail 'Codex ACP license input is missing'
[[ "$(hash_of "$codex_acp_license")" == "$expected_codex_acp_license" ]] || fail 'Codex ACP license checksum mismatch'
[[ "$codex_cli_license" == /* && -f "$codex_cli_license" && ! -L "$codex_cli_license" ]] || fail 'OpenAI Codex license input is missing'
[[ "$(hash_of "$codex_cli_license")" == "$expected_codex_cli_license" ]] || fail 'OpenAI Codex license checksum mismatch'
[[ -f "$codex_patch" && ! -L "$codex_patch" && "$(hash_of "$codex_patch")" == "$expected_codex_patch" ]] || fail 'Codex ACP steer patch checksum mismatch'
[[ "$(hash_of "$codex_raw_dir/package-lock.json")" == "$expected_codex_lock" ]] || fail 'Codex ACP package-lock checksum mismatch'
[[ "$(hash_of "$codex_raw_dir/node_modules/.package-lock.json")" == "$expected_codex_modules_lock" ]] || fail 'Codex ACP installed package-lock checksum mismatch'
[[ "$(hash_of "$codex_raw_dir/node_modules/@agentclientprotocol/codex-acp/dist/index.js")" == "$expected_codex_base" ]] || fail 'Codex ACP base entrypoint checksum mismatch'
cmp -- "$codex_acp_license" "$codex_raw_dir/node_modules/@agentclientprotocol/codex-acp/LICENSE" >/dev/null || fail 'Codex ACP installed license differs from the pinned upstream tag'
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

install -d -m 0700 -- "$build_root"
[[ ! -L "$build_root" && "$build_root" == "$(realpath -m -- "$build_root")" ]] || fail 'canonical build root is unsafe'
exec 9>"$build_root/.lock"
flock -n 9 || fail 'another managed-resource preparation is running'
for path in "$data_root" "$home_root" "$stage" "$executable_list"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "stale canonical preparation path requires operator review: $path"
done
trap cleanup EXIT INT TERM

mkdir -m 0700 -- "$home_root"
if [[ -n "$raw_dir" ]]; then
  [[ "$raw_dir" == /* && -d "$raw_dir" && ! -L "$raw_dir" ]] || fail 'raw managed-resource input must be an absolute real directory'
  [[ "$(realpath -m -- "$raw_dir")" == "$raw_dir" ]] || fail 'raw managed-resource input must be canonical'
  mkdir -m 0700 -- "$stage"
  (cd "$raw_dir" && tar -cf - .) | (cd "$stage" && tar -xf - --no-same-owner --no-same-permissions)
else
  [[ "$prepare_binary" == /* && -x "$prepare_binary" && -f "$prepare_binary" && ! -L "$prepare_binary" ]] || \
    fail 'AIONCORE_PREPARE_BINARY must name an absolute AionCore executable when no raw tree is supplied'
  [[ "$("$prepare_binary" --version)" == 'aioncore 0.1.42-editfork.10' ]] || fail 'AionCore preparation binary version mismatch'
  mkdir -m 0700 -- "$data_root" "$data_root/runtime" "$data_root/runtime/node"
  tar --extract --gzip --file "$node_archive" --directory "$data_root/runtime/node" \
    --no-same-owner --no-same-permissions
  env HOME="$home_root" XDG_CACHE_HOME="$home_root/cache" npm_config_userconfig="$home_root/blank-npmrc" \
    "$prepare_binary" --data-dir "$data_root" prepare-managed-resources --bundle-out "$stage"
fi

node_root="$stage/node/node-v24.11.0-linux-x64"
codex_tool_root="$stage/acp/codex-acp"
codex_root="$codex_tool_root/0.16.0-aion-fork-steer.6/linux-x64"
claude_root="$stage/acp/claude-agent-acp/0.39.0/linux-x64"
[[ -x "$node_root/bin/node" && -d "$codex_tool_root" && -f "$claude_root/manifest.json" ]] || \
  fail 'prepared managed-resource layout is incomplete'

# AionCore 0.1.42 retains the historical 0.16 compatibility slot name, but
# AionUi 2.1.0-beta.editfork.20 requires the slot contents to be the patched
# JavaScript @agentclientprotocol/codex-acp 1.1.2 runtime plus Codex 0.144.4.
# The raw npm tree is independently pinned and the checked-in AionUi patch is
# applied only after its exact upstream entrypoint digest is verified.
remove_pruned_path "$codex_tool_root"
mkdir -p -- "$codex_root"
(cd "$codex_raw_dir" && tar -cf - .) | (cd "$codex_root" && tar -xf - --no-same-owner --no-same-permissions)
codex_entrypoint="$codex_root/node_modules/@agentclientprotocol/codex-acp/dist/index.js"
codex_native="$codex_root/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
[[ "$(hash_of "$codex_entrypoint")" == "$expected_codex_base" ]] || fail 'copied Codex ACP base entrypoint checksum mismatch'
(cd "$codex_root/node_modules/@agentclientprotocol/codex-acp" && patch --batch --fuzz=0 --forward -p1 < "$codex_patch")
[[ "$(hash_of "$codex_entrypoint")" == "$expected_codex_patched" ]] || fail 'patched Codex ACP entrypoint checksum mismatch'
[[ "$(hash_of "$codex_native")" == "$expected_codex_binary" ]] || fail 'managed OpenAI Codex binary checksum mismatch'

printf '%s\n' \
  '{' \
  '  "entrypoint": "node_modules/@agentclientprotocol/codex-acp/dist/index.js",' \
  '  "path_entries": [' \
  '    "node_modules/.bin"' \
  '  ]' \
  '}' > "$codex_root/manifest.json"
install -m 0644 -- "$codex_acp_license" "$codex_root/LICENSE"
install -m 0644 -- "$codex_cli_license" "$codex_root/LICENSE.openai-codex"

# dist/index.js is the upstream self-contained production bundle. Keep the
# direct Codex wrapper/platform package, and retain exact license texts plus
# package-lock inventory for every embedded transitive package. Removing the
# duplicate unbundled JavaScript/declaration/test copies keeps the signed
# release below its 10,000-file evidence limit without changing runtime code.
while IFS='|' read -r source_path destination_path; do
  install -D -m 0644 -- "$codex_root/$source_path" "$codex_root/$destination_path"
done <<'LICENSE_PATHS'
node_modules/@agentclientprotocol/sdk/LICENSE|licenses/npm/@agentclientprotocol/sdk/LICENSE
node_modules/bundle-name/license|licenses/npm/bundle-name/license
node_modules/default-browser-id/license|licenses/npm/default-browser-id/license
node_modules/default-browser/license|licenses/npm/default-browser/license
node_modules/define-lazy-prop/license|licenses/npm/define-lazy-prop/license
node_modules/diff/LICENSE|licenses/npm/diff/LICENSE
node_modules/is-docker/license|licenses/npm/is-docker/license
node_modules/is-in-ssh/license|licenses/npm/is-in-ssh/license
node_modules/is-inside-container/license|licenses/npm/is-inside-container/license
node_modules/is-wsl/license|licenses/npm/is-wsl/license
node_modules/open/license|licenses/npm/open/license
node_modules/powershell-utils/license|licenses/npm/powershell-utils/license
node_modules/run-applescript/license|licenses/npm/run-applescript/license
node_modules/vscode-jsonrpc/License.txt|licenses/npm/vscode-jsonrpc/License.txt
node_modules/wsl-utils/license|licenses/npm/wsl-utils/license
node_modules/zod/LICENSE|licenses/npm/zod/LICENSE
LICENSE_PATHS
for relative_path in \
  node_modules/.bin/is-docker \
  node_modules/.bin/is-inside-container \
  node_modules/@agentclientprotocol/sdk \
  node_modules/bundle-name \
  node_modules/default-browser \
  node_modules/default-browser-id \
  node_modules/define-lazy-prop \
  node_modules/diff \
  node_modules/is-docker \
  node_modules/is-in-ssh \
  node_modules/is-inside-container \
  node_modules/is-wsl \
  node_modules/open \
  node_modules/powershell-utils \
  node_modules/run-applescript \
  node_modules/vscode-jsonrpc \
  node_modules/wsl-utils \
  node_modules/zod; do
  remove_pruned_path "$codex_root/$relative_path"
done

# These are build/development-only portions of the official Node distribution.
# The bundled runtime retains Node, npm, npx, their licenses, and the complete
# npm implementation required by AionCore's runtime validation.
remove_pruned_path "$stage/.staging"
remove_pruned_path "$node_root/include"
remove_pruned_path "$node_root/share"
remove_pruned_path "$node_root/tools"
remove_pruned_path "$node_root/README.md"
remove_pruned_path "$node_root/CHANGELOG.md"
remove_pruned_path "$node_root/bin/corepack"
remove_pruned_path "$node_root/lib/node_modules/corepack"

# The production target is the pinned OpenCloudOS glibc host. npm installs the
# optional musl Claude binary as well; retaining it would add an unused 224 MiB
# executable and would imply an unsupported musl target.
remove_pruned_path "$claude_root/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64-musl"

# npm emits relative executable symlinks. Signed WorkAgent releases reject all
# symlinks, so replace each with a regular launcher that executes the original
# in-tree target without changing its path-dependent module semantics.
while IFS= read -r -d '' link; do
  link_dir="$(dirname -- "$link")"
  resolved="$(realpath -- "$link")"
  case "$resolved" in
    "$stage"/*) ;;
    *) fail "managed-resource symlink escapes the tree: $link" ;;
  esac
  [[ -f "$resolved" && ! -L "$resolved" ]] || fail "managed-resource symlink does not resolve to a regular file: $link"
  relative_target="$(realpath --relative-to="$link_dir" -- "$resolved")"
  case "$relative_target" in
    *[!A-Za-z0-9@._/+:-]*) fail "managed-resource symlink target contains unsupported characters: $link" ;;
  esac
  unlink -- "$link"
  # The generated launcher expands these variables at execution time.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'link_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)' \
    "exec \"\$link_dir/$relative_target\" \"\$@\"" > "$link"
  chmod 0755 "$link"
done < <(find "$stage" -type l -print0 | LC_ALL=C sort -z)

find "$stage" -type f -perm /111 -printf '%P\0' | LC_ALL=C sort -z > "$executable_list"
find "$stage" -type f -exec chmod 0444 {} +
(cd "$stage" && xargs -0 -r chmod 0555 -- < "$executable_list")
find "$stage" -type d -exec chmod 0555 {} +
[[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'normalized managed resources still contain a symbolic link'
[[ -z "$(find "$stage" ! -type d ! -type f -print -quit)" ]] || fail 'normalized managed resources contain a special file'

PATH="$node_root/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
[[ "$("$node_root/bin/node" --version)" == v24.11.0 ]] || fail 'bundled Node version smoke test failed'
[[ "$("$node_root/bin/npm" --version)" == 11.6.1 ]] || fail 'bundled npm version smoke test failed'
[[ "$($node_root/bin/npx --version)" == 11.6.1 ]] || fail 'bundled npx version smoke test failed'
[[ "$($node_root/bin/node -p "require('$codex_root/node_modules/@agentclientprotocol/codex-acp/package.json').version")" == 1.1.2 ]] || \
  fail 'Codex ACP package version mismatch'
[[ "$($node_root/bin/node -p "require('$codex_root/node_modules/@openai/codex/package.json').version")" == 0.144.4 ]] || \
  fail 'managed OpenAI Codex package version mismatch'
[[ "$($node_root/bin/node -p "require('$claude_root/node_modules/@agentclientprotocol/claude-agent-acp/package.json').version")" == 0.39.0 ]] || \
  fail 'Claude Agent ACP package version mismatch'
$node_root/bin/node --check "$codex_entrypoint"
$node_root/bin/node --check "$codex_root/node_modules/@openai/codex/bin/codex.js"
$node_root/bin/node --check "$claude_root/node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js"
[[ "$($node_root/bin/node "$codex_entrypoint" --version)" == '@agentclientprotocol/codex-acp 1.1.2' ]] || fail 'Codex ACP version smoke test failed'
[[ "$($node_root/bin/node "$codex_root/node_modules/@openai/codex/bin/codex.js" --version)" == 'codex-cli 0.144.4' ]] || fail 'managed OpenAI Codex version smoke test failed'
grep -F '.onRequest(methods.agent.session.fork' "$codex_entrypoint" >/dev/null || fail 'Codex ACP session/fork wire route is missing'
grep -F '.onRequest("__aionui/session/steer"' "$codex_entrypoint" >/dev/null || fail 'Codex ACP steer compatibility wire route is missing'
grep -F '.onRequest("_aionui/session/steer"' "$codex_entrypoint" >/dev/null || fail 'Codex ACP steer wire route is missing'
(cd "$codex_root" && ! find node_modules -path '*/@zed-industries/*' -print -quit | grep -q .) || \
  fail 'deprecated @zed Codex ACP package remains in the managed resource tree'
(cd "$codex_root" && sha256sum --strict --check "$component_root/CODEX-ACP-LICENSES.sha256") >/dev/null || \
  fail 'Codex ACP or embedded dependency license checksum mismatch'
readelf -h "$codex_native" | \
  grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'managed OpenAI Codex binary architecture mismatch'
readelf -h "$claude_root/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude" | \
  grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'Claude binary architecture mismatch'
"$node_root/bin/node" "$component_root/tests/codex-acp-wire-smoke.mjs" "$node_root/bin/node" "$codex_root"

tree_hash="$(canonical_tree_hash "$stage")"
if [[ "$accept_unpinned" == 0 && -f "$component_root/MANAGED-RESOURCES.sha256" ]]; then
  expected_tree="$(cut -d' ' -f1 < "$component_root/MANAGED-RESOURCES.sha256")"
  [[ "$tree_hash" == "$expected_tree" ]] || fail "managed-resource tree checksum mismatch: $tree_hash"
elif [[ "$accept_unpinned" == 0 ]]; then
  fail "managed-resource tree is not approved; candidate checksum is $tree_hash"
fi

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'AionCore managed resources: %s\n' "$output_dir"
printf '%s  canonical-aioncore-managed-resources-tree.tar\n' "$tree_hash"
