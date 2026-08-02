#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/aionui"
noble_component_root="$repo_root/components/noble-hashes"
source_root="${AIONUI_SOURCE_DIR:-$repo_root/.tools/sources/aionui-editfork28-windows}"
reference_root="${AIONUI_REFERENCE_DIR:-$repo_root/.tools/reference/aionui-2.1.0-beta.editfork.28}"
bun_binary="${AIONUI_BUN_BINARY:-$repo_root/.tools/toolchains/bun-linux-x64/bun}"
noble_root="${AIONUI_NOBLE_HASHES_DIR:-$source_root/node_modules/.bun/@noble+hashes@2.2.0/node_modules/@noble/hashes}"
version="$(tr -d '\r\n' < "$component_root/VERSION")"
output_dir="${AIONUI_OUTPUT_DIR:-$repo_root/.tools/artifacts/aionui-${version}-linux-x64}"

fail() {
  printf 'build-aionui-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" . | sha256sum | cut -d' ' -f1
}

canonical_absent_output() {
  [[ "$1" == /* ]] || fail 'output directory must be absolute'
  [[ "$1" == "$(realpath -m -- "$1")" ]] || fail 'output directory must be canonical'
  [[ ! -e "$1" && ! -L "$1" ]] || fail "output already exists; refusing to overwrite: $1"
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
[[ "$version" == 2.1.0-beta.editfork.29 ]] || fail 'unexpected AionUi release identity'
for command in chmod cmp cut find grep head install mkdir mktemp mv node patch realpath rm sed sha256sum sort tar wc xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
for directory in "$source_root" "$reference_root" "$noble_root"; do
  [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || fail "input must be an absolute real directory: $directory"
done
[[ -x "$bun_binary" && ! -L "$bun_binary" ]] || fail 'verified Bun executable is missing or unsafe'
canonical_absent_output "$output_dir"

(cd "$repo_root" && sha256sum --strict --check "$component_root/BUN.sha256" "$component_root/REFERENCE.sha256") >/dev/null
(cd "$source_root" && sha256sum --strict --check "$component_root/WEB-HOST-SOURCE.sha256") >/dev/null
(cd "$component_root" && sha256sum --strict --check WEB-HOST-PATCH.sha256) >/dev/null
(cd "$source_root" && sha256sum --strict --check "$component_root/LICENSE.sha256") >/dev/null || fail 'AionUi license checksum mismatch'
[[ "$(canonical_tree_hash "$noble_root")" == b74fceb0006b617ed388254677b3d3847aeceb7e3f57db0cc9acc54644dabba6 ]] || fail '@noble/hashes package-tree checksum mismatch'
[[ "$(find "$noble_root" -type f | wc -l)" == 98 ]] || fail '@noble/hashes file count mismatch'
if find "$noble_root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
  fail '@noble/hashes package contains a link or special file'
fi
(cd "$noble_root" && sha256sum --strict --check "$noble_component_root/FILES.sha256") >/dev/null
[[ "$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$noble_root/package.json" | head -n 1)" == 2.2.0 ]] || fail '@noble/hashes version mismatch'
[[ "$(hash_of "$reference_root/windows-reference.json")" == 667154aa35b523cee01e32bc717db9f35fb9be6c748a4523f150461ea0023b0e ]] || fail 'Windows reference identity checksum mismatch'
[[ "$(hash_of "$reference_root/package.json")" == b5142c71c44dc092bbd00514f9c7ac1868b42c5cd48cadfad4150a7b17948b83 ]] || fail 'Windows package metadata checksum mismatch'
[[ "$(hash_of "$component_root/package.json")" == 55ae9e09c666ad9e3482fd1f0908b46c850b410e9a38494639f8c9da4d03228e ]] || fail 'Linux package metadata checksum mismatch'

mkdir -p -- "$repo_root/.tools/build"
work_dir="$(mktemp -d "$repo_root/.tools/build/aionui.XXXXXX")"
cleanup() {
  case "$work_dir" in
    "$repo_root"/.tools/build/aionui.*) rm -rf -- "$work_dir" ;;
    *) printf 'build-aionui-linux: refusing unsafe cleanup path: %s\n' "$work_dir" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

# Prove that the checked-in compatibility patch is a lossless, zero-fuzz
# transformation from the pinned upstream files to the exact source being
# compiled. This catches an accidentally refreshed or hand-edited snapshot in
# either direction before tests or the compiler run.
reversal_probe="$work_dir/source-reversal"
install -d -m 0755 -- "$reversal_probe"
while read -r _ relative; do
  [[ "$relative" != /* && "$relative" != *'..'* ]] || fail 'unsafe path in web-host source manifest'
  [[ -f "$source_root/$relative" && ! -L "$source_root/$relative" ]] || fail "web-host source input is missing or linked: $relative"
  install -D -m 0644 -- "$source_root/$relative" "$reversal_probe/$relative"
done < "$component_root/WEB-HOST-SOURCE.sha256"
(
  cd "$reversal_probe"
  patch --batch --reverse --fuzz=0 --no-backup-if-mismatch -p1 < "$component_root/aionui-webhost-workagent-runtime-auth.patch"
  sha256sum --strict --check "$component_root/WEB-HOST-BASE.sha256"
) >/dev/null || fail 'web-host patch does not reverse exactly to the pinned upstream base'
while read -r relative; do
  [[ "$relative" != /* && "$relative" != *'..'* ]] || fail 'unsafe path in web-host absent-file manifest'
  [[ ! -e "$reversal_probe/$relative" && ! -L "$reversal_probe/$relative" ]] || fail "web-host reverse patch left a base-absent path: $relative"
done < "$component_root/WEB-HOST-BASE-ABSENT"
(
  cd "$reversal_probe"
  patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < "$component_root/aionui-webhost-workagent-runtime-auth.patch"
  sha256sum --strict --check "$component_root/WEB-HOST-SOURCE.sha256"
) >/dev/null || fail 'web-host patch does not reproduce the pinned build source'

# Qualify the full source snapshot. One upstream DOM file uses process-global
# storage and one Help-page DOM test exceeds its fixed timeout under the full
# parallel project load, so run both files explicitly in isolation while
# keeping every test in the gate. Then cover the package-local start
# orchestration test which the repository-level Vitest project does not select.
(cd "$source_root" && WORKAGENT_TEST_BUN="$bun_binary" "$bun_binary" run test -- \
  --exclude tests/unit/skills/SkillsHubSettings.dom.test.tsx \
  --exclude tests/unit/pages/HelpPage.dom.test.tsx)
(cd "$source_root" && WORKAGENT_TEST_BUN="$bun_binary" "$bun_binary" run test -- tests/unit/skills/SkillsHubSettings.dom.test.tsx)
(cd "$source_root" && WORKAGENT_TEST_BUN="$bun_binary" "$bun_binary" run test -- tests/unit/pages/HelpPage.dom.test.tsx)
(cd "$source_root/packages/web-host" && WORKAGENT_TEST_BUN="$bun_binary" "$source_root/node_modules/.bin/vitest" --config vitest.config.ts run tests/start-web-host.test.ts)
"$source_root/node_modules/.bin/tsc" -p "$source_root/packages/web-host/tsconfig.json" --noEmit
"$source_root/node_modules/.bin/tsc" -p "$source_root/packages/web-cli/tsconfig.json" --noEmit
"$source_root/node_modules/.bin/oxfmt" -c "$source_root/.oxfmtrc.json" --check \
  "$source_root/packages/web-cli/src/index.ts" \
  "$source_root/packages/web-cli/src/workagent-bootstrap.ts" \
  "$source_root/packages/web-host/package.json" \
  "$source_root/packages/web-host/src/backend-launcher.test.ts" \
  "$source_root/packages/web-host/src/backend-launcher.ts" \
  "$source_root/packages/web-host/src/index.ts" \
  "$source_root/packages/web-host/src/runtime-socket-bootstrap.test.ts" \
  "$source_root/packages/web-host/src/runtime-socket-bootstrap.ts" \
  "$source_root/packages/web-host/src/static-server.ts" \
  "$source_root/packages/web-host/src/static-server.unit.test.ts" \
  "$source_root/packages/web-host/src/types.ts" \
  "$source_root/packages/web-host/src/workagent-runtime-auth.test.ts" \
  "$source_root/packages/web-host/src/workagent-runtime-auth.ts" \
  "$source_root/packages/web-host/tests/runtime-artifact-smoke.ts" \
  "$source_root/packages/web-host/tests/start-web-host.test.ts" \
  "$source_root/tests/unit/skills/SkillsHubSettings.dom.test.tsx"

expected_files="$work_dir/reference.expected"
actual_files="$work_dir/reference.actual"
sed -E 's#^[0-9a-f]{64}  \.tools/reference/aionui-2\.1\.0-beta\.editfork\.28/##' \
  "$reference_root.files.sha256" | LC_ALL=C sort > "$expected_files"
(cd "$reference_root" && find . -type f -printf '%P\n' | LC_ALL=C sort) > "$actual_files"
cmp -s "$expected_files" "$actual_files" || fail 'Windows reference file set differs from its pinned manifest'
if find "$reference_root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
  fail 'Windows reference contains a link or special file'
fi
(cd "$repo_root" && sha256sum --strict --check "$reference_root.files.sha256") >/dev/null
[[ "$(find "$reference_root/static" -type f | wc -l)" == 549 ]] || fail 'Windows static file count mismatch'
[[ "$(find "$reference_root/workagent-builtin-assistants" -type f | wc -l)" == 83 ]] || fail 'WorkAgent assistant file count mismatch'

stage="$work_dir/artifact"
install -d -m 0755 "$stage/bin" "$stage/share/workagent-components/aionui" \
  "$stage/share/workagent-components/noble-hashes"
"$bun_binary" build --compile --target=bun-linux-x64 \
  --outfile="$stage/bin/aionui-web" "$source_root/packages/web-cli/src/workagent-bootstrap.ts"
expected_web_host_binary="$(cut -d' ' -f1 < "$component_root/WEB-HOST-BINARY.sha256")"
actual_web_host_binary="$(hash_of "$stage/bin/aionui-web")"
[[ "$actual_web_host_binary" == "$expected_web_host_binary" ]] || fail "Linux web-host binary checksum mismatch: expected $expected_web_host_binary, got $actual_web_host_binary"
install -m 0444 "$component_root/package.json" "$stage/bin/package.json"
(cd "$reference_root" && tar -cf - static workagent-builtin-assistants) | (cd "$stage" && tar -xf - --no-same-owner --no-same-permissions)

install -m 0444 "$component_root/VERSION" "$component_root/SOURCE" "$component_root/package.json" "$component_root/BUN.sha256" \
  "$component_root/REFERENCE.sha256" "$component_root/WEB-HOST-SOURCE.sha256" "$component_root/WEB-HOST-BASE.sha256" \
  "$component_root/WEB-HOST-BASE-ABSENT" "$component_root/WEB-HOST-PATCH.sha256" \
  "$component_root/aionui-webhost-workagent-runtime-auth.patch" \
  "$component_root/WEB-HOST-BINARY.sha256" "$component_root/LICENSE.sha256" "$source_root/LICENSE" \
  "$stage/share/workagent-components/aionui/"
install -m 0444 "$noble_component_root/VERSION" "$noble_component_root/SOURCE" \
  "$noble_component_root/SOURCE.sha256" "$noble_component_root/FILES.sha256" \
  "$noble_root/LICENSE" "$stage/share/workagent-components/noble-hashes/"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "noble-hashes",' \
  '  "version": "2.2.0",' \
  '  "package_tree_sha256": "b74fceb0006b617ed388254677b3d3847aeceb7e3f57db0cc9acc54644dabba6",' \
  '  "sha2_js_sha256": "0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973"' \
  '}' > "$stage/share/workagent-components/noble-hashes/BUILD-INFO.json"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "aionui",' \
  '  "version": "2.1.0-beta.editfork.29",' \
  '  "platform": "linux-x64",' \
  '  "frontend_material": "windows-readonly-reference",' \
  '  "frontend_reference_manifest_sha256": "975fb6f54c6debdb06934bb3f4d24142cbffa7b2e9b391a9795a7fea07058776",' \
  '  "linux_web_host_source": "2.1.0-beta.editfork.28-dirty-readonly-snapshot+workagent-runtime-auth",' \
  '  "linux_web_host_source_manifest_sha256": "'"$(hash_of "$component_root/WEB-HOST-SOURCE.sha256")"'",' \
  '  "linux_web_host_base_manifest_sha256": "'"$(hash_of "$component_root/WEB-HOST-BASE.sha256")"'",' \
  '  "linux_web_host_base_absent_manifest_sha256": "'"$(hash_of "$component_root/WEB-HOST-BASE-ABSENT")"'",' \
  '  "linux_web_host_patch_sha256": "'"$(hash_of "$component_root/aionui-webhost-workagent-runtime-auth.patch")"'",' \
  '  "workagent_runtime_auth": "fd3-seqpacket-possession-token-v1",' \
  '  "license_file": "LICENSE",' \
  '  "linux_web_host_sha256": "'"$actual_web_host_binary"'"' \
  '}' > "$stage/share/workagent-components/aionui/BUILD-INFO.json"

[[ "$("$stage/bin/aionui-web" version)" == "$version" ]] || fail 'final AionUi version smoke test failed'
"$stage/bin/aionui-web" --help | grep -F 'Usage: aionui-web' >/dev/null || fail 'final AionUi help smoke test failed'
runtime_smoke="$work_dir/aionui-runtime-artifact-smoke"
"$bun_binary" build --compile --target=bun-linux-x64 \
  --outfile="$runtime_smoke" "$source_root/packages/web-host/tests/runtime-artifact-smoke.ts"
"$runtime_smoke" --orchestrate --artifact "$stage/bin/aionui-web" \
  --static-root "$stage/static" --scratch "$work_dir/runtime-artifact-smoke-state"

(cd "$stage" && find . -type f ! -path './share/workagent-components/aionui/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/aionui/SHA256SUMS)
find "$stage" -type f -exec chmod 0444 {} +
chmod 0555 "$stage/bin/aionui-web"
find "$stage" -type d -exec chmod 0555 {} +

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'AionUi %s Linux release: %s\n' "$version" "$output_dir"
sha256sum "$output_dir/bin/aionui-web"
