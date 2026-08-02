#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/codex"
archive="${CODEX_PLATFORM_ARCHIVE:-$repo_root/.tools/downloads/codex-0.144.4/openai-codex-0.144.4-linux-x64.tgz}"
license_input="${CODEX_LICENSE_FILE:-$repo_root/.tools/downloads/codex-0.144.4/LICENSE.rust-v0.144.4}"
version="$(tr -d '\r\n' < "$component_root/VERSION")"
output_dir="${CODEX_OUTPUT_DIR:-$repo_root/.tools/artifacts/codex-${version}-linux-x64}"

fail() {
  printf 'build-codex-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
[[ "$version" == 0.144.4 ]] || fail 'unexpected Codex version'
for command in chmod cmp cut dirname find grep install mkdir mktemp mv readelf realpath rm sha256sum sort tar timeout xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ "$archive" == /* && -f "$archive" && ! -L "$archive" ]] || fail 'platform archive must be an absolute regular file'
[[ "$(hash_of "$archive")" == 9a4a45314e80b53c4761b80067e3a68c2302f9a9026059b5f54f22dec8f34323 ]] || fail 'official Codex archive checksum mismatch'
[[ "$license_input" == /* && -f "$license_input" && ! -L "$license_input" ]] || fail 'official Codex license input must be an absolute regular file'
[[ "$(hash_of "$license_input")" == d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc ]] || fail 'official Codex license checksum mismatch'
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

mkdir -p -- "$repo_root/.tools/build"
work_dir="$(mktemp -d "$repo_root/.tools/build/codex.XXXXXX")"
cleanup() {
  case "$work_dir" in
    "$repo_root"/.tools/build/codex.*) rm -rf -- "$work_dir" ;;
    *) printf 'build-codex-linux: refusing unsafe cleanup path: %s\n' "$work_dir" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

tar --extract --gzip --file "$archive" --directory "$work_dir" --no-same-owner --no-same-permissions
package_root="$work_dir/package"
[[ -d "$package_root" && ! -L "$package_root" ]] || fail 'npm package root is missing or unsafe'
if find "$package_root" \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
  fail 'official Codex archive contains a link or special file'
fi
(cd "$package_root" && find . -type f -printf '%P\n' | LC_ALL=C sort) > "$work_dir/actual-files"
LC_ALL=C sort "$component_root/ARCHIVE-FILES" > "$work_dir/expected-files"
cmp -s "$work_dir/expected-files" "$work_dir/actual-files" || fail 'official Codex archive file set mismatch'
[[ "$(hash_of "$package_root/package.json")" == e4a98018015cbf52ace817e22a356e30be9081774bcfaeb6f620df4dab2405f5 ]] || fail 'Codex package metadata checksum mismatch'
vendor="$package_root/vendor/x86_64-unknown-linux-musl"
(cd "$vendor" && sha256sum --strict --check "$component_root/VENDOR.sha256") >/dev/null
readelf -h "$vendor/bin/codex" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'Codex executable architecture mismatch'

stage="$work_dir/artifact"
install -d -m 0755 "$stage/bin" "$stage/libexec/codex" "$stage/share/workagent-components/codex"
(cd "$vendor" && tar -cf - .) | (cd "$stage/libexec/codex" && tar -xf - --no-same-owner --no-same-permissions)
install -m 0555 "$component_root/codex-wrapper.sh" "$stage/bin/codex"
install -m 0444 "$license_input" "$stage/share/workagent-components/codex/LICENSE"
install -m 0444 "$component_root/VERSION" "$component_root/SOURCE" "$component_root/ARCHIVE.sha256" \
  "$component_root/VENDOR.sha256" "$component_root/ARCHIVE-FILES" "$component_root/LICENSE.sha256" \
  "$component_root/LICENSE-SOURCE" "$package_root/package.json" \
  "$package_root/README.md" "$stage/share/workagent-components/codex/"
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "codex",' \
  '  "version": "0.144.4",' \
  '  "platform": "x86_64-unknown-linux-musl",' \
  '  "archive_sha256": "9a4a45314e80b53c4761b80067e3a68c2302f9a9026059b5f54f22dec8f34323",' \
  '  "license_source_tag": "rust-v0.144.4",' \
  '  "license_sha256": "d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc",' \
  '  "native_binary_sha256": "2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a"' \
  '}' > "$stage/share/workagent-components/codex/BUILD-INFO.json"

find "$stage" -type f -exec chmod 0444 {} +
chmod 0555 "$stage/bin/codex" "$stage/libexec/codex/bin/codex" \
  "$stage/libexec/codex/bin/codex-code-mode-host" "$stage/libexec/codex/codex-path/rg" \
  "$stage/libexec/codex/codex-resources/bwrap" "$stage/libexec/codex/codex-resources/zsh/bin/zsh"
[[ "$("$stage/bin/codex" --version)" == 'codex-cli 0.144.4' ]] || fail 'Codex version smoke test failed'
"$stage/bin/codex" --help | grep -F 'Codex CLI' >/dev/null || fail 'Codex help smoke test failed'
timeout 5 "$stage/libexec/codex/bin/codex-code-mode-host" --help >/dev/null || fail 'Codex code-mode host smoke test failed'
"$stage/libexec/codex/codex-path/rg" --version | grep -F 'ripgrep 15.1.0' >/dev/null || fail 'bundled ripgrep smoke test failed'
"$stage/libexec/codex/codex-resources/bwrap" --version | grep -F 'bubblewrap built for Codex' >/dev/null || fail 'bundled bubblewrap smoke test failed'
"$stage/libexec/codex/codex-resources/zsh/bin/zsh" --version 2>/dev/null | grep -F 'zsh 5.9' >/dev/null || fail 'bundled zsh smoke test failed'

(cd "$stage" && find . -type f ! -path './share/workagent-components/codex/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/codex/SHA256SUMS)
chmod 0444 "$stage/share/workagent-components/codex/SHA256SUMS"
find "$stage" -type d -exec chmod 0555 {} +

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'Codex %s Linux release: %s\n' "$version" "$output_dir"
sha256sum "$output_dir/libexec/codex/bin/codex"
