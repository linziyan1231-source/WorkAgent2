#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )); then
  echo "usage: scripts/build-chatforward.sh ABSOLUTE_SOURCE_DIRECTORY ABSOLUTE_NODE_ARCHIVE ABSOLUTE_WS_ARCHIVE ABSOLUTE_EMPTY_OUTPUT_DIRECTORY" >&2
  exit 2
fi

source_directory=$1
node_archive=$2
ws_archive=$3
output_directory=$4
for path in "$source_directory" "$node_archive" "$ws_archive" "$output_directory"; do
  case "$path" in
    /*) ;;
    *) echo "all ChatForward build paths must be absolute" >&2; exit 2 ;;
  esac
done
if [[ ! -d $source_directory || -L $source_directory ]]; then
  echo "ChatForward source must be a real directory" >&2
  exit 1
fi
if [[ ! -f $node_archive || -L $node_archive || $(basename -- "$node_archive") != node-v24.15.0-linux-x64.tar.xz ]]; then
  echo "the pinned Node.js archive is missing or unsafe" >&2
  exit 1
fi
if [[ ! -f $ws_archive || -L $ws_archive || $(basename -- "$ws_archive") != ws-8.21.1.tgz ]]; then
  echo "the pinned ws dependency archive is missing or unsafe" >&2
  exit 1
fi
if [[ -e $output_directory && ! -d $output_directory ]]; then
  echo "ChatForward output path is not a directory" >&2
  exit 1
fi
if [[ -d $output_directory && -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "ChatForward output directory must be empty" >&2
  exit 1
fi

for command in sha256sum sha512sum find sort comm cmp tar gzip mktemp stat touch sed grep awk cp chmod uname; do
  command -v -- "$command" >/dev/null || { echo "required build command is missing: $command" >&2; exit 1; }
done
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "ChatForward production packaging supports Linux x86_64 only" >&2
  exit 1
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
component_directory=$repository_root/components/chatforward
source_manifest=$component_directory/SOURCE.sha256
node_manifest=$component_directory/NODE.sha256
dependency_manifest=$component_directory/DEPENDENCIES.sha512
dependency_sha256_manifest=$component_directory/DEPENDENCIES.sha256
version=$(tr -d '\r\n' < "$component_directory/VERSION")
if [[ $version != zombie-reap-20260725-2329 ]]; then
  echo "ChatForward server release does not match the Windows production contract" >&2
  exit 1
fi

temporary_directory=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT INT TERM
expected_files=$temporary_directory/expected-files
actual_files=$temporary_directory/actual-files
sed -E 's/^[0-9a-f]{64}  //' "$source_manifest" | LC_ALL=C sort > "$expected_files"
(cd "$source_directory" && find . -type f -printf '%P\n' | LC_ALL=C sort) > "$actual_files"
if ! cmp -s "$expected_files" "$actual_files"; then
  echo "ChatForward source file set does not match the read-only Windows snapshot" >&2
  comm -3 "$expected_files" "$actual_files" >&2 || true
  exit 1
fi
if [[ -n $(find "$source_directory" -type l -print -quit) ]]; then
  echo "ChatForward source snapshot must not contain symbolic links" >&2
  exit 1
fi
(cd "$source_directory" && sha256sum --strict --check "$source_manifest") >/dev/null
(cd "$(dirname -- "$node_archive")" && sha256sum --strict --check "$node_manifest") >/dev/null
(cd "$(dirname -- "$ws_archive")" && sha512sum --strict --check "$dependency_manifest") >/dev/null
(cd "$(dirname -- "$ws_archive")" && sha256sum --strict --check "$dependency_sha256_manifest") >/dev/null

test_root=$temporary_directory/test-root
toolchain_root=$temporary_directory/node-toolchain
release_name=workagent-chatforward-$version
release_root=$temporary_directory/$release_name
mkdir -p "$test_root/app" "$test_root/npm-home" "$toolchain_root" "$release_root/app" "$release_root/node/bin" "$release_root/integration" "$output_directory"
(cd "$source_directory" && tar -cf - -- .) | (cd "$test_root/app" && tar -xf -)
tar -xf "$node_archive" -C "$toolchain_root" --strip-components=1

export PATH=$toolchain_root/bin:/usr/bin:/bin
export HOME=$test_root/npm-home
export npm_config_cache=$test_root/npm-cache
export npm_config_audit=false
export npm_config_fund=false
export npm_config_ignore_scripts=true
export npm_config_update_notifier=false
if [[ $(node --version) != v24.15.0 || $(npm --version) != 11.12.1 ]]; then
  echo "the pinned Node.js archive has an unexpected runtime or npm version" >&2
  exit 1
fi
(cd "$test_root/app" && npm cache add "$ws_archive")
(cd "$test_root/app" && npm ci --offline --omit=dev --ignore-scripts --no-audit --no-fund)
(cd "$test_root/app" && node --test)
bash -n "$component_directory/integration/run-server.sh" "$component_directory/integration/run-browser.sh" "$component_directory/integration/login.sh"
(cd "$repository_root" && node --test components/chatforward/test/*.test.mjs)

(cd "$source_directory" && tar -cf - -- README.md package.json package-lock.json src public extension) | (cd "$release_root/app" && tar -xf -)
(cd "$test_root/app" && tar -cf - -- node_modules) | (cd "$release_root/app" && tar -xf -)
(cd "$component_directory/integration" && tar -cf - -- .) | (cd "$release_root/integration" && tar -xf -)
cp -- "$toolchain_root/bin/node" "$release_root/node/bin/node"
cp -- "$toolchain_root/LICENSE" "$release_root/node/LICENSE"
cp -- "$source_manifest" "$node_manifest" "$dependency_manifest" "$component_directory/VERSION" "$release_root/"

# Chrome 137+ ignores --load-extension outside developer mode, so the browser
# extension ships as a CRX installed through a managed policy. The signing key
# is host-pinned so the derived extension ID is stable across rebuilds.
extension_key=${CHATFORWARD_EXTENSION_KEY:-/etc/workagent/chatforward-extension.pem}
if [[ ! -f $extension_key || -L $extension_key || $(stat -Lc '%u:%a' -- "$extension_key") != "0:600" ]]; then
  echo "the pinned ChatForward extension signing key is missing or unsafe: $extension_key" >&2
  exit 1
fi
chromium_packager=${CHATFORWARD_CHROMIUM_BIN:-/usr/bin/google-chrome-stable}
"$chromium_packager" --pack-extension="$release_root/app/extension" --pack-extension-key="$extension_key" --no-sandbox --user-data-dir="$temporary_directory/pack-profile" >/dev/null 2>&1 ||
  { echo "ChatForward extension CRX packing failed" >&2; exit 1; }
mv -- "$release_root/app/extension.crx" "$release_root/extension.crx"
extension_id=$(openssl rsa -in "$extension_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}' | cut -c1-32 | tr '0-9a-f' 'a-p')
extension_version=$(sed -n 's/.*"version": *"\([0-9.]*\)".*/\1/p' "$release_root/app/extension/manifest.json")
printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">' \
  "  <app appid=\"$extension_id\">" \
  "    <updatecheck codebase=\"file:///opt/workagent/shared/chatforward/extension.crx\" version=\"$extension_version\" />" \
  '  </app>' \
  '</gupdate>' > "$release_root/update.xml"

source_manifest_sha256=$(sha256sum "$source_manifest" | awk '{print $1}')
node_archive_sha256=$(sha256sum "$node_archive" | awk '{print $1}')
package_lock_sha256=$(sha256sum "$source_directory/package-lock.json" | awk '{print $1}')
ws_archive_sha512=$(sha512sum "$ws_archive" | awk '{print $1}')
build_information=$release_root/BUILD-INFO.json
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "chatforward",' \
  '  "version": "zombie-reap-20260725-2329",' \
  '  "platform": "linux-x64",' \
  '  "source_snapshot": "windows-readonly-20260725T2329+0800",' \
  "  \"source_manifest_sha256\": \"$source_manifest_sha256\"," \
  '  "node_version": "24.15.0",' \
  '  "npm_version": "11.12.1",' \
  "  \"node_archive_sha256\": \"$node_archive_sha256\"," \
  "  \"package_lock_sha256\": \"$package_lock_sha256\"," \
  "  \"ws_archive_sha512\": \"$ws_archive_sha512\"," \
  '  "extension_version": "0.16.0",' \
  '  "listen": "127.0.0.1:3210",' \
  '  "max_pairs": 3' \
  '}' > "$build_information"

find "$release_root" -type d -exec chmod 0755 {} +
find "$release_root" -type f -exec chmod 0644 {} +
chmod 0755 "$release_root/node/bin/node"
chmod 0755 "$release_root/integration/readiness.mjs" "$release_root/integration/run-server.sh" "$release_root/integration/run-browser.sh" "$release_root/integration/login.sh"
source_date_epoch=${SOURCE_DATE_EPOCH:-1784993340}
if [[ ! $source_date_epoch =~ ^[1-9][0-9]{9}$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a ten-digit positive Unix timestamp" >&2
  exit 1
fi
find "$release_root" -exec touch -h -d "@$source_date_epoch" {} +

archive_name=$release_name-linux-x64.tar.gz
archive_path=$output_directory/$archive_name
tar --sort=name --format=gnu --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C "$temporary_directory" -cf - "$release_name" | gzip -n -9 > "$archive_path"
(cd "$output_directory" && sha256sum "$archive_name" > SHA256SUMS)
echo "ChatForward package: $archive_path"
