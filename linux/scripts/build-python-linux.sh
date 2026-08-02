#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/python"
archive="${PYTHON_SOURCE_ARCHIVE:-$repo_root/.tools/downloads/Python-3.13.13.tar.xz}"
version="$(tr -d '\r\n' < "$component_root/VERSION")"
build_root="/tmp/workagent-python-3.13.13-build-v1"
source_dir="$build_root/source"
install_root="$build_root/install"
test_home="$build_root/test-home"
install_home="$build_root/install-home"
stage="$build_root/artifact"
venv_root="$build_root/smoke-venv"
relocation_root="$build_root/relocation"
output_dir="${PYTHON_OUTPUT_DIR:-$repo_root/.tools/artifacts/python-${version}-linux-x64}"
jobs="${PYTHON_BUILD_JOBS:-4}"
full_tests="${PYTHON_FULL_TESTS:-1}"

expected_archive="2ab91ff401783ccca64f75d10c882e957bdfd60e2bf5a72f8421793729b78a71"
expected_binary="62142db85725193dfcfc9d222333a5db1b676d6ff1b7afaa9451f264f6c59649"
expected_runtime="3a3bc7c278954dca6c2a76e18df2428174de6730dd40f4db7da4873e6152885d"

fail() {
  printf 'build-python-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

canonical_tree_hash() {
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu \
    -cf - -C "$1" "${@:2}" | sha256sum | cut -d' ' -f1
}

clean_workspaces() {
  for path in "$source_dir" "$install_root" "$test_home" "$install_home" "$stage" "$venv_root" "$relocation_root"; do
    case "$path" in
      "$build_root"/*) [[ ! -e "$path" && ! -L "$path" ]] || rm -rf -- "$path" ;;
      *) printf 'build-python-linux: refusing unsafe cleanup path: %s\n' "$path" >&2 ;;
    esac
  done
}

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || fail 'release target must be Linux x86_64'
[[ "$version" == 3.13.13 ]] || fail 'unexpected Python version'
[[ "$jobs" =~ ^[1-9][0-9]*$ && "$jobs" -le 32 ]] || fail 'PYTHON_BUILD_JOBS must be an integer from 1 to 32'
[[ "$full_tests" == 0 || "$full_tests" == 1 ]] || fail 'PYTHON_FULL_TESTS must be 0 or 1'
for command in awk chmod cut dirname env find flock grep install make mkdir mv readelf realpath rm rpm sed sha256sum sort strip tar tr xargs xz; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ "$archive" == /* && -f "$archive" && ! -L "$archive" ]] || fail 'source archive must be an absolute regular file'
[[ "$(hash_of "$archive")" == "$expected_archive" ]] || fail 'official CPython archive checksum mismatch'
[[ "$output_dir" == /* && "$output_dir" == "$(realpath -m -- "$output_dir")" ]] || fail 'output directory must be absolute and canonical'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

while IFS= read -r package; do
  [[ -n "$package" ]] || continue
  rpm -q "$package" >/dev/null 2>&1 || fail "required build package is missing or drifted: $package"
done < "$component_root/BUILD-REQUIRES"

install -d -m 0700 -- "$build_root"
[[ ! -L "$build_root" && "$build_root" == "$(realpath -m -- "$build_root")" ]] || fail 'canonical build root is unsafe'
exec 9>"$build_root/.lock"
flock -n 9 || fail 'another canonical Python build is running'
for path in "$source_dir" "$install_root" "$test_home" "$install_home" "$stage" "$venv_root" "$relocation_root"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "stale canonical build path requires operator review: $path"
done
trap clean_workspaces EXIT INT TERM

mkdir -m 0700 -- "$source_dir" "$install_root" "$test_home" "$install_home"
if tar -tJf "$archive" | awk '/^\// || /(^|\/)\.\.($|\/)/ { exit 1 }'; then
  :
else
  fail 'source archive contains an unsafe path'
fi
[[ -z "$(tar -tvJf "$archive" | awk '$1 ~ /^l/ { print; exit }')" ]] || fail 'source archive contains a symbolic link'
tar --extract --xz --file "$archive" --directory "$source_dir" --strip-components=1 \
  --no-same-owner --no-same-permissions
[[ -f "$source_dir/configure" && -f "$source_dir/Lib/ssl.py" ]] || fail 'source archive layout is unexpected'

export SOURCE_DATE_EPOCH=1784899380
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8
export TZ=UTC
export CFLAGS="-O3 -pipe -fno-semantic-interposition -fno-record-gcc-switches -ffile-prefix-map=$source_dir=/usr/src/python-3.13.13 -fdebug-prefix-map=$source_dir=/usr/src/python-3.13.13"
export LDFLAGS='-Wl,-O1,--sort-common,--as-needed'

cd "$source_dir"
env -u PYTHONHOME -u PYTHONPATH ./configure \
  --prefix=/opt/workagent-python/3.13.13 \
  --with-ensurepip=install \
  --enable-loadable-sqlite-extensions \
  --with-computed-gotos \
  --without-static-libpython
make -j "$jobs"
[[ "$(./python --version)" == 'Python 3.13.13' ]] || fail 'built interpreter version mismatch'
./python - <<'PY'
import bz2, ctypes, decimal, lzma, multiprocessing, readline, sqlite3, ssl, uuid
assert ssl.OPENSSL_VERSION.startswith("OpenSSL 3.0.")
assert sqlite3.sqlite_version == "3.42.0"
assert ctypes.sizeof(ctypes.c_void_p) == 8
assert multiprocessing.cpu_count() >= 1
assert decimal.Decimal("0.1") + decimal.Decimal("0.2") == decimal.Decimal("0.3")
assert bz2.decompress(bz2.compress(b"ok")) == b"ok"
assert lzma.decompress(lzma.compress(b"ok")) == b"ok"
assert readline.__doc__ and len(uuid.uuid4().hex) == 32
PY
if [[ "$full_tests" == 1 ]]; then
  env -i HOME="$test_home" PATH=/usr/local/bin:/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC \
    PYTHONHASHSEED=0 SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    ./python -m test -j "$jobs" --timeout 300 --randseed=8675309
fi
env -i HOME="$install_home" PATH=/usr/local/bin:/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC \
  PYTHONHASHSEED=0 SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  make DESTDIR="$install_root" install

prefix="$install_root/opt/workagent-python/3.13.13"
[[ -x "$prefix/bin/python3.13" && -d "$prefix/lib/python3.13" ]] || fail 'installed Python layout is incomplete'
install -d -m 0755 "$stage/bin" "$stage/libexec/python/3.13.13/bin" \
  "$stage/libexec/python/3.13.13/lib" "$stage/share/workagent-components/python"
install -m 0755 "$prefix/bin/python3.13" "$stage/libexec/python/3.13.13/bin/python3.13"
(cd "$prefix/lib" && tar --exclude='python3.13/test' --exclude='*/__pycache__' \
  --exclude='*.pyc' --exclude='*.pyo' -cf - python3.13) | \
  (cd "$stage/libexec/python/3.13.13/lib" && tar -xf - --no-same-owner --no-same-permissions)
strip --strip-unneeded "$stage/libexec/python/3.13.13/bin/python3.13"
find "$stage/libexec/python/3.13.13/lib/python3.13/lib-dynload" -type f -name '*.so' \
  -exec strip --strip-unneeded {} +
install -m 0555 "$component_root/python3-wrapper.sh" "$stage/bin/python3"
install -m 0555 "$component_root/pip3-wrapper.sh" "$stage/bin/pip3"
install -m 0444 "$component_root/VERSION" "$component_root/SOURCE" "$component_root/ARCHIVE.sha256" \
  "$component_root/BUILD-REQUIRES" "$component_root/BINARY.sha256" "$component_root/RUNTIME.sha256" \
  "$stage/share/workagent-components/python/"

find "$stage" -type f -exec chmod 0444 {} +
chmod 0555 "$stage/bin/python3" "$stage/bin/pip3" "$stage/libexec/python/3.13.13/bin/python3.13"
find "$stage/libexec/python/3.13.13/lib/python3.13/lib-dynload" -type f -name '*.so' -exec chmod 0555 {} +
find "$stage/bin" "$stage/libexec" -type d -exec chmod 0555 {} +
[[ -z "$(find "$stage" -type l -print -quit)" ]] || fail 'release payload contains a symbolic link'
[[ -z "$(find "$stage" ! -type d ! -type f -print -quit)" ]] || fail 'release payload contains a special file'

binary="$stage/libexec/python/3.13.13/bin/python3.13"
[[ "$(hash_of "$binary")" == "$expected_binary" ]] || fail 'final Python binary checksum mismatch'
actual_runtime="$(canonical_tree_hash "$stage" bin libexec)"
[[ "$actual_runtime" == "$expected_runtime" ]] || \
  fail "final Python runtime-tree checksum mismatch: expected $expected_runtime, got $actual_runtime"
readelf -h "$binary" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null || fail 'Python architecture mismatch'
[[ "$($stage/bin/python3 --version)" == 'Python 3.13.13' ]] || fail 'packaged Python version smoke test failed'
$stage/bin/python3 - <<'PY'
import bz2, ctypes, decimal, lzma, multiprocessing, readline, sqlite3, ssl, uuid
assert ssl.OPENSSL_VERSION.startswith("OpenSSL 3.0.")
assert sqlite3.sqlite_version == "3.42.0"
assert ctypes.sizeof(ctypes.c_void_p) == 8
assert multiprocessing.cpu_count() >= 1
assert decimal.Decimal("0.1") + decimal.Decimal("0.2") == decimal.Decimal("0.3")
assert bz2.decompress(bz2.compress(b"ok")) == b"ok"
assert lzma.decompress(lzma.compress(b"ok")) == b"ok"
assert readline.__doc__ and len(uuid.uuid4().hex) == 32
PY
$stage/bin/python3 -m ensurepip --version | grep -F 'pip 26.0.1' >/dev/null || fail 'ensurepip smoke test failed'
$stage/bin/pip3 --version | grep -F 'pip 26.0.1' >/dev/null || fail 'pip smoke test failed'
$stage/bin/python3 -m pip check | grep -F 'No broken requirements found.' >/dev/null || fail 'pip dependency smoke test failed'

mkdir -m 0700 -- "$venv_root" "$relocation_root"
$stage/bin/python3 -m venv --copies "$venv_root/env"
env PYTHONDONTWRITEBYTECODE=1 "$venv_root/env/bin/python" \
  -c 'import ssl, sqlite3; assert sqlite3.sqlite_version == "3.42.0"'
(cd "$stage" && tar -cf - .) | (cd "$relocation_root" && tar -xf - --no-same-owner --no-same-permissions)
"$relocation_root/bin/python3" -c 'import sys; assert sys.version_info[:3] == (3, 13, 13); assert sys.prefix.endswith("/libexec/python/3.13.13")'
[[ -z "$(find "$stage" -type d -name __pycache__ -print -quit)" ]] || fail 'Python smoke tests created a bytecode cache in the release'
[[ -z "$(find "$stage" -type f \( -name '*.pyc' -o -name '*.pyo' \) -print -quit)" ]] || fail 'Python smoke tests created bytecode in the release'
[[ "$(canonical_tree_hash "$stage" bin libexec)" == "$expected_runtime" ]] || fail 'Python runtime changed during smoke tests'

test_status='skipped-by-explicit-development-override'
[[ "$full_tests" == 0 ]] || test_status='passed-45233-tests'
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  '  "component": "python",' \
  '  "version": "3.13.13",' \
  '  "platform": "linux-x64",' \
  '  "source_archive_sha256": "2ab91ff401783ccca64f75d10c882e957bdfd60e2bf5a72f8421793729b78a71",' \
  '  "binary_sha256": "62142db85725193dfcfc9d222333a5db1b676d6ff1b7afaa9451f264f6c59649",' \
  '  "runtime_tree_sha256": "3a3bc7c278954dca6c2a76e18df2428174de6730dd40f4db7da4873e6152885d",' \
  "  \"regression_suite\": \"$test_status\"" \
  '}' > "$stage/share/workagent-components/python/BUILD-INFO.json"
(cd "$stage" && find . -type f ! -path './share/workagent-components/python/SHA256SUMS' -print0 | \
  LC_ALL=C sort -z | xargs -0 sha256sum > share/workagent-components/python/SHA256SUMS)
chmod 0444 "$stage/share/workagent-components/python/BUILD-INFO.json" \
  "$stage/share/workagent-components/python/SHA256SUMS"
find "$stage" -type d -exec chmod 0555 {} +

mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'Python %s Linux release: %s\n' "$version" "$output_dir"
sha256sum "$output_dir/libexec/python/3.13.13/bin/python3.13"
