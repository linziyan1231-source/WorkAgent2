#!/usr/bin/env bash
set -euo pipefail

umask 022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
component_root="$repo_root/components/kimi-code"
version="$(tr -d '\r\n' < "$component_root/VERSION")"
source_zip="${KIMI_CODE_SOURCE_ZIP:-$repo_root/.tools/sources/kimi-code-0.29.1/kimi-code-source.zip}"
node_archive="${KIMI_CODE_NODE_ARCHIVE:-$repo_root/.tools/downloads/node-v24.15.0-linux-x64.tar.xz}"
pnpm_store="${KIMI_CODE_PNPM_STORE:-$repo_root/.tools/pnpm-store}"
corepack_home="${KIMI_CODE_COREPACK_HOME:-$repo_root/.tools/corepack}"
# Node SEA records the main module's absolute build path. Keep this canonical
# path stable so identical inputs produce an identical ELF on every builder.
build_root="/tmp/workagent-kimi-code-build-v1"
output_dir="${KIMI_CODE_OUTPUT_DIR:-$repo_root/.tools/artifacts/kimi-code-${version}-linux-x64}"

expected_source="d00c6a1eff46bfe4213fe9f0547b51d7d812f2e9acd2e335ef282bb8d78a97af"
expected_node="472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6"
expected_patch="26fe77028896bd05633479d00bab009fbce2d94e63cdea8f3ed121e38535d64b"
expected_resp_patch="8d81608ab936e939024de6f0015c8d16a6e666c05a199f4078103a411049f466"
source_revision="f4c3967a417a539372eadab6c809d27b8a14c005"
patch_file="$component_root/kimi-code-0.29.1-acp-session-fork-steer.patch"
resp_patch_file="$component_root/kimi-code-0.29.1-minidb-resp-recovery.patch"

fail() {
  printf 'build-kimi-code-linux: %s\n' "$*" >&2
  exit 1
}

hash_of() {
  sha256sum -- "$1" | cut -d' ' -f1
}

[[ "$(uname -s)" == "Linux" ]] || fail 'the release target is Linux only'
[[ "$(uname -m)" == "x86_64" ]] || fail 'the release target is x86_64 only'
for command in sha256sum unzip patch tar mktemp install flock; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ -f "$source_zip" ]] || fail "source ZIP is missing: $source_zip"
[[ -f "$node_archive" ]] || fail "Node archive is missing: $node_archive"
[[ -d "$pnpm_store/v10" ]] || fail "pnpm v10 offline store is missing: $pnpm_store"
[[ -d "$corepack_home/v1/pnpm/10.33.0" ]] || fail "Corepack pnpm 10.33.0 cache is missing: $corepack_home"
[[ "$(hash_of "$source_zip")" == "$expected_source" ]] || fail 'source ZIP checksum mismatch'
[[ "$(hash_of "$node_archive")" == "$expected_node" ]] || fail 'Node archive checksum mismatch'
[[ "$(hash_of "$patch_file")" == "$expected_patch" ]] || fail 'fork/steer patch checksum mismatch'
[[ "$(hash_of "$resp_patch_file")" == "$expected_resp_patch" ]] || fail 'RESP recovery patch checksum mismatch'
[[ ! -e "$output_dir" ]] || fail "output already exists; refusing to overwrite: $output_dir"

[[ ! -L "$build_root" ]] || fail "canonical build root must not be a symlink: $build_root"
install -d -m 0700 -- "$build_root"
exec 9>"$build_root/.lock"
flock -n 9 || fail 'another canonical Kimi build is running'
work_dir="$build_root/work"
[[ ! -e "$work_dir" ]] || fail "stale canonical build workspace requires operator review: $work_dir"
mkdir -m 0700 -- "$work_dir"
test_clone=""
cleanup() {
  if [[ -n "$test_clone" ]]; then
    case "$test_clone" in
      /tmp/workagent-kimi-tests.*) rm -rf -- "$test_clone" ;;
      *) printf 'build-kimi-code-linux: refusing unsafe test cleanup path: %s\n' "$test_clone" >&2 ;;
    esac
  fi
  case "$work_dir" in
    "$build_root"/work) rm -rf -- "$work_dir" ;;
    *) printf 'build-kimi-code-linux: refusing unsafe cleanup path: %s\n' "$work_dir" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p -- "$work_dir/source" "$work_dir/node" "$work_dir/bin" "$work_dir/cache"
unzip -q "$source_zip" -d "$work_dir/source"
source_root="$work_dir/source/MoonshotAI-kimi-code-785c319"
[[ -f "$source_root/apps/kimi-code/package.json" ]] || fail 'source archive root is unexpected'
(cd "$source_root" && sha256sum --strict --check "$component_root/LICENSE.sha256") >/dev/null || fail 'Kimi Code license checksum mismatch'
patch --batch --forward -d "$source_root" -p1 < "$patch_file"
patch --batch --forward -d "$source_root" -p1 < "$resp_patch_file"
[[ "$(hash_of "$source_root/packages/acp-adapter/src/server.ts")" == "61711be46bceeae859dc68f5629d8996f9383946f3ea3cb60cf6b1459266fc02" ]] || fail 'patched ACP server checksum mismatch'
[[ "$(hash_of "$source_root/packages/acp-adapter/src/session.ts")" == "f57d1b977f269cc5ae2a02f2fe1eba27d176b4b815521fa559ebb4c736e655c7" ]] || fail 'patched ACP session checksum mismatch'
[[ "$(hash_of "$source_root/packages/minidb/src/server.ts")" == "94601a5b129c38b3c041443c56cc2853d97250d256e026c9b5056cf60c4e22e1" ]] || fail 'patched MiniDb RESP server checksum mismatch'
install -m 0644 "$component_root/tests/aionui-fork-steer.test.ts" "$source_root/packages/acp-adapter/test/aionui-fork-steer.test.ts"

tar --extract --xz --file "$node_archive" --directory "$work_dir/node" --strip-components=1 --no-same-owner
node_bin="$work_dir/node/bin/node"
corepack_bin="$work_dir/node/bin/corepack"
[[ "$("$node_bin" --version)" == "v24.15.0" ]] || fail 'Node version mismatch'
COREPACK_HOME="$corepack_home" "$corepack_bin" enable --install-directory "$work_dir/bin"

export PATH="$work_dir/node/bin:$work_dir/bin:/usr/local/bin:/usr/bin:/bin"
export COREPACK_HOME="$corepack_home"
export COREPACK_ENABLE_NETWORK=0
export XDG_CACHE_HOME="$work_dir/cache"
export PNPM_HOME="$work_dir/bin"
export SOURCE_DATE_EPOCH=1784899380
pnpm="$work_dir/bin/pnpm"

cd "$source_root"
[[ "$("$pnpm" --version)" == "10.33.0" ]] || fail 'pnpm version mismatch'
[[ "$("$node_bin" -p "require('./apps/kimi-code/package.json').version")" == "0.29.1" ]] || fail 'Kimi source version mismatch'

"$pnpm" install --frozen-lockfile --offline --ignore-scripts --store-dir "$pnpm_store"
"$pnpm" --filter @moonshot-ai/acp-adapter typecheck
"$pnpm" exec vitest run packages/acp-adapter/test/aionui-fork-steer.test.ts
"$pnpm" --filter @moonshot-ai/acp-adapter test
"$pnpm" exec vitest run \
  packages/node-sdk/test/create-session-transport.test.ts \
  packages/node-sdk/test/session-prompt-events.test.ts \
  packages/node-sdk/test/session-steer.test.ts
if [[ "${KIMI_CODE_FULL_TESTS:-1}" == "1" ]]; then
  if [[ "$(id -u)" != "0" ]]; then
    "$pnpm" test
  else
    for command in bwrap cp; do
      command -v "$command" >/dev/null 2>&1 || fail "root full-test isolation requires: $command"
    done
    test_uid="$(id -u nobody)"
    test_gid="$(id -g nobody)"
    test_clone="$(mktemp -d /tmp/workagent-kimi-tests.XXXXXX)"
    mkdir -p "$test_clone/source" "$test_clone/node" "$test_clone/home/user-21a3230e"
    cp -a --reflink=auto "$source_root/." "$test_clone/source/"
    cp -a --reflink=auto "$work_dir/node/." "$test_clone/node/"
    # The test suite contains intentional fixed /tmp paths. A private tmpfs
    # prevents a prior root test run (or another workload on the builder) from
    # changing the result, while the unprivileged uid still exercises normal
    # production permissions. Seed one ordinary home directory because the
    # slash-command completion contract expects ~/ to contain a directory.
    bwrap \
      --die-with-parent \
      --new-session \
      --unshare-user \
      --ro-bind / / \
      --dev-bind /dev /dev \
      --tmpfs /tmp \
      --chmod 1777 /tmp \
      --tmpfs /mnt \
      --dir /mnt/work \
      --bind "$test_clone/source" /mnt/work/source \
      --ro-bind "$test_clone/node" /mnt/work/node \
      --bind "$test_clone/home" /mnt/work/home \
      --chdir /mnt/work/source \
      --clearenv \
      --setenv HOME /mnt/work/home \
      --setenv LANG C.UTF-8 \
      --setenv LOGNAME nobody \
      --setenv NO_COLOR 1 \
      --setenv PATH /mnt/work/node/bin:/usr/local/bin:/usr/bin:/bin \
      --setenv TMPDIR /tmp \
      --setenv USER nobody \
      --uid "$test_uid" \
      --gid "$test_gid" \
      /mnt/work/node/bin/node /mnt/work/source/node_modules/vitest/vitest.mjs run
    rm -rf -- "$test_clone"
    test_clone=""
  fi
fi

export KIMI_CODE_CHANNEL=fork-steer.1
export KIMI_CODE_COMMIT="$source_revision"
export KIMI_CODE_BUILD_TARGET=linux-x64
"$pnpm" --filter @moonshot-ai/kimi-code build
"$pnpm" --filter @moonshot-ai/kimi-code build:native:sea

binary="$source_root/apps/kimi-code/dist-native/bin/linux-x64/kimi"
[[ -x "$binary" ]] || fail 'native Kimi executable was not produced'
[[ "$(env HOME="$work_dir/home" KIMI_CODE_HOME="$work_dir/home/.kimi-code" NO_COLOR=1 "$binary" --version)" == "0.29.1" ]] || fail 'native Kimi version probe failed'
env HOME="$work_dir/home" KIMI_CODE_HOME="$work_dir/home/.kimi-code" NO_COLOR=1 "$binary" --help | grep -F 'acp [options]' >/dev/null || fail 'native Kimi help probe failed'
"$node_bin" "$component_root/tests/native-acp-smoke.mjs" "$binary"

stage="$work_dir/artifact"
install -d -m 0755 "$stage/bin"
install -m 0555 "$binary" "$stage/bin/kimi"
install -m 0444 "$component_root/VERSION" "$stage/VERSION"
install -m 0444 "$component_root/SOURCE" "$stage/SOURCE"
install -m 0444 "$component_root/SOURCE.sha256" "$stage/SOURCE.sha256"
install -m 0444 "$component_root/NODE.sha256" "$stage/NODE.sha256"
install -m 0444 "$component_root/PATCH.sha256" "$stage/PATCH.sha256"
install -m 0444 "$component_root/RESP-PATCH.sha256" "$stage/RESP-PATCH.sha256"
install -m 0444 "$component_root/LICENSE.sha256" "$stage/LICENSE.sha256"
install -m 0444 "$source_root/LICENSE" "$stage/LICENSE"
install -m 0444 "$patch_file" "$stage/kimi-code-0.29.1-acp-session-fork-steer.patch"
install -m 0444 "$resp_patch_file" "$stage/kimi-code-0.29.1-minidb-resp-recovery.patch"
(
  cd "$stage"
  sha256sum bin/kimi SOURCE VERSION SOURCE.sha256 NODE.sha256 PATCH.sha256 RESP-PATCH.sha256 LICENSE LICENSE.sha256 \
    kimi-code-0.29.1-acp-session-fork-steer.patch kimi-code-0.29.1-minidb-resp-recovery.patch > SHA256SUMS
  chmod 0444 SHA256SUMS
)
mkdir -p -- "$(dirname "$output_dir")"
mv -- "$stage" "$output_dir"
printf 'Kimi Code %s Linux release: %s\n' "$version" "$output_dir"
sha256sum "$output_dir/bin/kimi"
