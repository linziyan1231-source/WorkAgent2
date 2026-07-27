#!/usr/bin/env bash
set -euo pipefail

# Every payload mode is frozen explicitly below. A private fixed umask also
# makes the surrounding evidence files deterministic and prevents a permissive
# caller umask from widening a partially generated artifact directory.
umask 0077
export LC_ALL=C

# Git's command-scope configuration and repository-routing environment outrank
# global/system configuration. Remove every caller-controlled override before
# resolving the source identity or creating the sanitized object repository.
unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_GRAFT_FILE \
  GIT_TEMPLATE_DIR GIT_EXEC_PATH GIT_REPLACE_REF_BASE GIT_EXTERNAL_DIFF \
  GIT_DIFF_OPTS || true
for git_config_variable in ${!GIT_CONFIG_KEY_@} ${!GIT_CONFIG_VALUE_@}; do
  unset "$git_config_variable"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_ATTR_NOSYSTEM=1
export GIT_NO_REPLACE_OBJECTS=1

source_gate_mode=${SOURCE_GATE_MODE:-quality}
case "$source_gate_mode" in
  quality|artifact) ;;
  *) echo "SOURCE_GATE_MODE must be quality or artifact" >&2; exit 2 ;;
esac

if (( $# != 1 )); then
  echo "usage: scripts/source-gate.sh ABSOLUTE_EMPTY_ARTIFACT_DIRECTORY" >&2
  exit 2
fi

artifact_directory=$1
case "$artifact_directory" in
  /*) ;;
  *) echo "artifact directory must be absolute" >&2; exit 2 ;;
esac
if [[ $(realpath -m -- "$artifact_directory") != "$artifact_directory" || -L $artifact_directory ]]; then
  echo "artifact directory must be canonical and must not be a symlink" >&2
  exit 2
fi
if [[ -e $artifact_directory ]]; then
  shopt -s dotglob nullglob
  initial_artifact_entries=("$artifact_directory"/*)
  shopt -u dotglob nullglob
  if (( ${#initial_artifact_entries[@]} != 0 )); then
    echo "artifact directory must be empty" >&2
    exit 2
  fi
fi
mkdir -p "$artifact_directory"
chmod 0700 "$artifact_directory"

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
snapshot=
quality_snapshot=
test_snapshot=
build_snapshot=
object_repository=
locked_tree_inventory=
empty_git_template=
shell_file_inventory=
privileged_test_root=
source_gate_cache_root=
go_test_repository=$repo_root
source_gate_uid=$(id -u)
source_gate_gid=$(id -g)

source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
if [[ ! $source_revision =~ ^[0-9a-f]{40}$ || ! $source_tree =~ ^[0-9a-f]{40}$ ]]; then
  echo "source gate could not lock a 40-hex source commit and tree" >&2
  exit 1
fi
if [[ -n ${EXPECTED_SOURCE_REVISION:-} && $EXPECTED_SOURCE_REVISION != "$source_revision" ]]; then
  echo "source gate revision does not match EXPECTED_SOURCE_REVISION" >&2
  exit 1
fi
if [[ $source_gate_mode == artifact ]]; then
  if [[ -z ${EXPECTED_SOURCE_REVISION:-} || ${QUALITY_GATE_SOURCE_REVISION:-} != "$source_revision" ]]; then
    echo "artifact-only source gate requires matching expected and prerequisite quality revisions" >&2
    exit 1
  fi
fi
readonly source_revision source_tree

cleanup_source_gate() {
  if [[ -n ${snapshot:-} && -d $snapshot ]]; then
    rm -rf -- "$snapshot"
  fi
  if [[ -n ${quality_snapshot:-} && -d $quality_snapshot ]]; then
    rm -rf -- "$quality_snapshot"
  fi
  if [[ -n ${build_snapshot:-} && -d $build_snapshot ]]; then
    rm -rf -- "$build_snapshot"
  fi
  if [[ -n ${test_snapshot:-} && -d $test_snapshot ]]; then
    if ! rm -rf -- "$test_snapshot" 2>/dev/null; then
      if (( EUID == 0 )); then
        rm -rf -- "$test_snapshot"
      else
        sudo -n rm -rf -- "$test_snapshot"
      fi
    fi
  fi
  if [[ -n ${privileged_test_root:-} && -e $privileged_test_root ]]; then
    if (( EUID == 0 )); then
      rm -rf -- "$privileged_test_root"
    else
      sudo -n rm -rf -- "$privileged_test_root"
    fi
  fi
  if [[ -n ${source_gate_cache_root:-} && -d $source_gate_cache_root ]]; then
    rm -rf -- "$source_gate_cache_root"
  fi
  if [[ -n ${object_repository:-} && -d $object_repository ]]; then
    rm -rf -- "$object_repository"
  fi
  if [[ -n ${locked_tree_inventory:-} && -e $locked_tree_inventory ]]; then
    rm -f -- "$locked_tree_inventory"
  fi
  if [[ -n ${empty_git_template:-} && -d $empty_git_template ]]; then
    rm -rf -- "$empty_git_template"
  fi
  if [[ -n ${shell_file_inventory:-} && -e $shell_file_inventory ]]; then
    rm -f -- "$shell_file_inventory"
  fi
}
trap cleanup_source_gate EXIT INT TERM

go_binary=${GO_BIN:-go}
gitleaks_binary=${GITLEAKS_BIN:-gitleaks}
syft_binary=${SYFT_BIN:-syft}
govulncheck_binary=${GOVULNCHECK_BIN:-govulncheck}
shellcheck_binary=${SHELLCHECK_BIN:-shellcheck}

go_binary=$(command -v -- "$go_binary")
go_binary=$(readlink -f -- "$go_binary")
go_directory=$(dirname -- "$go_binary")
go_root=$(dirname -- "$go_directory")
export PATH="$go_directory:$PATH"
export GOROOT="$go_root"
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export GOENV=off
export GO111MODULE=on
export GOWORK=off
export GOOS=linux
export GOARCH=amd64
export GOAMD64=v1
export GOEXPERIMENT=
export GOFIPS140=off
export GOCACHEPROG=
export GOTELEMETRY=off

if [[ $($go_binary version) != go\ version\ go1.26.5\ linux/amd64 ]]; then
  echo "source gate requires Go 1.26.5 linux/amd64" >&2
  exit 1
fi
[[ $($gitleaks_binary version) == 8.28.0 ]]
syft_version_output=$("$syft_binary" version)
govulncheck_version_output=$("$govulncheck_binary" -version)
shellcheck_version_output=$("$shellcheck_binary" --version)
grep -Fxq 'Version:       1.29.0' <<< "$syft_version_output"
grep -Fq 'v1.6.0' <<< "$govulncheck_version_output"
grep -Fq 'version: 0.11.0' <<< "$shellcheck_version_output"
unset syft_version_output govulncheck_version_output shellcheck_version_output

export SYFT_CHECK_FOR_APP_UPDATE=false

# Do not trust or contaminate a caller's compiled-object cache. Tests and the
# final artifact build deliberately use distinct new caches so the release
# binaries are compiled independently after every source test has completed.
source_gate_cache_root=$(mktemp -d /tmp/workagent-source-gate-go-cache.XXXXXX)
mkdir -m 0700 -- "$source_gate_cache_root/test" "$source_gate_cache_root/build"
export GOCACHE="$source_gate_cache_root/test"

run_go_tests_as_production_owner() {
  if (( EUID == 0 )); then
    "$go_binary" test "$@"
    return
  fi
  if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
    echo "source gate requires non-interactive sudo for root-ownership release tests" >&2
    return 1
  fi
  if [[ -z $privileged_test_root ]]; then
    runner_module_cache=$($go_binary env GOMODCACHE)
    runner_module_cache=$(realpath -e -- "$runner_module_cache")
    if [[ $runner_module_cache != /* || ! -d $runner_module_cache ]]; then
      echo "source gate could not resolve the verified Go module cache" >&2
      return 1
    fi
    privileged_test_root=$(mktemp -d /tmp/workagent-source-gate-root-tests.XXXXXX)
    sudo -n mkdir -p -- "$privileged_test_root/gocache" "$privileged_test_root/gomodcache"
    sudo -n cp -a -- "$runner_module_cache/." "$privileged_test_root/gomodcache/"
    sudo -n chown -R 0:0 -- "$privileged_test_root"
    sudo -n env \
      GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOENV=off GO111MODULE=on GOWORK=off \
      GOOS=linux GOARCH=amd64 GOAMD64=v1 GOEXPERIMENT= GOFIPS140=off \
      GOROOT="$go_root" GOCACHEPROG= GOTELEMETRY=off \
      GOPROXY=off GOSUMDB=off \
      GOCACHE="$privileged_test_root/gocache" \
      GOMODCACHE="$privileged_test_root/gomodcache" \
      "$go_binary" mod verify
  fi
  sudo -n env \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    GOENV=off \
    GO111MODULE=on \
    GOWORK=off \
    GOOS=linux \
    GOARCH=amd64 \
    GOAMD64=v1 \
    GOEXPERIMENT= \
    GOFIPS140=off \
    GOROOT="$go_root" \
    GOCACHEPROG= \
    GOTELEMETRY=off \
    GOPROXY=off \
    GOSUMDB=off \
    GOCACHE="$privileged_test_root/gocache" \
    GOMODCACHE="$privileged_test_root/gomodcache" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_ATTR_NOSYSTEM=1 \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0="$go_test_repository" \
    "$go_binary" test "$@"
}

require_clean_source() {
  local current_revision current_tree status clean_index
  if ! current_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}') ||
    ! current_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}'); then
    echo "source gate could not revalidate the locked source identity" >&2
    return 1
  fi
  if [[ $current_revision != "$source_revision" || $current_tree != "$source_tree" ]]; then
    echo "source gate source commit or tree changed after it was locked" >&2
    return 1
  fi

  # Inspect the original worktree through the sanitized object repository and
  # a private index. This does not load the source repository's local config,
  # hooks, fsmonitor, filters, info/attributes, or caller Git configuration.
  clean_index=$(mktemp /tmp/workagent-source-gate-index.XXXXXX)
  rm -f -- "$clean_index"
  if ! GIT_INDEX_FILE=$clean_index git --git-dir="$object_repository" --work-tree="$repo_root" \
      -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
      read-tree "$source_revision" ||
    ! status=$(GIT_INDEX_FILE=$clean_index git --git-dir="$object_repository" --work-tree="$repo_root" \
      -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
      status --porcelain=v1 --untracked-files=all -- . ':(top,literal,exclude).git'); then
    rm -f -- "$clean_index"
    echo "source gate could not inspect repository cleanliness through the sanitized index" >&2
    return 1
  fi
  rm -f -- "$clean_index"
  if [[ -n $status ]]; then
    echo "source gate requires a clean committed revision" >&2
    return 1
  fi
}

require_empty_artifact_directory() {
  local -a entries
  shopt -s dotglob nullglob
  entries=("$artifact_directory"/*)
  shopt -u dotglob nullglob
  if (( ${#entries[@]} != 0 )); then
    echo "source gate artifact directory changed before evidence generation" >&2
    return 1
  fi
}

validate_source_relative_path() {
  local root=$1
  local relative=$2
  if [[ -z $relative || $relative == . || $relative == /* ||
        $relative == .git || $relative == .git/* ||
        $relative =~ [[:cntrl:]] ||
        $(realpath -m -- "$root/$relative") != "$root/$relative" ]]; then
    echo "source gate locked tree contains a non-canonical path" >&2
    return 1
  fi
}

prepare_locked_tree_inventory() {
  local temporary record metadata relative mode object_type object_id object_size expected_type
  local parent nul_count observed_count=0 blob_count=0 total_blob_size=0
  local -A expected_types=([.]=d)

  if [[ -n $locked_tree_inventory ]]; then
    echo "source gate locked tree inventory was already prepared" >&2
    return 1
  fi
  temporary=$(mktemp /tmp/workagent-source-gate-tree.XXXXXX)
  if ! git --git-dir="$object_repository" ls-tree -r -t -z --full-tree "$source_revision" > "$temporary"; then
    rm -f -- "$temporary"
    echo "source gate could not enumerate the complete locked tree" >&2
    return 1
  fi
  if [[ ! -s $temporary || $(stat -c '%s' -- "$temporary") -gt 33554432 ]]; then
    rm -f -- "$temporary"
    echo "source gate locked tree inventory is empty or too large" >&2
    return 1
  fi
  nul_count=$(tr -cd '\000' < "$temporary" | wc -c)
  if (( nul_count == 0 || nul_count > 20000 )); then
    rm -f -- "$temporary"
    echo "source gate locked tree entry count is invalid" >&2
    return 1
  fi
  locked_tree_inventory=$temporary
  while IFS= read -r -d '' record; do
    ((observed_count += 1))
    if [[ $record != *$'\t'* ]]; then
      echo "source gate locked tree inventory record is malformed" >&2
      return 1
    fi
    metadata=${record%%$'\t'*}
    relative=${record#*$'\t'}
    read -r mode object_type object_id <<< "$metadata"
    if ! validate_source_relative_path "$repo_root" "$relative" ||
      [[ ! $object_id =~ ^[0-9a-f]{40}$ ]]; then
      echo "source gate locked tree contains an unsupported entry" >&2
      return 1
    fi
    case "$mode $object_type" in
      '040000 tree') expected_type=d ;;
      '100644 blob'|'100755 blob') expected_type=f ;;
      *) echo "source gate locked tree contains a symlink, submodule, or unsupported mode" >&2; return 1 ;;
    esac
    if [[ -n ${expected_types[$relative]+present} ]]; then
      echo "source gate locked tree contains a duplicate or conflicting path" >&2
      return 1
    fi
    expected_types[$relative]=$expected_type
    parent=$(dirname -- "$relative")
    while [[ $parent != . ]]; do
      if [[ -n ${expected_types[$parent]+present} && ${expected_types[$parent]} != d ]]; then
        echo "source gate locked tree contains a file/directory conflict" >&2
        return 1
      fi
      expected_types[$parent]=d
      parent=$(dirname -- "$parent")
    done
    if [[ $object_type == blob ]]; then
      if ! object_size=$(git --git-dir="$object_repository" cat-file -s "$object_id") ||
        [[ ! $object_size =~ ^[0-9]+$ ]] || (( object_size > 134217728 )); then
        echo "source gate locked tree contains a missing or oversized blob" >&2
        return 1
      fi
      ((blob_count += 1))
      ((total_blob_size += object_size))
      if (( total_blob_size > 1073741824 )); then
        echo "source gate locked source bytes exceed the production bound" >&2
        return 1
      fi
    elif ! git --git-dir="$object_repository" cat-file -e "$object_id^{tree}"; then
      echo "source gate locked tree object is missing" >&2
      return 1
    fi
  done < "$temporary"
  if (( observed_count != nul_count || blob_count == 0 )); then
    echo "source gate locked tree inventory was truncated or has no files" >&2
    return 1
  fi
  chmod 0400 -- "$temporary"
}

verify_materialized_snapshot() {
  local fixed_snapshot=$1
  local purpose=$2
  local include_repository=$3
  local record metadata relative mode object_type object_id expected_mode path
  local parent actual_mode actual_uid actual_gid actual_links actual_object status
  local current_revision current_tree entry_type expected_type
  local expected_count=0 actual_count=0 tree_entries=0
  local -A expected_types=([.]=d)

  if [[ ! -d $fixed_snapshot || -L $fixed_snapshot || $(realpath -e -- "$fixed_snapshot") != "$fixed_snapshot" ]]; then
    echo "source gate $purpose snapshot root is unsafe" >&2
    return 1
  fi
  if [[ $(stat -c '%a' -- "$fixed_snapshot") != 700 ]]; then
    echo "source gate $purpose snapshot root mode drifted" >&2
    return 1
  fi
  if [[ $include_repository == true ]]; then
    if ! current_revision=$(git -C "$fixed_snapshot" rev-parse --verify 'HEAD^{commit}') ||
      ! current_tree=$(git -C "$fixed_snapshot" rev-parse --verify 'HEAD^{tree}') ||
      ! status=$(git -C "$fixed_snapshot" status --porcelain=v1 --untracked-files=all); then
      echo "source gate could not inspect the $purpose repository metadata" >&2
      return 1
    fi
    if [[ $current_revision != "$source_revision" || $current_tree != "$source_tree" || -n $status ]]; then
      echo "source gate $purpose repository metadata does not match the locked revision" >&2
      return 1
    fi
  fi

  while IFS= read -r -d '' record; do
    ((tree_entries += 1))
    if (( tree_entries > 20000 )) || [[ $record != *$'\t'* ]]; then
      echo "source gate locked tree inventory is invalid or too large" >&2
      return 1
    fi
    metadata=${record%%$'\t'*}
    relative=${record#*$'\t'}
    read -r mode object_type object_id <<< "$metadata"
    if ! validate_source_relative_path "$fixed_snapshot" "$relative" ||
      [[ ! $object_id =~ ^[0-9a-f]{40}$ ]]; then
      echo "source gate locked tree contains an unsupported entry" >&2
      return 1
    fi
    case "$mode $object_type" in
      '040000 tree') expected_mode=700; expected_type=d ;;
      '100644 blob') expected_mode=600; expected_type=f ;;
      '100755 blob') expected_mode=700; expected_type=f ;;
      *) echo "source gate locked tree contains a symlink, submodule, or unsupported mode" >&2; return 1 ;;
    esac
    if [[ -n ${expected_types[$relative]+present} ]]; then
      echo "source gate locked tree contains a duplicate or conflicting path" >&2
      return 1
    fi
    expected_types[$relative]=$expected_type
    parent=$(dirname -- "$relative")
    while [[ $parent != . ]]; do
      if [[ -n ${expected_types[$parent]+present} && ${expected_types[$parent]} != d ]]; then
        echo "source gate locked tree contains a file/directory conflict" >&2
        return 1
      fi
      expected_types[$parent]=d
      parent=$(dirname -- "$parent")
    done

    if [[ $object_type == tree ]]; then
      continue
    fi
    path=$fixed_snapshot/$relative
    if [[ ! -f $path || -L $path ]]; then
      echo "source gate $purpose snapshot is missing a locked regular file" >&2
      return 1
    fi
    read -r actual_mode actual_uid actual_gid actual_links < <(stat -c '%a %u %g %h' -- "$path")
    if [[ $actual_mode != "$expected_mode" || $actual_uid != "$source_gate_uid" ||
          $actual_gid != "$source_gate_gid" || $actual_links != 1 ]]; then
      echo "source gate $purpose snapshot file metadata drifted: $relative" >&2
      return 1
    fi
    actual_object=$(git --git-dir="$object_repository" hash-object --no-filters -- "$path")
    if [[ $actual_object != "$object_id" ]]; then
      echo "source gate $purpose snapshot bytes differ from the locked Git blob: $relative" >&2
      return 1
    fi
  done < "$locked_tree_inventory"
  if (( tree_entries == 0 )); then
    echo "source gate locked tree is empty" >&2
    return 1
  fi

  for relative in "${!expected_types[@]}"; do
    ((expected_count += 1))
    if [[ ${expected_types[$relative]} != d ]]; then
      continue
    fi
    if [[ $relative == . ]]; then
      path=$fixed_snapshot
    else
      path=$fixed_snapshot/$relative
    fi
    if [[ ! -d $path || -L $path ]]; then
      echo "source gate $purpose snapshot directory inventory drifted: $relative" >&2
      return 1
    fi
    read -r actual_mode actual_uid actual_gid < <(stat -c '%a %u %g' -- "$path")
    if [[ $actual_mode != 700 || $actual_uid != "$source_gate_uid" || $actual_gid != "$source_gate_gid" ]]; then
      echo "source gate $purpose snapshot directory metadata drifted: $relative" >&2
      return 1
    fi
  done

  while IFS= read -r -d '' path; do
    ((actual_count += 1))
    relative=${path#"$fixed_snapshot"/}
    if [[ -z ${expected_types[$relative]+present} || -L $path ]]; then
      echo "source gate $purpose snapshot contains an extra or unsafe entry: $relative" >&2
      return 1
    fi
    if [[ -d $path ]]; then
      entry_type=d
    elif [[ -f $path ]]; then
      entry_type=f
    else
      echo "source gate $purpose snapshot contains a special entry: $relative" >&2
      return 1
    fi
    expected_type=${expected_types[$relative]}
    if [[ $entry_type != "$expected_type" ]]; then
      echo "source gate $purpose snapshot entry type drifted: $relative" >&2
      return 1
    fi
  done < <(find "$fixed_snapshot" -mindepth 1 -path "$fixed_snapshot/.git" -prune -o -print0)
  if (( actual_count + 1 != expected_count )); then
    echo "source gate $purpose snapshot inventory is incomplete or has extras" >&2
    return 1
  fi
}

materialize_locked_tree() {
  local destination=$1
  local include_repository=$2
  local record metadata relative mode object_type object_id path parent expected_mode
  local -a entries

  if [[ ! -d $destination || -L $destination || $(realpath -e -- "$destination") != "$destination" ]]; then
    echo "source gate materialization destination is unsafe" >&2
    return 1
  fi
  shopt -s dotglob nullglob
  entries=("$destination"/*)
  shopt -u dotglob nullglob
  if (( ${#entries[@]} != 0 )); then
    echo "source gate materialization destination is not empty" >&2
    return 1
  fi
  if [[ $include_repository == true ]]; then
    git init --quiet --template="$empty_git_template" -- "$destination"
    git -C "$destination" config core.autocrlf false
    git -C "$destination" config core.filemode true
    git -C "$destination" config core.attributesFile /dev/null
    git -C "$destination" config core.hooksPath /dev/null
    git -C "$destination" -c fetch.fsckObjects=true fetch --quiet --no-tags "$object_repository" refs/workagent/source
    git -C "$destination" update-ref --no-deref HEAD "$source_revision"
    git -C "$destination" read-tree "$source_revision"
  fi

  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    relative=${record#*$'\t'}
    read -r mode object_type object_id <<< "$metadata"
    if ! validate_source_relative_path "$destination" "$relative" ||
      [[ ! $object_id =~ ^[0-9a-f]{40}$ ]]; then
      echo "source gate locked tree contains an unsupported entry" >&2
      return 1
    fi
    case "$mode $object_type" in
      '040000 tree') expected_mode=0700 ;;
      '100644 blob') expected_mode=0600 ;;
      '100755 blob') expected_mode=0700 ;;
      *) echo "source gate locked tree contains a symlink, submodule, or unsupported mode" >&2; return 1 ;;
    esac
    path=$destination/$relative
    if [[ $object_type == tree ]]; then
      mkdir -p -- "$path"
      chmod "$expected_mode" -- "$path"
      continue
    fi
    parent=$(dirname -- "$path")
    mkdir -p -- "$parent"
    git --git-dir="$object_repository" cat-file blob "$object_id" > "$path"
    chmod "$expected_mode" -- "$path"
  done < "$locked_tree_inventory"
  find "$destination" -mindepth 1 -path "$destination/.git" -prune -o -type d -exec chmod 0700 -- {} +
  chmod 0700 -- "$destination"
  verify_materialized_snapshot "$destination" "newly materialized" "$include_repository"
}

verify_build_snapshot() {
  verify_materialized_snapshot "$build_snapshot" "clean build" true
}

verify_artifact_envelope() {
  local include_evidence=$1
  local root_mode path name entry_type entry_mode entry_links expected
  local -a entries
  local -A expected_specs=(
    [control-plane]='d 555'
    [control-plane.spdx.json]='f 600'
    [control-plane.tree-modes.tsv]='f 400'
    [migration-tools]='d 500'
    [migration-tools.spdx.json]='f 600'
    [migration-tools.tree-modes.tsv]='f 400'
    [source-gate.json]='f 600'
    [source.spdx.json]='f 600'
  )
  root_mode=$(stat -c '%a' -- "$artifact_directory")
  if [[ ! -d $artifact_directory || -L $artifact_directory || $root_mode != 700 ]]; then
    echo "source gate artifact envelope root is unsafe" >&2
    return 1
  fi
  if [[ $include_evidence == true ]]; then
    expected_specs[EVIDENCE.sha256]='f 600'
  fi
  shopt -s dotglob nullglob
  entries=("$artifact_directory"/*)
  shopt -u dotglob nullglob
  if (( ${#entries[@]} != ${#expected_specs[@]} )); then
    echo "source gate artifact envelope inventory is incomplete or has extras" >&2
    return 1
  fi
  for path in "${entries[@]}"; do
    name=${path##*/}
    if [[ -z ${expected_specs[$name]+present} || -L $path ]]; then
      echo "source gate artifact envelope type, mode, or name drifted" >&2
      return 1
    fi
    if [[ -d $path ]]; then
      entry_type=d
    elif [[ -f $path ]]; then
      entry_type=f
    else
      echo "source gate artifact envelope contains a special entry" >&2
      return 1
    fi
    entry_mode=$(stat -c '%a' -- "$path")
    expected=${expected_specs[$name]}
    if [[ "$entry_type $entry_mode" != "$expected" ]]; then
      echo "source gate artifact envelope type, mode, or name drifted" >&2
      return 1
    fi
    if [[ $entry_type == f ]]; then
      entry_links=$(stat -c '%h' -- "$path")
      if (( entry_links != 1 )); then
        echo "source gate artifact envelope contains a multiply-linked file" >&2
        return 1
      fi
    fi
  done
}

# Fetch only Git objects into a new repository with no source-local config,
# hooks, info/attributes, or caller global/system configuration. Every later
# source tree is materialized directly from locked blob objects without any
# checkout, smudge, clean, text-conversion, or archive attribute path.
empty_git_template=$(mktemp -d /tmp/workagent-source-gate-git-template.XXXXXX)
object_repository=$(mktemp -d /tmp/workagent-source-gate-objects.XXXXXX)
git init --quiet --bare --template="$empty_git_template" -- "$object_repository"
git -c fetch.fsckObjects=true --git-dir="$object_repository" \
  fetch --quiet --no-tags "$repo_root" HEAD
fetched_revision=$(git --git-dir="$object_repository" rev-parse --verify 'FETCH_HEAD^{commit}')
fetched_tree=$(git --git-dir="$object_repository" rev-parse --verify 'FETCH_HEAD^{tree}')
if [[ $fetched_revision != "$source_revision" || $fetched_tree != "$source_tree" ]]; then
  echo "source gate object repository does not match the locked source" >&2
  exit 1
fi
git --git-dir="$object_repository" update-ref refs/workagent/source "$source_revision"
# Anchor status comparisons to the locked source rather than the bare
# repository's unborn default branch. The sole excluded worktree path in
# require_clean_source is the original repository metadata directory; locked
# tree validation rejects a committed .git entry before any materialization.
git --git-dir="$object_repository" update-ref --no-deref HEAD "$source_revision"
if [[ $(git --git-dir="$object_repository" rev-parse --verify 'HEAD^{commit}') != "$source_revision" ||
  $(git --git-dir="$object_repository" rev-parse --verify 'HEAD^{tree}') != "$source_tree" ]]; then
  echo "source gate object repository HEAD does not match the locked source" >&2
  exit 1
fi
git --git-dir="$object_repository" fsck --strict --no-dangling "$source_revision" >/dev/null
prepare_locked_tree_inventory

test_snapshot=$(mktemp -d)
materialize_locked_tree "$test_snapshot" true
verify_materialized_snapshot "$test_snapshot" "clean test" true
cd "$test_snapshot"
go_test_repository=$test_snapshot

# All checks that consume repository file bytes run only after the exact Git
# blobs have crossed the sanitized materialization boundary above.
shell_file_inventory=$(mktemp /tmp/workagent-source-gate-shell-files.XXXXXX)
if ! git ls-files -z -- '*.bash' '*.sh' \
  'deploy/libexec/workagent-core-activation-admission-v1' \
  'deploy/libexec/workagent-edge-publication-admission-v1' \
  'deploy/libexec/workagent-fixed-root-exec-v1' \
  'deploy/libexec/workagent-recovery-activation-admission-v1' > "$shell_file_inventory"; then
  echo "source gate could not enumerate managed shell scripts" >&2
  exit 1
fi
mapfile -d '' tracked_shell_files < "$shell_file_inventory"
rm -f -- "$shell_file_inventory"
shell_file_inventory=
if (( ${#tracked_shell_files[@]} == 0 )); then
  echo "source gate found no managed shell scripts" >&2
  exit 1
fi
for shell_file in "${tracked_shell_files[@]}"; do
  case "$shell_file" in
    scripts/*|components/*|deploy/libexec/workagent-core-activation-admission-v1|deploy/libexec/workagent-edge-publication-admission-v1|deploy/libexec/workagent-fixed-root-exec-v1|deploy/libexec/workagent-recovery-activation-admission-v1) ;;
    *) echo "tracked shell script is outside the explicit managed roots: $shell_file" >&2; exit 1 ;;
  esac
  if [[ ! -f $shell_file || -L $shell_file ]]; then
    echo "managed shell script is missing or is a symlink: $shell_file" >&2
    exit 1
  fi
done
bash -n "${tracked_shell_files[@]}"
$shellcheck_binary "${tracked_shell_files[@]}"
require_clean_source
empty_tree=$(git -C "$test_snapshot" hash-object -t tree /dev/null)
git -C "$test_snapshot" diff --check "$empty_tree" "$source_revision" -- .
$go_binary mod verify
$go_binary mod download all
$go_binary mod verify
export GOPROXY=off
export GOSUMDB=off
$go_binary list ./... >/dev/null
if [[ $source_gate_mode != artifact ]] && (( EUID != 0 )); then
  # Production includes both privileged control helpers and unprivileged
  # services. Run every package except the deliberately root-owned release
  # fixture under the runner identity, uncached, before repeating the complete
  # suites as root. This also proves frozen 0500/0400 fixture cleanup works.
  if ! package_list=$($go_binary list ./...); then
    echo "source gate could not enumerate the non-root Go test suite" >&2
    exit 1
  fi
  nonroot_packages=()
  while IFS= read -r package; do
    if [[ -n $package && $package != github.com/linziyan1231-source/WorkAgent2/linux/internal/release ]]; then
      nonroot_packages+=("$package")
    fi
  done <<< "$package_list"
  if (( ${#nonroot_packages[@]} == 0 )); then
    echo "source gate could not enumerate the non-root Go test suite" >&2
    exit 1
  fi
  $go_binary test -count=1 "${nonroot_packages[@]}"
  $go_binary test -count=1 -race "${nonroot_packages[@]}"
fi
if [[ $source_gate_mode != artifact ]]; then
  run_go_tests_as_production_owner -count=1 ./...
  run_go_tests_as_production_owner -count=1 -race ./...
  $go_binary vet ./...
  $govulncheck_binary ./...
  scripts/audit-tree.sh
  scripts/gitleaks-config-self-test.sh "$gitleaks_binary"
  verify_materialized_snapshot "$test_snapshot" "clean test" true
  quality_snapshot=$(mktemp -d)
  materialize_locked_tree "$quality_snapshot" false
  $gitleaks_binary dir --config "$quality_snapshot/.gitleaks.toml" --ignore-gitleaks-allow \
    --no-banner --redact --exit-code 1 "$quality_snapshot"
  verify_materialized_snapshot "$quality_snapshot" "quality scan" false
  if [[ $source_gate_mode == quality ]]; then
    require_clean_source
    require_empty_artifact_directory
    echo "source quality gate: PASS"
    exit 0
  fi
fi
require_clean_source
require_empty_artifact_directory
$go_binary mod verify
$go_binary list ./... >/dev/null

snapshot=$(mktemp -d)
materialize_locked_tree "$snapshot" false
verify_materialized_snapshot "$snapshot" "source evidence" false
$gitleaks_binary dir --config "$snapshot/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$snapshot"
$syft_binary scan "dir:$snapshot" --output "spdx-json=$artifact_directory/source.spdx.json"
verify_materialized_snapshot "$snapshot" "source evidence after scanners" false

# A fresh cache makes the artifact compilation independent of every test and
# analysis binary compiled above while retaining the separately verified,
# offline module cache.
export GOCACHE="$source_gate_cache_root/build"
build_snapshot=$(mktemp -d)
materialize_locked_tree "$build_snapshot" true
verify_build_snapshot
cd "$build_snapshot"
mode_freeze_helper=$build_snapshot/scripts/freeze-release-tree-modes.sh
content_manifest_helper=$build_snapshot/scripts/release-tree-sha256.sh
printf '%s\n' \
  '{' \
  '  "schema_version": 2,' \
  "  \"source_revision\": \"$source_revision\"," \
  '  "target": "linux/amd64",' \
  '  "go_version": "1.26.5",' \
  '  "gitleaks_version": "8.28.0",' \
  '  "syft_version": "1.29.0",' \
  '  "govulncheck_version": "1.6.0",' \
  '  "shellcheck_version": "0.11.0",' \
  '  "content_manifest_version": 1,' \
  '  "tree_mode_manifest_version": 1,' \
  '  "control_plane_mode_profile": "public",' \
  '  "migration_tools_mode_profile": "root-only"' \
  '}' > "$artifact_directory/source-gate.json"

verify_go_build_identity() {
  if (( $# != 2 )); then
    echo "verify_go_build_identity requires a binary path and evidence label" >&2
    return 1
  fi
  local binary_path=$1
  local evidence_label=$2
  local expected_main_path=github.com/linziyan1231-source/WorkAgent2/linux/cmd/$evidence_label
  local build_information
  local path_keys path_matches vcs_keys vcs_matches revision_keys revision_matches modified_keys modified_matches

  build_information=$($go_binary version -m "$binary_path") || {
    echo "could not read embedded build information from $evidence_label" >&2
    return 1
  }
  read -r path_keys path_matches vcs_keys vcs_matches revision_keys revision_matches modified_keys modified_matches < <(
    /usr/bin/awk -F '\t' -v expected_path="$expected_main_path" -v revision="$source_revision" '
      $2 == "path" { path_keys++; if ($3 == expected_path) path_matches++ }
      $2 == "build" && index($3, "vcs=") == 1 { vcs_keys++; if ($3 == "vcs=git") vcs_matches++ }
      $2 == "build" && index($3, "vcs.revision=") == 1 { revision_keys++; if ($3 == "vcs.revision=" revision) revision_matches++ }
      $2 == "build" && index($3, "vcs.modified=") == 1 { modified_keys++; if ($3 == "vcs.modified=false") modified_matches++ }
      END { print path_keys+0, path_matches+0, vcs_keys+0, vcs_matches+0, revision_keys+0, revision_matches+0, modified_keys+0, modified_matches+0 }
    ' <<< "$build_information"
  )
  if [[ $path_keys != 1 || $path_matches != 1 || $vcs_keys != 1 || $vcs_matches != 1 || $revision_keys != 1 || $revision_matches != 1 ||
        $modified_keys != 1 || $modified_matches != 1 ]]; then
    echo "$evidence_label does not embed one exact clean Git source identity" >&2
    return 1
  fi
}

binary_directory=$artifact_directory/control-plane/bin
mkdir -p "$binary_directory"
go_control_commands=(
  workagent-admin
  workagent-backup
  workagent-cliproxy
  workagent-import-stage
  workagent-notification
  workagent-portal
  workagent-provision
  workagent-release
  workagent-secret
  workagent-userhost
)
for command in "${go_control_commands[@]}"; do
  CGO_ENABLED=0 $go_binary build -trimpath -buildvcs=true -ldflags=-buildid= \
    -o "$binary_directory/$command" "./cmd/$command"
done
for command in "${go_control_commands[@]}"; do
  verify_go_build_identity "$binary_directory/$command" "$command"
done
install -m 0555 scripts/production-healthcheck.sh "$binary_directory/workagent-healthcheck"
administration_directory=$artifact_directory/control-plane/admin
mkdir -p "$administration_directory"
install -m 0555 scripts/install-edge-publication-admission-v1.sh "$administration_directory/install-edge-publication-admission-v1"
install -m 0555 scripts/install-core-activation-admission-v1.sh "$administration_directory/install-core-activation-admission-v1"
install -m 0555 scripts/install-fixed-root-exec-v1.sh "$administration_directory/install-fixed-root-exec-v1"
install -m 0555 scripts/install-recovery-activation-admission-v1.sh "$administration_directory/install-recovery-activation-admission-v1"
install -m 0555 scripts/production-host-prepare.sh "$administration_directory/production-host-prepare"
install -m 0555 scripts/production-preflight.sh "$administration_directory/production-preflight"
install -m 0555 scripts/smoke-chatforward-browser-sandbox.sh "$administration_directory/smoke-chatforward-browser-sandbox"
install -m 0555 scripts/verify-host-rpms.sh "$administration_directory/verify-host-rpms"
share_directory=$artifact_directory/control-plane/share
mkdir -p "$share_directory"
cp -a -- LICENSE_STATUS.md SECURITY.md config deploy docs "$share_directory/"
printf '%s\n' \
  '[' \
  '  {' \
  '    "name": "workagent-control",' \
  "    \"version\": \"git-${source_revision:0:12}\"," \
  "    \"source_revision\": \"$source_revision\"" \
  '  }' \
  ']' > "$artifact_directory/control-plane/components.portal.json"
"$content_manifest_helper" write "$artifact_directory/control-plane" >/dev/null
control_executables=(
  admin/install-core-activation-admission-v1
  admin/install-edge-publication-admission-v1
  admin/install-fixed-root-exec-v1
  admin/install-recovery-activation-admission-v1
  admin/production-host-prepare
  admin/production-preflight
  admin/smoke-chatforward-browser-sandbox
  admin/verify-host-rpms
  bin/workagent-admin
  bin/workagent-backup
  bin/workagent-cliproxy
  bin/workagent-healthcheck
  bin/workagent-import-stage
  bin/workagent-notification
  bin/workagent-portal
  bin/workagent-provision
  bin/workagent-release
  bin/workagent-secret
  bin/workagent-userhost
  share/deploy/libexec/workagent-core-activation-admission-v1
  share/deploy/libexec/workagent-edge-publication-admission-v1
  share/deploy/libexec/workagent-fixed-root-exec-v1
  share/deploy/libexec/workagent-recovery-activation-admission-v1
)
"$mode_freeze_helper" freeze public "$artifact_directory/control-plane" \
  "$artifact_directory/control-plane.tree-modes.tsv" "${control_executables[@]}"
"$binary_directory/workagent-release" validate-layout \
  --root "$artifact_directory/control-plane" --profile public >/dev/null
"$content_manifest_helper" verify "$artifact_directory/control-plane" >/dev/null
$syft_binary scan "dir:$artifact_directory/control-plane" \
  --output "spdx-json=$artifact_directory/control-plane.spdx.json"
$gitleaks_binary dir --config "$build_snapshot/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$artifact_directory/control-plane"

# The Windows capture and migration commands are intentionally a separate,
# root-only offline package:
# it is source-gated but cannot be mistaken for an online production service.
migration_directory=$artifact_directory/migration-tools/bin
mkdir -p "$migration_directory"
go_migration_commands=(
  workagent-capture-windows
  workagent-migrate-windows
)
for command in "${go_migration_commands[@]}"; do
  CGO_ENABLED=0 $go_binary build -trimpath -buildvcs=true -ldflags=-buildid= \
    -o "$migration_directory/$command" "./cmd/$command"
done
for command in "${go_migration_commands[@]}"; do
  verify_go_build_identity "$migration_directory/$command" "$command"
done
"$content_manifest_helper" write "$artifact_directory/migration-tools" >/dev/null
migration_executables=(
  bin/workagent-capture-windows
  bin/workagent-migrate-windows
)
"$mode_freeze_helper" freeze root-only "$artifact_directory/migration-tools" \
  "$artifact_directory/migration-tools.tree-modes.tsv" "${migration_executables[@]}"
"$binary_directory/workagent-release" validate-layout \
  --root "$artifact_directory/migration-tools" --profile root-only >/dev/null
"$content_manifest_helper" verify "$artifact_directory/migration-tools" >/dev/null
$syft_binary scan "dir:$artifact_directory/migration-tools" \
  --output "spdx-json=$artifact_directory/migration-tools.spdx.json"
$gitleaks_binary dir --config "$build_snapshot/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$artifact_directory/migration-tools"

# Scanners are not trusted to preserve metadata. Revalidate the exact executable
# allow-lists, complete type/mode/path manifests, link counts, xattr policy and
# content inventories for both payloads immediately before outer evidence is
# published.
"$mode_freeze_helper" verify public "$artifact_directory/control-plane" \
  "$artifact_directory/control-plane.tree-modes.tsv" "${control_executables[@]}"
"$binary_directory/workagent-release" validate-layout \
  --root "$artifact_directory/control-plane" --profile public >/dev/null
"$content_manifest_helper" verify "$artifact_directory/control-plane" >/dev/null
"$mode_freeze_helper" verify root-only "$artifact_directory/migration-tools" \
  "$artifact_directory/migration-tools.tree-modes.tsv" "${migration_executables[@]}"
"$binary_directory/workagent-release" validate-layout \
  --root "$artifact_directory/migration-tools" --profile root-only >/dev/null
"$content_manifest_helper" verify "$artifact_directory/migration-tools" >/dev/null
# Repeat embedded package/VCS identity admission after scanners and the final
# content checks. This independently catches accidental cross-command binary
# substitution even if a local content manifest was regenerated before the
# outer evidence envelope is sealed. Checksum-pinned scanners remain trusted
# for non-Go payloads such as the healthcheck script.
for command in "${go_control_commands[@]}"; do
  verify_go_build_identity "$binary_directory/$command" "$command"
done
for command in "${go_migration_commands[@]}"; do
  verify_go_build_identity "$migration_directory/$command" "$command"
done
require_clean_source
verify_build_snapshot
chmod 0600 -- \
  "$artifact_directory/control-plane.spdx.json" \
  "$artifact_directory/migration-tools.spdx.json" \
  "$artifact_directory/source-gate.json" \
  "$artifact_directory/source.spdx.json"
verify_artifact_envelope false

(
  cd "$artifact_directory"
  sha256sum \
    control-plane.spdx.json \
    control-plane/SHA256SUMS \
    control-plane.tree-modes.tsv \
    migration-tools.spdx.json \
    migration-tools/SHA256SUMS \
    migration-tools.tree-modes.tsv \
    source-gate.json \
    source.spdx.json > EVIDENCE.sha256
)
chmod 0600 -- "$artifact_directory/EVIDENCE.sha256"
verify_artifact_envelope true

echo "source artifact gate: PASS"
