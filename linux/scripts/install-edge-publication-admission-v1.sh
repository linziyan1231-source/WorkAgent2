#!/bin/bash
set -euo pipefail
export LC_ALL=C
export PATH=/usr/bin:/bin

readonly destination=/usr/libexec/workagent-edge-publication-admission-v1
readonly install_lock=/run/workagent/fixed-root-exec-v1-install.lock
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
readonly source_file=$script_directory/../share/deploy/libexec/workagent-edge-publication-admission-v1
readonly stage_prefix=/usr/libexec/.workagent-edge-publication-admission-v1.
temporary=
temporary_durable=false

fail() {
  printf 'install-edge-publication-admission-v1: %s\n' "$*" >&2
  exit 1
}

valid_stage_name() {
  local staged=$1 suffix
  [[ $staged == "$stage_prefix"* ]] || return 1
  suffix=${staged#"$stage_prefix"}
  [[ $suffix =~ ^[A-Za-z0-9]{8}$ ]]
}

verify_work_stage() {
  local staged=$1
  valid_stage_name "$staged" || return 1
  [[ -f $staged && ! -L $staged ]] || return 1
  [[ $(stat -Lc '%u:%g:%a:%h' -- "$staged" 2>/dev/null || true) == 0:0:600:1 ]]
}

cleanup() {
  if [[ $temporary_durable == false && -n $temporary ]] && verify_work_stage "$temporary"; then
    unlink -- "$temporary" 2>/dev/null || true
    sync -f -- /usr/libexec 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if (( $# != 0 )); then
  fail "this installer accepts no arguments"
fi
if (( EUID != 0 )); then
  fail "root is required"
fi
if [[ ! -f $source_file || -L $source_file || $(stat -Lc '%U:%G:%a:%h' -- "$source_file" 2>/dev/null || true) != root:root:555:1 ]]; then
  fail "the immutable edge publication admission helper is absent from final source-gate evidence"
fi
for directory in /usr /usr/libexec; do
  if [[ -L $directory || ! -d $directory || $(readlink -f -- "$directory" 2>/dev/null || true) != "$directory" ]]; then
    fail "$directory is not a canonical directory"
  fi
  directory_owner=$(stat -Lc '%u:%g' -- "$directory" 2>/dev/null || true)
  directory_mode=$(stat -Lc '%a' -- "$directory" 2>/dev/null || true)
  if [[ $directory_owner != 0:0 || ! $directory_mode =~ ^[0-7]{3,4}$ ]] || (( (8#$directory_mode & 022) != 0 )); then
    fail "$directory is writable by an unprivileged account"
  fi
done
if [[ ! -f $install_lock || -L $install_lock || $(stat -Lc '%u:%g:%a:%h:%s' -- "$install_lock" 2>/dev/null || true) != 0:0:600:1:0 ]]; then
  fail "the immutable-helper installer lock is unsafe"
fi
exec 9<>"$install_lock"
/usr/bin/flock --exclusive 9 || fail "acquire immutable-helper installer serialization lock"
if [[ $(readlink /proc/self/fd/9 2>/dev/null || true) != "$install_lock" ||
      $(stat -Lc '%u:%g:%a:%h:%s' -- /proc/self/fd/9 2>/dev/null || true) != 0:0:600:1:0 ||
      $(stat -Lc '%d:%i' -- /proc/self/fd/9 2>/dev/null || true) != $(stat -Lc '%d:%i' -- "$install_lock" 2>/dev/null || true) ]]; then
  fail "the immutable-helper installer lock changed during acquisition"
fi

verify_copy() {
  local path=$1 expected_links=$2
  [[ -f $path && ! -L $path ]] || return 1
  [[ $(stat -Lc '%U:%G:%a:%h' -- "$path" 2>/dev/null || true) == "root:root:555:$expected_links" ]] || return 1
  cmp -s -- "$source_file" "$path"
}

verify_installed() { verify_copy "$destination" 1; }

discard_work_stage() {
  local staged=$1
  verify_work_stage "$staged" || return 1
  unlink -- "$staged" || fail "could not discard the interrupted admission-helper work stage"
  if [[ $temporary == "$staged" ]]; then
    temporary=
    temporary_durable=false
  fi
  sync -f -- /usr/libexec || fail "could not make the discarded admission-helper stage durable"
}

finish_linked_copy() {
  local staged=$1 staged_inode destination_inode
  verify_copy "$staged" 2 || fail "the interrupted staged admission helper is unsafe"
  verify_copy "$destination" 2 || fail "the interrupted admission-helper destination is unsafe"
  staged_inode=$(stat -Lc '%d:%i' -- "$staged" 2>/dev/null || true)
  destination_inode=$(stat -Lc '%d:%i' -- "$destination" 2>/dev/null || true)
  [[ -n $staged_inode && $staged_inode == "$destination_inode" ]] || fail "interrupted admission-helper links do not name one inode"
  sync -f -- "$destination"
  sync -f -- /usr/libexec
  unlink -- "$staged"
  if [[ $temporary == "$staged" ]]; then
    temporary=
    temporary_durable=false
  fi
  sync -f -- /usr/libexec
  verify_installed || fail "the reconciled admission helper failed its durable read-back"
}

publish_staged_copy() {
  local staged=$1
  verify_copy "$staged" 1 || fail "the staged admission helper has unsafe bytes or metadata"
  sync -f -- "$staged"
  ln -T -- "$staged" "$destination" || fail "the versioned admission-helper destination appeared with conflicting state"
  sync -f -- /usr/libexec
  finish_linked_copy "$staged"
}

create_staged_copy() {
  local source_size staged_size
  temporary=$(mktemp --tmpdir=/usr/libexec .workagent-edge-publication-admission-v1.XXXXXXXX)
  valid_stage_name "$temporary" || fail "mktemp returned an unexpected admission-helper stage name"
  [[ $(stat -Lc '%u:%g:%a:%h:%s' -- "$temporary" 2>/dev/null || true) == 0:0:600:1:0 ]] ||
    fail "mktemp created an unsafe admission-helper stage"
  sync -f -- /usr/libexec || fail "could not make the empty admission-helper stage durable"
  /usr/bin/dd if="$source_file" of="$temporary" bs=4096 conv=notrunc status=none
  source_size=$(stat -Lc '%s' -- "$source_file" 2>/dev/null || true)
  staged_size=$(stat -Lc '%s' -- "$temporary" 2>/dev/null || true)
  [[ $source_size =~ ^[1-9][0-9]*$ && $staged_size == "$source_size" ]] || fail "the staged admission-helper copy is incomplete"
  verify_work_stage "$temporary" || fail "the staged admission-helper work inode changed"
  cmp -s -- "$source_file" "$temporary" || fail "the staged admission-helper copy does not match its source"
  sync -f -- "$temporary" || fail "could not make the mode-0600 admission-helper copy durable"
  chmod 0555 -- "$temporary"
  sync -f -- "$temporary" || fail "could not make the admission-helper mode transition durable"
  verify_copy "$temporary" 1 || fail "the staged admission-helper bytes or metadata changed"
  temporary_durable=true
}

shopt -s nullglob
reserved_temporaries=("$stage_prefix"*)
shopt -u nullglob
if (( ${#reserved_temporaries[@]} > 1 )); then
  fail "multiple interrupted admission-helper stages are ambiguous"
fi
if (( ${#reserved_temporaries[@]} == 1 )); then
  temporary=${reserved_temporaries[0]}
  temporary_durable=true
  valid_stage_name "$temporary" || fail "the reserved admission-helper namespace contains an unexpected entry"
fi

destination_present=false
if [[ -e $destination || -L $destination ]]; then
  destination_present=true
fi
if [[ -n $temporary && $destination_present == true ]]; then
  temporary_inode=$(stat -Lc '%d:%i' -- "$temporary" 2>/dev/null || true)
  destination_inode=$(stat -Lc '%d:%i' -- "$destination" 2>/dev/null || true)
  if verify_copy "$temporary" 2 && verify_copy "$destination" 2 && [[ -n $temporary_inode && $temporary_inode == "$destination_inode" ]]; then
    finish_linked_copy "$temporary"
    printf 'reconciled linked immutable edge publication admission helper v1\n'
    exit 0
  fi
  fail "the interrupted admission-helper state is ambiguous or conflicting"
elif [[ -n $temporary ]]; then
  if verify_copy "$temporary" 1; then
    publish_staged_copy "$temporary"
    printf 'resumed immutable edge publication admission helper v1 installation\n'
    exit 0
  elif discard_work_stage "$temporary"; then
    printf 'discarded interrupted admission-helper work stage before retry\n'
  else
    fail "the interrupted admission-helper stage is neither complete nor an authorized work inode"
  fi
elif [[ $destination_present == true ]]; then
  verify_installed || fail "the versioned admission-helper destination exists with conflicting bytes or metadata"
  printf 'edge publication admission helper v1 is already installed and verified\n'
  exit 0
fi

create_staged_copy
publish_staged_copy "$temporary"
printf 'installed immutable edge publication admission helper v1\n'
