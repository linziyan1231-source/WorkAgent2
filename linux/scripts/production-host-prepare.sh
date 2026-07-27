#!/usr/bin/env bash
set -Eeuo pipefail

# Creates only the dedicated tenant-storage image and its mount unit. It never
# archives, moves, removes, follows, or mounts over an existing tenant entry.

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 0077

readonly image_path=/var/lib/workagent-storage/tenants.xfs
readonly image_parent=/var/lib/workagent-storage
readonly mount_path=/srv/workagent/users
readonly mount_parent=/srv/workagent
readonly mount_unit_name=srv-workagent-users.mount
readonly mount_unit_path=/etc/systemd/system/$mount_unit_name
# XFS labels are limited to 12 bytes.
readonly image_label=wa-tenants
readonly tenant_count=8
readonly tenant_quota_bytes=$((20 * 1024 * 1024 * 1024))
readonly total_quota_bytes=$((tenant_count * tenant_quota_bytes))
readonly image_size_bytes=$((192 * 1024 * 1024 * 1024))
readonly backing_reserve_bytes=$((32 * 1024 * 1024 * 1024))
readonly minimum_backing_available_bytes=$((image_size_bytes + backing_reserve_bytes))
readonly confirmation=PREPARE-WORKAGENT-TENANT-STORAGE

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(dirname -- "$script_directory")
unit_source=
unit_source_override=
mode=check
replace_mount_unit=false
confirmed=false

usage() {
  cat >&2 <<EOF
usage:
  scripts/production-host-prepare.sh --check
  scripts/production-host-prepare.sh --apply --confirm $confirmation [--replace-mount-unit] [--unit-source ABSOLUTE_PATH]

--check is read-only. --apply refuses active WorkAgent services, non-empty
$mount_path, unsafe existing files, insufficient backing space, or a differing
mount unit unless --replace-mount-unit is also explicit. It does not migrate or
archive tenant data.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --check)
      mode=check
      shift
      ;;
    --apply)
      mode=apply
      shift
      ;;
    --confirm)
      (( $# >= 2 )) || { usage; exit 2; }
      [[ $2 == "$confirmation" ]] || { echo "invalid confirmation token" >&2; exit 2; }
      confirmed=true
      shift 2
      ;;
    --replace-mount-unit)
      replace_mount_unit=true
      shift
      ;;
    --unit-source)
      (( $# >= 2 )) || { usage; exit 2; }
      unit_source_override=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -n $unit_source_override ]]; then
  [[ $unit_source_override == /* && $unit_source_override != *//* && $unit_source_override != */../* && $unit_source_override != */./* && $unit_source_override != */.. && $unit_source_override != */. && $unit_source_override != */ ]] || { echo "--unit-source must be a clean absolute path" >&2; exit 2; }
  unit_source=$unit_source_override
elif [[ -f $repository_root/deploy/systemd/$mount_unit_name ]]; then
  unit_source=$repository_root/deploy/systemd/$mount_unit_name
elif [[ -f $repository_root/share/deploy/systemd/$mount_unit_name ]]; then
  unit_source=$repository_root/share/deploy/systemd/$mount_unit_name
else
  unit_source=$repository_root/deploy/systemd/$mount_unit_name
fi

failures=0
created_temporary=
created_unit_temporary=
created_backup_temporary=
created_acl_test=

pass() { printf 'PASS  %s\n' "$*"; }
info() { printf 'INFO  %s\n' "$*"; }
fail() { printf 'BLOCK %s\n' "$*" >&2; failures=$((failures + 1)); }
die() { printf 'BLOCK %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n $created_temporary && $created_temporary == "$image_parent"/.tenants.xfs.* && -f $created_temporary && ! -L $created_temporary ]]; then
    rm -f -- "$created_temporary"
  fi
  if [[ -n $created_unit_temporary && $created_unit_temporary == /etc/systemd/system/.srv-workagent-users.mount.* && -f $created_unit_temporary && ! -L $created_unit_temporary ]]; then
    rm -f -- "$created_unit_temporary"
  fi
  if [[ -n $created_backup_temporary && $created_backup_temporary == /etc/systemd/system/srv-workagent-users.mount.backup.* && -f $created_backup_temporary && ! -L $created_backup_temporary ]]; then
    rm -f -- "$created_backup_temporary"
  fi
  if [[ -n $created_acl_test && $created_acl_test == "$mount_path"/.workagent-acl-check.* && -f $created_acl_test && ! -L $created_acl_test ]]; then
    rm -f -- "$created_acl_test"
  fi
}
trap cleanup EXIT

require_commands() {
  local command
  for command in awk blkid chmod chown cmp cut date df find findmnt getfacl grep id install ln losetup mkfs.xfs mktemp mountpoint mv rm setfacl sha256sum stat sync systemctl systemd-analyze truncate uname xfs_info xfs_quota; do
    if command -v "$command" >/dev/null 2>&1; then
      pass "required command is available: $command"
    else
      fail "required command is unavailable: $command"
    fi
  done
}

safe_root_directory() {
  local path=$1 required_mode=$2 owner mode
  [[ -d $path && ! -L $path ]] || return 1
  owner=$(stat -Lc '%u:%g' -- "$path") || return 1
  mode=$(stat -Lc '%a' -- "$path") || return 1
  [[ $owner == 0:0 && $mode == "$required_mode" ]]
}

directory_is_empty() {
  [[ -d $1 && ! -L $1 ]] || return 1
  [[ -z $(find "$1" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null) ]]
}

workagent_services_inactive() {
  local unit state active=0
  local -a units=(
    workagent-portal.service
    workagent-tenant-catalog-ready.target
    workagent-tenant-config-reconcile.service
    cliproxyapi.service
    workagent-notification.service
    workagent-chatforward.service
    workagent-chatforward-browser.service
    workagent-backup.service
    workagent-backup.timer
    workagent-healthcheck.service
    workagent-healthcheck.timer
    srv-workagent-users.mount
  )
  while IFS= read -r unit; do
    [[ -n $unit ]] && units+=("$unit")
  done < <(systemctl list-units --all --type=service --plain --no-legend 'workagent-userhost@*.service' 2>/dev/null | awk '{print $1}')
  while IFS= read -r unit; do
    [[ -n $unit ]] && units+=("$unit")
  done < <(systemctl list-units --all --type=socket --plain --no-legend 'workagent-userhost@*.socket' 2>/dev/null | awk '{print $1}')
  for unit in "${units[@]}"; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    if [[ $state == active || $state == activating || $state == deactivating ]]; then
      fail "$unit must be inactive before tenant storage preparation"
      active=1
    fi
  done
  (( active == 0 ))
}

check_host_primitives() {
  local version controllers ptrace_scope
  if [[ $EUID == 0 ]]; then
    pass "running as root for complete host verification"
  else
    fail "run as root for complete host verification"
  fi
  if [[ $(uname -s) == Linux ]]; then
    pass "Linux kernel detected"
  else
    fail "Linux is required"
  fi
  version=$(systemctl --version 2>/dev/null | awk 'NR == 1 {print $2}')
  if [[ $version =~ ^[0-9]+$ ]] && (( version >= 255 )); then
    pass "systemd $version satisfies the service contract"
  else
    fail "systemd 255 or newer is required for named OpenFile lifecycle guards"
  fi
  if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    controllers=$(< /sys/fs/cgroup/cgroup.controllers)
    if [[ " $controllers " == *" cpu "* && " $controllers " == *" memory "* && " $controllers " == *" pids "* ]]; then
      pass "cgroup v2 exposes cpu, memory, and pids controllers"
    else
      fail "cgroup v2 is missing cpu, memory, or pids control"
    fi
  else
    fail "unified cgroup v2 is not active"
  fi
  ptrace_scope=
  if [[ -r /proc/sys/kernel/yama/ptrace_scope ]]; then
    IFS= read -r ptrace_scope < /proc/sys/kernel/yama/ptrace_scope || true
  fi
  if [[ $ptrace_scope =~ ^[0-3]$ ]] && (( ptrace_scope >= 2 )); then
    pass "kernel ptrace scope $ptrace_scope protects tenant supervisor secrets"
  else
    fail "kernel.yama.ptrace_scope must be at least 2"
  fi
  if [[ -s $unit_source && ! -L $unit_source ]] &&
     [[ $(stat -Lc '%u' -- "$unit_source" 2>/dev/null || true) == 0 ]] &&
     (( (8#$(stat -Lc '%a' -- "$unit_source" 2>/dev/null || printf 777) & 022) == 0 )); then
    pass "tracked mount unit is available"
  else
    fail "tracked mount unit is unavailable or linked"
  fi
}

check_backing_capacity() {
  local purpose=${1:-existing} available filesystem minimum description
  available=$(df -B1 --output=avail "$image_parent" 2>/dev/null | awk 'NR == 2 {print $1}')
  filesystem=$(findmnt -rn -T "$image_parent" -o FSTYPE 2>/dev/null || true)
  if [[ $filesystem == xfs ]]; then
    pass "tenant image is backed by XFS"
  else
    fail "tenant image backing filesystem must be XFS (found ${filesystem:-unknown})"
  fi
  if [[ $purpose == creation ]]; then
    minimum=$minimum_backing_available_bytes
    description='224 GiB creation headroom'
  else
    minimum=$backing_reserve_bytes
    description='32 GiB emergency reserve'
  fi
  if [[ $available =~ ^[0-9]+$ ]] && (( available >= minimum )); then
    pass "backing filesystem preserves the required $description"
  else
    fail "backing filesystem does not preserve the required $description"
  fi
}

check_existing_image() {
  local owner mode size type label
  if [[ ! -e $image_path && ! -L $image_path ]]; then
    fail "tenant image has not been created"
    return 1
  fi
  if [[ -L $image_path || ! -f $image_path ]]; then
    fail "existing tenant image path is not a regular non-symlink file"
    return 1
  fi
  owner=$(stat -Lc '%u:%g' -- "$image_path")
  mode=$(stat -Lc '%a' -- "$image_path")
  size=$(stat -Lc '%s' -- "$image_path")
  type=$(blkid -p -s TYPE -o value -- "$image_path" 2>/dev/null || true)
  label=$(blkid -p -s LABEL -o value -- "$image_path" 2>/dev/null || true)
  if [[ $owner != 0:0 || $mode != 600 || $size != "$image_size_bytes" || $type != xfs || $label != "$image_label" ]]; then
    fail "existing tenant image does not match the protected 192 GiB XFS contract"
    return 1
  fi
  pass "existing tenant image matches the protected 192 GiB XFS contract"
}

check_mount() {
  local filesystem options source loops loop
  if ! mountpoint -q -- "$mount_path"; then
    info "$mount_path is not mounted"
    return 1
  fi
  filesystem=$(findmnt -rn -T "$mount_path" -o FSTYPE)
  options=$(findmnt -rn -T "$mount_path" -o OPTIONS)
  source=$(findmnt -rn -T "$mount_path" -o SOURCE)
  if [[ $filesystem != xfs || ,$options, != *,prjquota,* && ,$options, != *,pquota,* ]]; then
    fail "$mount_path is mounted without XFS project-quota enforcement"
    return 1
  fi
  loops=$(losetup -j "$image_path" 2>/dev/null | cut -d: -f1 || true)
  loop=false
  while IFS= read -r candidate; do
    [[ -n $candidate && $source == "$candidate" ]] && loop=true
  done <<< "$loops"
  if [[ $loop != true ]]; then
    fail "$mount_path is not backed by the dedicated tenant image"
    return 1
  fi
  if xfs_quota -x -c state "$mount_path" 2>/dev/null | grep -Eq 'Project quota state.*|Project quota.*ON' &&
     xfs_quota -x -c state "$mount_path" 2>/dev/null | grep -Eq 'Accounting:.*ON' &&
     xfs_quota -x -c state "$mount_path" 2>/dev/null | grep -Eq 'Enforcement:.*ON'; then
    pass "XFS project-quota accounting and enforcement are active"
  else
    fail "XFS project-quota accounting or enforcement is inactive"
    return 1
  fi
  pass "$mount_path uses the dedicated loopback XFS image"
}

read_only_check() {
  require_commands
  check_host_primitives
  if [[ -e $image_parent ]]; then
    if safe_root_directory "$image_parent" 700; then
      pass "$image_parent is a protected root-owned directory"
      if [[ -e $image_path && ! -L $image_path ]]; then
        check_backing_capacity existing
      else
        check_backing_capacity creation
      fi
    else
      fail "$image_parent exists with unsafe type, owner, or mode"
    fi
  else
    fail "$image_parent has not been created"
    available=$(df -B1 --output=avail /var/lib 2>/dev/null | awk 'NR == 2 {print $1}')
    if [[ $available =~ ^[0-9]+$ ]] && (( available >= minimum_backing_available_bytes )); then
      pass "/var/lib has at least 224 GiB available for preparation"
    else
      fail "/var/lib lacks the required 224 GiB preparation headroom"
    fi
  fi
  if [[ -e $mount_path || -L $mount_path ]]; then
    if [[ -L $mount_path || ! -d $mount_path ]]; then
      fail "$mount_path is not a real directory"
    elif mountpoint -q -- "$mount_path"; then
      check_existing_image || true
      check_mount || true
    elif directory_is_empty "$mount_path"; then
      pass "$mount_path is empty and safe to mount"
      check_existing_image || true
      fail "$mount_path is not mounted"
    else
      fail "$mount_path is not mounted and contains existing entries; archive them separately before preparation"
    fi
  else
    fail "$mount_path does not exist"
  fi
  if [[ -e $mount_unit_path || -L $mount_unit_path ]]; then
    if [[ ! -L $mount_unit_path && -f $mount_unit_path ]] && cmp -s -- "$unit_source" "$mount_unit_path"; then
      pass "installed mount unit matches the tracked production unit"
    else
      fail "installed mount unit differs or is unsafe"
    fi
  else
    fail "dedicated mount unit has not been installed"
  fi
  if (( failures > 0 )); then
    return 1
  fi
}

create_image() {
  local temporary
  if [[ -e $image_path || -L $image_path ]]; then
    check_existing_image || die "refusing to replace the existing tenant image"
    return
  fi
  temporary=$(mktemp --tmpdir="$image_parent" .tenants.xfs.XXXXXXXX)
  created_temporary=$temporary
  truncate -s "$image_size_bytes" -- "$temporary"
  chmod 0600 -- "$temporary"
  chown root:root -- "$temporary"
  mkfs.xfs -f -L "$image_label" -- "$temporary" >/dev/null
  [[ $(blkid -p -s TYPE -o value -- "$temporary") == xfs ]] || die "new tenant image did not format as XFS"
  [[ $(blkid -p -s LABEL -o value -- "$temporary") == "$image_label" ]] || die "new tenant image label verification failed"
  sync -f "$temporary"
  ln -- "$temporary" "$image_path" || die "tenant image appeared concurrently; refusing to replace it"
  rm -f -- "$temporary"
  created_temporary=
  sync -f "$image_parent"
  pass "created the protected sparse 192 GiB tenant image"
}

install_mount_unit() {
  local temporary backup timestamp replace_existing=false expected_identity current_identity
  if [[ -e $mount_unit_path || -L $mount_unit_path ]]; then
    if [[ ! -L $mount_unit_path && -f $mount_unit_path ]] && cmp -s -- "$unit_source" "$mount_unit_path"; then
      pass "mount unit already matches the tracked production unit"
      return
    fi
    [[ $replace_mount_unit == true ]] || die "a differing mount unit exists; inspect it and rerun with --replace-mount-unit only if replacement is approved"
    [[ ! -L $mount_unit_path && -f $mount_unit_path ]] || die "refusing to replace a linked or non-regular mount unit"
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    backup=$(mktemp --tmpdir=/etc/systemd/system "$mount_unit_name.backup.$timestamp.XXXXXXXX")
    created_backup_temporary=$backup
    install -o root -g root -m 0600 -- "$mount_unit_path" "$backup"
    sync -f "$backup"
    created_backup_temporary=
    expected_identity=$(stat -Lc '%d:%i' -- "$mount_unit_path")
    replace_existing=true
    pass "backed up the previous mount unit to $backup"
  fi
  temporary=$(mktemp --tmpdir=/etc/systemd/system .srv-workagent-users.mount.XXXXXXXX)
  created_unit_temporary=$temporary
  install -o root -g root -m 0644 -- "$unit_source" "$temporary"
  systemd-analyze --recursive-errors=no verify "$unit_source" >/dev/null 2>&1 || die "tracked mount unit failed systemd validation"
  sync -f "$temporary"
  if [[ $replace_existing == true ]]; then
    [[ ! -L $mount_unit_path && -f $mount_unit_path ]] || die "mount unit changed type during replacement"
    current_identity=$(stat -Lc '%d:%i' -- "$mount_unit_path")
    if [[ $current_identity != "$expected_identity" ]] || ! cmp -s -- "$mount_unit_path" "$backup"; then
      die "mount unit changed after backup; refusing replacement"
    fi
    mv -T -- "$temporary" "$mount_unit_path"
  else
    ln -- "$temporary" "$mount_unit_path" || die "mount unit appeared concurrently; refusing to replace it"
    rm -f -- "$temporary"
  fi
  created_unit_temporary=
  sync -f /etc/systemd/system
  pass "installed the mount unit atomically"
}

verify_acl() {
  local test_file test_acl
  test_file=$(mktemp --tmpdir="$mount_path" .workagent-acl-check.XXXXXXXX)
  created_acl_test=$test_file
  chmod 0600 -- "$test_file"
  setfacl -m u:root:r -- "$test_file"
  test_acl=$(getfacl -cp -- "$test_file")
  [[ $test_file == "$mount_path"/.workagent-acl-check.* ]] || die "internal ACL test path escaped the tenant mount"
  rm -f -- "$test_file"
  created_acl_test=
  [[ $test_acl == *'user:root:r--'* ]] || die "POSIX ACL read-back failed"
  pass "POSIX ACL write/read verification succeeded"
}

write_receipt() {
  local receipt temporary uuid unit_hash
  receipt=$image_parent/prepare.receipt
  uuid=$(blkid -p -s UUID -o value -- "$image_path")
  unit_hash=$(sha256sum "$mount_unit_path" | awk '{print $1}')
  temporary=$(mktemp --tmpdir="$image_parent" .prepare.receipt.XXXXXXXX)
  {
    printf 'schema_version=1\n'
    printf 'prepared_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'image=%s\n' "$image_path"
    printf 'image_size_bytes=%s\n' "$image_size_bytes"
    printf 'image_uuid=%s\n' "$uuid"
    printf 'mount=%s\n' "$mount_path"
    printf 'mount_unit_sha256=%s\n' "$unit_hash"
    printf 'tenant_quota_total_bytes=%s\n' "$total_quota_bytes"
  } >"$temporary"
  chmod 0600 -- "$temporary"
  chown root:root -- "$temporary"
  sync -f "$temporary"
  mv -T -- "$temporary" "$receipt"
  sync -f "$image_parent"
  pass "wrote a non-secret preparation receipt"
}

apply_prepare() {
  [[ $EUID == 0 ]] || die "--apply must run as root"
  [[ $confirmed == true ]] || die "--apply requires --confirm $confirmation"
  require_commands
  (( failures == 0 )) || die "required host tools are missing"
  check_host_primitives
  (( failures == 0 )) || die "host primitives do not satisfy the production contract"
  workagent_services_inactive || die "active WorkAgent services make storage preparation unsafe"
  if [[ -e $mount_parent || -L $mount_parent ]]; then
    safe_root_directory "$mount_parent" 755 || die "$mount_parent must be a root-owned non-symlink mode-0755 directory"
  else
    die "$mount_parent is absent; create and review the canonical parent before applying"
  fi
  if [[ -e $mount_path || -L $mount_path ]]; then
    [[ ! -L $mount_path && -d $mount_path ]] || die "$mount_path must be a real directory"
    mountpoint -q -- "$mount_path" && die "$mount_path is already mounted; use --check instead"
    directory_is_empty "$mount_path" || die "$mount_path contains existing entries; archive them separately before applying"
    safe_root_directory "$mount_path" 711 || die "$mount_path must be root-owned mode 0711"
  else
    install -d -o root -g root -m 0711 -- "$mount_path"
  fi
  if [[ -e $image_parent || -L $image_parent ]]; then
    safe_root_directory "$image_parent" 700 || die "$image_parent exists with unsafe type, owner, or mode"
  else
    install -d -o root -g root -m 0700 -- "$image_parent"
  fi
  if [[ -e $image_path && ! -L $image_path ]]; then
    check_backing_capacity existing
  else
    check_backing_capacity creation
  fi
  (( failures == 0 )) || die "backing capacity check failed"
  create_image
  install_mount_unit
  systemctl daemon-reload
  systemctl enable --now "$mount_unit_name"
  check_mount || die "mounted tenant storage failed verification"
  xfs_info "$mount_path" >/dev/null
  verify_acl
  write_receipt
  pass "tenant storage preparation completed; no tenant data was moved"
}

if [[ $mode == check ]]; then
  read_only_check
  exit $?
fi

apply_prepare
