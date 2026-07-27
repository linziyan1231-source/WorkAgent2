#!/usr/bin/env bash
set -u -o pipefail

# Read-only production-state audit. It intentionally never prints configuration
# contents, credentials, cookies, OAuth material, tenant identifiers, or logs.

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly public_domain=workagent.example.invalid
readonly public_ipv4=192.0.2.1
readonly portal_origin=https://$public_domain
readonly portal_loopback=http://127.0.0.1:42580
readonly backup_mount=/mnt/workagent-backup
readonly minimum_backing_reserve_bytes=$((32 * 1024 * 1024 * 1024))

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(dirname -- "$script_directory")
if [[ ! -d $repository_root/deploy && -d $repository_root/share/deploy ]]; then
  repository_root=$repository_root/share
fi
blocks=0
warnings=0

pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; warnings=$((warnings + 1)); }
block() { printf 'BLOCK %s\n' "$*" >&2; blocks=$((blocks + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

installed_unit_matches() {
  local unit=$1 relative=$2 fragment candidate
  fragment=$(systemctl show --property=FragmentPath --value "$unit" 2>/dev/null || true)
  if [[ -z $fragment ]]; then
    for candidate in "/etc/systemd/system/$unit" "/usr/lib/systemd/system/$unit"; do
      if [[ -f $candidate && ! -L $candidate ]]; then
        fragment=$candidate
        break
      fi
    done
  fi
  if [[ -n $fragment && -f $fragment && ! -L $fragment ]] &&
     [[ $(stat -Lc '%u' "$fragment" 2>/dev/null || true) == 0 ]] &&
     (( (8#$(stat -Lc '%a' "$fragment" 2>/dev/null || printf 777) & 022) == 0 )) &&
     cmp -s "$repository_root/$relative" "$fragment"; then
    pass "$unit matches the tracked production unit"
  else
    block "$unit is absent or differs from the tracked production unit"
  fi
}

installed_dropin_matches() {
  local unit=$1 filename=$2 relative=$3 candidate
  for candidate in "/etc/systemd/system/$unit.d/$filename" "/usr/lib/systemd/system/$unit.d/$filename"; do
    if [[ -f $candidate && ! -L $candidate ]] &&
       [[ $(stat -Lc '%u' "$candidate" 2>/dev/null || true) == 0 ]] &&
       (( (8#$(stat -Lc '%a' "$candidate" 2>/dev/null || printf 777) & 022) == 0 )) &&
       cmp -s "$repository_root/$relative" "$candidate"; then
      pass "$unit $filename matches the tracked production drop-in"
      return
    fi
  done
  block "$unit $filename is absent or differs from the tracked production drop-in"
}

protected_file() {
  local path=$1 description=$2 maximum_mode=${3:-640} owner mode
  if [[ -L $path || ! -f $path ]]; then
    block "$description is missing or is not a regular non-symlink file"
    return 1
  fi
  owner=$(stat -Lc '%u' -- "$path" 2>/dev/null || true)
  mode=$(stat -Lc '%a' -- "$path" 2>/dev/null || true)
  if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]]; then
    block "$description has unsafe ownership or permissions"
    return 1
  fi
  if (( (8#$mode & 022) != 0 || 8#$mode > 8#$maximum_mode )); then
    block "$description has unsafe ownership or permissions"
    return 1
  fi
  pass "$description is a protected root-owned file"
}

protected_service_file() {
  local path=$1 description=$2 expected_group=$3 expected_mode=$4 identity
  protected_file "$path" "$description" "$expected_mode" || return 1
  identity=$(stat -Lc '%U:%G:%a' -- "$path" 2>/dev/null || true)
  if [[ $identity == "root:$expected_group:$expected_mode" ]]; then
    pass "$description is readable only through its intended service group"
  else
    block "$description must be root:$expected_group mode $expected_mode"
    return 1
  fi
}

protected_root_file_exact() {
  local path=$1 description=$2 expected_mode=$3 identity
  protected_file "$path" "$description" "$expected_mode" || return 1
  identity=$(stat -Lc '%U:%G:%a' -- "$path" 2>/dev/null || true)
  if [[ $identity == "root:root:$expected_mode" ]]; then
    pass "$description has its exact root-only identity"
  else
    block "$description must be root:root mode $expected_mode"
    return 1
  fi
}

protected_lock_inode() {
  local path=$1 description=$2 expected_mode=$3 shape
  protected_root_file_exact "$path" "$description" "$expected_mode" || return 1
  shape=$(stat -Lc '%h:%s' -- "$path" 2>/dev/null || true)
  if [[ $shape == 1:0 ]]; then
    pass "$description is an empty single-link lock inode"
  else
    block "$description must be empty and have exactly one hard link"
    return 1
  fi
}

protected_service_lock_inode() {
  local path=$1 description=$2 expected_group=$3 expected_mode=$4 shape
  protected_service_file "$path" "$description" "$expected_group" "$expected_mode" || return 1
  shape=$(stat -Lc '%h:%s' -- "$path" 2>/dev/null || true)
  if [[ $shape == 1:0 ]]; then
    pass "$description is an empty single-link lock inode"
  else
    block "$description must be empty and have exactly one hard link"
    return 1
  fi
}

protected_canonical_root_directory() {
  local path=$1 description=$2 owner mode
  if [[ $path != /* || -L $path || ! -d $path || $(readlink -f -- "$path" 2>/dev/null || true) != "$path" ]]; then
    block "$description is not a canonical directory"
    return 1
  fi
  owner=$(stat -Lc '%u:%g' -- "$path" 2>/dev/null || true)
  mode=$(stat -Lc '%a' -- "$path" 2>/dev/null || true)
  if [[ $owner != 0:0 || ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 022) != 0 )); then
    block "$description is writable by an unprivileged account"
    return 1
  fi
  pass "$description is canonical and root protected"
}

absent_path() {
  local path=$1 description=$2 expected_parent_mode=${3:-700} parent leaf parent_identity found find_status
  parent=${path%/*}
  leaf=${path##*/}
  if [[ $path != /* || -z $leaf || $leaf == *[!A-Za-z0-9._-]* || -L $parent || ! -d $parent ||
        $(readlink -f -- "$parent" 2>/dev/null || true) != "$parent" ]]; then
    block "$description cannot be inspected through a safe parent"
    return 1
  fi
  parent_identity=$(stat -Lc '%U:%G:%a' -- "$parent" 2>/dev/null || true)
  if [[ $parent_identity != "root:root:$expected_parent_mode" ]]; then
    block "$description parent must be root:root mode $expected_parent_mode"
    return 1
  fi
  if [[ -e $path || -L $path ]]; then
    block "$description is present"
    return 1
  fi
  found=$(/usr/bin/find "$parent" -mindepth 1 -maxdepth 1 -name "$leaf" -print -quit 2>/dev/null)
  find_status=$?
  if (( find_status != 0 )); then
    block "$description absence could not be proved"
    return 1
  fi
  if [[ -n $found ]]; then
    block "$description is present"
    return 1
  fi
  pass "$description is absent"
}

protected_executable() {
  local path=$1 description=$2 real owner mode
  if [[ $path != /* || ! -x $path ]]; then
    block "$description is unavailable at its canonical path"
    return 1
  fi
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  if [[ $real != /* || ! -f $real ]]; then
    block "$description does not resolve to a regular file"
    return 1
  fi
  owner=$(stat -Lc '%u' -- "$real")
  mode=$(stat -Lc '%a' -- "$real")
  if [[ $owner != 0 ]]; then
    block "$description is writable by an unprivileged account"
    return 1
  fi
  if (( (8#$mode & 022) != 0 )); then
    block "$description is writable by an unprivileged account"
    return 1
  fi
  pass "$description is installed at its protected canonical path"
}

verified_rpm_payload() {
  local package=$1 description=$2 allowed_config=${3:-} output status unexpected
  output=$(rpm -V "$package" 2>&1)
  status=$?
  if [[ -z $output && $status == 0 ]]; then
    pass "$description installed files match the RPM database"
    return
  fi
  if [[ -n $allowed_config && -n $output && $status == 1 ]]; then
    unexpected=$(awk -v allowed="$allowed_config" '
      NF == 0 { next }
      NF == 3 && $1 ~ /^[SM5DLUGTP?.]{9}$/ && $2 == "c" && $3 == allowed { next }
      { print "unexpected"; exit }
    ' <<<"$output")
    if [[ -z $unexpected ]]; then
      # The exact managed configuration is checked independently below. No
      # other package file may differ, even when rpm -V exits non-zero for it.
      pass "$description package files match except for the tracked managed configuration"
      return
    fi
  fi
  block "$description installed package files failed RPM verification"
}

unit_active() {
  local unit=$1 required=${2:-true} state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  if [[ $state == active ]]; then
    pass "$unit is active"
  elif [[ $required == true ]]; then
    block "$unit is not active"
  else
    warn "$unit is not active"
  fi
}

unit_enabled() {
  local unit=$1 state
  state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  if [[ $state == enabled || $state == static || $state == generated ]]; then
    pass "$unit has an activation policy"
  else
    block "$unit is not enabled"
  fi
}

loopback_listener() {
  local port=$1 description=$2 sockets local_addresses
  sockets=$(ss -H -ltn "sport = :$port" 2>/dev/null || true)
  if [[ -z $sockets ]]; then
    block "$description is not listening"
    return
  fi
  local_addresses=$(awk '{print $4}' <<<"$sockets")
  if grep -Eq '^(0\.0\.0\.0|\*|\[::\]):' <<<"$local_addresses"; then
    block "$description is exposed beyond loopback"
    return
  fi
  if grep -Eq "^127\\.0\\.0\\.1:$port$|^\\[::1\\]:$port$" <<<"$local_addresses"; then
    pass "$description is loopback-only"
  else
    block "$description does not use the required numeric loopback address"
  fi
}

check_template_contract() {
  local file=$1 description=$2
  shift 2
  local expected
  if [[ ! -f $file || -L $file ]]; then
    block "$description template is unavailable"
    return
  fi
  for expected in "$@"; do
    if ! grep -Fq -- "$expected" "$file"; then
      block "$description template is missing a required non-secret production value"
      return
    fi
  done
  pass "$description template matches the non-secret production contract"
}

printf 'WorkAgent2 Linux production preflight (read-only)\n'
printf 'Expected public origin: %s\n\n' "$portal_origin"

if [[ $EUID == 0 ]]; then
  pass "running as root for complete metadata and quota checks"
else
  block "run preflight as root for complete metadata and quota checks"
fi

for command in awk caddy cmp curl date df findmnt getent grep mountpoint openssl readlink rpm sort ss stat systemctl systemd-analyze timedatectl timeout xfs_quota; do
  if have "$command"; then
    pass "required command is available: $command"
  else
    block "required command is unavailable: $command"
  fi
done

if [[ -r /etc/os-release ]] && grep -Eq '^ID=(opencloudos|"opencloudos")$' /etc/os-release && grep -Eq '^VERSION_ID="?9([.]|"|$)' /etc/os-release; then
  pass "OpenCloudOS 9 host detected"
else
  block "the audited production target is OpenCloudOS 9"
fi

systemd_version=$(systemctl --version 2>/dev/null | awk 'NR == 1 {print $2}')
if [[ $systemd_version =~ ^[0-9]+$ ]] && (( systemd_version >= 255 )); then
  pass "systemd $systemd_version satisfies the sandbox contract"
else
  block "systemd 255 or newer is required for named OpenFile lifecycle guards"
fi
if [[ -f /sys/fs/cgroup/cgroup.controllers ]] && grep -qw cpu /sys/fs/cgroup/cgroup.controllers && grep -qw memory /sys/fs/cgroup/cgroup.controllers && grep -qw pids /sys/fs/cgroup/cgroup.controllers; then
  pass "cgroup v2 cpu, memory, and pids controllers are available"
else
  block "unified cgroup v2 with cpu, memory, and pids controllers is required"
fi
ptrace_scope=
if [[ -r /proc/sys/kernel/yama/ptrace_scope ]]; then
  IFS= read -r ptrace_scope < /proc/sys/kernel/yama/ptrace_scope || true
fi
if [[ $ptrace_scope =~ ^[0-3]$ ]] && (( ptrace_scope >= 2 )); then
  pass "kernel ptrace scope $ptrace_scope protects tenant supervisor secrets"
else
  block "kernel.yama.ptrace_scope must be at least 2"
fi
if [[ $(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true) == yes ]] &&
   [[ $(timedatectl show --property=LocalRTC --value 2>/dev/null || true) == no ]]; then
  pass "system clock is NTP-synchronized with UTC hardware-clock semantics"
else
  block "NTP synchronization and a non-local hardware clock are required for TLS and OAuth"
fi

protected_executable /usr/bin/google-chrome-stable "Google Chrome"
if [[ -x /usr/bin/google-chrome-stable ]]; then
  chrome_version=$(/usr/bin/google-chrome-stable --version 2>/dev/null || true)
  chrome_package=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' google-chrome-stable 2>/dev/null || true)
  if [[ $chrome_version == 'Google Chrome 150.0.7871.186 ' || $chrome_version == 'Google Chrome 150.0.7871.186' ]] &&
     [[ $chrome_package == 'google-chrome-stable-150.0.7871.186-1.x86_64' ]]; then
    pass "the accepted Google Chrome 150.0.7871.186-1 package is installed"
    verified_rpm_payload google-chrome-stable "Google Chrome"
  else
    block "Google Chrome must match the accepted 150.0.7871.186-1 x86_64 package"
  fi
fi
protected_executable /usr/bin/caddy "Caddy edge proxy"
if [[ -x /usr/bin/caddy ]]; then
  caddy_version=$(/usr/bin/caddy version 2>/dev/null || true)
  caddy_package=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' caddy 2>/dev/null || true)
  if [[ $caddy_version == 'v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=' ]] &&
     [[ $caddy_package == 'caddy-2.11.4-2.el9.x86_64' ]]; then
    pass "the accepted Caddy 2.11.4-2 package is installed"
    verified_rpm_payload caddy "Caddy" /etc/caddy/Caddyfile
  else
    block "Caddy must match the accepted 2.11.4-2.el9 x86_64 package"
  fi
fi
protected_executable /usr/bin/Xvfb "Xvfb"
protected_executable /usr/bin/xauth "xauth"
protected_executable /bin/bash "service lifecycle shell"
protected_executable /usr/bin/flock "service lifecycle lock helper"
protected_executable /usr/bin/awk "service lifecycle descriptor parser"
protected_executable /usr/bin/getent "service lifecycle group resolver"
protected_executable /usr/bin/readlink "service lifecycle path resolver"
protected_executable /usr/bin/stat "service lifecycle metadata inspector"
protected_executable /usr/libexec/workagent-core-activation-admission-v1 "immutable core activation admission helper v1"
protected_executable /usr/libexec/workagent-edge-publication-admission-v1 "immutable edge publication admission helper v1"
protected_executable /usr/libexec/workagent-fixed-root-exec-v1 "immutable fixed-root lifecycle supervisor v1"
protected_executable /usr/libexec/workagent-recovery-activation-admission-v1 "immutable recovery activation admission helper v1"
protected_executable /usr/sbin/node_exporter "node_exporter"
node_exporter_package=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' node_exporter 2>/dev/null || true)
if [[ $node_exporter_package == 'node_exporter-1.5.0-7.oc9.x86_64' ]]; then
  pass "the accepted OpenCloudOS node_exporter 1.5.0-7 package is installed"
  verified_rpm_payload node_exporter "node_exporter" /etc/sysconfig/node_exporter
else
  block "node_exporter must match the accepted 1.5.0-7.oc9 x86_64 package"
fi

check_template_contract "$repository_root/config/portal.example.json" "Portal" \
  '"public_origin": "https://workagent.example.invalid"' \
  '"outbound_proxy_url": "http://127.0.0.1:8118"' \
  '"max_concurrent_instances": 20' \
  '"idle_reap_seconds": 1800' \
  '"endpoint": "http://127.0.0.1:25888/notification"'
check_template_contract "$repository_root/config/chatforward.example.env" "ChatForward" \
  'CHATFORWARD_PORTAL_URL=http://127.0.0.1:42580' \
  'CHATFORWARD_MIRROR_URL=https://workagent.example.invalid/chatgpt/' \
  'CHATFORWARD_CHROMIUM_BIN=/usr/bin/google-chrome-stable' \
  'CHATFORWARD_OUTBOUND_PROXY_URL=http://127.0.0.1:8118'
check_template_contract "$repository_root/deploy/cliproxyapi/config.yaml" "CLIProxyAPI" \
  'host: "127.0.0.1"' 'port: 8317' 'allow-remote: false' \
  'proxy-url: "http://127.0.0.1:8118"'
check_template_contract "$repository_root/deploy/node_exporter/node_exporter.sysconfig" "node_exporter" \
  '--web.listen-address=127.0.0.1:9100' \
  '--collector.textfile.directory=/var/lib/node_exporter/textfile_collector'

unit_templates=(
  "$repository_root"/deploy/systemd/*.service
  "$repository_root"/deploy/systemd/*.socket
  "$repository_root"/deploy/systemd/*.mount
  "$repository_root"/deploy/systemd/*.timer
  "$repository_root"/deploy/systemd/*.target
)
if systemd-analyze --recursive-errors=no verify "${unit_templates[@]}" >/dev/null 2>&1; then
  pass "tracked systemd units pass the host parser"
else
  block "tracked systemd units fail systemd-analyze verify"
fi
if caddy validate --config "$repository_root/deploy/caddy/Caddyfile" >/dev/null 2>&1; then
  pass "tracked Caddy configuration is valid"
else
  block "tracked Caddy configuration is invalid"
fi

if [[ -f /etc/systemd/journald.conf.d/99-workagent-production.conf && ! -L /etc/systemd/journald.conf.d/99-workagent-production.conf ]] && cmp -s "$repository_root/deploy/journald/99-workagent-production.conf" /etc/systemd/journald.conf.d/99-workagent-production.conf; then
  pass "installed journal retention policy matches the tracked production boundary"
else
  block "bounded production journal retention is not installed"
fi
if [[ -d /var/log/caddy && ! -L /var/log/caddy ]]; then
  caddy_log_owner=$(stat -Lc '%U:%G' /var/log/caddy 2>/dev/null || true)
  caddy_log_mode=$(stat -Lc '%a' /var/log/caddy 2>/dev/null || true)
  if [[ $caddy_log_owner == caddy:caddy && $caddy_log_mode == 750 ]]; then
    pass "Caddy rolling-log directory has the production ownership and mode"
  else
    block "Caddy rolling-log directory ownership or mode is not production-safe"
  fi
else
  block "Caddy rolling-log directory is missing or linked"
fi

protected_file /etc/caddy/Caddyfile "installed Caddy configuration" 644
if [[ -f /etc/caddy/Caddyfile && ! -L /etc/caddy/Caddyfile ]] && cmp -s "$repository_root/deploy/caddy/Caddyfile" /etc/caddy/Caddyfile; then
  pass "installed Caddy configuration matches the tracked production boundary"
else
  block "installed Caddy configuration is absent or does not match the tracked production boundary"
fi

for unit_asset in \
  'srv-workagent-users.mount:deploy/systemd/srv-workagent-users.mount' \
	'caddy.service:deploy/systemd/caddy.service' \
  'cliproxyapi.service:deploy/systemd/cliproxyapi.service' \
  'workagent-notification.service:deploy/systemd/workagent-notification.service' \
  'workagent-chatforward.service:deploy/systemd/workagent-chatforward.service' \
  'workagent-chatforward-browser.service:deploy/systemd/workagent-chatforward-browser.service' \
  'workagent-tenant-catalog-ready.target:deploy/systemd/workagent-tenant-catalog-ready.target' \
  'workagent-tenant-config-reconcile.service:deploy/systemd/workagent-tenant-config-reconcile.service' \
  'workagent-portal.service:deploy/systemd/workagent-portal.service' \
  'workagent-userhost@.service:deploy/systemd/workagent-userhost@.service' \
  'workagent-userhost@.socket:deploy/systemd/workagent-userhost@.socket' \
  'workagent-backup.service:deploy/systemd/workagent-backup.service' \
  'workagent-backup.timer:deploy/systemd/workagent-backup.timer' \
  'workagent-healthcheck.service:deploy/systemd/workagent-healthcheck.service' \
  'workagent-healthcheck.timer:deploy/systemd/workagent-healthcheck.timer'; do
  installed_unit_matches "${unit_asset%%:*}" "${unit_asset#*:}"
done
installed_dropin_matches workagent-portal.service chatforward.conf deploy/systemd/workagent-portal.service.d/chatforward.conf
installed_dropin_matches caddy.service workagent.conf deploy/systemd/caddy.service.d/workagent.conf
protected_file /etc/systemd/system/workagent-portal.service.d/credentials.conf "Portal encrypted-credential drop-in" 644
if [[ -f /etc/systemd/system/workagent-portal.service.d/credentials.conf ]]; then
  check_template_contract /etc/systemd/system/workagent-portal.service.d/credentials.conf "installed Portal credential drop-in" \
    'LoadCredentialEncrypted=cliproxy-management-key:' \
    'LoadCredentialEncrypted=chatforward-key:' \
    'LoadCredentialEncrypted=notifications-key:'
fi

resolved_ipv4=$(getent ahostsv4 "$public_domain" 2>/dev/null | awk '{print $1}' | sort -u || true)
if grep -Fxq "$public_ipv4" <<<"$resolved_ipv4"; then
  pass "$public_domain resolves to the expected public IPv4 address"
else
  block "$public_domain does not resolve to the expected public IPv4 address"
fi

port80=$(ss -H -ltnp 'sport = :80' 2>/dev/null || true)
if [[ -n $port80 ]]; then
  if grep -Fqi caddy <<<"$port80"; then
    block "Caddy must not bind TCP 80 on this shared host"
  else
    pass "TCP 80 remains owned by a non-Caddy workload as required"
  fi
else
  warn "TCP 80 currently has no listener; it is intentionally unused by this deployment"
fi
if [[ -n $(ss -H -ltn 'sport = :2019' 2>/dev/null || true) ]]; then
  block "Caddy administrative API must not use loopback TCP 2019"
else
  pass "Caddy administrative API has no tenant-reachable TCP listener"
fi
if [[ -S /run/caddy-admin/admin.sock && ! -L /run/caddy-admin/admin.sock ]] &&
   [[ $(stat -Lc '%U:%G:%a' /run/caddy-admin 2>/dev/null || true) == caddy:caddy:700 ]]; then
  pass "Caddy administrative API uses its protected Unix-socket directory"
else
  block "Caddy protected administrative Unix socket is unavailable or unsafe"
fi

if timeout 10 openssl s_client -connect 127.0.0.1:443 -servername "$public_domain" -verify_hostname "$public_domain" -verify_return_error </dev/null >/dev/null 2>&1; then
  pass "local TCP 443 serves a trusted certificate for the production hostname"
else
  block "local TCP 443 does not serve a trusted certificate for the production hostname"
fi
if curl --noproxy '*' --fail --silent --show-error --max-time 12 --resolve "$public_domain:443:$public_ipv4" "$portal_origin/readyz" >/dev/null 2>&1; then
  pass "the host can traverse its public IPv4 HTTPS path"
  warn "an independent external-network TLS and WebSocket test is still mandatory"
else
  block "the public IPv4 HTTPS path is unreachable or not ready; cloud ingress/ACME remains unresolved"
fi

unit_active mihomo.service
loopback_listener 8118 "mihomo HTTP proxy"
if curl --proxy http://127.0.0.1:8118 --noproxy '' --fail --silent --show-error --max-time 12 https://www.gstatic.com/generate_204 >/dev/null 2>&1; then
  pass "mihomo provides HTTPS provider egress"
else
  block "mihomo cannot complete the non-secret HTTPS connectivity probe"
fi

host_prepare=
if [[ -x $repository_root/scripts/production-host-prepare.sh ]]; then
  host_prepare=$repository_root/scripts/production-host-prepare.sh
elif [[ -x $script_directory/production-host-prepare ]]; then
  host_prepare=$script_directory/production-host-prepare
fi
if [[ -z $host_prepare ]]; then
  block "production host preparation checker is unavailable"
elif "$host_prepare" --check; then
  pass "tenant storage host preparation is complete"
else
  block "tenant storage is not ready; do not run --apply until legacy entries are archived separately"
fi

backing_available=$(df -B1 --output=avail /var/lib/workagent-storage 2>/dev/null | awk 'NR == 2 {print $1}' || true)
if [[ $backing_available =~ ^[0-9]+$ ]] && (( backing_available >= minimum_backing_reserve_bytes )); then
  pass "tenant image backing filesystem retains at least 32 GiB emergency space"
else
  block "tenant image backing filesystem lacks the 32 GiB emergency reserve"
fi

protected_file /etc/workagent/portal.json "installed Portal configuration" 640
protected_file /etc/workagent/policy.json "installed model policy" 640
protected_service_file /etc/workagent/chatforward.env "installed ChatForward environment" workagent-chatforward 640
protected_service_file /etc/workagent/notification.json "installed notification payload" workagent-notification 640
protected_service_file /etc/cliproxyapi/config.yaml "installed CLIProxyAPI template" cliproxyapi 640
protected_lock_inode /run/workagent/activation.lock "tenant activation lifecycle lock" 600
protected_lock_inode /run/workagent/release-config.lock "release configuration lifecycle lock" 600
protected_lock_inode /run/workagent/fixed-root-exec-v1-install.lock "fixed-root supervisor v1 installer lock" 600
protected_service_lock_inode /run/workagent/cliproxy-migration.lock "CLIProxy migration lifecycle lock" cliproxyapi 640
protected_service_lock_inode /run/workagent/cliproxy-oauth.lock "CLIProxy OAuth writer lock" cliproxyapi 640
protected_lock_inode /opt/workagent/control.lock "control release lifecycle lock" 600
protected_lock_inode /opt/workagent/shared.lock "shared release lifecycle lock" 600
protected_lock_inode /opt/workagent/aionui/current.json.lock "runtime release lifecycle lock" 600
protected_lock_inode /run/workagent-backup/recovery-install.lock "blank-host recovery install lock" 600
protected_canonical_root_directory /usr "immutable helper /usr ancestor"
protected_canonical_root_directory /usr/libexec "immutable helper libexec parent"
protected_root_file_exact /usr/libexec/workagent-core-activation-admission-v1 "immutable core activation admission helper v1" 555
if [[ -f /usr/libexec/workagent-core-activation-admission-v1 && ! -L /usr/libexec/workagent-core-activation-admission-v1 ]] &&
   cmp -s "$repository_root/deploy/libexec/workagent-core-activation-admission-v1" /usr/libexec/workagent-core-activation-admission-v1; then
  pass "immutable core activation admission helper v1 matches final source-gate evidence"
else
  block "immutable core activation admission helper v1 differs from final source-gate evidence"
fi
protected_root_file_exact /usr/libexec/workagent-edge-publication-admission-v1 "immutable edge publication admission helper v1" 555
if [[ -f /usr/libexec/workagent-edge-publication-admission-v1 && ! -L /usr/libexec/workagent-edge-publication-admission-v1 ]] &&
   cmp -s "$repository_root/deploy/libexec/workagent-edge-publication-admission-v1" /usr/libexec/workagent-edge-publication-admission-v1; then
  pass "immutable edge publication admission helper v1 matches final source-gate evidence"
else
  block "immutable edge publication admission helper v1 differs from final source-gate evidence"
fi
protected_root_file_exact /usr/libexec/workagent-fixed-root-exec-v1 "immutable fixed-root lifecycle supervisor v1" 555
if [[ -f /usr/libexec/workagent-fixed-root-exec-v1 && ! -L /usr/libexec/workagent-fixed-root-exec-v1 ]] &&
   cmp -s "$repository_root/deploy/libexec/workagent-fixed-root-exec-v1" /usr/libexec/workagent-fixed-root-exec-v1; then
  pass "immutable fixed-root lifecycle supervisor v1 matches final source-gate evidence"
else
  block "immutable fixed-root lifecycle supervisor v1 differs from final source-gate evidence"
fi
protected_root_file_exact /usr/libexec/workagent-recovery-activation-admission-v1 "immutable recovery activation admission helper v1" 555
if [[ -f /usr/libexec/workagent-recovery-activation-admission-v1 && ! -L /usr/libexec/workagent-recovery-activation-admission-v1 ]] &&
   cmp -s "$repository_root/deploy/libexec/workagent-recovery-activation-admission-v1" /usr/libexec/workagent-recovery-activation-admission-v1; then
  pass "immutable recovery activation admission helper v1 matches final source-gate evidence"
else
  block "immutable recovery activation admission helper v1 differs from final source-gate evidence"
fi
absent_path /run/workagent-backup/recovery-activation.permit "volatile blank-host recovery activation permit"
absent_path /var/lib/workagent-backup/recovery-activation.json "unfinished blank-host recovery activation journal"
absent_path /run/workagent-backup/quiesce.json "unfinished backup service quiescence journal"
absent_path /run/workagent-edge/publication.permit "volatile edge publication permit"
absent_path /var/lib/workagent-edge/publication.json "unfinished edge publication journal"
absent_path /run/workagent-core/activation.permit "volatile core activation permit"
absent_path /var/lib/workagent-core/activation.json "unfinished core activation journal"
absent_path /var/lib/workagent/tenant-activation.json "unfinished tenant activation transaction journal" 755
protected_file /etc/workagent/trust/release-signing.pub "release verification key" 644
if [[ -f /etc/workagent/portal.json ]]; then
  check_template_contract /etc/workagent/portal.json "installed Portal" \
    '"public_origin": "https://workagent.example.invalid"' \
    '"outbound_proxy_url": "http://127.0.0.1:8118"' \
    '"max_concurrent_instances": 20' \
    '"idle_reap_seconds": 1800'
fi
if [[ -f /etc/workagent/chatforward.env && ! -L /etc/workagent/chatforward.env ]] && cmp -s "$repository_root/config/chatforward.example.env" /etc/workagent/chatforward.env; then
  pass "installed ChatForward environment matches the tracked production contract"
else
  block "installed ChatForward environment differs from the tracked production contract"
fi
if [[ -f /etc/cliproxyapi/config.yaml && ! -L /etc/cliproxyapi/config.yaml ]] && cmp -s "$repository_root/deploy/cliproxyapi/config.yaml" /etc/cliproxyapi/config.yaml; then
  pass "installed CLIProxyAPI template matches the tracked production contract"
else
  block "installed CLIProxyAPI template differs from the tracked production contract"
fi
if [[ -f /etc/sysconfig/node_exporter && ! -L /etc/sysconfig/node_exporter ]] &&
   [[ $(stat -Lc '%U:%G:%a' /etc/sysconfig/node_exporter 2>/dev/null || true) == root:root:644 ]] &&
   cmp -s "$repository_root/deploy/node_exporter/node_exporter.sysconfig" /etc/sysconfig/node_exporter; then
  pass "installed node_exporter configuration is protected and loopback-only"
else
  block "installed node_exporter configuration identity or loopback-only contract differs"
fi
if [[ -d /var/lib/node_exporter/textfile_collector && ! -L /var/lib/node_exporter/textfile_collector ]] &&
   [[ $(stat -Lc '%U:%G:%a' /var/lib/node_exporter/textfile_collector 2>/dev/null || true) == root:node_exporter:750 ]]; then
  pass "node_exporter textfile directory is root-write/node_exporter-read only"
else
  block "node_exporter textfile directory ownership or mode is unsafe"
fi
for credential in cliproxy-management-key chatforward-key notifications-key; do
  protected_file "/etc/credstore.encrypted/workagent/$credential.cred" "encrypted $credential credential" 600
done

if [[ -x /opt/workagent/control/bin/workagent-admin ]]; then
  if /opt/workagent/control/bin/workagent-admin verify-host >/dev/null 2>&1; then
    pass "workagent-admin verifies the installed host contract"
  else
    block "workagent-admin rejects the installed host contract"
  fi
else
  block "the production workagent-admin binary is not installed"
fi

for unit in srv-workagent-users.mount cliproxyapi.service workagent-notification.service workagent-chatforward.service workagent-chatforward-browser.service workagent-portal.service caddy.service node_exporter.service workagent-backup.timer workagent-healthcheck.timer; do
  unit_enabled "$unit"
  unit_active "$unit"
done
unit_active workagent-tenant-catalog-ready.target

loopback_listener 8317 "CLIProxyAPI"
loopback_listener 25888 "local notification source"
loopback_listener 3210 "ChatForward bridge"
loopback_listener 42580 "Portal"
loopback_listener 9100 "node_exporter"

if curl --noproxy '*' --fail --silent --show-error --max-time 5 http://127.0.0.1:25888/readyz >/dev/null 2>&1; then
  pass "local notification source is ready"
else
  block "local notification source is not ready"
fi
if curl --noproxy '*' --fail --silent --show-error --max-time 8 http://127.0.0.1:3210/healthz >/dev/null 2>&1; then
  pass "ChatForward bridge reports healthy"
else
  block "ChatForward bridge is not healthy"
fi
if curl --noproxy '*' --fail --silent --show-error --max-time 8 -H "Host: $public_domain" -H 'X-Forwarded-Proto: https' "$portal_loopback/readyz" >/dev/null 2>&1; then
  pass "Portal and its required dependencies report ready"
else
  block "Portal readiness is not green"
fi

protected_file /etc/workagent/backup.json "installed backup configuration" 600
if [[ -f /etc/workagent/backup.json ]]; then
  check_template_contract /etc/workagent/backup.json "installed backup" \
    '"local_directory": "/var/lib/workagent-backup/local"' \
    '"off_host_directory": "/mnt/workagent-backup/off-host"' \
    '"require_remote_filesystem": true'
fi
if mountpoint -q "$backup_mount"; then
  backup_fstype=$(findmnt -rn -T "$backup_mount" -o FSTYPE 2>/dev/null || true)
  case "$backup_fstype" in
    nfs|nfs4|cifs|smb3|ceph|fuse.*)
      pass "off-host backup root uses an approved remote filesystem"
      ;;
    *)
      block "off-host backup root is not an approved remote filesystem"
      ;;
  esac
else
  block "off-host backup root is not a mount point; local-only backup is forbidden"
fi

backup_metric=/var/lib/node_exporter/textfile_collector/workagent_backup.prom
if [[ -r $backup_metric && ! -L $backup_metric ]]; then
  backup_timestamp=$(awk '$1 == "workagent_backup_last_success_timestamp_seconds" && $2 ~ /^[0-9]+([.][0-9]+)?$/ {print int($2); exit}' "$backup_metric")
  now=$(date +%s)
  if [[ $backup_timestamp =~ ^[0-9]+$ ]] && (( backup_timestamp <= now && now - backup_timestamp <= 90000 )); then
    pass "a verified off-host backup completed within 25 hours"
  else
    block "no verified off-host backup completed within 25 hours"
  fi
else
  block "verified backup success metric is missing"
fi

if [[ -x /usr/sbin/getenforce ]]; then
  selinux_state=$(/usr/sbin/getenforce 2>/dev/null || true)
  if [[ $selinux_state == Enforcing ]]; then
    warn "SELinux is enforcing; retain separate policy and denial-review evidence"
  else
    warn "SELinux is not enforcing on this host"
  fi
fi

printf '\nSummary: %d blocker(s), %d warning(s).\n' "$blocks" "$warnings"
if (( blocks > 0 )); then
  printf 'Production cutover is NOT authorized by this report.\n' >&2
  exit 1
fi
printf 'Local preflight passed; external ingress and browser/provider acceptance remain separately evidenced gates.\n'
