#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 0077

readonly public_domain=workagent.example.invalid
readonly portal_loopback=http://127.0.0.1:42580
readonly tenant_mount=/srv/workagent/users
readonly tenant_image=/var/lib/workagent-storage/tenants.xfs
readonly backup_mount=/mnt/workagent-backup

if (( $# != 1 )) || [[ $1 != /* ]]; then
  echo "usage: workagent-healthcheck ABSOLUTE_TEXTFILE_OUTPUT" >&2
  exit 2
fi
[[ $EUID == 0 ]] || { echo "workagent-healthcheck must run as root" >&2; exit 1; }

output=$1
parent=$(dirname -- "$output")
if [[ -L $parent || ! -d $parent ]]; then
  echo "health metric parent is missing or linked" >&2
  exit 1
fi
parent_owner=$(stat -Lc '%u' -- "$parent")
parent_mode=$(stat -Lc '%a' -- "$parent")
if [[ $parent_owner != 0 ]] || (( (8#$parent_mode & 022) != 0 )); then
  echo "health metric parent is not protected" >&2
  exit 1
fi
if [[ -e $output || -L $output ]]; then
  [[ ! -L $output && -f $output ]] || { echo "health metric output is unsafe" >&2; exit 1; }
  output_owner=$(stat -Lc '%u' -- "$output")
  output_mode=$(stat -Lc '%a' -- "$output")
  if [[ $output_owner != 0 ]] || (( (8#$output_mode & 022) != 0 )); then
    echo "health metric output has unsafe ownership or permissions" >&2
    exit 1
  fi
fi

metric_boolean() {
  "$@" >/dev/null 2>&1 && printf 1 || printf 0
}

service_active() {
  [[ $(systemctl is-active "$1" 2>/dev/null || true) == active ]]
}

loopback_listener() {
  local port=$1 sockets local_addresses
  sockets=$(ss -H -ltn "sport = :$port" 2>/dev/null || true)
  [[ -n $sockets ]] || return 1
  local_addresses=$(awk '{print $4}' <<<"$sockets")
  ! grep -Eq '^(0\.0\.0\.0|\*|\[::\]):' <<<"$local_addresses" || return 1
  grep -Eq "^127\\.0\\.0\\.1:$port$|^\\[::1\\]:$port$" <<<"$local_addresses"
}

project_quota_ready() {
  local filesystem options source loops candidate
  mountpoint -q "$tenant_mount" || return 1
  filesystem=$(findmnt -rn -T "$tenant_mount" -o FSTYPE 2>/dev/null || true)
  options=$(findmnt -rn -T "$tenant_mount" -o OPTIONS 2>/dev/null || true)
  source=$(findmnt -rn -T "$tenant_mount" -o SOURCE 2>/dev/null || true)
  [[ $filesystem == xfs ]] || return 1
  [[ ,$options, == *,prjquota,* || ,$options, == *,pquota,* ]] || return 1
  loops=$(losetup -j "$tenant_image" 2>/dev/null | cut -d: -f1 || true)
  while IFS= read -r candidate; do
    [[ -n $candidate && $source == "$candidate" ]] || continue
    xfs_quota -x -c state "$tenant_mount" 2>/dev/null | grep -Eq 'Accounting:.*ON' || return 1
    xfs_quota -x -c state "$tenant_mount" 2>/dev/null | grep -Eq 'Enforcement:.*ON' || return 1
    return 0
  done <<<"$loops"
  return 1
}

remote_backup_ready() {
  local filesystem
  mountpoint -q "$backup_mount" || return 1
  filesystem=$(findmnt -rn -T "$backup_mount" -o FSTYPE 2>/dev/null || true)
  case "$filesystem" in
    nfs|nfs4|cifs|smb3|ceph|fuse.*) return 0 ;;
    *) return 1 ;;
  esac
}

tls_certificate=
tls_expiry=0
if tls_certificate=$(timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$public_domain" -verify_hostname "$public_domain" -verify_return_error </dev/null 2>/dev/null); then
  if expiry_text=$(openssl x509 -noout -enddate <<<"$tls_certificate" 2>/dev/null); then
    expiry_text=${expiry_text#notAfter=}
    tls_expiry=$(date -d "$expiry_text" +%s 2>/dev/null || printf 0)
  fi
fi
unset tls_certificate expiry_text

backing_available=0
if [[ -d /var/lib/workagent-storage && ! -L /var/lib/workagent-storage ]]; then
  candidate=$(df -B1 --output=avail /var/lib/workagent-storage 2>/dev/null | awk 'NR == 2 {print $1}')
  [[ $candidate =~ ^[0-9]+$ ]] && backing_available=$candidate
fi

temporary=$(mktemp --tmpdir="$parent" .workagent-host.prom.XXXXXXXX)
cleanup() {
  [[ $temporary == "$parent"/.workagent-host.prom.* && -f $temporary && ! -L $temporary ]] && rm -f -- "$temporary"
}
trap cleanup EXIT

{
  printf '# HELP workagent_host_healthcheck_timestamp_seconds Unix timestamp of the last local health run.\n'
  printf '# TYPE workagent_host_healthcheck_timestamp_seconds gauge\n'
  printf 'workagent_host_healthcheck_timestamp_seconds %s\n' "$(date +%s)"
  printf '# HELP workagent_host_service_active Whether a required local systemd unit is active.\n'
  printf '# TYPE workagent_host_service_active gauge\n'
  for unit in caddy.service cliproxyapi.service mihomo.service node_exporter.service srv-workagent-users.mount workagent-chatforward-browser.service workagent-chatforward.service workagent-notification.service workagent-portal.service; do
    printf 'workagent_host_service_active{unit="%s"} %s\n' "$unit" "$(metric_boolean service_active "$unit")"
  done
  printf '# HELP workagent_host_loopback_listener Whether a private service listens only on loopback.\n'
  printf '# TYPE workagent_host_loopback_listener gauge\n'
  for entry in 'cliproxyapi:8317' 'notification:25888' 'chatforward:3210' 'portal:42580'; do
    name=${entry%%:*}
    port=${entry##*:}
    printf 'workagent_host_loopback_listener{service="%s"} %s\n' "$name" "$(metric_boolean loopback_listener "$port")"
  done
  printf '# HELP workagent_portal_local_ready Whether Portal and required local dependencies are ready.\n'
  printf '# TYPE workagent_portal_local_ready gauge\n'
  printf 'workagent_portal_local_ready %s\n' "$(metric_boolean curl --noproxy '*' --fail --silent --max-time 8 -H "Host: $public_domain" -H 'X-Forwarded-Proto: https' "$portal_loopback/readyz")"
  printf '# HELP workagent_chatforward_local_ready Whether the ChatForward bridge health contract is green.\n'
  printf '# TYPE workagent_chatforward_local_ready gauge\n'
  printf 'workagent_chatforward_local_ready %s\n' "$(metric_boolean curl --noproxy '*' --fail --silent --max-time 8 http://127.0.0.1:3210/healthz)"
  printf '# HELP workagent_notification_local_ready Whether the local notification source is ready.\n'
  printf '# TYPE workagent_notification_local_ready gauge\n'
  printf 'workagent_notification_local_ready %s\n' "$(metric_boolean curl --noproxy '*' --fail --silent --max-time 5 http://127.0.0.1:25888/readyz)"
  printf '# HELP workagent_mihomo_proxy_reachable Whether approved proxy egress can complete HTTPS.\n'
  printf '# TYPE workagent_mihomo_proxy_reachable gauge\n'
  printf 'workagent_mihomo_proxy_reachable %s\n' "$(metric_boolean curl --proxy http://127.0.0.1:8118 --noproxy '' --fail --silent --max-time 12 https://www.gstatic.com/generate_204)"
  printf '# HELP workagent_storage_project_quota_enabled Whether dedicated XFS project-quota enforcement is active.\n'
  printf '# TYPE workagent_storage_project_quota_enabled gauge\n'
  printf 'workagent_storage_project_quota_enabled %s\n' "$(metric_boolean project_quota_ready)"
  printf '# HELP workagent_storage_backing_available_bytes Available bytes on the filesystem backing the sparse tenant image.\n'
  printf '# TYPE workagent_storage_backing_available_bytes gauge\n'
  printf 'workagent_storage_backing_available_bytes %s\n' "$backing_available"
  printf '# HELP workagent_backup_remote_mount_ready Whether the backup root is an approved remote filesystem.\n'
  printf '# TYPE workagent_backup_remote_mount_ready gauge\n'
  printf 'workagent_backup_remote_mount_ready %s\n' "$(metric_boolean remote_backup_ready)"
  printf '# HELP workagent_public_tls_valid Whether local TCP 443 serves a trusted certificate for the public hostname.\n'
  printf '# TYPE workagent_public_tls_valid gauge\n'
  if (( tls_expiry > 0 )); then
    printf 'workagent_public_tls_valid 1\n'
  else
    printf 'workagent_public_tls_valid 0\n'
  fi
  printf '# HELP workagent_public_tls_expiry_timestamp_seconds Public certificate expiry timestamp, or zero when invalid.\n'
  printf '# TYPE workagent_public_tls_expiry_timestamp_seconds gauge\n'
  printf 'workagent_public_tls_expiry_timestamp_seconds %s\n' "$tls_expiry"
} >"$temporary"

chmod 0644 "$temporary"
chown root:root "$temporary"
mv -T -- "$temporary" "$output"
trap - EXIT
