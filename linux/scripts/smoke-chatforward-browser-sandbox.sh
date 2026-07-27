#!/usr/bin/env bash
set -Eeuo pipefail

# Starts the real ChatForward browser launcher in an isolated transient unit.
# It never uses the production profile, controller, account, or network: all
# writable paths are private runtime bind mounts and Chrome is pointed at a
# deliberately closed loopback proxy.

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 0077

readonly unit=workagent-chatforward-browser-smoke.service
readonly smoke_seconds=8
readonly expected_chatforward_root=/opt/workagent/shared/chatforward

usage() {
  echo "usage: scripts/smoke-chatforward-browser-sandbox.sh ABSOLUTE_CHATFORWARD_ROOT ABSOLUTE_CHROME_BINARY" >&2
}

(( $# == 2 )) || { usage; exit 2; }
chatforward_root=$1
chrome_input=$2

[[ $EUID == 0 ]] || { echo "ChatForward browser sandbox smoke must run as root" >&2; exit 1; }

canonical_path() {
  [[ $1 == /* && $1 != *//* && $1 != */../* && $1 != */./* && $1 != */.. && $1 != */. &&
     $(readlink -f -- "$1" 2>/dev/null || true) == "$1" ]]
}

protected_file() {
  local path=$1 executable=${2:-false} identity owner mode
  canonical_path "$path" || return 1
  [[ -f $path && ! -L $path ]] || return 1
  [[ $executable != true || -x $path ]] || return 1
  identity=$(stat -Lc '%u:%a' -- "$path" 2>/dev/null || true)
  owner=${identity%%:*}
  mode=${identity#*:}
  [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 ))
}

protected_directory_chain() {
  local current=$1 identity owner mode
  while :; do
    [[ -d $current && ! -L $current && $(readlink -f -- "$current" 2>/dev/null || true) == "$current" ]] || return 1
    identity=$(stat -Lc '%u:%a' -- "$current" 2>/dev/null || true)
    owner=${identity%%:*}
    mode=${identity#*:}
    [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
    [[ $current == / ]] && return 0
    current=${current%/*}
    [[ -n $current ]] || current=/
  done
}

for command in find grep install mktemp readlink rm rmdir stat systemctl systemd-run tail timeout; do
  command -v "$command" >/dev/null 2>&1 || { echo "required browser smoke command is unavailable: $command" >&2; exit 1; }
done
if [[ $chatforward_root != "$expected_chatforward_root" ]] || ! canonical_path "$chatforward_root" ||
   ! protected_directory_chain "$chatforward_root"; then
  echo "ChatForward smoke root must be the protected production shared path" >&2
  exit 1
fi
launcher=$chatforward_root/integration/run-browser.sh
node_binary=$chatforward_root/node/bin/node
extension_manifest=$chatforward_root/app/extension/manifest.json
protected_file "$launcher" true || { echo "ChatForward browser launcher is missing or unsafe" >&2; exit 1; }
protected_file "$node_binary" true || { echo "ChatForward Node runtime is missing or unsafe" >&2; exit 1; }
protected_file "$extension_manifest" false || { echo "ChatForward extension manifest is missing or unsafe" >&2; exit 1; }
[[ $chrome_input == /* && $chrome_input != *//* && $chrome_input != */../* && $chrome_input != */./* &&
   $chrome_input != */.. && $chrome_input != */. && -x $chrome_input ]] || { echo "Google Chrome path is invalid" >&2; exit 1; }
chrome_binary=$(readlink -f -- "$chrome_input" 2>/dev/null || true)
protected_file "$chrome_binary" true || { echo "Google Chrome executable is missing or unsafe" >&2; exit 1; }
protected_directory_chain "${chrome_binary%/*}" || { echo "Google Chrome parent path is unsafe" >&2; exit 1; }
protected_file /usr/bin/Xvfb true || { echo "Xvfb is missing or unsafe" >&2; exit 1; }
protected_file /usr/bin/xauth true || { echo "xauth is missing or unsafe" >&2; exit 1; }
[[ $("$node_binary" --version 2>/dev/null || true) == v24.15.0 ]] || { echo "ChatForward Node runtime version mismatch" >&2; exit 1; }
chrome_version=$("$chrome_binary" --version 2>/dev/null || true)
[[ $chrome_version == 'Google Chrome 150.0.7871.186 ' || $chrome_version == 'Google Chrome 150.0.7871.186' ]] || {
  echo "Google Chrome version mismatch" >&2
  exit 1
}
grep -Fq '"version": "0.16.0"' "$extension_manifest" || { echo "ChatForward extension version mismatch" >&2; exit 1; }
if systemctl is-active --quiet "$unit"; then
  echo "a ChatForward browser sandbox smoke is already active" >&2
  exit 1
fi

for parent in /var/lib/workagent /var/cache /run/workagent; do
  [[ -d $parent && ! -L $parent && $(readlink -f -- "$parent" 2>/dev/null || true) == "$parent" ]] || {
    echo "browser smoke bind-mount parent is missing or unsafe" >&2
    exit 1
  }
done

declare -a cleanup_paths=()
for candidate in /var/lib/workagent/chatforward /var/cache/workagent /var/cache/workagent/chatforward /run/workagent/chatforward; do
  if [[ -e $candidate || -L $candidate ]]; then
    [[ -d $candidate && ! -L $candidate ]] || { echo "browser smoke bind target is unsafe" >&2; exit 1; }
  else
    cleanup_paths+=("$candidate")
  fi
done

work_directory=$(mktemp -d /tmp/workagent-chatforward-browser-smoke.XXXXXXXX)
cleanup() {
  local original_status=$? cleanup_failed=false index path
  trap - EXIT INT TERM
  systemctl stop "$unit" >/dev/null 2>&1 || true
  for ((index=${#cleanup_paths[@]} - 1; index >= 0; index--)); do
    path=${cleanup_paths[$index]}
    if [[ -d $path && ! -L $path ]]; then
      if ! rmdir -- "$path" 2>/dev/null; then
        echo "browser smoke left a non-empty path for inspection: $path" >&2
        cleanup_failed=true
      fi
    elif [[ -e $path || -L $path ]]; then
      echo "browser smoke bind target changed type: $path" >&2
      cleanup_failed=true
    fi
  done
  if [[ $work_directory == /tmp/workagent-chatforward-browser-smoke.* && -d $work_directory ]]; then
    rm -r -- "$work_directory"
  else
    echo "refusing unsafe browser smoke cleanup path" >&2
    cleanup_failed=true
  fi
  if [[ $cleanup_failed == true && $original_status == 0 ]]; then original_status=1; fi
  exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set +e
systemd-run --quiet --unit="$unit" --collect --wait --pipe \
  --property=Type=exec --property=DynamicUser=yes \
  --property='RuntimeDirectory=workagent-chatforward-smoke-lib workagent-chatforward-smoke-cache workagent-chatforward-smoke-run' \
  --property=RuntimeDirectoryMode=0700 \
  --property='BindPaths=/run/workagent-chatforward-smoke-lib:/var/lib/workagent/chatforward /run/workagent-chatforward-smoke-cache:/var/cache/workagent/chatforward /run/workagent-chatforward-smoke-run:/run/workagent/chatforward' \
  --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= --property=AmbientCapabilities= \
  --property=PrivateDevices=yes --property=PrivateTmp=yes --property=ProtectClock=yes \
  --property=PrivateNetwork=yes \
  --property=ProtectControlGroups=yes --property=ProtectHome=yes --property=ProtectHostname=yes \
  --property=ProtectKernelLogs=yes --property=ProtectKernelModules=yes --property=ProtectKernelTunables=yes \
  --property=ProtectProc=invisible --property=ProcSubset=pid --property=ProtectSystem=strict \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
  --property='RestrictNamespaces=user pid net' --property=RestrictRealtime=yes --property=LockPersonality=yes \
  --property=SystemCallArchitectures=native --property=KillMode=control-group \
  --property='ReadWritePaths=/var/lib/workagent/chatforward /var/cache/workagent/chatforward /run/workagent/chatforward' \
  --property='InaccessiblePaths=-/srv/workagent/users' \
  --property=MemoryHigh=3G --property=MemoryMax=4G --property=CPUQuota=300% --property=TasksMax=1024 \
  --setenv="CHATFORWARD_CHROMIUM_BIN=$chrome_binary" \
  --setenv=CHATFORWARD_XVFB_BIN=/usr/bin/Xvfb --setenv=CHATFORWARD_XAUTH_BIN=/usr/bin/xauth \
  --setenv=CHATFORWARD_DISPLAY=:177 --setenv=CHATFORWARD_OUTBOUND_PROXY_URL=http://127.0.0.1:9 \
  -- /bin/bash -c "install -d -m 0700 /var/lib/workagent/chatforward/chromium /var/lib/workagent/chatforward/config /var/cache/workagent/chatforward/chromium && exec /usr/bin/timeout --signal=TERM --kill-after=5s ${smoke_seconds}s '$launcher'" \
  >"$work_directory/probe.log" 2>&1
probe_status=$?
set -e

if (( probe_status != 124 )); then
  echo "ChatForward browser launcher exited before the bounded sandbox smoke completed" >&2
  tail -n 40 "$work_directory/probe.log" >&2
  exit 1
fi
if grep -Eiq 'FATAL|setuid sandbox is not running|Failed to move to new namespace|Operation not permitted' "$work_directory/probe.log"; then
  echo "ChatForward browser sandbox reported a fatal isolation error" >&2
  tail -n 40 "$work_directory/probe.log" >&2
  exit 1
fi
if systemctl is-active --quiet "$unit"; then
  echo "ChatForward browser sandbox smoke did not terminate its transient unit" >&2
  exit 1
fi

echo "PASS  real ChatForward launcher, Xvfb, extension, Node, and Chrome user-namespace sandbox remained healthy for ${smoke_seconds}s"
