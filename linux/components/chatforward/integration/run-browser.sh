#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
  echo "usage: run-browser.sh" >&2
  exit 2
fi

umask 0077
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
release_directory=$(dirname -- "$script_directory")
extension_directory=$release_directory/app/extension
node_binary=$release_directory/node/bin/node
profile_directory=/var/lib/workagent/chatforward/chromium
cache_directory=/var/cache/workagent/chatforward/chromium
runtime_directory=/run/workagent/chatforward
target_url=https://chatgpt.com/g/g-p-6a2bacd1b27c8191b25aa2ba5f614b83-workagent/project
chromium_binary=${CHATFORWARD_CHROMIUM_BIN:-/usr/bin/chromium}
xvfb_binary=${CHATFORWARD_XVFB_BIN:-/usr/bin/Xvfb}
xauth_binary=${CHATFORWARD_XAUTH_BIN:-/usr/bin/xauth}
display=${CHATFORWARD_DISPLAY:-:77}
proxy_arguments=()

protected_executable() {
  local executable=$1 real owner mode
  [[ $executable == /* && -x $executable ]] || return 1
  real=$(readlink -f -- "$executable")
  [[ $real == /* && -f $real ]] || return 1
  owner=$(stat -Lc '%u' -- "$real")
  mode=$(stat -Lc '%a' -- "$real")
  [[ $owner == 0 ]] && (( (8#$mode & 022) == 0 ))
}

private_owned_directory() {
  local directory=$1 uid owner mode
  uid=$(id -u)
  [[ ! -L $directory && -d $directory ]] || return 1
  owner=$(stat -Lc '%u' -- "$directory")
  mode=$(stat -Lc '%a' -- "$directory")
  [[ $owner == "$uid" ]] && (( (8#$mode & 077) == 0 ))
}

if ! protected_executable "$chromium_binary"; then
  echo "configured Chromium executable is missing or writable by an unprivileged account" >&2
  exit 1
fi
if ! protected_executable "$xvfb_binary"; then
  echo "configured Xvfb executable is missing or writable by an unprivileged account" >&2
  exit 1
fi
if ! protected_executable "$xauth_binary"; then
  echo "configured xauth executable is missing or writable by an unprivileged account" >&2
  exit 1
fi
if [[ ! -x $node_binary || $($node_binary --version) != v24.15.0 ]]; then
  echo "ChatForward browser release is missing its pinned Node.js runtime" >&2
  exit 1
fi
if [[ ! $display =~ ^:[1-9][0-9]{0,2}$ ]]; then
  echo "CHATFORWARD_DISPLAY must be a local X display from :1 through :999" >&2
  exit 1
fi
if [[ -n ${CHATFORWARD_OUTBOUND_PROXY_URL:-} ]]; then
  if [[ ! $CHATFORWARD_OUTBOUND_PROXY_URL =~ ^https?://127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] || (( 10#${BASH_REMATCH[1]} > 65535 )); then
    echo "CHATFORWARD_OUTBOUND_PROXY_URL must be an exact loopback HTTP(S) proxy origin" >&2
    exit 1
  fi
  proxy_arguments+=("--proxy-server=$CHATFORWARD_OUTBOUND_PROXY_URL" "--proxy-bypass-list=localhost;127.0.0.1")
fi
for directory in "$profile_directory" "$cache_directory" "$runtime_directory"; do
  if ! private_owned_directory "$directory"; then
    echo "ChatForward private directory is missing or unsafe: $directory" >&2
    exit 1
  fi
done
if [[ -L $extension_directory || ! -f $extension_directory/manifest.json ]]; then
  echo "ChatForward extension is missing or unsafe" >&2
  exit 1
fi
extension_owner=$(stat -Lc '%u' -- "$extension_directory/manifest.json")
extension_mode=$(stat -Lc '%a' -- "$extension_directory/manifest.json")
if [[ $extension_owner != 0 ]] || (( (8#$extension_mode & 022) != 0 )); then
  echo "ChatForward extension manifest is not protected" >&2
  exit 1
fi
if ! grep -Fq '"version": "0.16.0"' "$extension_directory/manifest.json"; then
  echo "ChatForward extension version does not match the production contract" >&2
  exit 1
fi

export DISPLAY=$display
export HOME=/var/lib/workagent/chatforward
export XDG_CACHE_HOME=$cache_directory
export XDG_CONFIG_HOME=/var/lib/workagent/chatforward/config
export XDG_RUNTIME_DIR=$runtime_directory

display_number=${display#:}
display_socket=/tmp/.X11-unix/X${display_number}
xvfb_pid=
browser_pid=
xauthority_file=

# Both functions are invoked indirectly by the signal/exit traps below.
# shellcheck disable=SC2329
terminate_children() {
  [[ -z $browser_pid ]] || kill -TERM "$browser_pid" 2>/dev/null || true
  [[ -z $xvfb_pid ]] || kill -TERM "$xvfb_pid" 2>/dev/null || true
}
# shellcheck disable=SC2329
cleanup() {
  terminate_children
  [[ -z $browser_pid ]] || wait "$browser_pid" 2>/dev/null || true
  [[ -z $xvfb_pid ]] || wait "$xvfb_pid" 2>/dev/null || true
  [[ -z $xauthority_file ]] || rm -f -- "$xauthority_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

xauthority_file=$(mktemp --tmpdir="$runtime_directory" xvfb-xauthority.XXXXXX)
chmod 0600 "$xauthority_file"
xauth_cookie=$($node_binary -e 'process.stdout.write(require("node:crypto").randomBytes(16).toString("hex"))')
printf 'add %s MIT-MAGIC-COOKIE-1 %s\n' "$display" "$xauth_cookie" | "$xauth_binary" -f "$xauthority_file" source -
unset xauth_cookie
export XAUTHORITY=$xauthority_file

"$xvfb_binary" "$display" -screen 0 1920x1080x24 -nolisten tcp -noreset -auth "$xauthority_file" &
xvfb_pid=$!
for _attempt in {1..50}; do
  [[ -S $display_socket ]] && break
  if ! kill -0 "$xvfb_pid" 2>/dev/null; then
    wait "$xvfb_pid" || true
    echo "Xvfb exited before creating its private display" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! -S $display_socket ]]; then
  echo "Xvfb did not create its private display" >&2
  exit 1
fi

"$chromium_binary" \
  --user-data-dir="$profile_directory" \
  --disk-cache-dir="$cache_directory" \
  --password-store=basic \
  --ozone-platform=x11 \
  --no-first-run \
  --no-default-browser-check \
  --disable-default-apps \
  --disable-background-mode \
  --disable-sync \
  --disable-component-update \
  --disable-dev-shm-usage \
  --disable-background-timer-throttling \
  --disable-backgrounding-occluded-windows \
  --disable-renderer-backgrounding \
  --metrics-recording-only \
  --no-report-upload \
  --window-size=1920,1080 \
  "${proxy_arguments[@]}" \
  "$target_url" &
browser_pid=$!

set +e
wait "$browser_pid"
status=$?
set -e
browser_pid=
kill -TERM "$xvfb_pid" 2>/dev/null || true
wait "$xvfb_pid" 2>/dev/null || true
xvfb_pid=
exit "$status"
