#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
  echo "usage: sudo --preserve-env=DISPLAY,XAUTHORITY login.sh" >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo "ChatForward login preparation must run as root" >&2
  exit 1
fi
: "${DISPLAY:?Run this command from a trusted local or SSH -Y graphical session}"
if [[ ! $DISPLAY =~ ^(:|localhost:|127\.0\.0\.1:)[0-9]+(\.[0-9]+)?$ ]]; then
  echo "DISPLAY must be a local console or loopback SSH-forwarded X11 display" >&2
  exit 1
fi

umask 0077
service_user=workagent-chatforward
browser_unit=workagent-chatforward-browser.service
bridge_unit=workagent-chatforward.service
profile_directory=/var/lib/workagent/chatforward/chromium
cache_directory=/var/cache/workagent/chatforward/chromium
runtime_directory=/run/workagent/chatforward
configuration_file=/etc/workagent/chatforward.env
activation_guard=/opt/workagent/control/bin/workagent-admin
target_url=https://chatgpt.com/g/g-p-6a2bacd1b27c8191b25aa2ba5f614b83-workagent/project
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
release_directory=$(dirname -- "$script_directory")
extension_directory=$release_directory/app/extension
readiness_script=$script_directory/readiness.mjs
node_binary=$release_directory/node/bin/node
source_xauthority=${XAUTHORITY:-${SUDO_HOME:-/root}/.Xauthority}

for command in systemctl runuser xauth install stat readlink; do
  command -v -- "$command" >/dev/null || { echo "required login command is missing: $command" >&2; exit 1; }
done
if ! id "$service_user" >/dev/null 2>&1; then
  echo "ChatForward service account is not installed" >&2
  exit 1
fi
service_uid=$(id -u "$service_user")
service_gid=$(id -g "$service_user")
if [[ -L $configuration_file || ! -f $configuration_file || $(stat -Lc '%u' -- "$configuration_file") != 0 ]]; then
  echo "ChatForward configuration is missing or unsafe" >&2
  exit 1
fi
configuration_mode=$(stat -Lc '%a' -- "$configuration_file")
if (( (8#$configuration_mode & 022) != 0 )); then
  echo "ChatForward configuration is writable by an unprivileged account" >&2
  exit 1
fi
configured_chromium=
configured_proxy=
while IFS= read -r configuration_line || [[ -n $configuration_line ]]; do
  case "$configuration_line" in
    CHATFORWARD_CHROMIUM_BIN=*) configured_chromium=${configuration_line#*=} ;;
    CHATFORWARD_OUTBOUND_PROXY_URL=*) configured_proxy=${configuration_line#*=} ;;
  esac
done < "$configuration_file"
chromium_binary=${CHATFORWARD_CHROMIUM_BIN:-${configured_chromium:-/usr/bin/chromium}}
proxy_arguments=()
if [[ -n $configured_proxy ]]; then
  if [[ ! $configured_proxy =~ ^https?://127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] || (( 10#${BASH_REMATCH[1]} > 65535 )); then
    echo "configured ChatForward outbound proxy is not an exact loopback origin" >&2
    exit 1
  fi
  proxy_arguments+=("--proxy-server=$configured_proxy" "--proxy-bypass-list=localhost;127.0.0.1")
fi
if [[ ! $chromium_binary == /* || ! -x $chromium_binary ]]; then
  echo "configured Chromium executable is missing" >&2
  exit 1
fi
real_chromium=$(readlink -f -- "$chromium_binary")
chromium_owner=$(stat -Lc '%u' -- "$real_chromium")
chromium_mode=$(stat -Lc '%a' -- "$real_chromium")
if [[ $chromium_owner != 0 ]] || (( (8#$chromium_mode & 022) != 0 )); then
  echo "configured Chromium executable is not protected" >&2
  exit 1
fi
if [[ -L $source_xauthority || ! -f $source_xauthority ]]; then
  echo "XAUTHORITY is missing or unsafe; reconnect with ssh -Y and preserve XAUTHORITY through sudo" >&2
  exit 1
fi
if [[ ! -d $profile_directory || -L $profile_directory || ! -d $cache_directory || -L $cache_directory ]]; then
  echo "ChatForward profile directories are not prepared" >&2
  exit 1
fi
if [[ $(stat -Lc '%u' -- "$profile_directory") != "$service_uid" || $(stat -Lc '%u' -- "$cache_directory") != "$service_uid" ]]; then
  echo "ChatForward profile directories have the wrong owner" >&2
  exit 1
fi
if [[ ! -f $extension_directory/manifest.json || ! -x $node_binary || ! -f $readiness_script ]]; then
  echo "ChatForward release is incomplete" >&2
  exit 1
fi
if [[ ! -x $activation_guard ]]; then
  echo "WorkAgent activation guard is unavailable" >&2
  exit 1
fi

# The signed fixed-root supervisor passes only its already exclusively locked
# activation descriptor to this child. The verifier authenticates that exact
# open-file description and rejects either durable activation journal before
# the first profile or service mutation. The root supervisor retains the lock
# until this interactive child exits.
"$activation_guard" assert-activation-clean --lock-fd 3
exec 3<&-

install -d -m 0700 -o "$service_uid" -g "$service_gid" "$runtime_directory"
login_xauthority=$(mktemp --tmpdir="$runtime_directory" login-xauthority.XXXXXX)
cleanup() {
  rm -f -- "$login_xauthority"
}
trap cleanup EXIT INT TERM
chown "$service_uid:$service_gid" "$login_xauthority"
chmod 0600 "$login_xauthority"
if ! xauth -f "$source_xauthority" extract - "$DISPLAY" | xauth -f "$login_xauthority" merge -; then
  echo "could not transfer the current X11 authorization into the isolated login session" >&2
  exit 1
fi
if [[ ! -s $login_xauthority ]]; then
  echo "the current DISPLAY has no X11 authorization cookie" >&2
  exit 1
fi

systemctl stop "$browser_unit"
echo "A dedicated Chromium window will open. Confirm the ChatForward Source Bridge extension is present, sign in to ChatGPT, open the configured WorkAgent project, then close every Chromium window."

set +e
runuser --user "$service_user" -- env -i \
  HOME=/var/lib/workagent/chatforward \
  DISPLAY="$DISPLAY" \
  XAUTHORITY="$login_xauthority" \
  XDG_CACHE_HOME="$cache_directory" \
  XDG_CONFIG_HOME=/var/lib/workagent/chatforward/config \
  XDG_RUNTIME_DIR="$runtime_directory" \
  "$chromium_binary" \
    --user-data-dir="$profile_directory" \
    --disk-cache-dir="$cache_directory" \
    --load-extension="$extension_directory" \
    --disable-extensions-except="$extension_directory" \
    --password-store=basic \
    --no-first-run \
    --no-default-browser-check \
    --disable-default-apps \
    --disable-background-mode \
    --disable-sync \
    --disable-component-update \
    --new-window \
    "${proxy_arguments[@]}" \
    chrome://extensions/ \
    "$target_url"
browser_status=$?
set -e
if (( browser_status != 0 )); then
  echo "interactive Chromium exited with status $browser_status; the production browser remains stopped" >&2
  exit 1
fi

for profile_file in "$profile_directory/Local State" "$profile_directory/Default/Preferences"; do
  if [[ -L $profile_file || ! -s $profile_file || $(stat -Lc '%u' -- "$profile_file") != "$service_uid" ]]; then
    echo "Chromium did not create a safe persistent profile; the production browser remains stopped" >&2
    exit 1
  fi
done
cookie_database=$profile_directory/Default/Network/Cookies
if [[ ! -f $cookie_database ]]; then
  cookie_database=$profile_directory/Default/Cookies
fi
if [[ -L $cookie_database || ! -s $cookie_database || $(stat -Lc '%u' -- "$cookie_database") != "$service_uid" ]]; then
  echo "No persistent Chromium cookie database was created; the production browser remains stopped" >&2
  exit 1
fi

systemctl start "$bridge_unit"
systemctl start "$browser_unit"
"$node_binary" "$readiness_script" --require-controller --timeout-ms 30000
echo "ChatForward dedicated profile is prepared. Future restarts reuse this profile; repeat this command only when ChatGPT asks you to sign in again."
