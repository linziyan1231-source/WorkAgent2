#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: run-server.sh ABSOLUTE_SYSTEMD_CREDENTIAL_FILE" >&2
  exit 2
fi

umask 0077
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
release_directory=$(dirname -- "$script_directory")
node_binary=$release_directory/node/bin/node
server_entry=$release_directory/app/src/server.js
secret_file=$1

case "$secret_file" in
  /*) ;;
  *) echo "ChatForward credential path must be absolute" >&2; exit 1 ;;
esac
if [[ -L "$secret_file" || ! -f "$secret_file" ]]; then
  echo "ChatForward credential is missing or is not a regular file" >&2
  exit 1
fi
secret_size=$(stat -Lc '%s' -- "$secret_file")
secret_mode=$(stat -Lc '%a' -- "$secret_file")
# systemd exposes LoadCredentialEncrypted files as root:root 0440 with a
# service-identity ACL grant; world access remains forbidden.
if (( secret_size < 32 || secret_size > 4096 || (8#$secret_mode & 007) != 0 )); then
  echo "ChatForward credential size or permissions are unsafe" >&2
  exit 1
fi
if [[ ! -x "$node_binary" || ! -f "$server_entry" ]]; then
  echo "ChatForward release is incomplete" >&2
  exit 1
fi
if [[ $($node_binary --version) != v24.15.0 ]]; then
  echo "ChatForward requires its pinned Node.js v24.15.0 runtime" >&2
  exit 1
fi

: "${CHATFORWARD_PORTAL_URL:?CHATFORWARD_PORTAL_URL is required}"
: "${CHATFORWARD_MIRROR_URL:?CHATFORWARD_MIRROR_URL is required}"

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy
if [[ -n ${CHATFORWARD_OUTBOUND_PROXY_URL:-} ]]; then
  if [[ ! $CHATFORWARD_OUTBOUND_PROXY_URL =~ ^https?://127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] || (( 10#${BASH_REMATCH[1]} > 65535 )); then
    echo "CHATFORWARD_OUTBOUND_PROXY_URL must be an exact loopback HTTP(S) proxy origin" >&2
    exit 1
  fi
  export HTTP_PROXY=$CHATFORWARD_OUTBOUND_PROXY_URL
  export HTTPS_PROXY=$CHATFORWARD_OUTBOUND_PROXY_URL
  export NO_PROXY=127.0.0.1,localhost
fi

export CHATFORWARD_HOST=127.0.0.1
export CHATFORWARD_PORT=3210
export CHATFORWARD_MAX_PAIRS=3
export CHATFORWARD_SECRET_FILE=$secret_file
exec "$node_binary" --use-env-proxy "$server_entry"
