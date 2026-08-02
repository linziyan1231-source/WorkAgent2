#!/bin/sh
set -eu

bin_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec "$bin_dir/../libexec/codex/bin/codex" "$@"
