#!/bin/sh
set -eu

bin_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
runtime_root=$(CDPATH='' cd -- "$bin_dir/../libexec/python/3.13.13" && pwd -P)
unset PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE
export PYTHONHOME="$runtime_root"
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
exec "$runtime_root/bin/python3.13" "$@"
