#!/usr/bin/env bash
set -euo pipefail

umask 0077
export LC_ALL=C

fail() {
  echo "release tree SHA-256 inventory: $*" >&2
  exit 1
}

if (( $# != 2 )); then
  echo "usage: scripts/release-tree-sha256.sh <write|verify> ABSOLUTE_TREE_ROOT" >&2
  exit 2
fi

operation=$1
tree_root=$2
case "$operation" in
  write|verify) ;;
  *) fail "operation must be write or verify" ;;
esac

for command in cmp dirname find mktemp mv realpath sha256sum sort xargs; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

if [[ $tree_root != /* || $tree_root == / || ! -d $tree_root || -L $tree_root ]]; then
  fail "tree root must be an absolute non-root real directory"
fi
if [[ $(realpath -e -- "$tree_root") != "$tree_root" ]]; then
  fail "tree root must be canonical and symlink-free"
fi

manifest=$tree_root/SHA256SUMS
parent=$(dirname -- "$tree_root")
if [[ ! -d $parent || -L $parent || $(realpath -e -- "$parent") != "$parent" ]]; then
  fail "tree parent must be a canonical real directory"
fi

temporary=$(mktemp "$parent/.workagent-release-tree-sha256.XXXXXX")
cleanup() {
  if [[ -n ${temporary:-} && -e $temporary ]]; then
    rm -f -- "$temporary"
  fi
}
trap cleanup EXIT INT TERM

(
  cd "$tree_root"
  find . -type f ! -path './SHA256SUMS' -printf '%P\0' |
    sort -z |
    xargs -0 -r sha256sum --
) > "$temporary"
if [[ ! -s $temporary ]]; then
  fail "payload content inventory is empty"
fi

if [[ $operation == write ]]; then
  if [[ -e $manifest || -L $manifest ]]; then
    fail "SHA256SUMS destination already exists"
  fi
  mv -T --no-clobber -- "$temporary" "$manifest"
  temporary=
  if [[ ! -f $manifest || -L $manifest ]]; then
    fail "SHA256SUMS could not be published without replacement"
  fi
  echo "release tree SHA-256 inventory: WRITE PASS"
  exit 0
fi

if [[ ! -f $manifest || -L $manifest || ! -s $manifest ]]; then
  fail "SHA256SUMS is missing or unsafe"
fi
if ! cmp -s -- "$manifest" "$temporary"; then
  fail "SHA256SUMS does not exactly cover the current regular-file inventory"
fi
(
  cd "$tree_root"
  sha256sum --strict --check SHA256SUMS >/dev/null
) || fail "payload content hash verification failed"

echo "release tree SHA-256 inventory: VERIFY PASS"
