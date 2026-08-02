#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
deny_file=${WORKAGENT_AI_DENYLIST:-$repo_root/config/denylist.regex}

verify_sensitive_path_policy() {
  local probe path base
  local -a ignored_probes=(
    components/example/.env
    components/example/.env.local
    components/example/.env.example
    components/example/secrets/token.txt
    components/example/private/token.txt
    components/example/credentials/token.txt
    nested/probe.key
    nested/probe.pem
    nested/probe.p12
    nested/probe.pfx
    nested/probe.kdbx
    nested/probe.jks
    nested/probe.keystore
    nested/.netrc
    nested/id_rsa
    nested/id_ed25519
    config/cache.db
    config/cache.db-wal
    config/cache.db-shm
    config/cache.sqlite
    config/cache.sqlite-wal
    config/cache.sqlite-shm
    config/cache.sqlite3
    config/cache.sqlite3-wal
    config/cache.sqlite3-shm
  )
  for probe in "${ignored_probes[@]}"; do
    if ! git -C "$repo_root" check-ignore --quiet --no-index -- "$probe"; then
      echo "sensitive-path ignore policy does not cover a required path class" >&2
      return 1
    fi
  done
  if git -C "$repo_root" check-ignore --quiet --no-index -- .env.example; then
    echo "the reviewed root .env.example is unexpectedly ignored" >&2
    return 1
  fi

  while IFS= read -r -d '' path; do
    base=${path##*/}
    case "/$path/" in
      */secrets/*|*/private/*|*/credentials/*)
        echo "$path: tracked sensitive directory is forbidden" >&2
        return 1
        ;;
    esac
    case "$base" in
      .env|.env.*)
        if [[ $path != .env.example ]]; then
          echo "$path: tracked environment file is forbidden" >&2
          return 1
        fi
        ;;
      *.key|*.pem|*.p12|*.pfx|*.kdbx|*.jks|*.keystore|.netrc|id_rsa|id_ed25519)
        echo "$path: tracked credential container is forbidden" >&2
        return 1
        ;;
      *.db|*.db-wal|*.db-shm|*.sqlite|*.sqlite-wal|*.sqlite-shm|*.sqlite3|*.sqlite3-wal|*.sqlite3-shm)
        echo "$path: tracked database state is forbidden" >&2
        return 1
        ;;
    esac
  done < <(git -C "$repo_root" ls-files -z)
}

if [[ ${1:-} == --self-test ]]; then
  verify_sensitive_path_policy
  echo "tracked-tree deny-list self-check: PASS"
  exit 0
elif (( $# != 0 )); then
  echo "usage: scripts/audit-tree.sh [--self-test]" >&2
  exit 2
fi

if ! verify_sensitive_path_policy; then
  exit 2
fi

if [[ ! -r "$deny_file" ]]; then
  echo "deny-list is missing or unreadable: $deny_file" >&2
  exit 2
fi

fail=0
matches_file=$(mktemp "${TMPDIR:-/tmp}/workagent-audit-tree.XXXXXX")
chmod 600 "$matches_file"
cleanup() {
  rm -f -- "$matches_file"
}
trap cleanup EXIT
while IFS= read -r pattern; do
  [[ -z "$pattern" || "$pattern" == \#* ]] && continue
  set +e
  git -C "$repo_root" grep --untracked -nIiEz -- "$pattern" -- . \
    ':(exclude)config/denylist.regex' >"$matches_file"
  grep_status=$?
  set -e
  case "$grep_status" in
    0)
      while IFS= read -r -d '' file && IFS= read -r -d '' line_number && IFS= read -r -d '' _; do
        printf '%s:%s: forbidden pattern match\n' "$file" "$line_number" >&2
        fail=1
      done <"$matches_file"
      ;;
    1) ;;
    *)
      echo "deny-list scan failed for a pattern" >&2
      exit 2
      ;;
  esac
done < "$deny_file"

if (( fail != 0 )); then
  echo "forbidden tracked content detected" >&2
  exit 1
fi

echo "tracked-tree deny-list scan: PASS"
