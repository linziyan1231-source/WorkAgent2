#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
deny_file=${WORKAGENT_AI_DENYLIST:-$repo_root/config/denylist.regex}

# Keep exceptions local, exact, and reviewable.  Only the public Windows-user
# path rule may use them.  Production Go/configuration paths and every private
# release deny-list pattern remain unconditionally denied.
readonly windows_user_path_deny_pattern='[A-Za-z]:\\Users\\[^\\[:space:]]+'
readonly literal_backslash=$'\\'
readonly documentation_windows_root="C:${literal_backslash}Users${literal_backslash}<owner>${literal_backslash}AionUiPortal"
readonly fixture_windows_root="C:${literal_backslash}Users${literal_backslash}alice${literal_backslash}AionUiPortal"
allowed_documentation_line='An Aion database path outside `'
allowed_documentation_line+="${documentation_windows_root}"
# Markdown backticks and workspace text are intentionally literal here.
# shellcheck disable=SC2016
allowed_documentation_line+='` is rejected by default. An external workspace can be admitted only with an explicit private manifest inside the snapshot. The manifest binds one canonical Windows root to one Portal SID, one captured source directory, and one destination below the tenant'\''s `workspace/` directory.'
readonly allowed_documentation_line

allowed_test_lines=(
  $'\tif err := os.Symlink(`'"${fixture_windows_root}${literal_backslash}data${literal_backslash}builtin-skills${literal_backslash}actual.txt"$'`, filepath.Join(tenantSource, "data", "builtin-skills", "alias.txt")); err != nil {'
  $'\t\t"default_files": []string{`'"${fixture_windows_root}${literal_backslash}profile${literal_backslash}project${literal_backslash}file.txt"$'`, externalWindowsPath + `'"${literal_backslash}"$'src'"${literal_backslash}"$'main.js`},'
  $'\t\t{`INSERT INTO skills VALUES(?)`, []any{`'"${fixture_windows_root}${literal_backslash}data${literal_backslash}builtin-skills${literal_backslash}actual.txt"$'`}},'
  $'\t\t{`INSERT INTO teams VALUES(?)`, []any{`'"${fixture_windows_root}${literal_backslash}profile${literal_backslash}project"$'`}},'
  $'\t\t{`INSERT INTO assistant_sessions VALUES(?)`, []any{`'"${fixture_windows_root}${literal_backslash}profile${literal_backslash}project"$'`}},'
)
readonly -a allowed_test_lines

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

is_explicit_fixture_or_documentation_hit() {
  local pattern=$1
  local file=$2
  local content=$3
  local allowed

  [[ "$pattern" == "$windows_user_path_deny_pattern" ]] || return 1
  case "$file" in
    docs/WINDOWS_DATA_MIGRATION.md)
      [[ "$content" == "$allowed_documentation_line" ]]
      return
      ;;
    internal/winmigration/migrate_test.go)
      for allowed in "${allowed_test_lines[@]}"; do
        if [[ "$content" == "$allowed" ]]; then
          return 0
        fi
      done
      return 1
      ;;
    *)
      return 1
      ;;
  esac
}

self_check_exceptions() {
  local allowed
  if ! is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" docs/WINDOWS_DATA_MIGRATION.md "$allowed_documentation_line"; then
    echo "audit-tree exception self-check rejected its documentation fixture" >&2
    return 1
  fi
  for allowed in "${allowed_test_lines[@]}"; do
    if ! is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" internal/winmigration/migrate_test.go "$allowed"; then
      echo "audit-tree exception self-check rejected a migration test fixture" >&2
      return 1
    fi
  done
  if is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" internal/winmigration/migrate.go "${allowed_test_lines[0]}" ||
    is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" config/example.yaml "$allowed_documentation_line" ||
    is_explicit_fixture_or_documentation_hit 'private-release-pattern' docs/WINDOWS_DATA_MIGRATION.md "$allowed_documentation_line" ||
    is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" docs/WINDOWS_DATA_MIGRATION.md "${allowed_documentation_line} ${fixture_windows_root}" ||
    is_explicit_fixture_or_documentation_hit "$windows_user_path_deny_pattern" internal/winmigration/migrate_test.go "${allowed_test_lines[0]} extra"; then
    echo "audit-tree exception self-check detected an over-broad exception" >&2
    return 1
  fi
}

if [[ ${1:-} == --self-test ]]; then
  self_check_exceptions
  verify_sensitive_path_policy
  echo "tracked-tree deny-list exception self-check: PASS"
  exit 0
elif (( $# != 0 )); then
  echo "usage: scripts/audit-tree.sh [--self-test]" >&2
  exit 2
fi

if ! self_check_exceptions; then
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
exception_count=0
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
      while IFS= read -r -d '' file && IFS= read -r -d '' line_number && IFS= read -r content; do
        if is_explicit_fixture_or_documentation_hit "$pattern" "$file" "$content"; then
          printf 'deny-list documented exception: %s:%s\n' "$file" "$line_number"
          ((exception_count += 1))
          continue
        fi
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

echo "tracked-tree deny-list scan: PASS (${exception_count} documented fixture/documentation exceptions)"
