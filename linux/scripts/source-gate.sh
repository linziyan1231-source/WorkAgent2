#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: scripts/source-gate.sh ABSOLUTE_EMPTY_ARTIFACT_DIRECTORY" >&2
  exit 2
fi

artifact_directory=$1
case "$artifact_directory" in
  /*) ;;
  *) echo "artifact directory must be absolute" >&2; exit 2 ;;
esac
if [[ -e "$artifact_directory" ]] && [[ -n "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "artifact directory must be empty" >&2
  exit 2
fi
mkdir -p "$artifact_directory"
chmod 0700 "$artifact_directory"

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

go_binary=${GO_BIN:-go}
gitleaks_binary=${GITLEAKS_BIN:-gitleaks}
syft_binary=${SYFT_BIN:-syft}
govulncheck_binary=${GOVULNCHECK_BIN:-govulncheck}
shellcheck_binary=${SHELLCHECK_BIN:-shellcheck}

go_binary=$(command -v -- "$go_binary")
go_binary=$(readlink -f -- "$go_binary")
go_directory=$(dirname -- "$go_binary")
export PATH="$go_directory:$PATH"

if [[ $($go_binary version) != go\ version\ go1.26.5\ linux/amd64 ]]; then
  echo "source gate requires Go 1.26.5 linux/amd64" >&2
  exit 1
fi
[[ $($gitleaks_binary version) == 8.28.0 ]]
$syft_binary version | grep -Fxq 'Version:       1.29.0'
$govulncheck_binary -version | grep -Fq 'v1.6.0'
$shellcheck_binary --version | grep -Fq 'version: 0.11.0'

export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export SYFT_CHECK_FOR_APP_UPDATE=false

managed_shell_roots=(scripts components)
mapfile -d '' tracked_shell_files < <(git ls-files -z -- '*.bash' '*.sh')
if (( ${#tracked_shell_files[@]} == 0 )); then
  # A repository's first pre-commit audit has no index entries yet. Restrict
  # that fallback to the two explicit product-source roots; never recurse from
  # the repository root where ignored migration data and build artifacts live.
  for managed_root in "${managed_shell_roots[@]}"; do
    if [[ ! -d $managed_root || -L $managed_root ]]; then
      echo "managed shell source root is missing or unsafe: $managed_root" >&2
      exit 1
    fi
  done
  mapfile -d '' tracked_shell_files < <(find "${managed_shell_roots[@]}" -type f \( -name '*.bash' -o -name '*.sh' \) -print0 | sort -z)
fi
if (( ${#tracked_shell_files[@]} == 0 )); then
  echo "source gate found no managed shell scripts" >&2
  exit 1
fi
for shell_file in "${tracked_shell_files[@]}"; do
  case "$shell_file" in
    scripts/*|components/*) ;;
    *) echo "tracked shell script is outside the explicit managed roots: $shell_file" >&2; exit 1 ;;
  esac
  if [[ ! -f $shell_file || -L $shell_file ]]; then
    echo "managed shell script is missing or is a symlink: $shell_file" >&2
    exit 1
  fi
done
bash -n "${tracked_shell_files[@]}"
$shellcheck_binary "${tracked_shell_files[@]}"

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "source gate requires a clean committed revision" >&2
  exit 1
fi

empty_tree=$(git hash-object -t tree /dev/null)
git diff --check "$empty_tree" HEAD -- .
$go_binary mod verify
$go_binary list ./... >/dev/null
$go_binary test ./...
$go_binary test -race ./...
$go_binary vet ./...
$govulncheck_binary ./...
scripts/audit-tree.sh
scripts/gitleaks-config-self-test.sh "$gitleaks_binary"

snapshot=$(mktemp -d)
trap 'rm -rf -- "$snapshot"' EXIT
git archive --format=tar HEAD | tar --extract --file=- --directory "$snapshot" --no-same-owner
$gitleaks_binary dir --config "$repo_root/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$snapshot"
$syft_binary scan "dir:$snapshot" --output "spdx-json=$artifact_directory/source.spdx.json"

source_revision=$(git rev-parse --verify HEAD)
if [[ ! $source_revision =~ ^[0-9a-f]{40}$ ]]; then
  echo "source gate could not resolve a clean 40-hex revision" >&2
  exit 1
fi
printf '%s\n' \
  '{' \
  '  "schema_version": 1,' \
  "  \"source_revision\": \"$source_revision\"," \
  '  "target": "linux/amd64",' \
  '  "go_version": "1.26.5",' \
  '  "gitleaks_version": "8.28.0",' \
  '  "syft_version": "1.29.0",' \
  '  "govulncheck_version": "1.6.0",' \
  '  "shellcheck_version": "0.11.0"' \
  '}' > "$artifact_directory/source-gate.json"

binary_directory=$artifact_directory/control-plane/bin
mkdir -p "$binary_directory"
for command in workagent-admin workagent-backup workagent-cliproxy workagent-import-stage workagent-notification workagent-portal workagent-provision workagent-release workagent-secret workagent-userhost; do
  CGO_ENABLED=0 $go_binary build -trimpath -buildvcs=true -ldflags=-buildid= \
    -o "$binary_directory/$command" "./cmd/$command"
done
install -m 0555 scripts/production-healthcheck.sh "$binary_directory/workagent-healthcheck"
administration_directory=$artifact_directory/control-plane/admin
mkdir -p "$administration_directory"
install -m 0555 scripts/production-host-prepare.sh "$administration_directory/production-host-prepare"
install -m 0555 scripts/production-preflight.sh "$administration_directory/production-preflight"
install -m 0555 scripts/smoke-chatforward-browser-sandbox.sh "$administration_directory/smoke-chatforward-browser-sandbox"
install -m 0555 scripts/verify-host-rpms.sh "$administration_directory/verify-host-rpms"
share_directory=$artifact_directory/control-plane/share
mkdir -p "$share_directory"
git archive --format=tar HEAD LICENSE_STATUS.md SECURITY.md config deploy docs | tar --extract --file=- --directory "$share_directory" --no-same-owner
printf '%s\n' \
  '[' \
  '  {' \
  '    "name": "workagent-control",' \
  "    \"version\": \"git-${source_revision:0:12}\"," \
  "    \"source_revision\": \"$source_revision\"" \
  '  }' \
  ']' > "$artifact_directory/control-plane/components.portal.json"
(
  cd "$artifact_directory/control-plane"
  find admin bin share components.portal.json -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
$syft_binary scan "dir:$artifact_directory/control-plane" \
  --output "spdx-json=$artifact_directory/control-plane.spdx.json"
$gitleaks_binary dir --config "$repo_root/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$artifact_directory/control-plane"

# The Windows migration command is intentionally a separate, offline package:
# it is source-gated but cannot be mistaken for an online production service.
migration_directory=$artifact_directory/migration-tools/bin
mkdir -p "$migration_directory"
CGO_ENABLED=0 $go_binary build -trimpath -buildvcs=true -ldflags=-buildid= \
  -o "$migration_directory/workagent-migrate-windows" ./cmd/workagent-migrate-windows
CGO_ENABLED=0 $go_binary build -trimpath -buildvcs=true -ldflags=-buildid= \
  -o "$migration_directory/workagent-capture-windows" ./cmd/workagent-capture-windows
(
  cd "$artifact_directory/migration-tools"
  sha256sum bin/workagent-capture-windows bin/workagent-migrate-windows > SHA256SUMS
)
$syft_binary scan "dir:$artifact_directory/migration-tools" \
  --output "spdx-json=$artifact_directory/migration-tools.spdx.json"
$gitleaks_binary dir --config "$repo_root/.gitleaks.toml" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$artifact_directory/migration-tools"

(
  cd "$artifact_directory"
  sha256sum \
    control-plane.spdx.json \
    control-plane/SHA256SUMS \
    migration-tools.spdx.json \
    migration-tools/SHA256SUMS \
    source-gate.json \
    source.spdx.json > EVIDENCE.sha256
)

echo "source quality gate: PASS"
