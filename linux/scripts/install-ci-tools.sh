#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: scripts/install-ci-tools.sh ABSOLUTE_EMPTY_DESTINATION" >&2
  exit 2
fi

destination=$1
case "$destination" in
  /*) ;;
  *) echo "tool destination must be absolute" >&2; exit 2 ;;
esac
if [[ -e "$destination" ]] && [[ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "tool destination must be empty" >&2
  exit 2
fi
mkdir -p "$destination"
chmod 0700 "$destination"

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

download_and_verify() {
  local url=$1
  local expected=$2
  local archive=$3
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$archive" "$url"
  printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status
}

gitleaks_archive=$temporary/gitleaks.tar.gz
download_and_verify \
  https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz \
  a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb \
  "$gitleaks_archive"
tar --extract --gzip --file "$gitleaks_archive" --directory "$temporary" --no-same-owner gitleaks
install -m 0555 "$temporary/gitleaks" "$destination/gitleaks"

syft_archive=$temporary/syft.tar.gz
download_and_verify \
  https://github.com/anchore/syft/releases/download/v1.29.0/syft_1.29.0_linux_amd64.tar.gz \
  5b01c831cb5d712899d9179cabd80f55b6708dbd36af981ce27e59b6569e6690 \
  "$syft_archive"
tar --extract --gzip --file "$syft_archive" --directory "$temporary" --no-same-owner syft
install -m 0555 "$temporary/syft" "$destination/syft"

shellcheck_archive=$temporary/shellcheck.tar.xz
download_and_verify \
  https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz \
  8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 \
  "$shellcheck_archive"
tar --extract --xz --file "$shellcheck_archive" --directory "$temporary" --no-same-owner \
  shellcheck-v0.11.0/shellcheck
install -m 0555 "$temporary/shellcheck-v0.11.0/shellcheck" "$destination/shellcheck"

go_binary=${GO_BIN:-go}
GOBIN=$destination GOTOOLCHAIN=local "$go_binary" install golang.org/x/vuln/cmd/govulncheck@v1.6.0
chmod 0555 "$destination/govulncheck"

[[ $("$destination/gitleaks" version) == 8.28.0 ]]
"$destination/syft" version | grep -Fxq 'Version:       1.29.0'
"$destination/govulncheck" -version | grep -Fq 'v1.6.0'
"$destination/shellcheck" --version | grep -Fq 'version: 0.11.0'
echo "pinned CI tools installed"
