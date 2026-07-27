#!/usr/bin/env bash
set -Eeuo pipefail

# Verification only: this script never imports a key into the host RPM database
# and never installs a package.

export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 0077

readonly expected_google_key_sha256=54dea5f6c2a26091578cf52a999cebc6b64df478d37ad4dce96376b711e3b27c
readonly expected_google_primary_fingerprint=EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796
readonly expected_google_signing_fingerprint=0E225917414670F4442C250DFD533C07C264648F
readonly expected_chrome_sha256=918565ec80808f179b9b768f173af200d9c97f0a424700a510084a8a593d2796
readonly expected_chrome_nevra=google-chrome-stable-150.0.7871.186-1.x86_64
readonly expected_node_exporter_sha256=d95208cac34108f4c9dd079b676ea9de093fe0517aa13b9b6fb67a8c396b81d4
readonly expected_node_exporter_nevra=node_exporter-1.5.0-7.oc9.x86_64

usage() {
  echo "usage: scripts/verify-host-rpms.sh ABSOLUTE_GOOGLE_KEY ABSOLUTE_CHROME_RPM ABSOLUTE_NODE_EXPORTER_RPM" >&2
}

(( $# == 3 )) || { usage; exit 2; }
google_key=$1
chrome_rpm=$2
node_exporter_rpm=$3

verify_protected_parent_chain() {
  local current identity owner mode
  current=${1%/*}
  [[ -n $current ]] || current=/
  while :; do
    if [[ -L $current || ! -d $current || $(readlink -f -- "$current" 2>/dev/null || true) != "$current" ]]; then
      echo "host RPM verification input parent is unsafe" >&2
      exit 1
    fi
    identity=$(stat -Lc '%u:%a' -- "$current" 2>/dev/null || true)
    owner=${identity%%:*}
    mode=${identity#*:}
    if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 022) != 0 )); then
      echo "host RPM verification input parent must be protected and root-owned" >&2
      exit 1
    fi
    [[ $current == / ]] && break
    current=${current%/*}
    [[ -n $current ]] || current=/
  done
}

for input in "$google_key" "$chrome_rpm" "$node_exporter_rpm"; do
  if [[ $input != /* || $input == *//* || $input == */../* || $input == */./* || $input == */.. || $input == */. ||
        -L $input || ! -f $input || $(readlink -f -- "$input" 2>/dev/null || true) != "$input" ]]; then
    echo "host RPM verification input must be a canonical absolute regular file" >&2
    exit 1
  fi
  identity=$(stat -Lc '%u:%a' -- "$input" 2>/dev/null || true)
  owner=${identity%%:*}
  mode=${identity#*:}
  if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 022) != 0 )); then
    echo "host RPM verification input must be protected and root-owned" >&2
    exit 1
  fi
  verify_protected_parent_chain "$input"
done

for command in awk cp gpg grep mkdir mktemp readlink rm rpm sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || { echo "required verifier is unavailable: $command" >&2; exit 1; }
done

require_hash() {
  local path=$1 expected=$2 actual
  actual=$(sha256sum -- "$path" | awk '{print $1}')
  [[ $actual == "$expected" ]] || { echo "host package input checksum mismatch" >&2; exit 1; }
}

temporary_root=$(mktemp -d /tmp/workagent-host-rpm-verify.XXXXXXXX)
cleanup() {
  if [[ $temporary_root == /tmp/workagent-host-rpm-verify.* && -d $temporary_root ]]; then
    rm -r -- "$temporary_root"
  fi
}
trap cleanup EXIT
mkdir -m 0700 "$temporary_root/gnupg"

# All subsequent verification uses private copies. Exact hashes make a torn or
# concurrently replaced source fail, while protected parent chains prevent an
# unprivileged actor from swapping a verified input before an approved install.
verified_google_key=$temporary_root/google-linux-signing-key.pub
verified_chrome_rpm=$temporary_root/google-chrome.rpm
verified_node_exporter_rpm=$temporary_root/node-exporter.rpm
cp --no-dereference --reflink=never -- "$google_key" "$verified_google_key"
cp --no-dereference --reflink=never -- "$chrome_rpm" "$verified_chrome_rpm"
cp --no-dereference --reflink=never -- "$node_exporter_rpm" "$verified_node_exporter_rpm"
chmod 0400 "$verified_google_key" "$verified_chrome_rpm" "$verified_node_exporter_rpm"
for input in "$verified_google_key" "$verified_chrome_rpm" "$verified_node_exporter_rpm"; do
  [[ -f $input && ! -L $input ]] || { echo "private host RPM verification copy is unsafe" >&2; exit 1; }
done

require_hash "$verified_google_key" "$expected_google_key_sha256"
require_hash "$verified_chrome_rpm" "$expected_chrome_sha256"
require_hash "$verified_node_exporter_rpm" "$expected_node_exporter_sha256"

fingerprints=$(gpg --batch --no-options --homedir "$temporary_root/gnupg" --show-keys --with-colons "$verified_google_key" 2>/dev/null | awk -F: '$1 == "fpr" {print $10}')
grep -Fxq "$expected_google_primary_fingerprint" <<<"$fingerprints" || { echo "Google Linux signing primary key mismatch" >&2; exit 1; }
grep -Fxq "$expected_google_signing_fingerprint" <<<"$fingerprints" || { echo "Google Chrome signing subkey mismatch" >&2; exit 1; }

chrome_nevra=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$verified_chrome_rpm" 2>/dev/null || true)
node_exporter_nevra=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$verified_node_exporter_rpm" 2>/dev/null || true)
[[ $chrome_nevra == "$expected_chrome_nevra" ]] || { echo "Google Chrome package identity mismatch" >&2; exit 1; }
[[ $node_exporter_nevra == "$expected_node_exporter_nevra" ]] || { echo "node_exporter package identity mismatch" >&2; exit 1; }

mkdir "$temporary_root/rpmdb"
rpm --dbpath "$temporary_root/rpmdb" --initdb
rpm --dbpath "$temporary_root/rpmdb" --import "$verified_google_key"

chrome_signature=$(rpm --dbpath "$temporary_root/rpmdb" --verbose --checksig "$verified_chrome_rpm" 2>&1) || {
  echo "Google Chrome RPM signature verification failed" >&2
  exit 1
}
if [[ $chrome_signature != *"Header V4 RSA/SHA512 Signature, key ID c264648f: OK"* ||
      $chrome_signature != *"Payload SHA256 digest: OK"* ]]; then
  echo "Google Chrome RPM is not signed by the accepted key" >&2
  exit 1
fi

node_exporter_signature=$(rpm --checksig "$verified_node_exporter_rpm" 2>&1) || {
  echo "node_exporter RPM signature verification failed" >&2
  exit 1
}
if [[ $node_exporter_signature != *"signatures OK"* ]]; then
  echo "node_exporter RPM is not signed by an installed OpenCloudOS key" >&2
  exit 1
fi

echo "PASS  Google Chrome and node_exporter host RPM identities, checksums, and signatures are accepted"
