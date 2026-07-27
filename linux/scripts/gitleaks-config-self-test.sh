#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: scripts/gitleaks-config-self-test.sh ABSOLUTE_GITLEAKS_BINARY" >&2
  exit 2
fi
gitleaks_binary=$1
case "$gitleaks_binary" in
  /*) ;;
  *) echo "Gitleaks binary path must be absolute" >&2; exit 2 ;;
esac
if [[ ! -x $gitleaks_binary || $($gitleaks_binary version) != 8.28.0 ]]; then
  echo "Gitleaks self-test requires version 8.28.0" >&2
  exit 1
fi

repo_root=$(git rev-parse --show-toplevel)
configuration=$repo_root/.gitleaks.toml
candidate=third_party/cliproxyapi/windows-candidate-manifest.json
google_pin=scripts/verify-host-rpms.sh
websocket_patch=components/aionui/aionui-webhost-workagent-runtime-auth.patch
for required in "$configuration" "$repo_root/$candidate" "$repo_root/$google_pin" "$repo_root/$websocket_patch"; do
  if [[ ! -f $required || -L $required ]]; then
    echo "Gitleaks policy or allow-listed source is missing or unsafe" >&2
    exit 1
  fi
done

if [[ $configuration != "$repo_root/.gitleaks.toml" ]]; then
  echo "Gitleaks policy resolved unexpectedly" >&2
  exit 1
fi

# The one public SHA-256 provenance field must be ignored.
(
  cd "$repo_root"
  "$gitleaks_binary" dir --config "$configuration" --ignore-gitleaks-allow \
    --no-banner --redact --exit-code 1 "$candidate" >/dev/null
)

# The exception must not suppress another generic API-key-shaped value in the
# exact same file. Build the inert fixture value from pieces so no token-shaped
# string is ever committed to the repository.
temporary=$(mktemp -d "${TMPDIR:-/tmp}/workagent-gitleaks-self-test.XXXXXX")
cleanup() {
  case "$temporary" in
    "${TMPDIR:-/tmp}"/workagent-gitleaks-self-test.*) rm -rf -- "$temporary" ;;
    *) echo "refusing unsafe Gitleaks self-test cleanup" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM
mkdir -p "$temporary/third_party/cliproxyapi"
fixture=$temporary/$candidate
cp -- "$repo_root/$candidate" "$fixture"
# Source-gate scans an absolute extracted snapshot root, so test that path form
# independently from the repository-relative single-file scan above.
"$gitleaks_binary" dir --config "$configuration" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$temporary" >/dev/null
head -n -1 "$repo_root/$candidate" > "$fixture"
fixture_secret=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '  , "production_api_secret": "%s"\n}\n' "$fixture_secret" >> "$fixture"
unset fixture_secret
report=$temporary/report.json
set +e
"$gitleaks_binary" dir --config "$configuration" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 7 --report-format json --report-path "$report" "$temporary" >/dev/null
status=$?
set -e
if (( status != 7 )) || ! grep -Fq '"RuleID": "generic-api-key"' "$report" || ! grep -Fq 'third_party/cliproxyapi/windows-candidate-manifest.json"' "$report"; then
  echo "Gitleaks allow-list is broader than the single public provenance field" >&2
  exit 1
fi

# The two additional exceptions bind an exact public value to an exact line and
# path. First prove those originals are accepted from an absolute snapshot path.
allowlist_fixture_root=$temporary/allowlisted
mkdir -p "$allowlist_fixture_root/scripts" "$allowlist_fixture_root/components/aionui"
cp -- "$repo_root/$google_pin" "$allowlist_fixture_root/$google_pin"
cp -- "$repo_root/$websocket_patch" "$allowlist_fixture_root/$websocket_patch"
"$gitleaks_binary" dir --config "$configuration" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 1 "$allowlist_fixture_root" >/dev/null

# Then change one value on each otherwise identical allow-listed line. Assemble
# the inert fixtures from short pieces so this test source contains no complete
# key-shaped value of its own.
mutated_google_hash=918565ec80808f17
mutated_google_hash+=9b9b768f173af200
mutated_google_hash+=d9c97f0a424700a5
mutated_google_hash+=10084a8a593d2796
sed -i \
  "s/^readonly expected_google_key_sha256=.*/readonly expected_google_key_sha256=$mutated_google_hash/" \
  "$allowlist_fixture_root/$google_pin"
unset mutated_google_hash
mutated_websocket_nonce=dGhlIHNhbXBsZSBu
mutated_websocket_nonce+=b25jZQ0=
sed -i \
  "s#^+      'Sec-WebSocket-Key: .*',\$#+      'Sec-WebSocket-Key: $mutated_websocket_nonce',#" \
  "$allowlist_fixture_root/$websocket_patch"
unset mutated_websocket_nonce

report=$temporary/exact-line-report.json
set +e
"$gitleaks_binary" dir --config "$configuration" --ignore-gitleaks-allow \
  --no-banner --redact --exit-code 7 --report-format json --report-path "$report" "$allowlist_fixture_root" >/dev/null
status=$?
set -e
if (( status != 7 )) || \
  ! grep -Fq '"RuleID": "generic-api-key"' "$report" || \
  ! grep -Fq 'scripts/verify-host-rpms.sh"' "$report" || \
  ! grep -Fq 'components/aionui/aionui-webhost-workagent-runtime-auth.patch"' "$report"; then
  echo "Gitleaks exact-line allow-lists accepted a changed public value" >&2
  exit 1
fi

echo "Gitleaks release policy self-test: PASS"
