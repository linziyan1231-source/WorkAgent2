#!/usr/bin/env bash
set -euo pipefail

if (( $# != 9 )); then
  echo "usage: scripts/prepare-release-evidence.sh ABSOLUTE_PAYLOAD_ROOT ABSOLUTE_COMPONENTS_JSON RELEASE_ID SOURCE_REVISION SOURCE_URI BUILDER_ID BUILD_TYPE INVOCATION_ID ABSOLUTE_EMPTY_OUTPUT_DIRECTORY" >&2
  exit 2
fi

payload_root=$1
components_json=$2
release_id=$3
source_revision=$4
source_uri=$5
builder_id=$6
build_type=$7
invocation_id=$8
output_directory=$9

for path in "$payload_root" "$components_json" "$output_directory"; do
  case "$path" in
    /*) ;;
    *) echo "payload, component, and output paths must be absolute" >&2; exit 2 ;;
  esac
done
if [[ ! -d $payload_root || -L $payload_root || $(realpath -m -- "$payload_root") != "$payload_root" ]]; then
  echo "payload root must be a canonical real directory" >&2
  exit 1
fi
if [[ ! -f $components_json || -L $components_json || $(realpath -m -- "$components_json") != "$components_json" ]]; then
  echo "component list must be a canonical regular file" >&2
  exit 1
fi
if [[ ! $source_revision =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  echo "source revision must be lowercase 40- or 64-hex" >&2
  exit 1
fi
if [[ $output_directory != "$(realpath -m -- "$output_directory")" ]]; then
  echo "output directory must be canonical" >&2
  exit 1
fi
case "$output_directory/" in
  "$payload_root/"*) echo "evidence output must not be inside the payload being scanned" >&2; exit 1 ;;
esac
case "$payload_root/" in
  "$output_directory/"*) echo "payload must not be inside the evidence output" >&2; exit 1 ;;
esac
if [[ -e $output_directory && ! -d $output_directory ]]; then
  echo "evidence output exists and is not a directory" >&2
  exit 1
fi
if [[ -d $output_directory && -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo "evidence output directory must be empty" >&2
  exit 1
fi

syft_binary=${SYFT_BIN:-syft}
release_binary=${WORKAGENT_RELEASE_BIN:-workagent-release}
syft_binary=$(command -v -- "$syft_binary")
release_binary=$(command -v -- "$release_binary")
if ! "$syft_binary" version | grep -Fxq 'Version:       1.29.0'; then
  echo "release evidence requires Syft 1.29.0" >&2
  exit 1
fi

umask 0077
mkdir -p -- "$output_directory"
chmod 0700 -- "$output_directory"
export SYFT_CHECK_FOR_APP_UPDATE=false
"$syft_binary" scan "dir:$payload_root" --output "spdx-json=$output_directory/sbom.spdx.json"
"$release_binary" provenance \
  --release-id "$release_id" \
  --source-revision "$source_revision" \
  --source-uri "$source_uri" \
  --builder-id "$builder_id" \
  --build-type "$build_type" \
  --invocation-id "$invocation_id" \
  --components "$components_json" \
  --output "$output_directory/provenance.json" \
  --reproducible >/dev/null
"$release_binary" license-template \
  --components "$components_json" \
  --output "$output_directory/licenses.review.json" >/dev/null
(
  cd "$output_directory"
  sha256sum licenses.review.json provenance.json sbom.spdx.json > SHA256SUMS
)

echo "release evidence prepared; licenses.review.json is deliberately unapproved and must remain outside the release until an authorized reviewer completes it"
