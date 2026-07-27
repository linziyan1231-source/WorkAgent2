# WorkAgent shared-service component contract

The components.json file is the exact component list for a shared or combined
signed release. It binds CLIProxyAPI, every applied patch family, the policy
plugin, ChatForward, its browser extension, Node.js, and ws to their
checksum-locked inputs. It contains no OAuth state, provider account, browser
profile, management key, policy state, or user data.

The source revisions are hashes of the complete source archive/manifest or the
tracked composite input manifest, not invented Git commits. Release provenance
must include every revision, and a package signature does not replace the
component-level SPDX and license review required by LICENSE_STATUS.md.

The shared assembler accepts trusted inputs only through a symlink-free,
UID/GID-0-owned parent chain with no group/other write permission; the same
ownership, type and mode rule covers every CLIProxy tree entry. It binds the
complete CLIProxy artifact independently of its self-reported checksums: the
repository pins both the checksum of its full `SHA256SUMS` and a canonical tree
hash, requires an exact one-to-one file set, and rejects content, path, type or
mode drift before copying anything. The exact ChatForward archive argument is
independently bound to both its required basename and repository-pinned
SHA-256, so an alternate file beside a valid archive cannot bypass verification.

The output parent must already be root-protected and share the build directory's
filesystem. Final publication is an atomic no-clobber directory rename with a
postcondition check; a target created after preflight is rejected rather than
receiving the release as a nested child.
