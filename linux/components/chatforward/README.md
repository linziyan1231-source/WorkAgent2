# ChatForward Linux component

This directory pins the exact read-only ChatForward snapshot copied from the Windows production host and supplies Linux-only packaging and runtime integration. It does not contain browser cookies, Portal credentials, OAuth material, logs, or any other Windows runtime state.

- `VERSION` identifies the Windows server release `zombie-reap-20260725-2329`; the independently checked browser extension version is `0.16.0`.
- `SOURCE.sha256` is the complete 27-file source allow-list. The build rejects additions, omissions, symlinks, or changed bytes.
- `NODE.sha256` pins the official Node.js 24.15.0 Linux x64 archive. `DEPENDENCIES.sha256` and `DEPENDENCIES.sha512` independently pin the only npm dependency tarball so production builds run offline and shared-release provenance can use a valid SHA-256 revision.
- `integration/` is added to the package after the upstream source tests, shell syntax checks and Linux integration tests all pass.
- `test/` checks readiness fail-closed behavior and Linux deployment invariants.

The output of `scripts/build-chatforward.sh` is deterministic for the same inputs and `SOURCE_DATE_EPOCH`. It is an input to the approved package/release pipeline, not an authorization to install an unverified archive on a production host.

See `docs/CHATFORWARD_LINUX.md` for the production build, service and one-time ChatGPT login procedure.
