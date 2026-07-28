# Kimi Code Linux component

This component freezes the Windows production contract as a Linux x64 build:

- upstream Kimi Code `0.29.1`, annotated tag object `785c319619ad4cbf87d8598afaea36c989f6cb66`, release commit `f4c3967a417a539372eadab6c809d27b8a14c005`;
- source archive SHA-256 `d00c6a1eff46bfe4213fe9f0547b51d7d812f2e9acd2e335ef282bb8d78a97af`;
- the byte-identical Windows production ACP patch, SHA-256 `26fe77028896bd05633479d00bab009fbce2d94e63cdea8f3ed121e38535d64b`;
- a MiniDb RESP oversized-request recovery patch, SHA-256 `8d81608ab936e939024de6f0015c8d16a6e666c05a199f4078103a411049f466`;
- Node.js `24.15.0` and Corepack-selected pnpm `10.33.0`;
- release identity `0.29.1-fork-steer.1`. The upstream CLI intentionally still reports `0.29.1`; `fork-steer.1` identifies the immutable patched WorkAgent artifact.

The patch advertises ACP session fork, maps `_meta.aionui.turnIndex` to the SDK's persisted-session fork operation, retains the authentication gate, and implements the `_aionui/session/steer` live-turn extension. The contract tests cover valid and invalid turn indices, authentication, missing sessions, content conversion, and live steer routing. The native smoke test exercises these routes through the final ELF over ACP stdio.

The RESP recovery patch rejects a declared request larger than 64 MiB before repeatedly copying its payload, streams the rejected frame into a bounded discard state, and resumes at the exact next pipelined command. It fixes the reproducible upstream case where a 65 MiB request consumed the test timeout without returning either the expected error or the following `PONG`.

`scripts/build-kimi-code-linux.sh` performs a clean, fail-closed build from the pinned ZIP. It requires an already staged pnpm v10 content-addressed store and Corepack cache; network access is disabled during dependency installation. By default it runs the ACP tests, SDK fork/steer tests, the full monorepo test suite, the regular web/CLI build, the native Node SEA build, and final executable smoke tests. When the build orchestrator is root, the full test tree is reflink-copied and run as `nobody` inside a Bubblewrap mount namespace with a private `/tmp` and deterministic non-empty HOME. This preserves the upstream unreadable-file security test without allowing earlier root-owned test directories or unrelated builder state to change the result. Set only the material locations when they differ:

```bash
KIMI_CODE_SOURCE_ZIP=/secure/materials/kimi-code-source.zip \
KIMI_CODE_NODE_ARCHIVE=/secure/materials/node-v24.15.0-linux-x64.tar.xz \
KIMI_CODE_PNPM_STORE=/secure/materials/pnpm-store \
KIMI_CODE_COREPACK_HOME=/secure/materials/corepack \
scripts/build-kimi-code-linux.sh
```

The SEA build uses the locked canonical workspace `/tmp/workagent-kimi-code-build-v1`, guarded by an exclusive lock, because Node records its main module's absolute build path in the executable. This makes the final ELF byte-reproducible instead of allowing random temporary directory names to perturb the hash.

The result is an immutable-ready directory under `.tools/artifacts/` containing `bin/kimi`, the checksum-verified upstream `LICENSE`, provenance inputs, both patches, and `SHA256SUMS`. OAuth tokens, tenant API keys, user configuration, and chat credentials are never build inputs and are never copied into the artifact. The release assembler must still add the project-wide unsigned manifest and its SHA-256 inventory before activation.

The WorkAgent-managed model bootstrap remains the source of truth for the production Kimi catalog: `kimi-for-coding`, `kimi-for-coding-highspeed`, and `kimi-k3`; exact efforts `low`, `high`, `max`; K3 defaults to `low`, while Coding and HighSpeed default to `high`. Those values are enforced by the Go bootstrap and migration tests, not baked into this executable.
