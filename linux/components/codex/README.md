# Codex 0.144.4 Linux component

This component packages the official `@openai/codex@0.144.4-linux-x64` npm platform tarball after checking the registry artifact hash, its exact eight-file allow-list, and every vendor-file hash. It does not rebuild or re-label Codex.

`scripts/build-codex-linux.sh` creates an immutable-ready payload under `.tools/artifacts/` by default. `bin/codex` is a small audited launcher; the byte-identical official musl executable and its required layout remain under `libexec/codex/`:

- `bin/codex` and `bin/codex-code-mode-host`;
- `codex-resources/bwrap` and the bundled `zsh`;
- `codex-path/rg`;
- `codex-package.json`.

The launcher makes the release contract independent of Node.js and preserves the relative vendor layout used by the native executable. The build verifies `codex-cli 0.144.4`, help output, the code-mode host, ripgrep, bubblewrap and zsh. It also packages the checksum-pinned Apache-2.0 `LICENSE` from the official `rust-v0.144.4` source tag; the official npm metadata independently declares the same SPDX identifier. Executables are mode `0555`; metadata is `0444`; no OAuth state or `CODEX_HOME` is copied.
