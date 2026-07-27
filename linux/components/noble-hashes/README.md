# @noble/hashes 2.2.0 runtime lock

AionUi's resumable upload implementation imports `sha256` from `@noble/hashes/sha2.js` so hashing does not depend on `crypto.subtle`. The exact 98-file installed npm package tree, its package metadata, SHA-2 implementation, MIT license, and the SHA-512 integrity recorded in `bun.lock` are pinned here.

The package is compiled into the byte-verified AionUi frontend reference rather than shipped as a mutable runtime `node_modules` directory. `scripts/build-aionui-linux.sh` verifies this package evidence before accepting the frontend and records it as a distinct release component.
