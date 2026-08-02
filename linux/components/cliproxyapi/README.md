# CLIProxyAPI 7.2.81 Linux component

This component reproduces the Windows production behavior on Linux amd64 from
the two checksum-locked source archives copied read-only from WorkAgent2. It
applies the exact `per-key-models.4` model-catalog patch, the exact Windows
`cpa-key-policy` concurrency patch, and the additional Linux directory-fsync
durability patch. A separate Linux compatibility patch resolves four Go 1.26
static-analysis findings without changing the public protocol: it gives
`WriteTo` its standard byte-counting signature, removes dead code, and makes
ownership transfer of two stream cancellation functions explicit. It also
avoids rewriting an unchanged returned header map while a stream consumer may
legitimately inspect the already-initialized headers.

The Windows policy patch has one internally misnumbered hunk: after its earlier
hunks change the same file's line count, GNU patch cannot place the otherwise
exact `usageFlusher` initializer hunk. The build treats exactly that one reject
as an expected provenance defect, verifies both rejected lines, applies the
single replacement, then verifies hashes of every patched source file. Any
different reject or source result fails closed.

`scripts/build-cliproxyapi-linux.sh` runs the upstream Go and web tests, race
tests for both patched subsystems, vet, builds with Go 1.26.5 and CGO, validates
the ELF architecture/exported plugin ABI and embedded versions, and emits an
immutable-ready payload under `.tools/artifacts/`. It copies no OAuth token,
management credential, downstream API key, policy state, or provider account.
Two clean builds produced byte-identical core and plugin binaries; their hashes
are locked in `LINUX-ARTIFACTS.sha256`. The shared assembler additionally pins
the emitted full-manifest checksum in `LINUX-ARTIFACT-MANIFEST.sha256` and the
canonical artifact tree (including modes) in `LINUX-ARTIFACT-TREE.sha256`, so
the evidence files cannot be replaced or extended together with a rewritten
self-checksum list.
