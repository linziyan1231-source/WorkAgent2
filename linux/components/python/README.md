# Python 3.13.13 Linux component

This component builds the official CPython 3.13.13 source release into a tenant-safe, relocatable runtime. The source archive, compiler release and complete OpenCloudOS build dependency set are pinned. The build is offline after the official archive has been staged and uses a stable canonical build path plus `SOURCE_DATE_EPOCH` and compiler path remapping.

`scripts/build-python-linux.sh` runs the CPython regression suite by default, installs the standard library and bundled `pip`, removes build-only tests and bytecode caches, strips native runtime objects, and rejects every symlink or special file before producing the payload. The immutable release layout is:

- `bin/python3`, the version-probed WorkAgent launcher;
- `bin/pip3`, an offline-safe launcher for the bundled pip (pip itself may use the network only when an operator or agent explicitly asks it to install a package);
- `libexec/python/3.13.13/`, containing the real interpreter and standard library;
- audit material under `share/workagent-components/python/`.

The final smoke suite checks relocation, TLS, SQLite, compression, ctypes, decimal, multiprocessing, venv and ensurepip. No user site-packages, pip cache, credentials or Python environment variables are copied into the artifact.
