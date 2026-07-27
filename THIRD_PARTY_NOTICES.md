# Third-Party Notices

The custom license in [LICENSE](LICENSE) applies only to first-party material owned by this repository's copyright holder. It does not replace or restrict the licenses of third-party projects.

This repository does not vendor complete third-party source trees or release binaries. Go dependencies and exact versions are declared in `go.mod` and `go.sum`. Direct dependencies include:

- `github.com/Microsoft/go-winio`
- `golang.org/x/crypto`
- `golang.org/x/sys`
- `modernc.org/sqlite`

Each dependency, including transitive dependencies, remains subject to the license and notices distributed by its own copyright holders. Anyone building the project is responsible for obtaining those modules from their official sources and complying with their terms.

The `patches` directory contains source-level interoperability changes for two independently maintained projects:

- AionCore `v0.1.42`, from `https://github.com/iOfficeAI/AionCore`, with its upstream license reproduced in `patches/licenses/AIONCORE-LICENSE.txt`.
- Kimi Code `v0.29.1`, from `https://github.com/MoonshotAI/kimi-code`, under the MIT License reproduced in `patches/licenses/KIMI-CODE-LICENSE.txt`.

Those patch files include limited upstream context required by the unified diff format. Upstream material remains governed by its upstream license. The repository's custom license applies only to first-party modifications for which the repository copyright holder owns the rights.

Names of external products, APIs, and services appearing in interfaces or tests are used only to identify interoperability targets. Their trademarks belong to their respective owners. No external product binary, account credential, or service entitlement is included here.
