# Third-Party Notices

The custom license in [LICENSE](LICENSE) applies only to first-party material owned by this repository's copyright holder. It does not replace or restrict the licenses of third-party projects.

This repository does not vendor third-party source trees, release binaries, or private patches. Go dependencies and exact versions are declared in `go.mod` and `go.sum`. Direct dependencies include:

- `github.com/Microsoft/go-winio`
- `golang.org/x/crypto`
- `golang.org/x/sys`
- `modernc.org/sqlite`

Each dependency, including transitive dependencies, remains subject to the license and notices distributed by its own copyright holders. Anyone building the project is responsible for obtaining those modules from their official sources and complying with their terms.

Names of external products, APIs, and services appearing in interfaces or tests are used only to identify interoperability targets. Their trademarks belong to their respective owners. No external product binary, account credential, or service entitlement is included here.
