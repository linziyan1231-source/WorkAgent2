# Security Policy

## Supported version

Security fixes are applied to the current `main` branch. Historical commits and locally modified versions are not maintained separately.

## Reporting a vulnerability

Please do not publish credentials, host details, or an exploitable proof of concept in a public issue. Use GitHub's private vulnerability-reporting or Security Advisory feature for this repository.

Include:

- the affected component and version or commit;
- required privileges and preconditions;
- the expected and observed security boundary;
- the smallest safe reproduction;
- the potential effect on confidentiality, integrity, availability, or tenant isolation.

Use synthetic identities, paths, credentials, and infrastructure details in reports.

## Core security boundaries

- Browser authentication does not authorize browser-provided host paths or internal credentials.
- Windows SID is the tenant identity for private runtime and filesystem operations.
- Per-user process trees are constrained by ACLs, loopback listeners, restricted tokens where applicable, and Job Objects.
- Secret material must not enter command-line arguments, shared releases, logs, or browser responses.
- Immutable release files are validated against manifests before launch.
- Provider identities, model aliases, keys, and quotas are bound to stable server-managed records.

## Deployment responsibility

Passing unit tests is not a production security certification. Deployments must independently verify Windows service identities, profile ownership, ACL inheritance, reparse-point handling, filesystem quotas, TLS, cookies, public origin, OAuth callbacks, firewall rules, provider access, release hashes, upgrade behavior, and rollback evidence.
