# WorkAgent2 for Windows

This directory contains the Windows implementation of WorkAgent2. It provides the browser-facing portal, per-SID UserHost runtime supervision, administrative provisioning, immutable release validation, model-policy integration, and Windows-specific isolation helpers.

## Layout

| Path | Purpose |
|---|---|
| `cmd/aionui-portal` | Portal service entry point |
| `cmd/aionui-userhost` | Per-SID runtime supervisor entry point |
| `cmd/portal` | Administrative CLI entry point |
| `cmd/aion-agent-cli` | Stable agent launcher and release verifier |
| `internal/portal` | Sessions, HTTP/WebSocket proxying, quotas, notifications, and UI delivery |
| `internal/admin` | Privileged account provisioning and recovery orchestration |
| `internal/userhost` | Private runtime lifecycle, credentials, OAuth, projects, and agent defaults |
| `internal/winutil` | Accounts, ACLs, Job Objects, profiles, restricted tokens, and process helpers |
| `scripts` | Build and release-contract scripts |

## Build and test

Requirements: Windows 10/11 or Windows Server, Go 1.26 or newer, and PowerShell 7 for release-contract scripts.

```powershell
go test ./...
go vet ./...
go build ./cmd/aionui-portal
go build ./cmd/aionui-userhost
go build ./cmd/aion-agent-cli
go build ./cmd/portal
```

See [the Windows architecture](docs/ARCHITECTURE.md) and the repository-level [security policy](../SECURITY.md).
