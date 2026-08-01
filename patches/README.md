# Runtime extension patches

WorkAgent2 integrates with independently maintained agent runtimes. This directory records the source-level extensions used by the platform without vendoring complete third-party source trees or release binaries.

## AionCore

`aioncore-v0.1.42-workagent.patch` applies to the upstream AionCore `v0.1.42` tag. It contains the platform's conversation fork and steering integration, channel command handling, WeChat media and completion delivery, resumable uploads, built-in help, idle-conversation routing, project classification, and the related persistence and tests.

```powershell
git clone https://github.com/iOfficeAI/AionCore.git
cd AionCore
git checkout v0.1.42
git apply --check ..\aioncore-v0.1.42-workagent.patch
git apply ..\aioncore-v0.1.42-workagent.patch
```

The upstream AionCore source and patch context retain the upstream license reproduced in `licenses/AIONCORE-LICENSE.txt`.

## Kimi Code

`kimi-code-v0.29.1-acp-session-fork-steer.patch` applies to the upstream Kimi Code `v0.29.1` source. It adds the ACP session fork capability and an AionUI-compatible steer extension while preserving the runtime's authentication checks.

```powershell
git checkout v0.29.1
git apply --check ..\kimi-code-v0.29.1-acp-session-fork-steer.patch
git apply ..\kimi-code-v0.29.1-acp-session-fork-steer.patch
```

The upstream Kimi Code source and patch context retain the MIT license reproduced in `licenses/KIMI-CODE-LICENSE.txt`.

## Verification

Both patch files are generated from source-only working trees. Before publication they are checked against their stated upstream baselines and scanned for credentials, personal filesystem paths, Windows SIDs, private network endpoints, and release binaries.
