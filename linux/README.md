# WorkAgent2

WorkAgent2 是 Linux AI 工作空间平台。生产迁移数据只能进入 Git 忽略、权限受控的本机迁移区；客户数据、项目、凭据、OAuth 状态、会话、日志、缓存和备份不得进入仓库。

## 当前状态

Linux 控制面、离线 Windows 数据迁移、运行时/共享组件组装和生产门禁已实现：租户账号/ACL/XFS 配额、systemd socket 激活、AionCore 监督、登录与可选管理员代登录、受控出站代理、长流代理、OAuth、项目事务、CLIProxy 逐 key 策略、ChatForward、日志脱敏、签名发布、兼容回滚、强制异机加密备份和空白主机恢复均已落到代码与测试。同步锁定的生产组件为 AionUi `2.1.0-beta.editfork.21`（静态资源与内置助手逐字节绑定只读 Windows `.20` 参考，Linux host 增加 fd3 possession-channel 边界）、AionCore `v0.1.42-editfork.10`、Codex `0.144.4`、Kimi Code `0.29.1-fork-steer.1`、Python `3.13.13`、CLIProxyAPI `7.2.81 / per-key-models.4`、`cpa-key-policy 0.4.5`，以及 ChatForward `zombie-reap-20260725-2329` / 扩展 `0.16.0`。Portal 配置、tenant 配置均为 schema v5；Portal SQLite 数据库为 schema v4。

当前仍不能宣称已经生产启用。代码无法代替有权负责人完成许可/NOTICE/品牌审批，也不能自行开放公网 443、提供正式 TLS/OAuth 注册、启用生产 XFS `prjquota`、接入异机备份与告警、提供真实 Provider 账号或完成双租户浏览器和空白主机恢复验收。AionCore 的两次干净 Linux 构建已经逐字节及完整树一致并由外部 pin 固定；这只是构建资格证据，仍须纳入源码干净、法务获批且完整签名的正式 release，不能以版本字符串代替该发布链。完成这些外部门禁后，日常用户开通才可收敛为：在本机安装对应 Codex/Kimi/Python CLI，完成 CLIProxyAPI OAuth，并对聊天模式做一次账号登录。完整边界见 [生产交接输入](docs/PRODUCTION_HANDOFF.md)、[发布证据](docs/RELEASE_EVIDENCE.md)和[生产一致性合同](docs/PRODUCTION_PARITY.md)。

## 历史合成 staging

2026-07-22 的合成 staging 使用 runtime release v3，但 Portal 配置和数据库仍是 schema v2。它只验证了 loopback 和双租户隔离，不能代表当前 Portal/tenant 配置 schema v5、Portal 数据库 schema v4 或真实签名组件已部署。若保留该环境，只能通过 `https://127.0.0.1:42580` 或 SSH 端口转发访问；不要开放公网安全组。

两个 staging 密码分别保存在以下 Git 忽略、root-only 文件中，值不会出现在本文档、命令参数或日志里：

- `.local-deployment/credentials/workagent-admin.password`
- `.local-deployment/credentials/stage-user.password`

自签名证书只用于 loopback staging。浏览器可临时信任 `/etc/workagent/tls/staging.crt`；生产必须更换为 WorkAgent2 正式域名证书。

## 代码边界

- Windows 参考服务器始终只读；任何修改、构建和部署只发生在这台 Linux 主机。
- 参考快照、内部审批、连接信息和扫描隔离区位于 Git 忽略目录，不进入产品仓库。
- 新配置只使用 `tenant_id` UUID、`runtime_user` 和 `data_root`。只读迁移器保留经过校验的旧 Windows 字段解析，以便离线导入；在线服务不信任这些字段。
- 不提交密钥、数据库、租户数据、日志、备份、构建工具或二进制。

## 主要目录

| 路径 | 用途 |
|---|---|
| `cmd/` | Portal、UserHost、管理、发布、备份、租户、凭据和非生产验收工具 |
| `internal/` | Linux 身份、UDS、存储、发布、路径和 Web 安全实现 |
| `config/` | WorkAgent2 品牌、deny-all policy 和 fail-closed 配置示例 |
| `deploy/` | systemd、sysusers.d 和 tmpfiles.d 模板 |
| `docs/` | 架构、部署边界和上线门禁 |
| `audit/` | 不含敏感参考值的技术审计结果 |

## 开发门禁

使用精确的 Go 1.26.5：

```bash
go test ./...
go test -race ./...
go vet ./...
scripts/audit-tree.sh
```

`scripts/source-gate.sh` 还会固定运行 ShellCheck 0.11.0、Gitleaks 8.28.0、Syft 1.29.0 和 govulncheck 1.6.0，生成十个在线控制面二进制（包含受签名根管控、仅由 root 显式运行的 `workagent-import-stage`）、健康检查 helper、独立离线迁移工具、SPDX 和校验记录。真实发布随后必须通过 `workagent-release` 的许可证审批报告、可复现 provenance、Ed25519 签名、数据 schema 兼容性、预检和备份门禁；具体流程见 [发布证据](docs/RELEASE_EVIDENCE.md)。
