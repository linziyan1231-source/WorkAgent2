# WorkAgent2 Linux

WorkAgent2 Linux 是集中托管、浏览器访问的多用户 AI 工作空间实现。它将模型接入、员工工作区、运行时组件和行业工具统一部署在 Linux 服务器上，让任务不依赖个人电脑持续在线，同时为不同用户提供独立的数据、进程和资源边界。

## 核心能力

- 浏览器端 Portal、员工账号管理和资源用量视图
- 每位用户独立的 Linux 身份、私有目录、Unix socket、cgroup 与 XFS 项目配额
- 可恢复、可并发的员工开通流程，以及受保护的进度 IPC
- AionUi、AionCore、Codex、Kimi Code、CLIProxyAPI 和 ChatForward 的集中运行时管理
- OAuth、模型目录、逐 Key 策略、配额与共享容量管理
- 项目事务、运行时监督、日志脱敏与故障恢复
- 哈希校验发布、升级预检、兼容回滚和加密备份边界
- systemd socket activation、最小权限服务账号和 fail-closed 配置验证

## 架构概览

Portal 只负责浏览器认证、会话和输入校验。租户文件、凭据、项目、OAuth 状态及运行时操作由对应的 UserHost 在用户隔离边界内完成。专用 UID、私有数据根、ACL、cgroup 和 XFS project ID 共同构成租户身份与资源边界。

运行时组件使用锁定版本、哈希清单和不可变发布目录组装。Portal 不接触上游凭据；一次性凭据通过受限 IPC 或 systemd credentials 传递，并在消费后删除明文。

## 目录结构

| 路径 | 用途 |
|---|---|
| `cmd/` | Portal、UserHost、管理、发布、备份、凭据和开通工具 |
| `internal/` | Linux 身份、存储、IPC、租户隔离、发布和 Web 安全实现 |
| `config/` | 非敏感配置示例、模型策略与通用品牌资源 |
| `deploy/` | systemd、Caddy、sysusers.d、tmpfiles.d 和监控模板 |
| `components/` | 锁定的共享组件版本、补丁、清单和可复现构建信息 |
| `scripts/` | 构建、验证、发布和运维脚本 |
| `docs/` | 架构、安全边界、发布流程和组件说明 |

## 开发与验证

项目使用 Go 1.26.5。基础检查：

```bash
go test ./...
go test -race ./...
go vet ./...
scripts/audit-tree.sh
```

部分组件测试还需要 Node.js、ShellCheck、Gitleaks 和 govulncheck。构建与部署前请使用仓库锁定的工具版本，并在非生产环境验证配置、ACL、配额、备份和回滚流程。

## 安全

不要把客户数据、项目内容、密码、OAuth 状态、会话、日志、数据库、备份或本机部署配置提交到仓库。详细边界见 [SECURITY.md](SECURITY.md) 和 [架构文档](docs/ARCHITECTURE.md)。

## 许可

本目录适用仓库根目录的 [Personal and Internal Non-Monetized Source License](../LICENSE)。允许个人非商业使用及单一企业内部使用，不允许销售、对外托管、提供收费服务或以本项目及其衍生版本盈利。
