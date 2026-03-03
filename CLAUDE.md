# CLIProxyAPI

## 项目基础信息

- **技术栈**：Go（Gin HTTP API、Bubble Tea TUI、OAuth/API 代理、PostgreSQL/pgx、Docker）
- **最低支持版本**：Go 1.26.0

## 项目结构

- `cmd/`：程序入口与命令行启动
- `internal/`：核心业务逻辑（路由、认证、提供商适配、配置等）
- `sdk/`：可复用 Go SDK
- `auths/`：认证相关实现
- `docs/`：项目文档
- `examples/`：SDK/集成示例
- `test/`：测试与测试资源

## 开发协议

本项目使用 `.claude/skills/protocol-dev/` 中的开发协议 skill，包含完整的工作流规范、commit 规范、调试规范等。生成提交信息时必须遵循 skill 协议中的 commit 规范。

### 关键约束

- 任何代码变更需求，必须先给方案，等待用户明确授权后才能执行
- 禁止使用 `rm` 删除文件，必须使用 `trash`
- `git commit` 流程：先输出 commit 信息供用户审核，用户确认后再执行提交，提交内容必须与展示内容完全一致，禁止附加任何辅助编程标识信息（如 Co-Authored-By 等）
- 禁止使用 Markdown 表格
- `git worktree` 规范：新建 worktree 时，必须将工作树创建在项目同级目录下，目录名格式为 `{项目名}--{分支名}`（分支名中的 `/` 替换为 `-`）。例如项目为 `my-app`，分支为 `feat/login`，则 worktree 路径为 `../my-app--feat-login/`。禁止使用默认的 `.git/worktrees` 或项目内部路径
