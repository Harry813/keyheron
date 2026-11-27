# 青鹭插件开发接口 v1

一个插件 ID 对应一个可授权的动作。管理员部署插件清单和资源映射，将动作授予具体任务后，Agent 才能通过该任务的 Unix socket 发现和调用插件。Rust 库、Warden 与沙箱客户端应采用同一版本的源码或发行包。

## 开发一个读取工单状态的插件

[示例清单](../examples/team-issues.plugin.json) 将 `team-issues/read` 绑定到受信的 `https-json` 驱动。文件只有四个字段。

```json
{"api_version":1,"id":"team-issues","action":"read","driver":"https-json"}
```

v1 的扩展驱动包括 `https-json`、`postgresql`、`mysql` 和 `sqlserver`。清单 ID 和动作使用 1–128 个 ASCII 字符，以字母或数字起始，可以包含点、下划线、连字符和冒号。核心会拒绝重复 ID、覆盖内置 ID、未知字段和未知版本。管理员可以直接编写 JSON，也可以通过 Rust 库的 `agent_access_core::plugins::v1` 构造和验证清单。[可编译的 Rust 示例](../rust-core/examples/issue_reader.rs)

```sh
cargo run --locked --manifest-path rust-core/Cargo.toml --example issue_reader
```

在 Warden 的资源配置中增加该插件。下面的目标令牌文件用相对路径引用，省略该字段即可读取公开服务。使用企业私有 CA 时指定 `ca_file`。

```json
{
  "team-issues": {
    "release-blocker": {
      "origin": "https://tracker.example.com",
      "path": "/api/issues/42",
      "fields": ["state", "updated_at"],
      "token_file": "secrets/tracker.token"
    }
  }
}
```

Warden 和管理面板均在启动时添加 `--plugin-manifest /srv/keyheron/plugins/team-issues.plugin.json`。可重复传入该选项，最多 64 个清单，每个最大 4 KiB。将清单、资源配置和数据库配置放在管理员控制的目录，使用由 Warden 账户或 root 拥有且组和其他用户不可写的普通文件。更新后重启读取这些清单的进程。管理端和 Warden 应部署同一份清单；新动作语义或资源归属发生变化时使用新 ID 或别名，并重新授权。

在面板创建模板，将 `team-issues / read / release-blocker` 和有效期绑定给任务。此时可在 Agent 中运行：

```sh
python3 warden_client.py describe team-issues
python3 warden_client.py invoke team-issues read release-blocker
```

数据库扩展沿用相同接口。例如，清单可将 `finance-db/connect` 的 `driver` 设为 `postgresql`，资源配置则使用 `{"config":"databases.json","env":"DEV","target":"ledger-pg"}`。Rust 核心在 Warden 解锁数据库凭据前核对本次授权和实际目标引擎。原生登录、SQL 账户权限和撤权语义见 [Warden 使用说明](WARDEN.md)。

## 在沙箱内使用 CLI 或 MCP

CLI 适合脚本和原生数据库客户端。任务获准访问 PostgreSQL 时，运行 `python3 warden_client.py invoke postgresql connect orders` 会在沙箱内建立临时回环端口，输出私有连接描述文件的路径。用同一沙箱里的 `psql` 读取其中的连接信息，CLI 进程在连接期间保持运行。

支持 MCP 的 Agent 可以让自己的 MCP 客户端启动 stdio 适配器。构建 Agent 镜像时安装 `requirements-mcp.txt`，将 `warden_client.py` 与 `warden_mcp.py` 放在同一目录。沙箱仍只需挂载它所属任务的 Warden socket。下面是采用 `mcpServers` 配置格式的客户端示例。

```json
{
  "mcpServers": {
    "keyheron": {
      "command": "python3",
      "args": ["/opt/keyheron/warden_mcp.py", "--socket", "/run/keyheron/warden.sock"]
    }
  }
}
```

安装完整青鹭源码时，也可以使用 `python3 keyheron.py mcp`。适配器默认读取 `KEYHERON_WARDEN_SOCKET`。它使用官方 MCP Python SDK，通过标准输入输出通信。任务身份、授权判断和原生数据转发均走既有 Warden 路径。

| MCP 工具 | 参数 | 结果 |
| --- | --- | --- |
| `list_connectors` | 无 | 当前任务可用的插件、动作、资源和 TTL |
| `describe_connector` | `connector` | 插件接口及本任务可用的资源 |
| `invoke_connector` | `connector`、`action`、`resource` | JSON 插件返回获准字段；数据库插件返回 `handle`、`descriptor_path`、`expires_at` |
| `close_connection` | `handle` | 回收当前适配器实例创建的数据库连接 |

例如，Agent 调用 `invoke_connector` 并传入 `{"connector":"postgresql","action":"connect","resource":"orders"}`，把返回的文件路径交给同一沙箱里的原生客户端。临时登录口令仅写入权限为 `0600` 的描述文件，MCP 工具响应仅交付上述三个字段。每次调用仍要在线鉴权，数据库保持原有到期和撤权行为；主动关闭、适配器正常退出时也会清理连接。MCP 不接收上游地址、任意 SQL、授权声明或宿主凭据。

## Agent 的 Unix socket 接口

每个连接发送一行 UTF-8 JSON，以换行结尾，最大 4 KiB。每个连接处理一次请求。由 Warden 决定当前任务和对端 Server，Agent 只传插件、动作、资源别名。下列三行分别是三个独立连接的请求。

```jsonl
{"api_version":1,"op":"list"}
{"api_version":1,"op":"describe","connector":"team-issues"}
{"api_version":1,"op":"invoke","connector":"team-issues","action":"read","resource":"release-blocker"}
```

- `list` 返回 `{"result":[...]}`，每项包含 connector、action、resource 和 ttl。结果取当前任务授权与当前 Warden 已配置资源的交集。
- `describe` 返回 `{"result":{"api_version":1,"id":"team-issues","action":"read","driver":"https-json","native_stream":false,"legacy":false,"resources":[{"resource":"release-blocker","ttl":30}]}}`。仅已授权的插件和资源可见，ttl 为规则允许的秒数上限。
- JSON 插件的 `invoke` 返回白名单字段，例如 `{"result":{"state":"open","updated_at":"2026-11-27"}}`。原生数据库插件返回 `{"transport":"database-stream","result":{...}}`。其中是短期登录信息。客户端就绪后在同一连接发送单字节 0x01，然后交换数据库协议字节。随包客户端承担该握手、本地端口、临时文件和证书清理。
- 失败返回 `{"error":"…"}` 并关闭连接。客户端按 error 字段判断失败，错误文本用于展示。旧客户端使用的无版本 list/invoke 消息仍受同一授权约束。

## 安全边界

Rust 核心负责清单注册、请求与控制服务已确认授权的精确匹配、驱动选择、只读 HTTPS 执行，以及将 Warden 的已连接 Unix/TCP 套接字交给原生数据库中继。Warden 的 mTLS 客户端、控制服务、凭据解锁和各数据库协议的认证适配仍由 Python 实现。回收数据库会话时关闭活动流。与控制面失联、短时授权到期或审计不可用时，后续执行会停止。

HTTPS JSON 驱动仅对运维配置的固定 HTTPS 源和绝对路径发送 GET。有令牌时使用 Bearer；GitLab 内置驱动使用 PRIVATE-TOKEN。路径支持 ASCII 字母、数字及 `/-._~`，拒绝查询串、片段、转义和跳转路径。请求关闭重定向、环境代理和自动重试，响应上限为 1 MiB。通用 JSON 只返回配置的顶层标量字段，禁止通配或输出嵌套对象。Agent 无法在调用中提交 URL、请求头、文件路径、可执行命令或自签授权。提供任意原生代码的扩展需要单独的宿主信任与隔离设计；v1 接受上述声明式驱动。

一旦客户端收到数据，撤权只能约束后续访问。宿主管理员、控制服务以及管理员选择的上游需要可信。插件身份由管理员部署的配置决定，控制策略按插件 ID、动作和资源名授权。
