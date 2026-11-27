# 把自己的 HTTPS 服务接入 KeyHeron

## 先验证运行环境

使用预编译发行物时，将同一版本的源码 ZIP 和当前系统的原生程序下载在一起，校验 SHA256SUMS 后解压源码。例如，在 Linux x86_64 的解压目录中执行 `mkdir -p bin`，再执行 `install -m 755 /path/to/keyheron-core-linux-amd64 bin/agent-access-core-linux-amd64`。Apple Silicon Mac 对应 `keyheron-core-darwin-arm64` 和 `bin/agent-access-core-darwin-arm64`。外部 HTTPS 模式不使用 KeyFence 二进制。

在获得源码并构建 Rust 程序后，运行 `python3 verify_external.py`。这条验收会验证上游实际收到的 DEV 与 PROD 凭据、不同 TLS 根、单独撤销、自然到期、切环境后旧授权失效，以及审批通过的一次性写操作。客户端会分别使用 curl 和 Python 标准库。常规验收不会连接 GitHub 私有仓库。

## 使用 GitHub 令牌做受管读取

1. 将 `examples/github-readonly.json` 复制到仓库之外的私有目录并重命名为 `policy.json`。把两个示例路径替换成你有权读取的实际仓库。只用一个环境时，可以删除另一个环境段。
2. 给每个环境准备独立的只读凭据，限制到该环境的测试仓库和 Contents: read。在配置旁初始化 `vault/credentials.sqlite3`，用 `secrets put` 分别向 DEV 和 STG 录入名为 `github-reader` 的凭据。程序会在终端关闭回显。[凭据库操作说明](CREDENTIALS.md)
3. 从项目根目录启动服务，在申请人工作台选择环境并执行读取。工作台显示上游状态和配置的账户名。Bearer、API Key 和自定义认证头配置只支持受管操作。`keyheron run` 会在切换环境前提示需要客户端证书，直接调用 SDK 签发接口会收到 403。

```sh
python3 keyheron.py serve --config /path/to/private/policy.json --state-dir .keyheron --open
```

## 用客户端证书向 SDK 返回业务正文

给支持双向 TLS 的上游配置独立、最小权限的客户端身份。让上游验证客户端证书并授权对应路由，私钥只保存在可信代理上。在策略的 `environments` 中配置环境，例如：

```json
{
  "DEV": {
    "origin": "https://catalog.example.com",
    "client_identities": {"reader": "keys/reader.pem"},
    "routes": {"read": {"method": "GET", "path": "/records", "resource": "catalog", "credential": "reader"}}
  }
}
```

每个身份的 PEM 包含客户端证书链和对应私钥，应仅允许可信宿主账户读取。轮换证书后重启代理。每个任务选择一种上游认证方式，使用请求头凭据和使用客户端证书的服务需分别启动。启用 SDK 正文读取的上游应使用独立身份，勿将原有可复用令牌另行提供给该服务。

启动服务后，运行 `python3 keyheron.py run --state-dir .keyheron --env DEV -- python3 examples/read_resource.py`。客户端通过短期代理会话读取正文，上游通过 TLS 校验代理的客户端证书。切换环境会收回旧环境的会话。

## v1 策略

一份配置代表一个任务。根字段为 `version: 1`、`task`、`identities` 和 `environments`；身份标签来自启动方，不提供企业 SSO。配置 DEV、STG、PROD 中实际需要的环境，每个环境有一个 HTTPS 源。密钥和 CA 文件的相对路径均相对于配置文件。代理运行时为已配置主机生成短期代理证书，只把 CA 公共证书、代理会话信息和经过筛选的环境变量交给客户端。

| 字段 | 用途 |
|---|---|
| `origin` | HTTPS 主机，可带端口，不带路径、查询或账户信息。 |
| `credential_refs` | 从路由的凭据引用映射到同一环境的加密条目名。旧版 `credential_files` 可以继续引用由宿主管理的文件。同一引用只能配置一个来源。 |
| `client_identities` | 从路由的 `credential` 名称映射到上游客户端身份 PEM。使用此模式的任务中所有环境均使用客户端证书，不配置请求头凭据。 |
| `ca_file` | 可选的额外上游 CA，仅在该环境生效。默认验证正常的公共受信证书。 |
| `routes.read` | 要求固定 GET 路径；是通用 SDK 唯一可使用的动作。 |
| `routes.diagnose` | 可选的限时受管 GET；需独立审批。 |
| `routes.retry` | 可选的单次受管 POST；需独立审批。只有上游实际支持 Idempotency-Key 才应设 `idempotency_supported: true`。 |
| 各路由通用字段 | `method`、`path`、`resource`、`credential`，可选 `max_ttl`（1–900 秒）。使用请求头凭据时默认注入 Authorization: Bearer，自定义 API Key 可用 `auth_header: "X-API-Key"`、`auth_scheme: ""`。 |

下面两个示例使用请求头凭据，引用来自该环境的 `credential_refs` 或 `credential_files`。使用客户端证书时，路由的 `credential` 引用该环境的 `client_identities` 条目。上游地址、动作和参数由可信维护者配置，客户端不能自行改写。

```json
{
  "diagnose": {"method":"GET","path":"/v1/diagnostics/orders","resource":"orders-diagnostics","credential":"diagnostic-reader","max_ttl":120},
  "retry": {"method":"POST","path":"/v1/jobs/report-42/retry","resource":"report-42","credential":"job-runner","max_ttl":45,"body":{"reason":"operator-approved"},"idempotency_supported":true}
}
```

每个路由只接受一条规范的精确路径。首版不支持查询字符串、通配路由、透明重定向、WebSocket、gRPC、插件代码和任意调用者提供的 POST 正文。支持 HTTP/1.1、遵循显式代理且接受任务 CA 的客户端；使用证书固定的客户端需单独评估。代理会传回受信上游的有限大小响应正文，操作记录中仅保留元数据。不得批准会返回密钥的调试、回显或管理端点。

## 信任边界与故障

状态目录包含仅供可信启动器使用的申请人连接描述符，运行时会生成短期私钥。不要把整个目录、真实凭据文件或审批人链接交给不可信 Agent。同一 OS 用户具有读取宿主文件的能力；此预览对受信客户端提供凭据代理，在不可信执行环境中需要独立用户或容器和强制网络出口。回收会话阻止新授权请求，已经在途或已经完成的上游操作遵循上游生命周期。

启动器会分别创建权限为 0600 的申请人和审批人入口页。终端显示本地文件 URI，正常退出后文件会删除。若密钥管理器通过符号链接轮换凭据，请把稳定的链接路径写入策略，后续请求会打开它当时指向的文件。

`run` 收到 TERM、HUP 或 INT 时会终止客户端进程组并请求撤销会话。SIGKILL、宿主崩溃或控制服务不可达可能阻止撤销送达。此时服务端按会话剩余期限拒绝后续读取，CLI 签发的期限最多为 300 秒，也可在工作台提前结束任务。

若得到 407，检查子进程会话是否到期、结束或已切换环境；403 表示请求、角色或范围被拒绝；502 时检查上游证书、主机及受信 CA，保留证书验证。对外部服务的一次写操作出现未知结果时，先按操作号在上游查证，再决定是否重新审批。不要将 HTTP 202 解释成业务已完成。
