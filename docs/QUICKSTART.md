# 把自己的 HTTPS 服务接入 KeyHeron

## 先验证运行环境

使用预编译发行物时，将同一版本的源码 ZIP 和当前系统的原生程序下载在一起，校验 SHA256SUMS 后解压源码。例如，在 Linux x86_64 的解压目录中执行 `mkdir -p bin`，再执行 `install -m 755 /path/to/keyheron-core-linux-amd64 bin/agent-access-core-linux-amd64`。Apple Silicon Mac 对应 `keyheron-core-darwin-arm64` 和 `bin/agent-access-core-darwin-arm64`。外部 HTTPS 模式不使用 KeyFence 二进制。

在获得源码并构建 Rust 程序后，运行 `python3 verify_external.py`。这条验收会验证上游实际收到的 DEV 与 PROD 凭据、不同 TLS 根、单独撤销、自然到期、切环境后旧授权失效，以及审批通过的一次性写操作。客户端会分别使用 curl 和 Python 标准库。常规验收不会连接 GitHub 私有仓库。

## 接入你的私有 GitHub 测试仓

1. 将 `examples/github-readonly.json` 复制到仓库之外的私有目录并重命名为 `policy.json`。把两个示例路径替换成你有权读取的实际仓库。只用一个环境时，可以删除另一个环境段。
2. 给每个环境准备独立的只读凭据，限制到该环境的测试仓库和 Contents: read。分别保存在配置旁的 `secrets/dev-reader` 和 `secrets/stg-reader`，私有目录使用 0700、凭据文件使用 0600。也可以使用已有密钥管理器为宿主提供的文件路径。不要把值写进配置或粘贴到终端命令行。
3. 打开两个终端，在第一个启动服务，在第二个启动你的客户端。以下示例都从项目根目录运行；替换配置路径。

```sh
python3 keyheron.py serve --config /path/to/private/policy.json --state-dir .keyheron --open
```

```sh
python3 keyheron.py run --state-dir .keyheron --env DEV -- python3 examples/read_resource.py
python3 keyheron.py run --state-dir .keyheron --env STG -- python3 examples/read_resource.py
```

这个客户端只使用标准 HTTPS 请求并打印状态和字节数。也可以把命令换成 `curl --fail --silent --show-error https://api.github.com/repos/YOUR-ORG/YOUR-DEV-REPO/readme`；curl 会向终端输出响应，请只在受信终端使用。网页和客户端共享当前任务；改变环境会收回其他正在使用旧环境的会话。到工作台“操作记录”按环境过滤，核对签发、SDK 请求和回收事件。

## v1 策略

一份配置代表一个任务。根字段为 `version: 1`、`task`、`identities` 和 `environments`；身份标签来自启动方，不提供企业 SSO。配置 DEV、STG、PROD 中实际需要的环境，每个环境有一个 HTTPS 源。密钥和 CA 文件的相对路径均相对于配置文件。代理运行时为已配置主机生成短期代理证书，只把 CA 公共证书、代理会话信息和经过筛选的环境变量交给客户端。

| 字段 | 用途 |
|---|---|
| `origin` | HTTPS 主机，可带端口，不带路径、查询或账户信息。 |
| `credential_files` | 从凭据引用映射到文件。即使多个环境共用同一主机，也应给每个环境配置独立凭据与资源。 |
| `ca_file` | 可选的额外上游 CA，仅在该环境生效。默认验证正常的公共受信证书。 |
| `routes.read` | 要求固定 GET 路径；是通用 SDK 唯一可使用的动作。 |
| `routes.diagnose` | 可选的限时受管 GET；需独立审批。 |
| `routes.retry` | 可选的单次受管 POST；需独立审批。只有上游实际支持 Idempotency-Key 才应设 `idempotency_supported: true`。 |
| 各路由通用字段 | `method`、`path`、`resource`、`credential`，可选 `max_ttl`（1–900 秒）。默认注入 Authorization: Bearer；自定义 API Key 可用 `auth_header: "X-API-Key"`、`auth_scheme: ""`。 |

例如，下面两个条目可以放入某个环境的 `routes`。凭据引用必须在该环境的 `credential_files` 中声明。上游地址、动作和参数由可信维护者配置，客户端不能自行改写。

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
