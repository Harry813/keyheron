# KeyHeron 本地模拟工作台

用同一个本地客户端访问 DEV、STG、PROD 的模拟订单服务，在 PROD 临时读取诊断信息，然后经独立审批重跑指定作业。每个环境都运行一个真实的 KeyFence v0.4.0 进程，只能通过自身的凭据目录解析本环境的模拟账户。上游会验证收到的凭据，并返回实际识别到的账户名。

## 打开 Web 控制台

在本目录运行以下命令。Apple Silicon Mac 的压缩包内含 Rust release 程序和 KeyFence v0.4.0，需要 Python 3.10+ 启动本地模拟设施，不需要 Node.js、Rust 工具链或网络。

```sh
python3 web_demo.py --open
```

启动器只监听回环地址，分别为申请人 `alice` 和审批人 `owner` 创建一份仅当前用户可读的本地入口文件。终端显示两个文件的 URI，`--open` 会在浏览器中分别打开。入口仅在此次服务运行期间有效，正常退出时会删除。用 `--terminal` 可同时从终端操作这一个 Rust 服务，两种入口共享会话和审计记录。Ctrl+C 或退出交互终端后，模拟账户及会话会回收。

在申请人页依次选择 DEV、STG、PROD，点击“读取服务状态”查看实际上游账户。在 PROD 申请临时权限，在审批人页审阅资源和时限，回到申请人页执行。一次性重跑支持从上游账本查询执行回执。收回临时权限后基础读取仍然有效，“结束会话”会收回当前任务的剩余权限。

### 记录与目录

- Rust 控制服务在本地 SQLite 记录环境、操作主体、资源、申请编号、动作、时间和结果。一次性操作的受理和实际执行结果分开记录。正常到期、主动收回、环境切换引起的收回也会留痕。浏览器支持按环境筛选及游标分页。浏览历史和查看当前状态不会反过来产生新的审计事件。
- 默认数据库为 `data/events.sqlite3`。下次启动仍可查旧事件，活动授权和角色访问链接重新建立。可用 `--db 路径` 指定记录库。同一库一次只允许一个启动器。
- `web/` 是可独立维护的原生 HTML、CSS、JavaScript 前端。它使用同源 JSON API。审计保存在服务端，不依赖浏览器存储。标签页仅保存这次演示的角色登录信息，不持有上游凭据。
- `rust-core/` 是独立 Cargo crate。Rust 实现访问授权、会话切换、审批、撤销、受控调用、结果归因和审计。前端轮询和普通读取走独立的读路径；SQLite 使用 WAL、独立读写连接和 FULL 同步写入。成功的业务请求仍需完成其审计写入才返回。Python 负责启动测试设施、模拟上游和运行验收。KeyFence 保留为原版凭据代理。

### 从源码构建

在未附带原生二进制的平台上，使用近期稳定 Rust 工具链及系统 C 编译器，在本目录运行。本次 release 构建使用 rustc 1.99.1。

```sh
python3 tools.py --install
cargo build --manifest-path rust-core/Cargo.toml --release --locked
python3 web_demo.py --open --core rust-core/target/release/agent-access-core
```

### 复测授权与延迟

```sh
python3 verify_web.py
python3 bench.py --samples 1200 --concurrency 1 8 --json
```

基准在所有路径上读取同一个 DEV 上游账户，依次比较直接请求、仅经 KeyFence 和完整 Rust 授权 + KeyFence + SQLite 审计。客户端预热后分批轮换路径，报告成功请求的 p50/p95/p99、吞吐、错误、上游请求数和审计行数。每档分别比较分位数，未将两条独立请求当作配对样本。KeyFence v0.4.0 普通 HTTP 对本演示非标准上游端口的客户端连接复用有限制，基准显式让该代理段每请求建立连接；客户端到 Rust 的连接可复用。本机数据仅适用于测得的回环 HTTP 场景。实际测量和构建摘要见 `performance.json`，浏览器、权限和持久化验收见 `web-verification.json`。可用 `--max-added-p95-ms N` 指定允许的新增延迟（毫秒，以仅经 KeyFence 为基线）；任一并发档超出时脚本返回状态码 1。

## 命令行演示

在本目录运行以下命令。需要 Python 3.10 或更高版本。Apple Silicon Mac 的官方 KeyFence 可执行文件已随包提供，运行演示无需联网或安装 Python 依赖。

```sh
python3 demo.py --interactive
```

其他受支持平台为 macOS x86_64、Linux x86_64 和 Linux arm64。首次使用时在同一目录执行 `python3 tools.py --install`，安装器下载对应平台的 v0.4.0 文件并核对固定的 SHA-256。启动演示时也会校验摘要。本次实机验证使用 macOS arm64。[KeyFence 官方发行版](https://github.com/atgreen/keyfence/releases/tag/v0.4.0)

## 手动走一遍

默认进入 DEV。以下命令按顺序粘贴或逐条执行。终端中的 `alice` 代表任务申请人，`owner` 代表审批人；同一位演示操作员可以在本机观察两者的交互。

```text
read
env STG
read
env PROD
read
request diagnose 60
review 1
approve 1
status
use 1
revoke 1
use 1
read
request retry 60
review 2
approve 2
use 2
result 2
use 2
exit
```

三次环境读取应依次显示 `dev-reader`、`stg-reader`、`prod-reader`。批准的诊断使用 `prod-diagnostics`；撤销后的 `use 1` 会被拒绝，此时 `read` 仍然成功。第一次 `use 2` 使用 `prod-worker` 重跑模拟作业 `job-4821`，`result 2` 从上游模拟账本读取回执，第二次使用同一审批会被拒绝。要拒绝一项申请，在 `review 编号` 后立即输入 `reject 编号`。授权时限从提交申请开始计算。

## 参考实现的回归验证

```sh
python3 demo.py
python3 verify.py
```

`demo.py` 的自动流程和 `verify.py` 保留原 Python 参考实现，以独立临时设施验证并发切换、撤销确认失败、响应丢失和进程清理，报告见 `verification.json`。Web 工作台与交互终端均调用 Rust 服务。参考实现的单元与回归活动不会写入实际工作台数据库。

## 实现与边界

| 部件 | 职责 |
|---|---|
| `access.py` | 原 Python 授权参考实现，仅用于自动回归对照。 |
| `runtime.py` | 启动三个 KeyFence 进程和三个本地模拟 API。每个环境仅向自己的代理提供凭据；基础令牌限制到读取路径和 GET。高权令牌由控制器持有。 |
| `guard.py` | 监控控制进程持有的匿名管道；控制进程退出后停止对应代理并清理该环境的临时文件。 |
| `console.py` | 手动终端，用 HTTP 和网页共用 Rust 控制服务。 |

演示中所有上游均使用回环 HTTP 和临时合成凭据。三个代理与控制器位于同一操作系统用户下，身份和审批角色为固定的测试数据。业务结果按申请编号在模拟上游内存中防重，重新批准是一个新的业务操作。控制器重启会重建代理和账本。不要向本演示提供真实密钥。

生产试点仍需企业身份接入与真实审批人分离、按环境隔离运行身份和网络、可信代理强制验证 HTTPS 上游、审计归档与防篡改，以及能跨重启查询结果的业务幂等账本。此前对 KeyFence 的测试确认它可以向 HTTP 上游注入凭据，因此仅设置 `HTTPS_PROXY` 无法满足生产 HTTPS 要求。当前是一个任务、一个申请人和一个审批人的自托管演示。

上游 KeyFence 的原始 MIT 许可位于 `third_party/KEYFENCE-LICENSE.txt`。
