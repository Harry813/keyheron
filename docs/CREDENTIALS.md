# 加密保存上游凭据

青鹭使用独立的 SQLite 凭据库保存 HTTPS 令牌和数据库密码。每个凭据值在进入 SQLite 前用 AES-256-GCM 加密，每次写入使用新的 96 位随机 nonce 和 128 位认证标签。不同环境、不同名称的条目使用不同的密钥，并将库的盐值与完整引用绑定到认证数据。将一条记录的密文复制到另一条记录也会导致认证失败。

初始化时，青鹭生成一个 128 位随机盐，用 Argon2id 从解锁口令派生 256 位主密钥，参数为 128 MiB 内存、3 轮、4 路并行。主密钥和解锁口令都不会写入库中。库文件中的环境、凭据名称、格式信息和密文长度仍然可见。审计数据库继续单独存储操作元数据。[Argon2id 规范](https://www.rfc-editor.org/rfc/rfc9106.html) · [认证加密说明](https://cryptography.io/en/latest/hazmat/primitives/aead/)

## 初始化和录入

在受信宿主的 Python 环境中安装依赖。以下示例假设策略文件位于 `/private/keyheron/policy.json`，请将该目录替换为自己的私有目录。

```sh
python3 -m pip install -r requirements-credentials.txt
python3 keyheron.py secrets init --store /private/keyheron/vault/credentials.sqlite3
python3 keyheron.py secrets put --store /private/keyheron/vault/credentials.sqlite3 --env DEV --name pg-reader
```

首次初始化会要求输入并确认解锁口令。使用密码管理器生成的高熵口令，至少 16 个 UTF-8 字节，并将恢复副本与凭据库备份分开保管。青鹭无法恢复遗失的解锁口令。录入凭据时，程序在终端关闭回显。新库的文件权限为 `0600`。

## 在策略中使用

在策略根部添加 `"credential_store": {"path": "vault/credentials.sqlite3"}`。数据库目标用 `"password_ref": "pg-reader"` 选择本环境的凭据。HTTPS 环境用 `"credential_refs": {"github-reader": "github-reader"}` 将路由引用映射到本环境的存储名称。DEV 和 PROD 的同名条目需要分别录入。[数据库配置示例](../examples/databases.json) · [HTTPS 配置示例](../examples/github-readonly.json)

运行 `keyheron.py db` 或 `serve` 时，由可信操作员解锁一次。数据库代理只保留所选目标的条目读取能力，Rust HTTPS 服务通过私有启动管道取得已配置条目的解密密钥。Agent 获得的会话描述文件不包含这些密钥或解锁口令。使用 HTTPS 加密凭据时需从当前源码重新构建 Rust 核心，或使用包含本功能的同版本发行物。

**无人值守服务**可由现有密钥管理系统向宿主挂载解锁口令文件，在 `credential_store` 中指定 `passphrase_file`。文件属主必须是启动账户或 root，权限为 `0400` 或 `0600`。管理命令支持同名的 `--passphrase-file` 选项。该文件应放在独立的受限挂载中，只有受信服务能读取。Agent 与代理也应使用隔离的系统账户或沙箱；运行中的代理需要在内存中短暂使用真实凭据。

## 更新和迁移

对同一个环境和名称再次执行 `secrets put` 即可替换条目。下次 HTTPS 请求或新的数据库登录会读取并认证新密文，已经完成登录的数据库连接沿用现有会话。密文损坏或被替换到其他条目时，本次上游操作会被拒绝。

已有 `password_file` 或 `credential_files` 配置可以逐项迁移。在可信终端从原文件导入，再把策略改为对应的引用并重新启动受影响的代理。例如：

```sh
python3 keyheron.py secrets put --store /private/keyheron/vault/credentials.sqlite3 --env DEV --name pg-reader --stdin < /path/to/existing/pg-reader
```

导入只写入加密库，原文件及其历史备份由操作员管理。只持有旧库副本的人仍可尝试离线猜测口令；加密认证也不能识别整份旧备份的回放。若需要处置疑似泄露，以数据库或 API 提供方的实际凭据轮换为准。
