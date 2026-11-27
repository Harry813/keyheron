# 用现有客户端连接数据库

青鹭为一次任务开启一个回环端口。客户端用用户名 `keyheron` 和短期口令登录这个端口，青鹭再用管理员配置的数据库账户完成上游认证。连接建立后，可以像平时一样编写 SQL、运行参数化语句和使用事务。一个会话固定在一个环境和一个命名目标。

## 配置与签发

1. 在可信宿主准备 Python 3.11 或更新版本。PostgreSQL 模式还需要在代理的 Python 环境运行 `python3 -m pip install -r requirements-db-postgres.txt`。SQL Server 模式用 OpenSSL 生成本地会话证书。
2. 将[示例策略](../examples/databases.json)复制到代理账户的私有目录，保留需要的引擎，填写实际主机、初始数据库和最小权限数据库账户。初始化加密凭据库，按环境将口令录入目标的 `password_ref`。代理在每次新的数据库登录时读取并认证该条密文。已有宿主凭据文件可以逐项导入。[凭据库操作说明](CREDENTIALS.md)
3. 上游使用 TLS 并校验主机名及证书链。私有 CA 通过目标配置中的 `ca_file` 指定。默认端口分别为 5432、3306、1433，可以用数值字段 `port` 覆盖。每个目标可指定 `max_ttl`，默认 300 秒，范围 1–900 秒。已有 HTTPS 策略可在同一环境旁添加 `databases` 字段。
4. 由可信操作员开启会话。示例选用 DEV 的 PostgreSQL 目标，授予 120 秒连接时间。

```sh
python3 keyheron.py db --config /path/to/policy.json --env DEV --target orders-pg --ttl 120
```

终端会显示本次 `connection.json` 的路径。该文件权限为 `0600`，包含临时端口、数据库名、用户名 `keyheron`、随机会话口令和到期时间。将这份文件的内容交给需要连接的客户端。SQL Server 还需要其中指定的公开证书。上游口令始终由代理读取，客户端不需要知道它。请将真实口令、受信配置和管理进程放在 Agent 无权读取或控制的系统账户或沙箱边界内。将 `127.0.0.1` 回环网络安排在客户端可达的受信环境中。

## 客户端设置

| 目标 | 客户端如何连接本地端口 | 上游要求 |
|---|---|---|
| PostgreSQL | `psql "host=127.0.0.1 port=PORT dbname=orders user=keyheron sslmode=disable" -W`，在密码提示中输入会话口令 | PostgreSQL v3 协议、TLS、SCRAM-SHA-256 密码认证 |
| MySQL | `mysql --protocol=TCP --host=127.0.0.1 --port=PORT --user=keyheron --ssl-mode=DISABLED --local-infile=0 --password orders`，在提示中输入会话口令 | MySQL Classic 协议、TLS。客户端需支持 caching_sha2_password，上游支持 caching_sha2_password 或 mysql_native_password |
| SQL Server | 在支持 TDS 8.0 的客户端选择 SQL 密码登录，服务器为 `127.0.0.1,PORT`，数据库名取自连接文件，设置 `Encrypt=Strict`。为本次连接信任 `ca_file`，或在支持证书匹配的驱动里用 `server_certificate` 指定本地服务端公开证书 | SQL Server 2022 或更新版本、TDS 8.0 Strict、固定 TCP 端口、SQL 密码认证 |

将 `PORT` 和数据库名替换为连接文件中的值。DBeaver 等 GUI 采用相同的驱动和设置。macOS/Linux 的 ODBC 版 sqlcmd 可使用 `sqlcmd -Ns -J SERVER_CERTIFICATE -S tcp:127.0.0.1,PORT -U keyheron -d Orders`。PostgreSQL 和 MySQL 的本地明文设置仅用于可信回环；代理到数据库的连接始终独立验证 TLS。SQL Server 的本地连接和上游连接分别验证各自的证书。[Microsoft sqlcmd 参数说明](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility)。

## 权限、撤销与记录

- 可信操作员通过前台的 `db` 命令授权。数据库会话的到期和撤销由这个进程管理，与 HTTPS 工作台的授权独立。Ctrl+C 或向进程发送 TERM 会收回整个会话。到期时，青鹭同时关闭监听端口和已建立的客户端、上游连接。已经提交的更改会保留，在途语句的取消和未提交事务的处理遵循数据库自身行为。
- 数据库账户的实际授权决定 SQL 的读写及跨库访问范围。初始库名只用于登录。需要只读访问时，应为上游账户配置相应的库、表、视图或存储过程权限。Agent 能看到查询结果；数据库角色也应限制对敏感业务数据和管理能力的访问。
- 默认状态目录为 `.keyheron-db/`。其中的 `db-events.sqlite3` 记录任务、申请人、环境、目标、会话 ID、会话开关及登录结果。审计只记录连接元数据。数据库自身可按业务要求记录 SQL。正常退出会删除本次连接文件和会话证书；进程若被强杀，操作系统关闭套接字，遗留的短期口令不能在以后的会话使用。
- 当前 PostgreSQL 适配不提供带外的 CancelRequest；可通过结束青鹭会话来断开客户端。SQL Server 当前支持标准 SQL 登录，MARS、集成身份验证和服务器重定向未覆盖。每个会话最多同时受理 16 条连接。

## 本地验收

- PostgreSQL 已使用原生 psql 16.2 连接 PostgreSQL 17.8，执行查询并验证撤销会断开活动连接。`python3 scripts/verify_db_postgres.py` 会创建独立的 TLS/SCRAM 测试实例。可用 `PG_BIN` 选择服务端程序目录、用 `PSQL` 指定客户端。
- MySQL 已使用原生 mysql 客户端连接 MySQL Community 8.0.29，验证查询结果、只读角色拒绝写入、错误会话口令和主动断开。`python3 scripts/verify_db_mysql.py` 使用合成凭据启动临时 MySQL 8 实例，可通过 `MYSQL_BIN` 指定二进制目录。
- SQL Server 目前处于协议兼容性预览。微软 go-mssqldb 原生驱动已通过实际青鹭入口完成登录并提交 SQL 批次，测试上游校验了独立的宿主凭据。真实 SQL Server 实例及 SSMS 图形界面尚待验收。
- 安装 PostgreSQL 的可选依赖后，可运行 `python3 -m unittest discover -s scripts -p 'test_db_*.py'`，在本机复验三种协议的认证、会话隔离、撤销和到期行为。
