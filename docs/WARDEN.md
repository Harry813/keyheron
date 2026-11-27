# 按任务授权连接器

Server 保存模板、任务绑定和授权事件。每个 Warden 服务于一次任务，从受信目录读取连接器配置，使用自己的客户端证书向 Server 查询授权。Agent 从任务专属 Unix socket 提交插件名、动作和资源别名。首次列出能力和执行时都要连接 Server，执行时重新检查权限。Warden 和沙箱客户端需要 Python 3.11+，控制通道需要支持 TLS 1.3 的 OpenSSL。

| 插件与动作 | 授权单位 | 上游行为 |
| --- | --- | --- |
| `gitlab/read` | 一个别名对应固定 GitLab HTTPS 源、数值项目 ID 和 MR IID | 发起一次认证 GET，核对返回的项目和 MR，仅交付 MR 摘要；遇到重定向即停止。 |
| `postgresql/connect` | 指定环境的 PostgreSQL 目标 | 通过 PostgreSQL 协议建立限时连接。 |
| `mysql/connect` | 指定环境的 MySQL 目标 | 通过 MySQL 协议建立限时连接。 |
| `sqlserver/connect` | 指定环境的 SQL Server 目标 | 通过 TDS 建立限时连接。 |

三个数据库插件各自授权，共用会话、审计和撤权机制。目标配置的引擎必须与插件一致。即使资源都叫 `orders`，只授予 `postgresql/connect` 的任务也只能连接 PostgreSQL。客户端取得临时登录信息，可执行的 SQL 由目标数据库账户决定。

## 准备证书和配置

为 Server 准备含服务域名 DNS SAN 和 serverAuth 用途的证书，为每个 Warden 分别签发含 clientAuth 用途和唯一 URI SAN 的短期证书。示例 Warden 身份是 `spiffe://keyheron/warden/demo`。证书由现有内部 CA 或工作负载身份系统签发；实例注册、签发、自动续期和 CA 的保管由该系统负责。证书、私钥和策略都在 Agent 沙箱外。开发机可运行下文的集成测试，它会自行生成临时 CA 和证书。

在 Server 的私有目录复制并调整[控制策略](../examples/warden-policy.json)。在 Warden 的私有目录复制并调整[连接器配置](../examples/warden-plugins.json)。两个文件中的资源别名必须一致。GitLab 使用只读项目令牌文件，属主为 Warden 账户或 root，权限设为 0400 或 0600。私有 GitLab CA 可通过资源中的 `ca_file` 配置。数据库的目标配置沿用[数据库示例](../examples/databases.json)；若使用加密凭据库，为无人值守的 Warden 配置私有 `passphrase_file`。PostgreSQL 还需要安装 `requirements-db-postgres.txt` 的依赖。插件配置中的相对路径相对于该配置文件。

## 启动控制服务并分配模板

以下命令假定从青鹭项目目录执行，`/srv/keyheron` 是受信服务目录，`/run/keyheron` 可由 Warden 账户写入。Server 和 Warden 可以分别在不同主机上运行。

```sh
python3 keyheron.py warden-server --listen 127.0.0.1 --port 8443 \
  --policy /srv/keyheron/server/policy.json --audit /srv/keyheron/server/events.sqlite3 \
  --ca /srv/keyheron/server/warden-ca.pem --cert /srv/keyheron/server/server.pem \
  --key /srv/keyheron/server/server.key
```

示例只监听回环。跨主机使用时，将监听地址设为 Server 的受信接口地址，Warden 的 URL 使用 Server 证书覆盖的域名。Server 验证客户端证书的身份后，每次操作都按本地策略核对任务、插件、动作和资源。Warden 每次连接重新读取证书、私钥和信任根。替换 Server 证书或 Warden CA 后需重启控制服务。短连接独立握手，不发送 TLS 早期数据。

在 Server 上启动管理员工作台，指定同一策略和审计库。管理员入口是仅当前账户可读的本地文件。管理服务仅监听回环。这里可以创建含多条规则的基础模板，将模板绑定到已登记的 Warden 和任务，查看近期审计，或撤销任务授权。使用新模板名发布新版本，再显式切换任务绑定。给每次新的 Agent 运行分配独立任务名和 socket，以免旧实例重新取得同名任务的授权。

```sh
python3 keyheron.py warden-admin --policy /srv/keyheron/server/policy.json \
  --audit /srv/keyheron/server/events.sqlite3 --open
```

## 启动 Warden 与 Agent

```sh
python3 keyheron.py warden --task review-001 --server https://localhost:8443 \
  --ca /srv/keyheron/warden/server-ca.pem --cert /srv/keyheron/warden/warden.pem \
  --key /srv/keyheron/warden/warden.key --plugins /srv/keyheron/warden/plugins.json \
  --state-dir /run/keyheron/review-001
```

在受信终端可以用 `python3 keyheron.py connector --socket /run/keyheron/review-001/warden.sock list` 检查本次任务可用的操作。运行不受信任的 Agent 时，在同一台原生 Linux 主机上由可信操作员启动沙箱。以下镜像须已准备好，并包含独立的 `warden_client.py` 和 Python 3.11+。镜像中只放 Agent 所需程序和公开文件。宿主的 Docker 接口、项目目录、上游凭据及 Warden 的控制面私钥都不挂载。

```sh
python3 scripts/run_warden_sandbox.py --socket /run/keyheron/review-001/warden.sock \
  --image my-agent:local -- python3 /opt/keyheron/warden_client.py invoke gitlab read mr-42
```

容器通过 `KEYHERON_WARDEN_SOCKET` 找到任务入口，网络模式为 `none`，镜像根文件系统只读，可在容器的临时目录写入任务数据。启动器需要本机 Linux Docker Engine，以及能使用该 Engine、与 Warden 同 UID 的非 root 启动账户。拥有 Docker 管理权限的是宿主操作员。Agent 只收到任务 socket。单独在普通宿主 shell 启动 `warden` 和 `connector` 可用于功能测试，操作系统级隔离由沙箱启动器提供。

数据库任务先绑定对应模板，在同一个 Agent 沙箱内运行下述客户端。客户端在临时目录写入私有连接描述文件，将文件路径输出到标准输出，并等待一个原生 SQL 客户端连接。让此进程在 SQL 客户端运行期间保持存活。描述文件包含沙箱内回环地址、临时口令和过期时间。SQL Server 还会得到本次连接可用的公开证书文件。请按[原生客户端设置](DATABASES.md#客户端设置)登录。这个转发只能连接 Warden 为当前请求签发的数据库会话。

```sh
python3 /opt/keyheron/warden_client.py invoke postgresql connect orders
```

## 撤销和审计

已有任务可以继续使用显式配置和授权的 `database/connect`。新建模板时选择具体引擎。迁移时先更新 Warden 和沙箱内的 `warden_client.py`，在 Warden 配置中登记新插件和资源，重启该任务的 Warden，再把任务绑定到使用新插件名的模板，并更新 Agent 调用命令。旧模板和历史审计保留原名；迁移可为每个任务分别进行。

下一次请求会读到最新策略。活动数据库连接每轮复核后等待一秒，再次申请复核。最多 16 个会话共用 4 个复核线程；排队和请求合计最多四秒，单次请求从获得线程名额起最多一秒。授权到期、复核失败或发现撤销时，代理关闭活动连接。会话期限取目标配置和控制授权中更短的一项。撤销不会撤回已经取得的数据或已提交的事务。对只读任务应配置数据库只读角色；逐条 SQL 审批超出连接授权的粒度。

Server 的 SQLite 审计记录已认证的能力查询、授权决定和 Warden 上报的执行结果，管理页显示最近记录。数据库代理还在 Warden 私有状态目录记录登录及关闭事件。事件只含身份与操作元数据。控制面失联时，中心记录可能缺少最后的关闭回报，可核对 Warden 本地数据库审计。宿主与 Warden 均属于信任边界。本版插件由管理员部署，按代码中注册的动作分派，Agent 只能选择已配置的资源。

每个任务的 Warden 在建立控制连接前限制请求量。Server 按证书身份和任务再次检查，并对全服务设置上限。各类请求有独立额度，普通操作达到上限时，已开启的数据库会话仍能复核授权和上报关闭。

| 请求 | 每任务请求数/秒 | Server 请求数/秒 | 每任务同时处理数 | Server 同时处理数 |
| --- | ---: | ---: | ---: | ---: |
| 能力查询和新操作授权 | 48 | 96 | 8 | 12 |
| 数据库会话授权复核 | 48 | 64 | 4 | 8 |
| 成功或失败回报 | 48 | 64 | 2 | 6 |
| 关闭回报 | 16 | 32 | 2 | 6 |

已认证请求合计每秒最多 256 个，同时处理最多 32 个。触发 Server 限额的请求在读取策略和写入审计前返回 HTTP 429。Warden 为活动会话复核和关闭回报预留工作线程，向控制服务发起请求时，会话复核与结果回报最多等待 0.75 秒取得本机并发名额。关闭回报被明确限流时，Warden 等待一秒后再尝试一次。Agent 打开数据库流使用普通授权额度，达到限额时拒绝本次打开。后台复核发现授权已撤销或控制面不可用时，关闭相关数据库连接。

控制服务和 Warden 分开部署时，先升级控制服务，再升级 Warden。新服务继续接受旧版的授权请求。新版 Warden 通过 `/v1/session-check` 复核数据库会话，服务端同时验证当前策略和相同证书、任务、操作、资源上的近期授权记录。复核成功会刷新记录，使最长 900 秒的会话也能上报终态。旧版服务缺少此接口，新版 Warden 会关闭无法复核的会话。

中心审计对升级后写入的事件保留最近 65,536 条，每新增 256 条清理一次。过去 15 分钟内有效的成功授权会多保留到回报期限届满，以便已撤销的任务上报关闭。升级前已有的记录继续保留。需要长期保存全部事件时，应在滚动清理前定期归档。

请把控制策略和审计库放入受信目录。审计库及 SQLite 副文件只允许其受信属主访问。中心事件中的 reported 表示已认证 Warden 上报的结果；需要确认上游业务结果时应核对上游记录。当前管理工作台保存模板与绑定的最新状态，模板变更的人员历史需要由独立的配置管理流程留存。

## 添加连接器

插件使用版本化清单，由管理员通过 `--plugin-manifest` 加载。管理面板和 Warden 均从 Rust 核心获取注册信息。第三方可通过固定 HTTPS JSON 或数据库驱动增加插件，Agent 使用任务 socket 的 list、describe 和 invoke 接口。[v1 开发契约、示例与安全边界](PLUGIN-API.md)

## 验证

```sh
python3 -m unittest discover -s scripts -p 'test_warden_*.py'
```

GitLab 集成测试使用合成令牌和本地 HTTPS 服务，经真实 mTLS 连接和三个 CLI 入口核验读取、越权拒绝及撤销。在安装 PostgreSQL 工具和可选依赖的环境中，`python3 scripts/verify_db_postgres.py` 使用临时数据库和原生 psql 检查查询与撤销。原生 Linux 还可设置 `KEYHERON_SANDBOX_TEST_IMAGE` 为已存在、包含 Python 的本机镜像，运行容器隔离用例。
