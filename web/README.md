# KeyHeron Web（青鹭工作台）

前端由 `index.html`、`styles.css` 和 `app.js` 组成，无框架、构建或远程资源依赖。可以单独检出或维护。用完整演示包的启动器指向本目录即可接入实际 Rust 后端。

```sh
python3 web_demo.py --web-dir /path/to/keyheron-web --open
```

静态资源和 `/api/` 由同一回环源提供。启动器为申请人、审批人生成不同的访问链接。角色由服务器从访问凭据判定。进入页面后会清除 URL 片段，标签页持有的凭据只用于当前服务实例。演示身份仅用于本地体验。

| 用途 | API |
|---|---|
| 查看当前环境和有效授权 | `GET /api/state` 返回任务、已认证角色对应的主体标签、环境、服务能力、有效期上限和申请状态。 |
| 查询持久化事件 | `GET /api/events?environment=PROD&limit=30&before=100`。参数均可省略，游标为上一页最后一个事件 ID。 |
| 切换、结束或基础读取 | `POST /api/switch` 携带 `environment`，或 `POST /api/end`、`POST /api/read` 携带空对象。 |
| 申请权限 | `POST /api/request` 携带 `action` 和 `ttl`（秒）。支持 `diagnose`、`retry`。 |
| 处理申请或核对回执 | `POST /api/approve`、`deny`、`use`、`revoke` 携带 `id`。支持可信回执适配的上游通过 `outcome` 查询；外部 HTTPS 预览不提供业务回执对账。 |
| 真实 SDK 只读会话 | 启动器通过 `POST /api/sdk-session` 提供活动环境名和可选的 `ttl`（秒），获取独立的短期只读能力；命令结束后通过 `POST /api/sdk-revoke` 携带会话 `id` 回收。网页业务操作不需要持有该能力。 |

真实凭据、授权决定和记录均由后端负责。演示模式显示模拟上游实际认证的账号；配置模式显示本次使用的凭据引用。页面显示的“受理单次操作”与“上游成功”分别来自受理与执行结果事件。完整事件详情可以展开查看。
