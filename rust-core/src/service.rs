use crate::{audit::Audit, external::ExternalConfig, transport::Transport};
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock, Semaphore};
use uuid::Uuid;

#[derive(Clone, Serialize)]
pub struct Capability {
    pub method: String,
    pub path: String,
    pub resource: String,
    pub max_ttl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

pub struct Policy {
    pub task: String,
    capabilities: BTreeMap<String, BTreeMap<String, Capability>>,
    external: bool,
    applicant: String,
    approver: String,
}

impl Policy {
    pub fn new(
        external: Option<&ExternalConfig>,
        applicant: String,
        approver: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            applicant != approver
                && [&applicant, &approver].iter().all(|n| !n.is_empty()
                    && n.len() <= 100
                    && !n.chars().any(char::is_control)
                    && n.as_str() != "system"),
            "申请人和审批人需要独立、非空的受信标识"
        );
        let mut capabilities = BTreeMap::new();
        let task = if let Some(cfg) = external {
            for (name, env) in &cfg.environments {
                let routes = env
                    .routes
                    .iter()
                    .map(|(kind, r)| {
                        (
                            kind.clone(),
                            Capability {
                                method: r.method.clone(),
                                path: r.path.clone(),
                                resource: r.resource.clone(),
                                max_ttl: r.max_ttl,
                                origin: Some(env.origin.clone()),
                            },
                        )
                    })
                    .collect();
                capabilities.insert(name.clone(), routes);
            }
            cfg.task.clone()
        } else {
            for name in ["DEV", "STG", "PROD"] {
                let mut routes = BTreeMap::new();
                for (kind, method, path, resource) in [
                    ("read", "GET", "/service/status", "orders"),
                    ("diagnose", "GET", "/service/diagnostics", "orders"),
                    ("retry", "POST", "/jobs/job-4821/retry", "job-4821"),
                ] {
                    if kind == "read" || name == "PROD" {
                        routes.insert(
                            kind.into(),
                            Capability {
                                method: method.into(),
                                path: path.into(),
                                resource: resource.into(),
                                max_ttl: BASE_SECS,
                                origin: None,
                            },
                        );
                    }
                }
                capabilities.insert(name.into(), routes);
            }
            "orders-investigation".into()
        };
        Ok(Self {
            task,
            capabilities,
            external: external.is_some(),
            applicant,
            approver,
        })
    }
    fn route(&self, env: Option<&str>, kind: &str) -> Option<&Capability> {
        self.capabilities.get(env?)?.get(kind)
    }
    pub(crate) fn actor(&self, role: Role) -> &str {
        match role {
            Role::Alice => &self.applicant,
            Role::Owner => &self.approver,
            Role::System => "system",
        }
    }
}
const BASE_SECS: u64 = 900;
const MAX_GRANTS: usize = 1024;
const MAX_MANAGED_READS: usize = 16;

#[derive(Clone, Copy, PartialEq)]
pub enum Role {
    Alice,
    Owner,
    System,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Alice => "alice",
            Self::Owner => "owner",
            Self::System => "system",
        }
    }
}

struct Failure(StatusCode, &'static str);
impl Failure {
    fn denied(reason: &'static str) -> Self {
        Self(StatusCode::FORBIDDEN, reason)
    }
    fn invalid(reason: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, reason)
    }
    fn broker() -> Self {
        Self(StatusCode::BAD_GATEWAY, "代理暂不可用或没有确认执行结果")
    }
    fn audit() -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "无法确认审计记录；请核对状态后再操作",
        )
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
type Reply = Result<Json<Value>, Failure>;
type Outcome = Result<Value, Failure>;

#[derive(Serialize)]
struct Grant {
    id: String,
    environment: String,
    action: String,
    resource: String,
    status: &'static str,
    expires_at: i64,
    #[serde(skip)]
    deadline: Instant,
    #[serde(skip)]
    token: Option<String>,
    #[serde(skip)]
    revoke_requested_by: Option<Role>,
    #[serde(skip)]
    revoke_failed_logged: bool,
}
impl Grant {
    fn effective_status(&self, now: Instant) -> &'static str {
        if matches!(self.status, "pending" | "approved") && self.deadline <= now {
            "expired"
        } else {
            self.status
        }
    }
}

struct Session {
    environment: String,
    token: String,
    deadline: Instant,
    active: bool,
    close_reason: Option<&'static str>,
    revoke_failed_logged: bool,
}
#[derive(Default)]
struct Activity {
    closing: Option<&'static str>,
    sdk: BTreeMap<String, Session>,
    base: Option<Session>,
    grants: BTreeMap<String, Grant>,
}
impl Activity {
    fn env(&self) -> Option<&str> {
        if self.closing.is_some() {
            return None;
        }
        self.base
            .as_ref()
            .filter(|b| b.active && b.deadline > Instant::now())
            .map(|b| b.environment.as_str())
    }
    fn require_grant(&self, id: &str, status: &str) -> Result<&Grant, Failure> {
        let g = self
            .grants
            .get(id)
            .ok_or_else(|| Failure::denied("找不到该项授权"))?;
        if self.env() != Some(g.environment.as_str())
            || g.effective_status(Instant::now()) != status
        {
            return Err(Failure::denied("当前环境、有效期或授权状态不允许此操作"));
        }
        Ok(g)
    }
}

pub struct Service {
    audit: Audit,
    broker: Arc<Transport>,
    policy: Policy,
    activity: RwLock<Activity>,
    managed_reads: Semaphore,
    deadlines_changed: Notify,
}
impl Service {
    pub fn new(audit: Audit, broker: Arc<Transport>, policy: Policy) -> Arc<Self> {
        let service = Arc::new(Self {
            audit,
            broker,
            policy,
            activity: RwLock::new(Activity::default()),
            managed_reads: Semaphore::new(MAX_MANAGED_READS),
            deadlines_changed: Notify::new(),
        });
        tokio::spawn(service.clone().schedule_expiry());
        service
    }
    fn record(
        &self,
        actor: Role,
        env: Option<&str>,
        action: &str,
        resource: &str,
        result: &str,
        detail: &str,
    ) -> Result<(), Failure> {
        self.audit
            .record(
                self.policy.actor(actor),
                env,
                action,
                resource,
                result,
                detail,
            )
            .map_err(|_| Failure::audit())
    }
    fn finish(
        &self,
        actor: Role,
        env: Option<&str>,
        action: &str,
        resource: &str,
        success: &str,
        result: Outcome,
    ) -> Reply {
        let detail = result.as_ref().err().map_or(success, |e| e.1);
        self.record_result(actor, env, action, resource, detail, result)
    }
    fn record_result(
        &self,
        actor: Role,
        env: Option<&str>,
        action: &str,
        resource: &str,
        detail: &str,
        result: Outcome,
    ) -> Reply {
        let label = match &result {
            Ok(_) => "allowed",
            Err(e) if e.0.is_client_error() => "denied",
            Err(_) => "failed",
        };
        self.record(actor, env, action, resource, label, detail)?;
        result.map(Json)
    }
    fn read_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, Failure> {
        self.managed_reads.try_acquire().map_err(|_| {
            Failure(
                StatusCode::TOO_MANY_REQUESTS,
                "受管读取达到并发上限，请稍后再试",
            )
        })
    }
    fn expire_due(&self, a: &mut Activity) -> Result<(), Failure> {
        let now = Instant::now();
        if let Some(b) = &mut a.base {
            if b.active && b.deadline <= now {
                self.record(
                    Role::System,
                    Some(&b.environment),
                    "expire",
                    &self.policy.task,
                    "allowed",
                    "基础会话自然到期",
                )?;
                b.active = false;
            }
        }
        for g in a.grants.values_mut() {
            if matches!(g.status, "pending" | "approved") && g.deadline <= now {
                self.record(
                    Role::System,
                    Some(&g.environment),
                    "expire",
                    &g.resource,
                    "allowed",
                    &format!(
                        "申请 {} 的{}有效期已结束",
                        g.id,
                        if g.status == "pending" {
                            "待审"
                        } else {
                            "授权"
                        }
                    ),
                )?;
                g.status = "expired";
            }
        }
        Ok(())
    }

    async fn drop_sdk(
        &self,
        a: &mut Activity,
        id: &str,
        reason: &'static str,
    ) -> Result<(), Failure> {
        if let Some(sdk) = a.sdk.get_mut(id) {
            let reason = *sdk.close_reason.get_or_insert(reason);
            self.deadlines_changed.notify_one();
            if sdk.active {
                self.broker
                    .revoke(&sdk.environment, &sdk.token)
                    .await
                    .map_err(|_| Failure::broker())?;
                sdk.active = false;
            }
            self.record(
                Role::System,
                Some(&sdk.environment),
                "sdk-close",
                &self.policy.task,
                "allowed",
                &format!("SDK 会话 {id}：{reason}"),
            )?;
            a.sdk.remove(id);
        }
        Ok(())
    }

    async fn expire_sdks(&self, a: &mut Activity) -> Result<(), Failure> {
        let now = Instant::now();
        let expired: Vec<String> = a
            .sdk
            .iter()
            .filter(|(_, s)| s.close_reason.is_some() || s.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.drop_sdk(a, &id, "有效期已结束").await?;
        }
        Ok(())
    }

    async fn finish_requested_revoke(&self, grant: &mut Grant, actor: Role) -> Result<(), Failure> {
        if let Some(token) = &grant.token {
            self.broker
                .revoke(&grant.environment, token)
                .await
                .map_err(|_| Failure(StatusCode::BAD_GATEWAY, "本地已停用，代理未确认收回"))?;
            grant.token = None;
        }
        self.record(
            actor,
            Some(&grant.environment),
            "revoke",
            &grant.resource,
            "allowed",
            &format!("已收回授权 {}", grant.id),
        )?;
        grant.status = "revoked";
        grant.revoke_requested_by = None;
        Ok(())
    }

    async fn settle_due(&self, activity: &mut Activity) -> Result<(), Failure> {
        for grant in activity.grants.values_mut() {
            if let Some(actor) = grant.revoke_requested_by {
                self.finish_requested_revoke(grant, actor).await?;
            }
        }
        self.expire_sdks(activity).await?;
        self.expire_due(activity)
    }

    async fn schedule_expiry(self: Arc<Self>) {
        loop {
            let deadline = {
                let a = self.activity.read().await;
                if a.closing.is_some()
                    || a.grants.values().any(|g| g.revoke_requested_by.is_some())
                    || a.sdk.values().any(|s| s.close_reason.is_some())
                {
                    Some(Instant::now())
                } else {
                    a.grants
                        .values()
                        .filter(|g| matches!(g.status, "pending" | "approved"))
                        .map(|g| g.deadline)
                        .chain(a.base.as_ref().filter(|b| b.active).map(|b| b.deadline))
                        .chain(a.sdk.values().map(|s| s.deadline))
                        .min()
                }
            };
            match deadline {
                Some(t) if t <= Instant::now() => {
                    let result = {
                        let mut activity = self.activity.write().await;
                        if let Some(reason) = activity.closing {
                            self.clear_session(&mut activity, reason).await
                        } else {
                            self.settle_due(&mut activity).await
                        }
                    };
                    // A failed commit leaves unlogged expiry pending. Authorization
                    // itself uses monotonic deadlines and does not wait for SQLite.
                    if result.is_err() {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                Some(t) => {
                    tokio::select! {
                        _ = self.deadlines_changed.notified() => {},
                        _ = tokio::time::sleep_until(t.into()) => {},
                    }
                }
                None => self.deadlines_changed.notified().await,
            }
        }
    }

    async fn clear_session(&self, a: &mut Activity, reason: &'static str) -> Result<(), Failure> {
        let reason = *a.closing.get_or_insert(reason);
        self.deadlines_changed.notify_one();
        // SDK requests consult broker tickets directly. Invalidate all of them before
        // the first fallible audit, retaining handles and the reason for cleanup retries.
        let mut sdk_failed = false;
        for sdk in a.sdk.values_mut().filter(|s| s.active) {
            if self
                .broker
                .revoke(&sdk.environment, &sdk.token)
                .await
                .is_ok()
            {
                sdk.active = false;
            } else {
                sdk_failed = true;
            }
        }
        if sdk_failed {
            return Err(Failure::broker());
        }
        self.expire_due(a)?;
        if let Some(b) = a.base.as_mut() {
            b.active = false;
        }
        let mut complete = true;
        if let Some(b) = &mut a.base {
            if self.broker.revoke(&b.environment, &b.token).await.is_ok() {
                self.record(
                    Role::System,
                    Some(&b.environment),
                    "revoke",
                    &self.policy.task,
                    "allowed",
                    &format!("{reason}，代理已确认收回基础会话"),
                )?;
                a.base = None;
            } else {
                complete = false;
                if !b.revoke_failed_logged {
                    self.record(
                        Role::System,
                        Some(&b.environment),
                        "revoke",
                        &self.policy.task,
                        "failed",
                        &format!("{reason}，基础会话本地已停用，代理未确认"),
                    )?;
                    b.revoke_failed_logged = true;
                }
            }
        }
        for grant in a.grants.values_mut() {
            if let Some(actor) = grant.revoke_requested_by {
                self.finish_requested_revoke(grant, actor).await?;
                continue;
            }
            if matches!(grant.status, "pending" | "approved") {
                grant.status = "revoking";
            }
            if let Some(token) = &grant.token {
                if self.broker.revoke(&grant.environment, token).await.is_err() {
                    complete = false;
                    if !grant.revoke_failed_logged {
                        self.record(
                            Role::System,
                            Some(&grant.environment),
                            "revoke",
                            &grant.resource,
                            "failed",
                            &format!("{reason}，申请 {} 本地已停用，代理未确认", grant.id),
                        )?;
                        grant.revoke_failed_logged = true;
                    }
                    continue;
                }
                grant.token = None;
            }
            if grant.status == "revoking" || grant.revoke_failed_logged {
                self.record(
                    Role::System,
                    Some(&grant.environment),
                    "revoke",
                    &grant.resource,
                    "allowed",
                    &format!("{reason}，已收回申请 {}", grant.id),
                )?;
                if grant.status == "revoking" {
                    grant.status = "revoked";
                }
                grant.revoke_failed_logged = false;
            }
        }
        let ids: Vec<String> = a.sdk.keys().cloned().collect();
        for id in ids {
            if self.drop_sdk(a, &id, reason).await.is_err() {
                complete = false;
            }
        }
        if !complete {
            return Err(Failure::broker());
        }
        a.grants.clear();
        a.closing = None;
        Ok(())
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
pub fn routes(s: Arc<Service>) -> Router {
    Router::new()
        .route("/api/state", get(state))
        .route("/api/events", get(events))
        .route("/api/read", post(read))
        .route("/api/{action}", post(change))
        .with_state(s)
}

async fn state(State(s): State<Arc<Service>>, Extension(role): Extension<Role>) -> Json<Value> {
    let a = s.activity.read().await;
    let now = Instant::now();
    let mut grants: Vec<Value> = a
        .grants
        .values()
        .map(|g| {
            let mut view = json!(g);
            let status = g.effective_status(now);
            view["status"] = json!(if a.closing.is_some()
                && matches!(status, "pending" | "approved")
            {
                "revoking"
            } else {
                status
            });
            view
        })
        .collect();
    grants.sort_by(|a, b| b["expires_at"].as_i64().cmp(&a["expires_at"].as_i64()));
    Json(
        json!({"role":role.name(),"actor":s.policy.actor(role),"environment":a.env(),"task":s.policy.task,"grants":grants,
        "mode":if s.policy.external {"external"} else {"demo"}, "supports_outcome":!s.policy.external,
        "environments":s.policy.capabilities.keys().collect::<Vec<_>>(),"capabilities":s.policy.capabilities}),
    )
}

#[derive(Deserialize)]
struct Filter {
    environment: Option<String>,
    before: Option<i64>,
    limit: Option<u32>,
}
async fn events(State(s): State<Arc<Service>>, Query(q): Query<Filter>) -> Reply {
    if q.environment
        .as_deref()
        .is_some_and(|e| !s.policy.capabilities.contains_key(e))
    {
        return Err(Failure::invalid("未知环境筛选条件"));
    }
    let rows = s
        .audit
        .list(
            q.environment.as_deref(),
            q.before,
            q.limit.unwrap_or(50).clamp(1, 100),
        )
        .map_err(|_| Failure::audit())?;
    Ok(Json(json!({"events":rows})))
}

fn from_upstream(r: anyhow::Result<(u16, Value)>) -> Outcome {
    match r {
        Ok((200, value)) => Ok(value),
        Ok((401 | 403, _)) => Err(Failure::denied("代理或上游拒绝请求")),
        _ => Err(Failure::broker()),
    }
}
fn account_name(value: &Outcome, expected: &str) -> String {
    // Only known synthetic identities enter the audit database, never HTTP headers/body.
    if let Ok(v) = value {
        if v.get("status_source").and_then(Value::as_str) == Some("configured-credential") {
            return format!(
                "上游响应 {}，使用凭据引用 {}",
                v["upstream_status"],
                v["account"].as_str().unwrap_or("—")
            );
        }
    }
    if value.as_ref().ok().and_then(|x| x["account"].as_str()) == Some(expected) {
        format!("上游账户 {expected}，请求成功")
    } else {
        "上游请求完成".to_owned()
    }
}
async fn read(State(s): State<Arc<Service>>, Extension(role): Extension<Role>) -> Reply {
    let _permit = if role == Role::Alice {
        Some(s.read_permit()?)
    } else {
        None
    };
    // Snapshot admission, then release the control-state lock before the upstream I/O.
    let admitted = {
        let a = s.activity.read().await;
        a.env()
            .and_then(|env| a.base.as_ref().map(|b| (env.to_owned(), b.token.clone())))
    };
    let env = admitted.as_ref().map(|(env, _)| env.as_str());
    let result = if role != Role::Alice {
        Err(Failure::denied("仅任务申请人可读取服务"))
    } else if let Some((env, token)) = &admitted {
        from_upstream(s.broker.call(env, token, "read", None).await)
    } else {
        Err(Failure::denied("请先选择环境并建立有效会话"))
    };
    let detail = account_name(
        &result,
        &format!("{}-reader", env.unwrap_or("").to_lowercase()),
    );
    let resource = s
        .policy
        .route(env, "read")
        .map(|r| r.resource.as_str())
        .unwrap_or(&s.policy.task);
    s.finish(role, env, "read", resource, &detail, result)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Command {
    environment: Option<String>,
    id: Option<String>,
    action: Option<String>,
    ttl: Option<u64>,
}
async fn change(
    State(s): State<Arc<Service>>,
    Extension(role): Extension<Role>,
    Path(verb): Path<String>,
    payload: Result<Json<Command>, JsonRejection>,
) -> Reply {
    let verb = verb.as_str();
    if !matches!(
        verb,
        "switch"
            | "request"
            | "approve"
            | "deny"
            | "use"
            | "revoke"
            | "end"
            | "outcome"
            | "sdk-session"
            | "sdk-revoke"
    ) {
        return Err(Failure(StatusCode::NOT_FOUND, "未知操作"));
    }
    let c = match payload {
        Ok(Json(c)) => c,
        Err(_) => {
            return s.finish(
                role,
                None,
                verb,
                &s.policy.task,
                "",
                Err(Failure::invalid("请求字段或格式有误")),
            )
        }
    };
    let shape_ok = match verb {
        "end" => c.environment.is_none() && c.id.is_none() && c.action.is_none() && c.ttl.is_none(),
        "sdk-session" => c.environment.is_some() && c.id.is_none() && c.action.is_none(),
        "switch" => {
            c.environment.is_some() && c.id.is_none() && c.action.is_none() && c.ttl.is_none()
        }
        "request" => c.action.is_some() && c.id.is_none() && c.environment.is_none(),
        _ => {
            c.id.as_ref().is_some_and(|x| Uuid::parse_str(x).is_ok())
                && c.environment.is_none()
                && c.action.is_none()
                && c.ttl.is_none()
        }
    };
    if !shape_ok {
        return s.finish(
            role,
            None,
            verb,
            &s.policy.task,
            "",
            Err(Failure::invalid("请求字段与此操作不匹配")),
        );
    }
    let mut a = s.activity.write().await;
    let id = c.id.as_deref().unwrap_or("");
    let env = if matches!(verb, "switch" | "sdk-session") {
        c.environment
            .as_deref()
            .filter(|v| s.policy.capabilities.contains_key(*v))
    } else {
        a.grants
            .get(id)
            .map(|g| g.environment.as_str())
            .or_else(|| a.env())
    }
    .map(str::to_owned);
    let target = a
        .grants
        .get(id)
        .map(|g| g.resource.clone())
        .or_else(|| {
            s.policy
                .route(env.as_deref(), c.action.as_deref().unwrap_or("read"))
                .map(|r| r.resource.clone())
        })
        .unwrap_or_else(|| s.policy.task.clone());
    let role_ok = match verb {
        "approve" | "deny" => role == Role::Owner,
        "revoke" | "outcome" => true,
        _ => role == Role::Alice,
    };
    if !role_ok {
        return s.finish(
            role,
            env.as_deref(),
            verb,
            &target,
            "",
            Err(Failure::denied("当前身份无权执行此操作")),
        );
    }
    if verb == "use" && a.grants.get(id).is_some_and(|g| g.action == "diagnose") {
        let admitted = a.require_grant(id, "approved").and_then(|g| {
            g.token
                .clone()
                .map(|token| (g.environment.clone(), token))
                .ok_or_else(|| Failure::denied("授权无效"))
        });
        drop(a);
        let result = match admitted {
            Ok((env, token)) => {
                let _permit = s.read_permit()?;
                from_upstream(s.broker.call(&env, &token, "diagnose", None).await)
            }
            Err(error) => Err(error),
        };
        let detail = match &result {
            Ok(_) => account_name(
                &result,
                &format!(
                    "{}-diagnostics",
                    env.as_deref().unwrap_or("").to_lowercase()
                ),
            ),
            Err(error) => error.1.to_owned(),
        };
        return s.record_result(
            role,
            env.as_deref(),
            verb,
            &target,
            &format!("申请 {id}，{detail}"),
            result,
        );
    }
    let approved_retry = verb == "use"
        && a.grants
            .get(id)
            .is_some_and(|g| g.action == "retry" && g.status == "approved");
    let outcome = transition(&s, &mut a, role, verb, &c).await;
    match outcome {
        Ok((body, description)) => {
            if verb == "revoke" {
                // The retryable revocation completes its own audit before returning.
                return Ok(Json(body));
            }
            if let Err(err) = s.record(role, env.as_deref(), verb, &target, "allowed", &description)
            {
                // Do not expose an unaudited permission; the exclusive lock is
                // held until the newly-created capability is locally disabled.
                match verb {
                    "switch" => {
                        let _ = s.clear_session(&mut a, "审计失败，停用新会话").await;
                    }
                    "approve" => {
                        let g = a.grants.get_mut(id).unwrap();
                        g.status = "revoking";
                        if let Some(token) = &g.token {
                            if s.broker.revoke(&g.environment, token).await.is_ok() {
                                g.token = None;
                                g.status = "revoked";
                            }
                        }
                    }
                    "sdk-session" => {
                        if let Some(sid) = body["id"].as_str() {
                            let _ = s.drop_sdk(&mut a, sid, "审计未确认，撤回 SDK 会话").await;
                        }
                    }
                    "request" => {
                        if let Some(new_id) = body["id"].as_str() {
                            a.grants.remove(new_id);
                        }
                    }
                    _ => {}
                }
                return Err(err);
            }
            if matches!(verb, "request" | "switch" | "sdk-session") {
                s.deadlines_changed.notify_one();
            }
            Ok(Json(body))
        }
        Err(err) => {
            let submitted =
                approved_retry && a.grants.get(id).is_some_and(|g| g.status == "consumed");
            let detail = if submitted && err.0.is_server_error() {
                format!("申请 {id}，上游结果未知；须核对上游记录，不要重新执行")
            } else if a.grants.contains_key(id) {
                format!("申请 {id}，{}", err.1)
            } else {
                err.1.to_owned()
            };
            s.record_result(role, env.as_deref(), verb, &target, &detail, Err(err))
        }
    }
}

async fn transition(
    s: &Service,
    a: &mut Activity,
    role: Role,
    verb: &str,
    c: &Command,
) -> Result<(Value, String), Failure> {
    let id = c.id.as_deref().unwrap_or("");
    match verb {
        "sdk-session" => {
            if !s.policy.external {
                return Err(Failure::invalid("SDK 读取会话仅适用于配置的 HTTPS 服务"));
            }
            if a.closing.is_some() {
                return Err(Failure::denied("基础会话正在回收"));
            }
            let base = a
                .base
                .as_ref()
                .filter(|b| b.active && b.deadline > Instant::now())
                .ok_or_else(|| Failure::denied("需要活动的读取会话"))?;
            if c.environment.as_deref() != Some(&base.environment) {
                return Err(Failure::denied("目标环境与当前活动会话不符"));
            }
            if !s.broker.supports_sdk(&base.environment) {
                return Err(Failure::denied("此环境使用请求头凭据，仅支持受管读取。SDK 原始响应要求上游客户端证书认证"));
            }
            let cap = s
                .policy
                .route(Some(&base.environment), "read")
                .ok_or_else(|| Failure::denied("缺少读取规则"))?
                .max_ttl;
            let ttl = c.ttl.unwrap_or(cap.min(300));
            if !(1..=cap).contains(&ttl) {
                return Err(Failure::invalid("SDK 会话时长超出读取规则上限"));
            }
            let ttl = ttl.min(
                base.deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
            );
            if ttl == 0 {
                return Err(Failure::denied("基础会话即将到期"));
            }
            if a.sdk.len() >= 128 {
                return Err(Failure::denied("活动 SDK 会话数量达到上限"));
            }
            let id = Uuid::new_v4().to_string();
            let env = base.environment.clone();
            let deadline = Instant::now() + Duration::from_secs(ttl);
            let token = s
                .broker
                .issue_sdk(&env, ttl, &id)
                .await
                .map_err(|_| Failure::broker())?;
            let expires_at = unix_ms()
                + deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as i64;
            a.sdk.insert(
                id.clone(),
                Session {
                    environment: env.clone(),
                    token: token.clone(),
                    deadline,
                    active: true,
                    close_reason: None,
                    revoke_failed_logged: false,
                },
            );
            Ok((
                json!({"id":id,"environment":env,"expires_at":expires_at,"token":token}),
                format!("签发 SDK 只读会话 {id}，有效至 {expires_at}"),
            ))
        }
        "sdk-revoke" => {
            if !s.policy.external {
                return Err(Failure::invalid("SDK 读取会话仅适用于配置的 HTTPS 服务"));
            }
            s.drop_sdk(a, id, "调用方结束会话").await?;
            Ok((
                json!({"id":id,"closed":true}),
                format!("SDK 会话 {id} 已结束"),
            ))
        }
        "end" => {
            s.clear_session(a, "任务结束").await?;
            Ok((
                json!({"environment": null, "ended": true}),
                "任务结束，当前权限已清理".into(),
            ))
        }
        "outcome" => {
            if s.policy.external {
                return Err(Failure::invalid("该服务未配置上游回执适配器"));
            }
            let g = a
                .grants
                .get(id)
                .filter(|g| g.status == "consumed" && g.action == "retry")
                .ok_or_else(|| Failure::denied("只能查询本任务已提交的单次操作"))?;
            let receipt = from_upstream(s.broker.outcome(&g.environment, id).await)?;
            let state = if receipt["state"] == "applied" {
                "上游已执行"
            } else {
                "上游尚未确认执行"
            };
            Ok((receipt, format!("核对申请 {id}，{state}")))
        }
        "switch" => {
            let e = c.environment.as_deref().unwrap_or("");
            if !s.policy.capabilities.contains_key(e) {
                return Err(Failure::denied("环境不存在"));
            }
            s.clear_session(a, "切换环境").await?;
            let ttl = s
                .policy
                .route(Some(e), "read")
                .ok_or_else(|| Failure::denied("当前环境缺少基础读取规则"))?
                .max_ttl;
            let deadline = Instant::now() + Duration::from_secs(ttl);
            let token = s
                .broker
                .issue(e, "read", ttl)
                .await
                .map_err(|_| Failure::broker())?;
            a.base = Some(Session {
                environment: e.into(),
                token,
                deadline,
                active: true,
                close_reason: None,
                revoke_failed_logged: false,
            });
            Ok((json!({"environment":e}), "已切换环境并建立只读会话".into()))
        }
        "request" => {
            let env = a
                .env()
                .ok_or_else(|| Failure::denied("需先选择环境"))?
                .to_owned();
            let kind = c.action.as_deref().unwrap_or("");
            if !matches!(kind, "diagnose" | "retry") {
                return Err(Failure::invalid("未知临时权限模板"));
            }
            let route = s
                .policy
                .route(Some(&env), kind)
                .ok_or_else(|| Failure::denied("本环境未配置这项临时权限"))?;
            let ttl = c.ttl.unwrap_or(60.min(route.max_ttl));
            if !(1..=route.max_ttl).contains(&ttl) {
                return Err(Failure::invalid("授权时长超出该操作的配置范围"));
            }
            if a.grants.len() >= MAX_GRANTS {
                return Err(Failure::denied("当前会话申请已达上限，请重新建立会话"));
            }
            let now = Instant::now();
            let deadline = a
                .base
                .as_ref()
                .unwrap()
                .deadline
                .min(now + Duration::from_secs(ttl));
            let expires_at = unix_ms() + deadline.saturating_duration_since(now).as_millis() as i64;
            let id = Uuid::new_v4().to_string();
            let grant = Grant {
                id: id.clone(),
                environment: env,
                action: kind.into(),
                resource: route.resource.clone(),
                status: "pending",
                expires_at,
                deadline,
                token: None,
                revoke_requested_by: None,
                revoke_failed_logged: false,
            };
            a.grants.insert(id.clone(), grant);
            Ok((
                json!({"id":id,"expires_at":expires_at}),
                format!("申请 {id}，动作 {kind}，有效至 {expires_at}"),
            ))
        }
        "approve" | "deny" => {
            let g = a.require_grant(id, "pending")?;
            if verb == "deny" {
                a.grants.get_mut(id).unwrap().status = "denied";
                return Ok((
                    json!({"id":id,"status":"denied"}),
                    format!("已驳回申请 {id}"),
                ));
            }
            let remaining = g
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .div_ceil(1000) as u64;
            if remaining == 0 {
                return Err(Failure::denied("该申请已到期"));
            }
            let token = s
                .broker
                .issue(&g.environment, &g.action, remaining)
                .await
                .map_err(|_| Failure::broker())?;
            let g = a.grants.get_mut(id).unwrap();
            g.token = Some(token);
            g.status = "approved";
            Ok((
                json!({"id":id,"status":"approved"}),
                format!("已批准申请 {id}，动作 {}", g.action),
            ))
        }
        "revoke" => {
            let g = a
                .grants
                .get_mut(id)
                .ok_or_else(|| Failure::denied("找不到该项授权"))?;
            // Mark unusable first; retain the handle if the broker cannot confirm revocation.
            if !matches!(
                g.effective_status(Instant::now()),
                "pending" | "approved" | "revoking"
            ) {
                return Err(Failure::denied("这项授权已经结束"));
            }
            g.status = "revoking";
            let actor = *g.revoke_requested_by.get_or_insert(role);
            s.deadlines_changed.notify_one();
            s.finish_requested_revoke(g, actor).await?;
            Ok((json!({"id":id,"status":"revoked"}), String::new()))
        }
        "use" => {
            a.require_grant(id, "approved")?;
            let g = a.grants.get_mut(id).unwrap();
            if g.action != "retry" {
                return Err(Failure::denied("授权无效"));
            }
            // Persist and consume a one-shot admission before dispatch.
            s.record(
                role,
                Some(&g.environment),
                "admit",
                &g.resource,
                "allowed",
                &format!("已受理单次操作 {id}，等待上游回执"),
            )?;
            g.status = "consumed";
            let token = g
                .token
                .as_deref()
                .ok_or_else(|| Failure::denied("授权无效"))?;
            let result = from_upstream(
                s.broker
                    .call(&g.environment, token, &g.action, Some(id))
                    .await,
            );
            if s.broker.revoke(&g.environment, token).await.is_ok() {
                g.token = None;
            }
            let expected = format!("{}-worker", g.environment.to_lowercase());
            let msg = format!("申请 {id}，{}", account_name(&result, &expected));
            result.map(|body| (body, msg))
        }
        _ => unreachable!(),
    }
}
