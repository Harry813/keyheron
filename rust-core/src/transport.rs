use anyhow::{anyhow, bail, ensure, Result};
use reqwest::{redirect, Client, Method, Proxy, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Mutex, time::Duration};

#[derive(Clone, Deserialize)]
pub struct BrokerConfig {
    pub proxy_port: u16,
    pub control_port: u16,
    pub management_key: String,
    pub receipt_key: String,
    pub origin_port: u16,
}

struct Broker {
    cfg: BrokerConfig,
    data: Client,
    // Only the trusted service sees parent tokens. Keep them until revocation is acknowledged.
    parents: Mutex<HashMap<String, String>>,
}

pub struct DemoTransport {
    control: Client,
    brokers: HashMap<String, Broker>,
}

#[derive(Deserialize)]
struct Issued {
    token: String,
}

fn route(kind: &str) -> Result<(Method, &'static str, &'static str)> {
    match kind {
        "read" => Ok((Method::GET, "/service/status", "reader")),
        "diagnose" => Ok((Method::GET, "/service/diagnostics", "diagnostics")),
        "retry" => Ok((Method::POST, "/jobs/job-4821/retry", "worker")),
        _ => bail!("未知操作"),
    }
}

fn client() -> reqwest::ClientBuilder {
    Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(30))
}

impl DemoTransport {
    pub fn new(config: HashMap<String, BrokerConfig>) -> Result<Self> {
        ensure!(
            config.len() == 3
                && ["DEV", "STG", "PROD"]
                    .iter()
                    .all(|env| config.contains_key(*env)),
            "需要三个环境的代理配置"
        );
        let control = client().build()?;
        let mut brokers = HashMap::new();
        for (name, cfg) in config {
            ensure!(
                cfg.control_port != 0
                    && cfg.proxy_port != 0
                    && cfg.origin_port != 0
                    && !cfg.management_key.is_empty()
                    && !cfg.receipt_key.is_empty()
                    && cfg.receipt_key != cfg.management_key,
                "本地代理配置不完整"
            );
            let proxy = Proxy::http(format!("http://127.0.0.1:{}", cfg.proxy_port))?;
            let data = client().proxy(proxy).pool_max_idle_per_host(0).build()?;
            brokers.insert(
                name,
                Broker {
                    cfg,
                    data,
                    parents: Mutex::new(HashMap::new()),
                },
            );
        }
        Ok(Self { control, brokers })
    }

    fn broker(&self, env: &str) -> Result<&Broker> {
        self.brokers
            .get(env)
            .ok_or_else(|| anyhow!("没有该环境的代理"))
    }

    async fn mint(
        &self,
        broker: &Broker,
        endpoint: &str,
        auth: &str,
        payload: Value,
    ) -> Result<String> {
        let url = format!(
            "http://127.0.0.1:{}/tokens{}",
            broker.cfg.control_port, endpoint
        );
        let reply = self
            .control
            .post(url)
            .bearer_auth(auth)
            .json(&payload)
            .send()
            .await
            .map_err(|_| anyhow!("签发服务不可达"))?;
        ensure!(
            reply.status() == StatusCode::OK,
            "代理拒绝签发（HTTP {}）",
            reply.status().as_u16()
        );
        let token = reply
            .json::<Issued>()
            .await
            .map_err(|_| anyhow!("签发响应无效"))?
            .token;
        ensure!(
            token.starts_with("kf_")
                && token[3..].bytes().all(|c| c.is_ascii_hexdigit())
                && token.len() > 3,
            "签发响应中的代理令牌无效"
        );
        Ok(token)
    }

    async fn revoke_parent(&self, broker: &Broker, parent: &str) -> Result<()> {
        let url = format!(
            "http://127.0.0.1:{}/tokens/{}",
            broker.cfg.control_port, parent
        );
        let reply = self
            .control
            .delete(url)
            .bearer_auth(&broker.cfg.management_key)
            .send()
            .await
            .map_err(|_| anyhow!("代理未确认撤销"))?;
        ensure!(
            reply.status().is_success() || reply.status() == StatusCode::NOT_FOUND,
            "代理未确认撤销（HTTP {}）",
            reply.status().as_u16()
        );
        Ok(())
    }

    pub async fn issue(&self, env: &str, kind: &str, ttl: u64) -> Result<String> {
        let broker = self.broker(env)?;
        ensure!((1..=3600).contains(&ttl), "令牌时限超出范围");
        ensure!(kind == "read" || env == "PROD", "该环境不提供临时操作");
        let (method, path, credential) = route(kind)?;
        let parent = self
            .mint(
                broker,
                "",
                &broker.cfg.management_key,
                json!({
                    "destinations": [format!("localhost{path}")],
                    "credential_ref": credential,
                    "ttl_seconds": ttl,
                    "policy": if method == Method::GET { "readonly" } else { "standard" },
                    "agent_id": "alice",
                    "task_id": "orders-investigation",
                }),
            )
            .await?;
        match self
            .mint(
                broker,
                "/attenuate",
                &parent,
                json!({"allowed_methods":[method.as_str()]}),
            )
            .await
        {
            Ok(token) => {
                broker
                    .parents
                    .lock()
                    .map_err(|_| anyhow!("代理状态不可用"))?
                    .insert(token.clone(), parent);
                Ok(token)
            }
            Err(err) => {
                self.revoke_parent(broker, &parent).await?;
                Err(err)
            }
        }
    }

    pub async fn revoke(&self, env: &str, token: &str) -> Result<()> {
        let broker = self.broker(env)?;
        let parent = broker
            .parents
            .lock()
            .map_err(|_| anyhow!("代理状态不可用"))?
            .get(token)
            .cloned();
        if let Some(parent) = parent {
            self.revoke_parent(broker, &parent).await?;
            broker
                .parents
                .lock()
                .map_err(|_| anyhow!("代理状态不可用"))?
                .remove(token);
        }
        Ok(())
    }

    pub async fn call(
        &self,
        env: &str,
        token: &str,
        kind: &str,
        op_id: Option<&str>,
    ) -> Result<(u16, Value)> {
        let broker = self.broker(env)?;
        let (method, path, role) = route(kind)?;
        let url = format!("http://localhost:{}{}", broker.cfg.origin_port, path);
        // v0.4.0's plain-HTTP fixture path drops the non-default origin port on
        // subsequent requests on one socket. Keep management/client pools, close this hop.
        let mut request = broker
            .data
            .request(method, url)
            .bearer_auth(token)
            .header(reqwest::header::CONNECTION, "close");
        if kind == "retry" {
            request = request.header(
                "Idempotency-Key",
                op_id.ok_or_else(|| anyhow!("缺少操作编号"))?,
            );
        }
        let reply = request
            .send()
            .await
            .map_err(|_| anyhow!("代理或上游未确认请求结果"))?;
        let status = reply.status().as_u16();
        ensure!(
            !reply.status().is_success() || status == 200,
            "上游没有确认操作结果"
        );
        if status != 200 {
            return Ok((status, json!({"error":"代理或上游拒绝请求"})));
        }
        let value = reply
            .json::<Value>()
            .await
            .map_err(|_| anyhow!("上游响应格式错误"))?;
        ensure!(
            value["environment"] == env
                && value["account"] == format!("{}-{role}", env.to_ascii_lowercase()),
            "上游未确认环境账户"
        );
        let mut response = json!({"environment": env, "account": value["account"]});
        if kind == "retry" {
            ensure!(
                value["operation_id"].as_str() == op_id
                    && value["executions"].as_u64() == Some(1)
                    && value["run_number"].as_u64().is_some_and(|n| n > 0)
                    && value["replay"].is_boolean(),
                "上游未确认单次操作编号与结果"
            );
            for field in ["operation_id", "executions", "run_number", "replay"] {
                response[field] = value[field].clone();
            }
        }
        Ok((status, response))
    }

    pub async fn outcome(&self, env: &str, id: &str) -> Result<(u16, Value)> {
        ensure!(env == "PROD", "该环境没有可查询的重跑操作");
        let id = uuid::Uuid::parse_str(id).map_err(|_| anyhow!("无效的操作编号"))?;
        let broker = self.broker(env)?;
        let url = format!(
            "http://127.0.0.1:{}/__demo/receipts/{id}",
            broker.cfg.origin_port
        );
        let reply = self
            .control
            .get(url)
            .bearer_auth(&broker.cfg.receipt_key)
            .send()
            .await
            .map_err(|_| anyhow!("上游回执不可达"))?;
        ensure!(reply.status() == StatusCode::OK, "上游回执未能确认");
        let data = reply
            .json::<Value>()
            .await
            .map_err(|_| anyhow!("上游回执格式无效"))?;
        let state = data["state"].as_str();
        let number = data
            .get("run_number")
            .ok_or_else(|| anyhow!("上游回执缺少执行序号"))?;
        ensure!(
            (state == Some("applied") && number.as_u64().is_some_and(|n| n > 0))
                || (state == Some("unconfirmed") && number.is_null()),
            "上游回执状态与序号不一致"
        );
        Ok((200, json!({"state":state, "run_number":number})))
    }
}

use crate::{
    audit::Audit,
    external::{External, ExternalConfig},
};
use std::{net::SocketAddr, sync::Arc};

pub enum Transport {
    Demo(DemoTransport),
    Configured(Arc<External>),
}

impl Transport {
    pub fn new(config: HashMap<String, BrokerConfig>) -> Result<Self> {
        Ok(Self::Demo(DemoTransport::new(config)?))
    }
    pub fn external(config: ExternalConfig) -> Result<Self> {
        Ok(Self::Configured(Arc::new(External::new(config)?)))
    }
    pub fn is_external(&self) -> bool {
        matches!(self, Self::Configured(_))
    }
    pub async fn issue(&self, env: &str, kind: &str, ttl: u64) -> Result<String> {
        match self {
            Self::Demo(t) => t.issue(env, kind, ttl).await,
            Self::Configured(t) => t.issue(env, kind, ttl, None),
        }
    }
    pub async fn issue_sdk(&self, env: &str, ttl: u64, id: &str) -> Result<String> {
        match self {
            Self::Demo(_) => bail!("此模式未启用 SDK 代理"),
            Self::Configured(t) => t.issue(env, "read", ttl, Some(id)),
        }
    }
    pub async fn revoke(&self, env: &str, token: &str) -> Result<()> {
        match self {
            Self::Demo(t) => t.revoke(env, token).await,
            Self::Configured(t) => t.revoke(env, token),
        }
    }
    pub async fn call(
        &self,
        env: &str,
        token: &str,
        kind: &str,
        op: Option<&str>,
    ) -> Result<(u16, Value)> {
        match self {
            Self::Demo(t) => t.call(env, token, kind, op).await,
            Self::Configured(t) => t.call(env, token, kind, op).await,
        }
    }
    pub async fn outcome(&self, env: &str, id: &str) -> Result<(u16, Value)> {
        match self {
            Self::Demo(t) => t.outcome(env, id).await,
            Self::Configured(_) => Ok((200, json!({"state":"unconfirmed","run_number":null}))),
        }
    }
    pub async fn listen_external(self: &Arc<Self>, addr: SocketAddr, audit: Audit) -> Result<u16> {
        match self.as_ref() {
            Self::Configured(t) => t.clone().listen(addr, audit).await,
            Self::Demo(_) => bail!("此模式未启用 SDK 代理"),
        }
    }
}
