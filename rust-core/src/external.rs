//! A single-task, deny-by-default credential broker for explicitly configured HTTPS endpoints.
use crate::{
    audit::Audit,
    vault::{Binding, MAX_CREDENTIAL},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper::body::{Body, Buf, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, Sleep},
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_METADATA_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SDK_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
// Each SDK read reserves its worst-case body size before fetching. The permit
// is released only after the corresponding TLS response flushes or is aborted.
const MAX_SDK_IN_FLIGHT_BYTES: usize = 32 * 1024 * 1024;
const MAX_SDK_READS: usize = 16;
const SDK_RESPONSE_CHUNK_BYTES: usize = 16 * 1024;
const SDK_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(15);
const DENIAL_WINDOW: Duration = Duration::from_secs(30);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalConfig {
    pub task: String,
    pub environments: HashMap<String, ExternalEnvironment>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEnvironment {
    pub origin: String,
    #[serde(default)]
    pub credential_files: HashMap<String, PathBuf>,
    #[serde(default)]
    pub credential_bindings: HashMap<String, Binding>,
    pub routes: HashMap<String, Route>,
    pub ca_file: Option<PathBuf>,
    pub proxy_cert_file: PathBuf,
    pub proxy_key_file: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub credential: String,
    pub resource: String,
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    #[serde(default = "default_auth_scheme")]
    pub auth_scheme: String,
    pub body: Option<Value>,
    #[serde(default)]
    pub idempotency_supported: bool,
    #[serde(default = "default_ttl")]
    pub max_ttl: u64,
}

fn default_ttl() -> u64 {
    900
}
fn default_auth_header() -> String {
    "authorization".into()
}
fn default_auth_scheme() -> String {
    "Bearer".into()
}
fn safe_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 192 && s.chars().all(|c| !c.is_control())
}

struct Target {
    config: ExternalEnvironment,
    origin: Url,
    authority: String,
    host_header: String,
    upstream: Client,
    acceptor: TlsAcceptor,
}

#[derive(Clone)]
struct Ticket {
    env: String,
    kind: String,
    expires: Instant,
    sdk_id: Option<String>,
    closed: tokio::sync::watch::Sender<bool>,
}

pub struct External {
    task: String,
    targets: HashMap<String, Target>,
    sessions: Mutex<HashMap<String, Ticket>>,
    sdk_reads: Semaphore,
    sdk_response_bytes: Arc<Semaphore>,
    anonymous_denials: Arc<Mutex<Option<u64>>>,
}

struct Reply {
    status: u16,
    body: Bytes,
    mime: Option<HeaderValue>,
}

enum ResponseUse {
    Metadata,
    Sdk(Option<HeaderValue>),
}

impl ResponseUse {
    fn max_bytes(&self) -> usize {
        match self {
            Self::Metadata => MAX_METADATA_RESPONSE_BYTES,
            Self::Sdk(_) => MAX_SDK_RESPONSE_BYTES,
        }
    }
}

struct ActiveSdkResponse {
    _permit: OwnedSemaphorePermit,
    body_complete: bool,
    flushed: bool,
}

#[derive(Default)]
struct SdkConnectionState {
    active: Mutex<Option<ActiveSdkResponse>>,
}

impl SdkConnectionState {
    fn begin(&self, permit: OwnedSemaphorePermit) -> bool {
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        if active.is_some() {
            return false;
        }
        *active = Some(ActiveSdkResponse {
            _permit: permit,
            body_complete: false,
            flushed: false,
        });
        true
    }

    fn wrote(&self) {
        if let Ok(mut active) = self.active.lock() {
            if let Some(response) = active.as_mut() {
                response.flushed = false;
            }
        }
    }

    fn body_complete(&self) {
        if let Ok(mut active) = self.active.lock() {
            let release = active.as_mut().is_some_and(|response| {
                response.body_complete = true;
                response.flushed
            });
            if release {
                active.take();
            }
        }
    }

    fn flushed(&self) {
        if let Ok(mut active) = self.active.lock() {
            let release = active.as_mut().is_some_and(|response| {
                response.flushed = true;
                response.body_complete
            });
            if release {
                active.take();
            }
        }
    }

    fn abort(&self) {
        if let Ok(mut active) = self.active.lock() {
            active.take();
        }
    }
}

struct BudgetedBytes {
    bytes: Bytes,
    completes: Option<Arc<SdkConnectionState>>,
}

impl Buf for BudgetedBytes {
    fn remaining(&self) -> usize {
        self.bytes.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.bytes.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.bytes.advance(cnt);
    }
}

impl Drop for BudgetedBytes {
    fn drop(&mut self) {
        if let Some(connection) = &self.completes {
            connection.body_complete();
        }
    }
}

struct ProxyBody {
    bytes: Bytes,
    connection: Option<Arc<SdkConnectionState>>,
    complete: bool,
}

impl ProxyBody {
    fn immediate(bytes: Bytes) -> Self {
        Self {
            bytes,
            connection: None,
            complete: false,
        }
    }

    fn sdk(bytes: Bytes, connection: Arc<SdkConnectionState>) -> Self {
        let mut body = Self {
            bytes,
            connection: Some(connection),
            complete: false,
        };
        if body.bytes.is_empty() {
            body.connection.as_ref().unwrap().body_complete();
            body.complete = true;
        }
        body
    }
}

impl Drop for ProxyBody {
    fn drop(&mut self) {
        if !self.complete {
            if let Some(connection) = &self.connection {
                connection.abort();
            }
        }
    }
}

impl Body for ProxyBody {
    type Data = BudgetedBytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.bytes.is_empty() {
            return Poll::Ready(None);
        }
        let chunk = self
            .bytes
            .split_to(self.bytes.len().min(SDK_RESPONSE_CHUNK_BYTES));
        let completes = if self.bytes.is_empty() {
            self.complete = true;
            self.connection.as_ref().cloned()
        } else {
            None
        };
        Poll::Ready(Some(Ok(Frame::data(BudgetedBytes {
            bytes: chunk,
            completes,
        }))))
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.bytes.len() as u64)
    }
}

struct WriteTimeoutIo<T> {
    inner: T,
    response: Arc<SdkConnectionState>,
    stalled: bool,
    deadline: Pin<Box<Sleep>>,
}

impl<T> WriteTimeoutIo<T> {
    fn new(inner: T, response: Arc<SdkConnectionState>) -> Self {
        Self {
            inner,
            response,
            stalled: false,
            deadline: Box::pin(tokio::time::sleep(SDK_WRITE_STALL_TIMEOUT)),
        }
    }

    fn stalled_error(&mut self, cx: &mut TaskContext<'_>) -> Option<io::Error> {
        if !self.stalled {
            self.deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + SDK_WRITE_STALL_TIMEOUT);
            self.stalled = true;
        }
        if self.deadline.as_mut().poll(cx).is_ready() {
            self.response.abort();
            Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "SDK response write stalled",
            ))
        } else {
            None
        }
    }

    fn write_progress(&mut self) {
        self.stalled = false;
        self.response.wrote();
    }

    fn write_failed(&mut self) {
        self.stalled = false;
        self.response.abort();
    }

    fn flush_complete(&mut self) {
        self.stalled = false;
        self.response.flushed();
    }
}

impl<T> Drop for WriteTimeoutIo<T> {
    fn drop(&mut self) {
        self.response.abort();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WriteTimeoutIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WriteTimeoutIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                this.write_progress();
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                this.write_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => match this.stalled_error(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(written)) => {
                this.write_progress();
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                this.write_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => match this.stalled_error(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.flush_complete();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.write_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => match this.stalled_error(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.flush_complete();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.write_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => match this.stalled_error(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }
}

impl Target {
    fn new(environment: &str, config: ExternalEnvironment) -> Result<Self> {
        for (alias, binding) in &config.credential_bindings {
            ensure!(
                !config.credential_files.contains_key(alias),
                "每个凭据别名只能使用一种来源"
            );
            binding.validate(environment)?;
        }
        let origin = Url::parse(&config.origin).context("无效的 HTTPS 服务地址")?;
        ensure!(
            origin.scheme() == "https"
                && origin.has_host()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "origin 必须是不含认证、路径、查询或片段的 HTTPS 源"
        );
        let host = origin.host_str().context("缺少上游主机")?;
        let authority = format!("{host}:{}", origin.port_or_known_default().unwrap_or(443));
        let host_header = if origin.port().is_none() {
            host.to_string()
        } else {
            authority.clone()
        };

        ensure!(config.routes.contains_key("read"), "环境缺少 read 路由");
        for (kind, route) in &config.routes {
            ensure!(
                safe_label(&route.resource)
                    && safe_label(&route.credential)
                    && (1..=900).contains(&route.max_ttl),
                "resource、credential 或 max_ttl 不合法"
            );
            let path = &route.path;
            ensure!(
                path.starts_with('/')
                    && !path.contains("//")
                    && !path.split('/').any(|p| p == "." || p == "..")
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b)),
                "路由只支持固定的规范路径，不支持通配符、编码、查询或片段"
            );
            ensure!(
                config.credential_files.contains_key(&route.credential)
                    || config.credential_bindings.contains_key(&route.credential),
                "路由引用了未声明的凭据"
            );
            let name = header::HeaderName::from_bytes(route.auth_header.as_bytes())
                .context("认证请求头名称无效")?;
            let n = name.as_str();
            ensure!(
                (n == "authorization" || n == "api-key" || n.starts_with("x-"))
                    && !n.starts_with("x-forwarded-")
                    && !n.starts_with("x-proxy-")
                    && !["x-original-url", "x-rewrite-url", "x-http-method-override"].contains(&n),
                "仅支持 Authorization、Api-Key 或自定义 API x-* 认证头"
            );
            ensure!(
                route.auth_scheme.len() <= 32
                    && route
                        .auth_scheme
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "认证前缀仅支持 ASCII 名称或空值"
            );
            match kind.as_str() {
                "read" | "diagnose" => ensure!(
                    route.method == "GET" && route.body.is_none(),
                    "读取类能力需要无正文 GET"
                ),
                "retry" => ensure!(
                    route.method == "POST" && route.idempotency_supported,
                    "单次写操作须使用 POST 并显式确认上游支持 Idempotency-Key"
                ),
                _ => bail!("未识别的动作类型"),
            }
            if let Some(body) = &route.body {
                ensure!(
                    serde_json::to_vec(body)?.len() <= 64 * 1024,
                    "固定请求正文太大"
                );
            }
        }
        let mut client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("KeyHeron/0.1");
        if let Some(ca) = &config.ca_file {
            let certs = reqwest::Certificate::from_pem_bundle(
                &std::fs::read(ca).context("无法读取该环境的上游根证书")?,
            )?;
            ensure!(!certs.is_empty(), "上游根证书文件为空");
            for cert in certs {
                client = client.add_root_certificate(cert);
            }
        }
        let certs = CertificateDer::pem_file_iter(&config.proxy_cert_file)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&config.proxy_key_file)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config,
            origin,
            authority,
            host_header,
            upstream: client.build()?,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
        })
    }

    async fn credential(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(binding) = self.config.credential_bindings.get(alias) {
            let binding = binding.clone();
            return tokio::task::spawn_blocking(move || binding.read())
                .await
                .map_err(|_| anyhow!("加密凭据读取失败"))?;
        }
        let file = self
            .config
            .credential_files
            .get(alias)
            .context("凭据引用无效")?;
        // A rotation changes the next request. Never place the value in logs, URLs or user responses.
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
        let mut handle = options.open(file).await.context("该环境凭据不可用")?;
        ensure!(
            handle.metadata().await?.is_file(),
            "该环境凭据必须是普通文件"
        );
        let mut raw = Zeroizing::new(Vec::new());
        use tokio::io::AsyncReadExt;
        (&mut handle)
            .take(MAX_CREDENTIAL as u64 + 1)
            .read_to_end(&mut raw)
            .await
            .context("无法读取凭据")?;
        ensure!(raw.len() <= MAX_CREDENTIAL, "凭据文件超出限制");
        Ok(raw)
    }

    async fn fetch(
        &self,
        kind: &str,
        op: Option<&str>,
        response_use: ResponseUse,
    ) -> Result<Reply> {
        let route = self.config.routes.get(kind).context("环境未配置此动作")?;
        let raw = self.credential(&route.credential).await?;
        let secret = std::str::from_utf8(&raw)
            .context("凭据格式无效")?
            .trim_end_matches(['\r', '\n']);
        ensure!(
            !secret.is_empty() && secret.bytes().all(|b| (33..=126).contains(&b)),
            "凭据应为单个非空 Bearer token"
        );
        let mut url = self.origin.clone();
        url.set_path(&route.path);
        let method = Method::from_bytes(route.method.as_bytes())?;
        let mut value = HeaderValue::from_str(&if route.auth_scheme.is_empty() {
            secret.to_owned()
        } else {
            format!("{} {secret}", route.auth_scheme)
        })
        .context("凭据不能用于请求头")?;
        value.set_sensitive(true);
        let include_body = matches!(&response_use, ResponseUse::Sdk(_));
        let max_bytes = response_use.max_bytes();
        let accept = match response_use {
            ResponseUse::Metadata => None,
            ResponseUse::Sdk(accept) => accept,
        };
        let mut request = self
            .upstream
            .request(method, url)
            .header(route.auth_header.as_str(), value)
            .header(
                header::ACCEPT,
                accept.unwrap_or_else(|| HeaderValue::from_static("application/json")),
            );
        if kind == "retry" {
            let key = Uuid::parse_str(op.context("缺少操作编号")?).context("无效的操作编号")?;
            request = request.header("idempotency-key", key.to_string());
            if let Some(body) = &route.body {
                request = request.json(body);
            }
        }
        let mut resp = request
            .send()
            .await
            .map_err(|_| anyhow!("上游 HTTPS 未确认，未重试"))?;
        let status = resp.status().as_u16();
        let mime = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .filter(|v| {
                !v.as_bytes()
                    .windows(secret.len())
                    .any(|s| s == secret.as_bytes())
            })
            .cloned();
        // Never mirror upstream error payloads, redirect targets, cookies or authentication headers.
        if !(200..300).contains(&status) {
            return Ok(Reply {
                status,
                body: Bytes::new(),
                mime: None,
            });
        }
        ensure!(
            resp.content_length()
                .is_none_or(|len| len <= max_bytes as u64),
            "上游响应太大"
        );
        ensure!(
            resp.headers()
                .get(header::CONTENT_ENCODING)
                .is_none_or(|e| e == "identity"),
            "不转发压缩响应"
        );
        let mut bytes = Vec::new();
        let mut received = 0usize;
        let contains_secret =
            |data: &[u8]| data.windows(secret.len()).any(|s| s == secret.as_bytes());
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| anyhow!("没有收到完整上游响应"))?
        {
            received = received.saturating_add(chunk.len());
            ensure!(received <= max_bytes, "上游响应太大");
            bytes.extend_from_slice(&chunk);
            if !include_body {
                ensure!(!contains_secret(&bytes), "上游响应包含凭据，已拒绝返回");
                // Only the suffix can still match a credential split across two chunks.
                let discard = bytes.len().saturating_sub(secret.len() - 1);
                bytes.drain(..discard);
            }
        }
        if include_body {
            ensure!(!contains_secret(&bytes), "上游响应包含凭据，已拒绝返回");
        } else {
            bytes.clear();
        }
        Ok(Reply {
            status,
            body: Bytes::from(bytes),
            mime,
        })
    }
}

impl External {
    pub fn new(config: ExternalConfig) -> Result<Self> {
        ensure!(safe_label(&config.task), "任务名无效");
        ensure!(
            !config.environments.is_empty() && config.environments.len() <= 3,
            "需要一至三个环境"
        );
        let mut targets = HashMap::new();
        for (env, cfg) in config.environments {
            ensure!(matches!(env.as_str(), "DEV" | "STG" | "PROD"), "未知环境");
            let target = Target::new(&env, cfg)?;
            targets.insert(env, target);
        }
        Ok(Self {
            task: config.task,
            targets,
            sessions: Mutex::new(HashMap::new()),
            sdk_reads: Semaphore::new(MAX_SDK_READS),
            sdk_response_bytes: Arc::new(Semaphore::new(MAX_SDK_IN_FLIGHT_BYTES)),
            anonymous_denials: Arc::default(),
        })
    }

    pub fn issue(&self, env: &str, kind: &str, ttl: u64, sdk_id: Option<&str>) -> Result<String> {
        let route = self
            .targets
            .get(env)
            .and_then(|t| t.config.routes.get(kind))
            .context("环境未配置该能力")?;
        ensure!((1..=route.max_ttl).contains(&ttl), "授权超过配置的有效期");
        if let Some(id) = sdk_id {
            ensure!(
                kind == "read" && Uuid::parse_str(id).is_ok(),
                "SDK 仅支持只读能力"
            );
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("会话存储不可用"))?;
        let now = Instant::now();
        sessions.retain(|_, v| v.expires > now);
        ensure!(sessions.len() < 4096, "活动会话数量超出限制");
        let token = format!("aa_{}", Uuid::new_v4().simple());
        sessions.insert(
            token.clone(),
            Ticket {
                env: env.into(),
                kind: kind.into(),
                expires: now + Duration::from_secs(ttl),
                sdk_id: sdk_id.map(str::to_owned),
                closed: tokio::sync::watch::channel(false).0,
            },
        );
        Ok(token)
    }

    pub fn revoke(&self, env: &str, token: &str) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("会话存储不可用"))?;
        if let Some(ticket) = sessions.get(token) {
            ensure!(ticket.env == env, "令牌属于其他环境");
        }
        if let Some(ticket) = sessions.remove(token) {
            ticket.closed.send_replace(true);
        }
        Ok(())
    }

    fn ticket(&self, token: &str) -> Option<Ticket> {
        self.sessions
            .lock()
            .ok()?
            .get(token)
            .filter(|s| s.expires > Instant::now())
            .cloned()
    }

    pub async fn call(
        &self,
        env: &str,
        token: &str,
        kind: &str,
        op: Option<&str>,
    ) -> Result<(u16, Value)> {
        let admitted = self
            .ticket(token)
            .is_some_and(|s| s.env == env && s.kind == kind && s.sdk_id.is_none());
        if !admitted {
            return Ok((403, json!({"error":"受限或无效的会话"})));
        }
        let target = &self.targets[env];
        let response = target.fetch(kind, op, ResponseUse::Metadata).await?;
        if !(200..300).contains(&response.status) {
            return Ok((response.status, json!({"error":"上游未接受请求"})));
        }
        let route = &target.config.routes[kind];
        Ok((
            200,
            json!({"environment":env,"account":route.credential,"status_source":"configured-credential",
            "upstream_status":response.status,"operation_id":op}),
        ))
    }

    pub async fn listen(self: Arc<Self>, addr: SocketAddr, audit: Audit) -> Result<u16> {
        ensure!(addr.ip().is_loopback(), "SDK 出站代理仅绑定回环地址");
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        let slots = Arc::new(tokio::sync::Semaphore::new(128));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let state = self.clone();
                let audit = audit.clone();
                tokio::spawn(async move {
                    let slot = Arc::new(slot);
                    let conn =
                        http1::Builder::new()
                            .keep_alive(false)
                            .max_buf_size(16384)
                            .serve_connection(
                                TokioIo::new(tcp),
                                service_fn(move |req| {
                                    let state = state.clone();
                                    let audit = audit.clone();
                                    let slot = slot.clone();
                                    async move {
                                        Ok::<_, Infallible>(state.connect(req, audit, slot).await)
                                    }
                                }),
                            )
                            .with_upgrades();
                    let _ = timeout(Duration::from_secs(20), conn).await;
                });
            }
        });
        Ok(port)
    }

    async fn connect(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        audit: Audit,
        slot: Arc<tokio::sync::OwnedSemaphorePermit>,
    ) -> Response<ProxyBody> {
        let token = req
            .headers()
            .get(header::PROXY_AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(basic_token);
        let session = token
            .and_then(|token| self.ticket(&token).map(|s| (token, s)))
            .filter(|(_, s)| s.sdk_id.is_some() && s.kind == "read");
        if req.method() != Method::CONNECT {
            return match session {
                Some((_, ticket)) => {
                    refused(&audit, Some(&ticket), None, "仅接受 HTTPS CONNECT", 403)
                }
                None => self.anonymous_refusal(&audit, "仅接受 HTTPS CONNECT", 403),
            };
        }
        let Some((token, ticket)) = session else {
            let mut r = self.anonymous_refusal(&audit, "缺少有效 SDK 会话", 407);
            r.headers_mut().insert(
                header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"KeyHeron\""),
            );
            return r;
        };
        let target = &self.targets[&ticket.env];
        let resource = &target.config.routes["read"].resource;
        if req
            .uri()
            .authority()
            .is_none_or(|a| !a.as_str().eq_ignore_ascii_case(&target.authority))
            || req.uri().path_and_query().is_some()
            || req.uri().scheme().is_some()
        {
            return refused(
                &audit,
                Some(&ticket),
                Some(resource),
                "目标不在当前会话范围",
                403,
            );
        }
        let acceptor = target.acceptor.clone();
        let mut closed = ticket.closed.subscribe();
        let deadline = tokio::time::Instant::from_std(ticket.expires);
        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let _connection_slot = slot;
            // A late subscriber also observes an earlier revoke. The absolute
            // deadline covers expiry even when other tickets are never touched.
            let cancelled = async move {
                tokio::select! {
                    _ = closed.wait_for(|flag| *flag) => (),
                    _ = tokio::time::sleep_until(deadline) => (),
                }
            };
            tokio::pin!(cancelled);
            let upgrade = tokio::select! {
                biased;
                _ = &mut cancelled => return,
                result = timeout(Duration::from_secs(5), upgrade) => match result {
                    Ok(Ok(upgraded)) => upgraded,
                    _ => return,
                }
            };
            let tls = tokio::select! {
                biased;
                _ = &mut cancelled => return,
                result = timeout(Duration::from_secs(8), acceptor.accept(TokioIo::new(upgrade))) => match result {
                    Ok(Ok(tls)) => tls,
                    _ => {
                        let _ = refused(&audit, Some(&ticket), None, "客户端 TLS 握手未完成", 403);
                        return;
                    }
                }
            };
            let response_state = Arc::new(SdkConnectionState::default());
            let serve = http1::Builder::new().max_buf_size(16384).serve_connection(
                TokioIo::new(WriteTimeoutIo::new(tls, response_state.clone())),
                service_fn(move |r| {
                    let s = self.clone();
                    let t = ticket.clone();
                    let token = token.clone();
                    let a = audit.clone();
                    let state = response_state.clone();
                    async move { Ok::<_, Infallible>(s.forward(r, &t, &token, &a, state).await) }
                }),
            );
            tokio::pin!(serve);
            tokio::select! {
                _ = &mut serve => (),
                _ = &mut cancelled => {
                    // Drop keep-alive immediately. An admitted read may finish
                    // within the upstream's 15s timeout plus a short flush grace.
                    serve.as_mut().graceful_shutdown();
                    let _ = timeout(Duration::from_secs(16), &mut serve).await;
                }
            }
        });
        response(200, Bytes::new())
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        issued: &Ticket,
        token: &str,
        audit: &Audit,
        response_state: Arc<SdkConnectionState>,
    ) -> Response<ProxyBody> {
        let target = &self.targets[&issued.env];
        let route = &target.config.routes["read"];
        if !self
            .ticket(token)
            .is_some_and(|s| s.sdk_id == issued.sdk_id && s.env == issued.env)
        {
            return self.anonymous_refusal(audit, "授权已到期或收回", 403);
        }
        let valid_host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| {
                h.eq_ignore_ascii_case(&target.host_header)
                    || h.eq_ignore_ascii_case(&target.authority)
            });
        if req.method() != Method::GET
            || req.uri().scheme().is_some()
            || req.uri().authority().is_some()
            || req
                .uri()
                .path_and_query()
                .is_none_or(|p| p.as_str() != route.path)
            || !valid_host
            || req.headers().contains_key(header::TRANSFER_ENCODING)
            || req
                .headers()
                .get(header::CONTENT_LENGTH)
                .is_some_and(|v| v != "0")
        {
            return refused(
                audit,
                Some(issued),
                Some(&route.resource),
                "请求不匹配已授权的只读路由",
                403,
            );
        }
        let accept = req.headers().get(header::ACCEPT).cloned();
        let details = format!(
            "任务 {}，SDK 会话 {}",
            self.task,
            issued.sdk_id.as_deref().unwrap_or("-")
        );
        let read_permit = match self.sdk_reads.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                return refused(
                    audit,
                    Some(issued),
                    Some(&route.resource),
                    "SDK 读取达到并发上限，请稍后再试",
                    429,
                );
            }
        };
        let response_budget = match self
            .sdk_response_bytes
            .clone()
            .try_acquire_many_owned(MAX_SDK_RESPONSE_BYTES as u32)
        {
            Ok(permit) => permit,
            Err(_) => {
                return refused(
                    audit,
                    Some(issued),
                    Some(&route.resource),
                    "SDK 响应达到内存上限，请稍后再试",
                    429,
                );
            }
        };
        let reply = match target.fetch("read", None, ResponseUse::Sdk(accept)).await {
            Ok(r) => r,
            Err(_) => {
                return if audit
                    .record(
                        "agent",
                        Some(&issued.env),
                        "sdk_read",
                        &route.resource,
                        "failed",
                        &details,
                    )
                    .is_ok()
                {
                    response(502, Bytes::new())
                } else {
                    response(503, Bytes::new())
                };
            }
        };
        drop(read_permit);
        let status = reply.status;
        let label = if (200..300).contains(&status) {
            "allowed"
        } else if status == 401 || status == 403 {
            "denied"
        } else {
            "failed"
        };
        if !response_state.begin(response_budget) {
            return refused(
                audit,
                Some(issued),
                Some(&route.resource),
                "SDK 连接仍在发送先前的响应",
                429,
            );
        }
        if audit
            .record(
                "agent",
                Some(&issued.env),
                "sdk_read",
                &route.resource,
                label,
                &format!("{details}，上游 HTTP {status}"),
            )
            .is_err()
        {
            response_state.abort();
            return response(503, Bytes::new());
        }
        let mut res = sdk_response(status, reply.body, response_state);
        if let Some(mime) = reply.mime {
            res.headers_mut().insert(header::CONTENT_TYPE, mime);
        }
        res
    }

    fn anonymous_refusal(&self, audit: &Audit, reason: &str, status: u16) -> Response<ProxyBody> {
        let Ok(mut window) = self.anonymous_denials.lock() else {
            return response(503, Bytes::new());
        };
        if let Some(suppressed) = &mut *window {
            *suppressed = suppressed.saturating_add(1);
            return response(status, Bytes::new());
        }
        *window = Some(0);
        drop(window);

        // One fixed-size bucket per proxy, including expired tickets on open tunnels.
        let summary = DenialSummary {
            counts: self.anonymous_denials.clone(),
            audit: audit.clone(),
        };
        tokio::spawn(async move {
            tokio::time::sleep(DENIAL_WINDOW).await;
            drop(summary);
        });
        refused(audit, None, None, reason, status)
    }
}

struct DenialSummary {
    counts: Arc<Mutex<Option<u64>>>,
    audit: Audit,
}

// Flush the last partial window when orderly shutdown cancels the timer.
impl Drop for DenialSummary {
    fn drop(&mut self) {
        let suppressed = self.counts.lock().ok().and_then(|mut window| window.take());
        if let Some(n @ 1..) = suppressed {
            let _ = self.audit.record(
                "agent",
                None,
                "sdk_read",
                "sdk-proxy",
                "denied",
                &format!("另有 {n} 次未认证代理请求被拒绝"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_events_share_one_window_and_authenticated_events_remain_individual() -> Result<()>
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let active = runtime.enter();
        let path =
            std::env::temp_dir().join(format!("keyheron-denials-{}.sqlite3", Uuid::new_v4()));
        let audit = Audit::open(&path, "test", "requester", "approver", "external")?;
        let proxy = External {
            task: "test".into(),
            targets: HashMap::new(),
            sessions: Mutex::default(),
            sdk_reads: Semaphore::new(MAX_SDK_READS),
            sdk_response_bytes: Arc::new(Semaphore::new(MAX_SDK_IN_FLIGHT_BYTES)),
            anonymous_denials: Arc::default(),
        };
        assert_eq!(proxy.anonymous_refusal(&audit, "匿名", 407).status(), 407);
        assert_eq!(proxy.anonymous_refusal(&audit, "已到期", 403).status(), 403);
        assert_eq!(proxy.anonymous_refusal(&audit, "已收回", 403).status(), 403);
        let ticket = Ticket {
            env: "DEV".into(),
            kind: "read".into(),
            expires: Instant::now() + DENIAL_WINDOW,
            sdk_id: Some("known".into()),
            closed: tokio::sync::watch::channel(false).0,
        };
        refused(&audit, Some(&ticket), None, "范围错误", 403);
        assert_eq!(audit.list(None, None, 10)?.len(), 2);
        drop(active);
        drop(runtime);
        assert!(audit.list(None, None, 1)?[0].detail.contains("2 次"));
        assert!(proxy.anonymous_denials.lock().unwrap().is_none());
        assert_eq!(audit.list(None, None, 10)?.len(), 3);
        drop(audit);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn sdk_limits_cap_retained_response_fanout() {
        assert_eq!(
            ResponseUse::Metadata.max_bytes(),
            MAX_METADATA_RESPONSE_BYTES
        );
        assert_eq!(ResponseUse::Sdk(None).max_bytes(), MAX_SDK_RESPONSE_BYTES);
        assert!(MAX_SDK_RESPONSE_BYTES < MAX_METADATA_RESPONSE_BYTES);
        let budget = Arc::new(Semaphore::new(MAX_SDK_IN_FLIGHT_BYTES));
        let reservations: Vec<_> = (0..MAX_SDK_IN_FLIGHT_BYTES / MAX_SDK_RESPONSE_BYTES)
            .map(|_| {
                budget
                    .clone()
                    .try_acquire_many_owned(MAX_SDK_RESPONSE_BYTES as u32)
                    .expect("budget should admit the configured bounded fanout")
            })
            .collect();
        assert_eq!(budget.available_permits(), 0);
        assert!(budget
            .clone()
            .try_acquire_many_owned(MAX_SDK_RESPONSE_BYTES as u32)
            .is_err());
        drop(reservations);
        assert_eq!(budget.available_permits(), MAX_SDK_IN_FLIGHT_BYTES);
    }

    #[tokio::test]
    async fn sdk_budget_waits_for_transport_flush() {
        use http_body_util::BodyExt;

        let budget = Arc::new(Semaphore::new(MAX_SDK_IN_FLIGHT_BYTES));
        let permit = budget
            .clone()
            .try_acquire_many_owned(MAX_SDK_RESPONSE_BYTES as u32)
            .unwrap();
        let connection = Arc::new(SdkConnectionState::default());
        assert!(connection.begin(permit));
        let mut body = ProxyBody::sdk(
            Bytes::from_static(b"ordinary SDK response"),
            connection.clone(),
        );
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.data_ref().unwrap().chunk(), b"ordinary SDK response");
        assert_eq!(
            budget.available_permits(),
            MAX_SDK_IN_FLIGHT_BYTES - MAX_SDK_RESPONSE_BYTES
        );
        drop(body);
        assert_eq!(
            budget.available_permits(),
            MAX_SDK_IN_FLIGHT_BYTES - MAX_SDK_RESPONSE_BYTES
        );
        drop(frame);
        assert_eq!(
            budget.available_permits(),
            MAX_SDK_IN_FLIGHT_BYTES - MAX_SDK_RESPONSE_BYTES
        );
        connection.flushed();
        assert_eq!(budget.available_permits(), MAX_SDK_IN_FLIGHT_BYTES);
    }
}

fn basic_token(value: &str) -> Option<String> {
    let (scheme, text) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || text.len() > 160 {
        return None;
    }
    let text = String::from_utf8(STANDARD.decode(text).ok()?).ok()?;
    Some(text.strip_prefix("agent:")?.to_string())
}
fn response(status: u16, body: Bytes) -> Response<ProxyBody> {
    let mut r = Response::new(ProxyBody::immediate(body));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn sdk_response(
    status: u16,
    body: Bytes,
    connection: Arc<SdkConnectionState>,
) -> Response<ProxyBody> {
    let mut r = Response::new(ProxyBody::sdk(body, connection));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn refused(
    audit: &Audit,
    ticket: Option<&Ticket>,
    resource: Option<&str>,
    reason: &str,
    status: u16,
) -> Response<ProxyBody> {
    let detail = match ticket.and_then(|s| s.sdk_id.as_deref()) {
        Some(id) => format!("SDK 会话 {id}，{reason}"),
        None => reason.to_string(),
    };
    let recorded = audit
        .record(
            "agent",
            ticket.map(|s| s.env.as_str()),
            "sdk_read",
            resource.unwrap_or("sdk-proxy"),
            "denied",
            &detail,
        )
        .is_ok();
    response(if recorded { status } else { 503 }, Bytes::new())
}
