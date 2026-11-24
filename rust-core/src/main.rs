mod audit;
mod external;
mod service;
mod transport;

use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::{sync::watch, task::JoinSet, time::timeout};

#[derive(Deserialize)]
struct Config {
    listen: SocketAddr,
    db: String,
    web: PathBuf,
    alice: String,
    owner: String,
    #[serde(default)]
    environments: HashMap<String, transport::BrokerConfig>,
    external: Option<external::ExternalConfig>,
    proxy_listen: Option<SocketAddr>,
    applicant_name: Option<String>,
    approver_name: Option<String>,
}

struct Guard {
    port: u16,
    alice: String,
    owner: String,
}

async fn guard(State(auth): State<Arc<Guard>>, mut req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host != format!("127.0.0.1:{}", auth.port)
        && host != format!("localhost:{}", auth.port)
        && host != format!("[::1]:{}", auth.port)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"仅接受本地控制台域名"})),
        )
            .into_response();
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if origin.to_str().ok() != Some(format!("http://{host}").as_str()) {
            return (StatusCode::FORBIDDEN, Json(json!({"error":"拒绝跨站请求"}))).into_response();
        }
    }
    if req.uri().path().starts_with("/api/") {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let role = match token {
            Some(t) if t == auth.alice => service::Role::Alice,
            Some(t) if t == auth.owner => service::Role::Owner,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error":"请使用启动器提供的角色链接登录"})),
                )
                    .into_response()
            }
        };
        req.extensions_mut().insert(role);
    }
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    response
}

fn asset(web: &std::path::Path, name: &str, mime: &'static str) -> Result<Router> {
    let bytes = axum::body::Bytes::from(
        std::fs::read(web.join(name)).with_context(|| format!("读取界面文件 {name}"))?,
    );
    let path = if name == "index.html" {
        "/".into()
    } else {
        format!("/{name}")
    };
    Ok(Router::new().route(
        &path,
        get(move || {
            let bytes = bytes.clone();
            async move { ([(header::CONTENT_TYPE, mime)], bytes) }
        }),
    ))
}

async fn serve_control(
    mut listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
    capacity: usize,
    header_timeout: Duration,
) {
    let mut connections = JoinSet::new();
    let (stop, closed) = watch::channel(());
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            (socket, _) = axum::serve::Listener::accept(&mut listener) => {
                if connections.len() >= capacity {
                    continue;
                }
                let service = TowerToHyperService::new(app.clone());
                let mut closed = closed.clone();
                connections.spawn(async move {
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(header_timeout)
                        .serve_connection(TokioIo::new(socket), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => return,
                        _ = closed.changed() => {},
                        // Recycle peers that leave a request body or response unfinished.
                        _ = tokio::time::sleep(Duration::from_secs(120)) => {},
                    }
                    connection.as_mut().graceful_shutdown();
                    // An already-admitted 15s HTTPS call can still finish.
                    let _ = timeout(Duration::from_secs(25), connection).await;
                });
            }
        }
    }
    drop(listener);
    drop(stop);
    while connections.join_next().await.is_some() {}
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[tokio::test]
    async fn idle_connections_release_their_slot_and_shutdown_finishes() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let (stop, closed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_control(
            listener,
            Router::new().route("/", get(|| async { "ready" })),
            async {
                let _ = closed.await;
            },
            1,
            Duration::from_millis(300),
        ));
        let first = reqwest::Client::builder().no_proxy().build()?;
        let second = reqwest::Client::builder().no_proxy().build()?;
        assert_eq!(first.get(&url).send().await?.text().await?, "ready");
        assert!(second.get(&url).send().await.is_err());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(second.get(&url).send().await?.text().await?, "ready");
        let _ = stop.send(());
        timeout(Duration::from_secs(2), server).await??;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg: Config = serde_json::from_str(
        &std::io::stdin()
            .lock()
            .lines()
            .next()
            .context("需要启动器提供配置")??,
    )
    .context("配置格式有误")?;
    ensure!(cfg.listen.ip().is_loopback(), "请绑定回环地址");
    ensure!(
        cfg.alice.len() >= 24 && cfg.owner.len() >= 24 && cfg.alice != cfg.owner,
        "需要两个独立的随机角色令牌"
    );
    let policy = service::Policy::new(
        cfg.external.as_ref(),
        cfg.applicant_name.unwrap_or_else(|| "alice".into()),
        cfg.approver_name.unwrap_or_else(|| "owner".into()),
    )?;
    let task = policy.task.clone();
    let transport = Arc::new(match cfg.external {
        Some(external) => {
            ensure!(cfg.environments.is_empty(), "真实服务与演示环境不能混用");
            transport::Transport::external(external)?
        }
        None => {
            ensure!(
                cfg.proxy_listen.is_none(),
                "SDK 代理只支持配置的 HTTPS 服务"
            );
            ensure!(
                cfg.environments.len() == 3
                    && ["DEV", "STG", "PROD"]
                        .iter()
                        .all(|e| cfg.environments.contains_key(*e)),
                "必须配置 DEV、STG、PROD"
            );
            transport::Transport::new(cfg.environments)?
        }
    });
    let audit = audit::Audit::open(
        &cfg.db,
        &policy.task,
        policy.actor(service::Role::Alice),
        policy.actor(service::Role::Owner),
        if transport.is_external() {
            "external"
        } else {
            "demo"
        },
    )?;
    let proxy_port = if transport.is_external() {
        let addr = cfg
            .proxy_listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        ensure!(addr.ip().is_loopback(), "SDK 代理仅允许回环监听");
        Some(transport.listen_external(addr, audit.clone()).await?)
    } else {
        None
    };
    let state = service::Service::new(audit.clone(), transport, policy);
    let listener = TcpListener::bind(cfg.listen).await?;
    let port = listener.local_addr()?.port();
    let guard_state = Arc::new(Guard {
        port,
        alice: cfg.alice,
        owner: cfg.owner,
    });
    let app = service::routes(state)
        .merge(asset(&cfg.web, "index.html", "text/html; charset=utf-8")?)
        .merge(asset(&cfg.web, "app.js", "text/javascript; charset=utf-8")?)
        .merge(asset(&cfg.web, "styles.css", "text/css; charset=utf-8")?)
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(guard_state, guard));
    audit.record(
        "system",
        None,
        "startup",
        &task,
        "allowed",
        "控制服务启动，先前运行的基础会话与临时授权不会恢复",
    )?;
    println!("{}", json!({"port":port,"proxy_port":proxy_port}));
    std::io::stdout().flush()?;
    serve_control(
        listener,
        app,
        async {
            // The trusted launcher holds this pipe open for the service lifetime.
            let _ = tokio::task::spawn_blocking(|| {
                std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink())
            })
            .await;
        },
        128,
        Duration::from_secs(10),
    )
    .await;
    Ok(())
}
