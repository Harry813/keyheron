//! Read a fixed GitLab MR or an allowlisted JSON projection using a trusted host resource.
use anyhow::{anyhow, ensure, Result};
use reqwest::{header::HeaderValue, Client, StatusCode, Url};
use serde::de::{Error, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    fmt,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

const MAX_BODY: usize = 1024 * 1024;
const MAX_TOKEN: usize = 8192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabResource {
    origin: String,
    project: u64,
    iid: u64,
    token_file: PathBuf,
    ca_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonResource {
    origin: String,
    path: String,
    fields: Vec<String>,
    token_file: Option<PathBuf>,
    ca_file: Option<PathBuf>,
}

fn destination(origin: &str, path: &str) -> Result<Url> {
    // Inspect the literal authority first: URL parsers may normalize userinfo and path segments.
    let (scheme, rest) = origin
        .split_once("://")
        .ok_or_else(|| anyhow!("HTTPS origin 无效"))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    ensure!(
        scheme.eq_ignore_ascii_case("https")
            && !authority.is_empty()
            && !authority.contains(['/', '\\', '@', '?', '#'])
            && !origin.chars().any(|c| c.is_control() || c.is_whitespace()),
        "HTTPS origin 无效"
    );
    let mut url = Url::parse(origin).map_err(|_| anyhow!("HTTPS origin 无效"))?;
    ensure!(url.has_host() && url.port() != Some(0), "HTTPS origin 无效");
    ensure!(
        path.starts_with('/')
            && path.len() <= 2048
            && !path.contains("//")
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
            && !path.split('/').any(|segment| matches!(segment, "." | "..")),
        "固定路径无效"
    );
    url.set_path(path);
    Ok(url)
}

async fn read_file(path: &Path, limit: usize, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    let file = options.open(path).await?;
    let meta = file.metadata().await?;
    ensure!(
        meta.is_file() && meta.len() <= limit as u64,
        "文件类型或长度无效"
    );
    if private {
        // Check the opened inode to allow rotations through trusted secret-manager symlinks.
        ensure!(
            meta.mode() & 0o077 == 0
                && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() }),
            "凭据文件权限无效"
        );
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut data).await?;
    ensure!(data.len() <= limit, "文件过大");
    Ok(data)
}

enum Auth<'a> {
    PrivateToken(&'a Path),
    Bearer(&'a Path),
}

struct Object;
impl<'de> Visitor<'de> for Object {
    type Value = Map<String, Value>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON object")
    }
    fn visit_map<A: MapAccess<'de>>(
        self,
        mut pairs: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut object = Map::new();
        while let Some((key, value)) = pairs.next_entry()? {
            if object.insert(key, value).is_some() {
                return Err(A::Error::custom("重复的顶层字段"));
            }
        }
        Ok(object)
    }
}

async fn get(
    url: Url,
    ca: Option<&Path>,
    auth: Option<Auth<'_>>,
    timeout: Duration,
    project: impl FnOnce(Map<String, Value>) -> Result<Map<String, Value>>,
) -> Result<Value> {
    let mut client = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(timeout.min(Duration::from_secs(5)))
        .timeout(timeout);
    if let Some(ca) = ca {
        let data = read_file(ca, MAX_BODY, false).await?;
        let certs = reqwest::Certificate::from_pem_bundle(&data)?;
        ensure!(!certs.is_empty(), "上游 CA 为空");
        client = client.tls_built_in_root_certs(false);
        for cert in certs {
            client = client.add_root_certificate(cert);
        }
    }
    let mut request = client
        .build()?
        .get(url)
        .header("accept", "application/json");
    let mut secret = Zeroizing::new(Vec::new());
    if let Some(auth) = auth {
        let (path, header, prefix) = match auth {
            Auth::PrivateToken(path) => (path, "private-token", b"".as_slice()),
            Auth::Bearer(path) => (path, "authorization", b"Bearer ".as_slice()),
        };
        secret = read_file(path, MAX_TOKEN, true).await?;
        for end in [b'\n', b'\r'] {
            if secret.last() == Some(&end) {
                secret.pop();
            }
        }
        ensure!(
            !secret.is_empty() && secret.iter().all(|b| (33..=126).contains(b)),
            "凭据格式无效"
        );
        let mut encoded = Zeroizing::new(Vec::with_capacity(prefix.len() + secret.len()));
        encoded.extend_from_slice(prefix);
        encoded.extend_from_slice(&secret);
        let mut value = HeaderValue::from_bytes(&encoded)?;
        value.set_sensitive(true);
        request = request.header(header, value);
    }
    let mut resp = request.send().await?;
    ensure!(resp.status() == StatusCode::OK, "上游读取失败");
    ensure!(
        resp.content_length().is_none_or(|n| n <= MAX_BODY as u64),
        "上游响应过大"
    );
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = resp.chunk().await? {
        ensure!(chunk.len() <= MAX_BODY - body.len(), "上游响应过大");
        body.extend_from_slice(&chunk);
    }
    let mut de = serde_json::Deserializer::from_slice(&body);
    let object = serde::Deserializer::deserialize_map(&mut de, Object)?;
    de.end()?;
    let selected = project(object)?;
    if !secret.is_empty() {
        let token = std::str::from_utf8(&secret)?;
        for value in selected.values() {
            // Check decoded values too: an upstream may JSON-escape a reflected header.
            let reflected = match value {
                Value::String(s) => s.contains(token),
                scalar => scalar.to_string().contains(token),
            };
            ensure!(!reflected, "上游返回了凭据");
        }
    }
    Ok(Value::Object(selected))
}

pub async fn read(config: GitlabResource, timeout: Duration) -> Result<Value> {
    ensure!(
        config.project > 0 && config.iid > 0,
        "GitLab 项目和 MR 编号无效"
    );
    let path = format!(
        "/api/v4/projects/{}/merge_requests/{}",
        config.project, config.iid
    );
    let url = destination(&config.origin, &path)?;
    let request = get(
        url,
        config.ca_file.as_deref(),
        Some(Auth::PrivateToken(&config.token_file)),
        timeout,
        |mut mr| {
            ensure!(
                mr.get("project_id").and_then(Value::as_u64) == Some(config.project)
                    && mr.get("iid").and_then(Value::as_u64) == Some(config.iid),
                "上游 MR 身份不符"
            );
            let mut selected = Map::new();
            selected.insert("project_id".into(), config.project.into());
            selected.insert("iid".into(), config.iid.into());
            for field in [
                "title",
                "description",
                "state",
                "source_branch",
                "target_branch",
                "web_url",
            ] {
                if let Some(value @ Value::String(_)) = mr.remove(field) {
                    selected.insert(field.into(), value);
                }
            }
            Ok(selected)
        },
    );
    tokio::time::timeout(timeout, request)
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| anyhow!("GitLab 读取失败"))
}

pub async fn read_json(config: JsonResource, timeout: Duration) -> Result<Value> {
    let fields = &config.fields;
    let mut seen = HashSet::new();
    ensure!(
        (1..=64).contains(&fields.len())
            && fields.iter().all(|field| {
                (1..=64).contains(&field.len())
                    && field
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                    && field
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    && seen.insert(field.as_str())
            }),
        "顶层字段列表无效"
    );
    let url = destination(&config.origin, &config.path)?;
    let request = get(
        url,
        config.ca_file.as_deref(),
        config.token_file.as_deref().map(Auth::Bearer),
        timeout,
        |mut object| {
            let mut selected = Map::new();
            for key in fields {
                if let Some(value) = object.remove(key) {
                    ensure!(
                        !value.is_array() && !value.is_object(),
                        "选中字段必须为标量"
                    );
                    selected.insert(key.clone(), value);
                }
            }
            Ok(selected)
        },
    );
    tokio::time::timeout(timeout, request)
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| anyhow!("JSON 读取失败"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_literal_origin_and_origin_form_paths() {
        for bad in [
            "http://example.test",
            "https://example.test/hidden/..",
            "https://@example.test",
            "https://example.test:0",
        ] {
            assert!(destination(bad, "/api").is_err());
        }
        for bad in [
            "//other.test",
            "/a/../b",
            "/?q=2",
            "/a%2fb",
            "/a#b",
            "/\\bad",
        ] {
            assert!(destination("https://example.test", bad).is_err());
        }
        assert_eq!(
            destination("https://example.test:443/", "/a/v1.json")
                .unwrap()
                .as_str(),
            "https://example.test/a/v1.json"
        );
    }
}
