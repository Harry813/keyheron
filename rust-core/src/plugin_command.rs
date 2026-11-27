//! Private stdin/stdout boundary between the trusted Warden and native drivers.
use crate::gitlab_plugin;
use agent_access_core::plugins::v1::{DatabaseEngine, Manifest, Registry, Scope, API_VERSION};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    api_version: u32,
    manifests: Vec<Manifest>,
    command: Command,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Catalog,
    OpenDatabase {
        request: Scope,
        grant: Scope,
        actual_engine: DatabaseEngine,
    },
    Read {
        request: Scope,
        grant: Scope,
        target: Value,
        timeout_ms: u64,
    },
}

async fn dispatch(envelope: Envelope) -> Result<Value, &'static str> {
    if envelope.api_version != API_VERSION || envelope.manifests.len() > 64 {
        return Err("invalid");
    }
    let registry = Registry::new(envelope.manifests).map_err(|_| "invalid")?;
    match envelope.command {
        Command::Catalog => Ok(json!(registry.catalog())),
        Command::OpenDatabase { request, grant, actual_engine } => {
            let plan = registry
                .plan(&request, &grant, Some(actual_engine))
                .map_err(|_| "denied")?;
            Ok(json!(plan))
        }
        Command::Read { request, grant, target, timeout_ms } => {
            let plan = registry.plan(&request, &grant, None).map_err(|_| "denied")?;
            if !(1..=10_000).contains(&timeout_ms) {
                return Err("invalid");
            }
            let timeout = Duration::from_millis(timeout_ms);
            match plan.driver {
                "gitlab" => {
                    let config = serde_json::from_value(target).map_err(|_| "invalid")?;
                    gitlab_plugin::read(config, timeout).await
                }
                "https-json" => {
                    let config = serde_json::from_value(target).map_err(|_| "invalid")?;
                    gitlab_plugin::read_json(config, timeout).await
                }
                _ => return Err("denied"),
            }
            .map_err(|_| "upstream")
        }
    }
}

pub async fn run() {
    const MAX_REQUEST: u64 = 512 * 1024;
    let mut input = Vec::new();
    let message = match std::io::stdin().take(MAX_REQUEST + 1).read_to_end(&mut input) {
        Ok(_) if input.len() as u64 <= MAX_REQUEST => serde_json::from_slice(&input).ok(),
        _ => None,
    };
    let result = if let Some(message) = message {
        dispatch(message).await
    } else {
        Err("invalid")
    };
    let output = match result {
        Ok(value) => json!({"result": value}),
        Err(code) => json!({"error": code}),
    };
    println!("{output}");
}
