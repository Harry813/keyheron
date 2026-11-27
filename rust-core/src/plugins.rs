//! Version 1 of the declarative connector API.
//!
//! A manifest names one operation and one built-in execution driver. Administrators
//! bind resources and credentials on their Warden. Planning requires an independent,
//! authenticated grant for the same task, connector, action, and resource.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

pub const API_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseEngine {
    Postgresql,
    Mysql,
    Sqlserver,
}

impl DatabaseEngine {
    fn name(self) -> &'static str {
        match self {
            Self::Postgresql => "postgresql",
            Self::Mysql => "mysql",
            Self::Sqlserver => "sqlserver",
        }
    }
}

/// Execution drivers available to third-party manifest authors in API version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManifestDriver {
    Postgresql,
    Mysql,
    Sqlserver,
    #[serde(rename = "https-json")]
    HttpsJson,
}

impl ManifestDriver {
    fn engine(self) -> Option<DatabaseEngine> {
        match self {
            Self::Postgresql => Some(DatabaseEngine::Postgresql),
            Self::Mysql => Some(DatabaseEngine::Mysql),
            Self::Sqlserver => Some(DatabaseEngine::Sqlserver),
            Self::HttpsJson => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub api_version: u32,
    pub id: String,
    pub action: String,
    pub driver: ManifestDriver,
}

impl Manifest {
    pub fn v1(id: impl Into<String>, action: impl Into<String>, driver: ManifestDriver) -> Self {
        Self {
            api_version: API_VERSION,
            id: id.into(),
            action: action.into(),
            driver,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub task: String,
    pub connector: String,
    pub action: String,
    pub resource: String,
}

/// Public capability metadata, including the compatibility-only database connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginDescription {
    pub api_version: u32,
    pub id: String,
    pub action: String,
    /// None only for the legacy connector, whose engine comes from the Warden target.
    pub driver: Option<&'static str>,
    pub native_stream: bool,
    pub legacy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionPlan {
    /// Fixed, pre-registered driver name for the host dispatcher.
    pub driver: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginError {
    UnsupportedVersion,
    InvalidId,
    DuplicatePlugin,
    Denied,
    TargetMismatch,
}

impl fmt::Display for PluginError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::UnsupportedVersion => "unsupported connector API version",
            Self::InvalidId => "invalid connector identifier or action",
            Self::DuplicatePlugin => "duplicate or reserved connector identifier",
            Self::Denied => "connector operation is not authorized",
            Self::TargetMismatch => "target does not match the connector driver",
        })
    }
}

impl Error for PluginError {}

fn valid_id(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(b))
}

#[derive(Debug)]
pub struct Registry {
    plugins: BTreeMap<String, PluginDescription>,
}

impl Registry {
    /// Build a complete registry from trusted operator manifests; reject the whole
    /// registry on the first invalid, duplicate or reserved name.
    pub fn new(manifests: Vec<Manifest>) -> Result<Self, PluginError> {
        let mut registry = Self { plugins: BTreeMap::new() };
        registry.insert("gitlab", "read", Some("gitlab"), false, false)?;
        for engine in [DatabaseEngine::Postgresql, DatabaseEngine::Mysql, DatabaseEngine::Sqlserver] {
            registry.insert(engine.name(), "connect", Some(engine.name()), true, false)?;
        }
        registry.insert("database", "connect", None, true, true)?;
        for manifest in manifests {
            if manifest.api_version != API_VERSION {
                return Err(PluginError::UnsupportedVersion);
            }
            let engine = manifest.driver.engine();
            let driver = engine.map_or("https-json", DatabaseEngine::name);
            registry.insert(&manifest.id, &manifest.action, Some(driver), engine.is_some(), false)?;
        }
        Ok(registry)
    }

    fn insert(
        &mut self, id: &str, action: &str, driver: Option<&'static str>, native_stream: bool, legacy: bool,
    ) -> Result<(), PluginError> {
        if !valid_id(id) || !valid_id(action) {
            return Err(PluginError::InvalidId);
        }
        if self.plugins.contains_key(id) {
            return Err(PluginError::DuplicatePlugin);
        }
        self.plugins.insert(id.into(), PluginDescription {
            api_version: API_VERSION, id: id.into(), action: action.into(), driver, native_stream, legacy,
        });
        Ok(())
    }

    /// Stable identifier order; contains no target addresses, credentials, or grants.
    pub fn catalog(&self) -> Vec<PluginDescription> {
        self.plugins.values().cloned().collect()
    }

    /// The caller obtains `grant` from its trusted authorization service. A database
    /// caller obtains `actual_engine` from the very target snapshot it will execute.
    pub fn plan(
        &self,
        request: &Scope,
        grant: &Scope,
        actual_engine: Option<DatabaseEngine>,
    ) -> Result<ExecutionPlan, PluginError> {
        if request != grant || !valid_id(&request.task) || !valid_id(&request.resource) {
            return Err(PluginError::Denied);
        }
        let plugin = self.plugins.get(&request.connector)
            .filter(|plugin| plugin.action == request.action)
            .ok_or(PluginError::Denied)?;
        let driver = match (plugin.driver, actual_engine) {
            (Some(driver), None) if !plugin.native_stream => driver,
            (Some(driver), Some(engine)) if plugin.native_stream && driver == engine.name() => driver,
            (None, Some(engine)) if plugin.legacy => engine.name(),
            _ => return Err(PluginError::TargetMismatch),
        };
        Ok(ExecutionPlan { driver })
    }
}

/// Stable import path for version 1 integrations.
pub mod v1 {
    pub use super::{
        DatabaseEngine, ExecutionPlan, Manifest, ManifestDriver, PluginDescription, PluginError,
        Registry, Scope, API_VERSION,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn scope(connector: &str, action: &str) -> Scope {
        Scope {
            task: "review".into(), connector: connector.into(), action: action.into(), resource: "orders".into(),
        }
    }

    #[test]
    fn manifest_schema_rejects_executable_fields_and_unknown_drivers() {
        let original = json!({"api_version": 1, "id": "warehouse", "action": "query", "driver": "postgresql"});
        for field in ["command", "url", "token_file", "credential", "code", "library"] {
            let mut value = original.clone();
            value[field] = json!("untrusted");
            assert!(serde_json::from_value::<Manifest>(value).is_err());
        }
        for driver in [json!("gitlab"), json!("database"), json!("unknown"), Value::Null, json!(["mysql", "sqlserver"])] {
            let mut value = original.clone();
            value["driver"] = driver;
            assert!(serde_json::from_value::<Manifest>(value).is_err());
        }
        assert!(serde_json::from_str::<Manifest>(
            r#"{"api_version":1,"id":"a","id":"b","action":"get","driver":"https-json"}"#
        ).is_err());
        let mut unknown = original;
        unknown["api_version"] = json!(2);
        assert_eq!(
            Registry::new(vec![serde_json::from_value(unknown).unwrap()]).unwrap_err(),
            PluginError::UnsupportedVersion
        );
    }

    #[test]
    fn manifests_cannot_replace_existing_identifiers() {
        for builtin in ["gitlab", "database", "mysql", "postgresql", "sqlserver"] {
            let m = Manifest::v1(builtin, "read", ManifestDriver::HttpsJson);
            assert_eq!(Registry::new(vec![m]).unwrap_err(), PluginError::DuplicatePlugin);
        }
        let m = Manifest::v1("custom", "query", ManifestDriver::Postgresql);
        let another = Manifest::v1("custom", "open", ManifestDriver::Sqlserver);
        assert_eq!(Registry::new(vec![m, another]).unwrap_err(), PluginError::DuplicatePlugin);
        for bad in ["", "-task", "a/b", "a b", "a\nb"] {
            assert_eq!(
                Registry::new(vec![Manifest::v1(bad, "read", ManifestDriver::Mysql)]).unwrap_err(),
                PluginError::InvalidId
            );
        }
        let m = Manifest::v1("custom", "*", ManifestDriver::Postgresql);
        assert_eq!(Registry::new(vec![m]).unwrap_err(), PluginError::InvalidId);
    }

    #[test]
    fn catalog_and_plan_bind_each_driver_to_one_engine() {
        for (driver, engine) in [
            (ManifestDriver::Postgresql, DatabaseEngine::Postgresql),
            (ManifestDriver::Mysql, DatabaseEngine::Mysql),
            (ManifestDriver::Sqlserver, DatabaseEngine::Sqlserver),
        ] {
            let m = Manifest::v1("warehouse", "open", driver);
            let registry = Registry::new(vec![m]).unwrap();
            let desc = registry.catalog().into_iter().find(|d| d.id == "warehouse").unwrap();
            assert_eq!(
                serde_json::to_value(desc).unwrap(),
                json!({"api_version":1,"id":"warehouse","action":"open","driver":engine.name(),"legacy":false,"native_stream":true})
            );
            for (id, action) in [("warehouse", "open"), (engine.name(), "connect"), ("database", "connect")] {
                let req = scope(id, action);
                assert_eq!(
                    serde_json::to_value(registry.plan(&req, &req, Some(engine)).unwrap()).unwrap(),
                    json!({"driver": engine.name()})
                );
                assert_eq!(registry.plan(&req, &req, None), Err(PluginError::TargetMismatch));
                for other in [DatabaseEngine::Postgresql, DatabaseEngine::Mysql, DatabaseEngine::Sqlserver] {
                    if other != engine && id != "database" {
                        assert_eq!(registry.plan(&req, &req, Some(other)), Err(PluginError::TargetMismatch));
                    }
                }
            }
        }
    }

    #[test]
    fn all_scope_fields_are_exact_and_resource_ids_are_validated() {
        let registry = Registry::new(vec![Manifest::v1("warehouse", "query", ManifestDriver::Mysql)]).unwrap();
        let grant = scope("warehouse", "query");
        for request in [
            Scope { task: "other".into(), ..grant.clone() },
            Scope { connector: "mysql".into(), ..grant.clone() },
            Scope { action: "connect".into(), ..grant.clone() },
            Scope { resource: "other".into(), ..grant.clone() },
        ] {
            assert_eq!(registry.plan(&request, &grant, Some(DatabaseEngine::Mysql)), Err(PluginError::Denied));
        }
        for identity in [
            scope("warehouse", "connect"), scope("unknown", "query"),
            Scope { resource: "*".into(), ..grant.clone() }, Scope { task: "".into(), ..grant.clone() },
        ] {
            assert_eq!(registry.plan(&identity, &identity, Some(DatabaseEngine::Mysql)), Err(PluginError::Denied));
        }
        let new = scope("mysql", "connect");
        let old = scope("database", "connect");
        assert_eq!(registry.plan(&new, &old, Some(DatabaseEngine::Mysql)), Err(PluginError::Denied));
        assert_eq!(registry.plan(&old, &new, Some(DatabaseEngine::Mysql)), Err(PluginError::Denied));
    }

    #[test]
    fn json_plugins_plan_fixed_json_drivers_without_database_targets() {
        let registry = Registry::new(vec![Manifest::v1("team-issues", "read", ManifestDriver::HttpsJson)]).unwrap();
        for (id, driver) in [("gitlab", "gitlab"), ("team-issues", "https-json")] {
            let req = scope(id, "read");
            let desc = registry.catalog().into_iter().find(|d| d.id == id).unwrap();
            assert_eq!(desc.driver, Some(driver));
            assert!(!desc.native_stream && !desc.legacy);
            assert_eq!(registry.plan(&req, &req, None).unwrap().driver, driver);
            assert_eq!(registry.plan(&req, &req, Some(DatabaseEngine::Mysql)), Err(PluginError::TargetMismatch));
        }
    }
}
