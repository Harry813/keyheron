//! Emit the manifest for an operator-configured issue summary endpoint.
//! cargo run --example issue_reader --manifest-path rust-core/Cargo.toml

use agent_access_core::plugins::v1::{Manifest, ManifestDriver, Registry, Scope};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = Manifest::v1("team-issues", "read", ManifestDriver::HttpsJson);
    let registry = Registry::new(vec![manifest.clone()])?;

    // Stand-in for a grant retrieved by the trusted Warden for this example.
    let grant = Scope {
        task: "triage".into(),
        connector: "team-issues".into(),
        action: "read".into(),
        resource: "release-blocker".into(),
    };
    let request = grant.clone();
    assert_eq!(registry.plan(&request, &grant, None)?.driver, "https-json");
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
