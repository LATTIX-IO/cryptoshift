//! Demonstrates admitting bounded metadata without claiming payload validity.

use cryptoshift::{CriticalProfileReference, Limits, SchemaKind, SchemaVersion, VersionedEnvelope};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let referenced = [CriticalProfileReference {
        id: "synthetic-standards-fixture",
        kind: SchemaKind::StandardsProfile,
        version: SchemaVersion::V1_0,
        source_id: "local-public-test",
        expires_at_unix_secs: Some(2_000_000_000),
    }];
    let envelope = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: br#"{"records":[]}"#,
        source_id: "synthetic-inventory",
        critical_profiles: &referenced,
    };
    let admitted = envelope.preflight(&Limits::default(), 1_900_000_000)?;
    admitted.preflight_json_nesting(&Limits::default())?;
    println!(
        "Preflight OK: {} bytes for {}; payload semantics NOT validated",
        admitted.unparsed_payload().len(),
        admitted.schema().as_str()
    );
    Ok(())
}
