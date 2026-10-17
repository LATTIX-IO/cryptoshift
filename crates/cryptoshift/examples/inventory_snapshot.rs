//! Demonstrate an independent, source-attributed offline inventory contract.
use cryptoshift::{
    CollectionCompleteness, CollectionRun, IDENTITY_VERSION, InventorySnapshot, Limits,
    NORMALIZATION_VERSION, ValidatedInventorySnapshot,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = InventorySnapshot {
        identity_version: IDENTITY_VERSION,
        normalization_version: NORMALIZATION_VERSION,
        scope_id: "synthetic-lab".to_owned(),
        runs: vec![CollectionRun {
            id: "fixture-scan-1".to_owned(),
            source_id: "public-example".to_owned(),
            scope_id: "synthetic-lab".to_owned(),
            collected_at_unix_secs: 1,
            completeness: CollectionCompleteness::Partial,
        }],
        evidence: vec![],
        observations: vec![],
        absences: vec![],
    };
    let limits = Limits::default();
    let validated = ValidatedInventorySnapshot::new(snapshot, &limits)?;
    let artifact = validated.export(&limits)?;
    println!("inventory content id: {}", artifact.digest.as_identifier());
    println!("canonical bytes: {}", artifact.bytes.len());
    println!("coverage: partial; absence does not imply safe removal");
    println!("this is not a cryptographic policy or migration-planning decision");
    Ok(())
}
