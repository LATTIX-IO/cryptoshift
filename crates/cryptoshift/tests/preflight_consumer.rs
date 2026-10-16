//! Clean Rust consumer exercising the public preflight-only API.

use cryptoshift::{
    CriticalProfileReference, DiagnosticCode, Limits, ParseBudget, ResourceKind, SchemaKind,
    SchemaVersion, VersionedEnvelope,
};

#[test]
fn external_consumer_can_reject_untrusted_envelope() {
    let refs = [CriticalProfileReference {
        id: "sector-profile",
        kind: SchemaKind::TargetProfile,
        version: SchemaVersion::V1_0,
        source_id: "untrusted-catalog",
        expires_at_unix_secs: Some(300),
    }];
    let mut document = VersionedEnvelope {
        schema: SchemaKind::InventorySnapshot,
        version: SchemaVersion::V1_0,
        payload: b"{\"assets\":[]}",
        source_id: "collector-test",
        critical_profiles: &refs,
    };
    let limits = Limits::default();
    let checked = document.preflight(&limits, 100);
    assert!(checked.is_ok());
    document.version = SchemaVersion { major: 2, minor: 0 };
    let rejected = document.preflight(&limits, 100);
    assert!(rejected.is_err_and(|err| err.code == DiagnosticCode::UnsupportedSchemaVersion));
}

#[test]
fn external_parser_can_charge_structure_and_bytes_before_allocating() {
    let limits = Limits {
        max_input_bytes: 64,
        max_parse_tokens: 2,
        max_parse_depth: 2,
        ..Limits::default()
    };
    assert!(limits.check(ResourceKind::InputBytes, 64).is_ok());
    assert!(limits.check(ResourceKind::InputBytes, 65).is_err());
    let result = ParseBudget::new(limits);
    assert!(result.is_ok());
    if let Ok(mut budget) = result {
        assert!(budget.record(1, 1).is_ok());
        assert!(budget.record(2, 1).is_ok());
        assert!(budget.record(3, 1).is_err());
        assert_eq!(budget.visited(), 2);
    }
}
