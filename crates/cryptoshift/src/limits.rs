//! Shared bounded-processing contract for every analysis phase.

use crate::diagnostic::{Diagnostic, DiagnosticCode};

/// A metered dimension of untrusted processing or plan generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResourceKind {
    /// Bytes supplied to a future format adapter.
    InputBytes,
    /// Number of distinct graph nodes.
    GraphNodes,
    /// Number of directed graph edges.
    GraphEdges,
    /// Number of evidence records.
    EvidenceRecords,
    /// Number of referenced critical profiles.
    ProfileReferences,
    /// Maximum nested container depth while parsing a structured document.
    ParseDepth,
    /// Number of parsed values/tokens, including containers.
    ParseTokens,
    /// Number of candidates explored while planning.
    PlannerCandidates,
    /// Number of generated remediation actions.
    PlanActions,
    /// Number of generated migration waves.
    PlanWaves,
    /// Number of emitted diagnostics.
    Diagnostics,
    /// Number of bytes in a generated export.
    ExportBytes,
}

impl ResourceKind {
    const ALL: [Self; 12] = [
        Self::InputBytes,
        Self::GraphNodes,
        Self::GraphEdges,
        Self::EvidenceRecords,
        Self::ProfileReferences,
        Self::ParseDepth,
        Self::ParseTokens,
        Self::PlannerCandidates,
        Self::PlanActions,
        Self::PlanWaves,
        Self::Diagnostics,
        Self::ExportBytes,
    ];

    /// Stable metric name that never includes untrusted input content.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::GraphNodes => "graph_nodes",
            Self::GraphEdges => "graph_edges",
            Self::EvidenceRecords => "evidence_records",
            Self::ProfileReferences => "profile_references",
            Self::ParseDepth => "parse_depth",
            Self::ParseTokens => "parse_tokens",
            Self::PlannerCandidates => "planner_candidates",
            Self::PlanActions => "plan_actions",
            Self::PlanWaves => "plan_waves",
            Self::Diagnostics => "diagnostics",
            Self::ExportBytes => "export_bytes",
        }
    }

    /// Hard compile-time ceiling, including for caller-configured limits.
    #[must_use]
    pub const fn ceiling(self) -> usize {
        match self {
            Self::InputBytes => 64 * 1024 * 1024,
            Self::GraphNodes => 1_000_000,
            Self::GraphEdges => 4_000_000,
            Self::EvidenceRecords => 4_000_000,
            Self::ProfileReferences => 65_536,
            Self::ParseDepth => 128,
            Self::ParseTokens => 4_000_000,
            Self::PlannerCandidates => 1_000_000,
            Self::PlanActions => 1_000_000,
            Self::PlanWaves => 100_000,
            Self::Diagnostics => 65_536,
            Self::ExportBytes => 128 * 1024 * 1024,
        }
    }
}

/// Bounded-analysis limits shared across import, graph, planning, and export.
///
/// All limits must be greater than zero and at or below their hard ceiling.
/// Configured values are validated before use, including after modification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum bytes accepted for one imported document.
    pub max_input_bytes: usize,
    /// Maximum graph nodes.
    pub max_graph_nodes: usize,
    /// Maximum graph edges.
    pub max_graph_edges: usize,
    /// Maximum attached evidence records.
    pub max_evidence_records: usize,
    /// Maximum required profile references per envelope.
    pub max_profile_references: usize,
    /// Maximum nested parse-container depth.
    pub max_parse_depth: usize,
    /// Maximum parsed tokens/values.
    pub max_parse_tokens: usize,
    /// Maximum transition candidate evaluations.
    pub max_planner_candidates: usize,
    /// Maximum generated actions.
    pub max_plan_actions: usize,
    /// Maximum generated waves.
    pub max_plan_waves: usize,
    /// Maximum diagnostics in an analysis result.
    pub max_diagnostics: usize,
    /// Maximum serialized export bytes.
    pub max_export_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 4 * 1024 * 1024,
            max_graph_nodes: 50_000,
            max_graph_edges: 250_000,
            max_evidence_records: 250_000,
            max_profile_references: 4096,
            max_parse_depth: 32,
            max_parse_tokens: 250_000,
            max_planner_candidates: 20_000,
            max_plan_actions: 20_000,
            max_plan_waves: 4096,
            max_diagnostics: 4096,
            max_export_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Configured limit for one metered resource.
    #[must_use]
    pub const fn get(&self, resource: ResourceKind) -> usize {
        match resource {
            ResourceKind::InputBytes => self.max_input_bytes,
            ResourceKind::GraphNodes => self.max_graph_nodes,
            ResourceKind::GraphEdges => self.max_graph_edges,
            ResourceKind::EvidenceRecords => self.max_evidence_records,
            ResourceKind::ProfileReferences => self.max_profile_references,
            ResourceKind::ParseDepth => self.max_parse_depth,
            ResourceKind::ParseTokens => self.max_parse_tokens,
            ResourceKind::PlannerCandidates => self.max_planner_candidates,
            ResourceKind::PlanActions => self.max_plan_actions,
            ResourceKind::PlanWaves => self.max_plan_waves,
            ResourceKind::Diagnostics => self.max_diagnostics,
            ResourceKind::ExportBytes => self.max_export_bytes,
        }
    }

    /// Reject zero/oversized limits before any resource-intensive processing.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        for resource in ResourceKind::ALL {
            let bound = self.get(resource);
            if bound == 0 || bound > resource.ceiling() {
                return Err(Diagnostic::with_numbers(
                    DiagnosticCode::InvalidLimit,
                    resource.as_str(),
                    "limit must be positive and no greater than its hard ceiling",
                    bound,
                    resource.ceiling(),
                ));
            }
        }
        Ok(())
    }

    /// Ensure a requested count fits the active validated resource budget.
    pub fn check(&self, resource: ResourceKind, observed: usize) -> Result<(), Diagnostic> {
        self.validate()?;
        let maximum = self.get(resource);
        if observed > maximum {
            return Err(Diagnostic::with_numbers(
                DiagnosticCode::ResourceLimitExceeded,
                resource.as_str(),
                "resource demand exceeds configured limit",
                observed,
                maximum,
            ));
        }
        Ok(())
    }

    /// Add counters without overflow, then enforce the target resource limit.
    pub fn checked_add(
        &self,
        resource: ResourceKind,
        lhs: usize,
        rhs: usize,
    ) -> Result<usize, Diagnostic> {
        let sum = lhs.checked_add(rhs).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCode::ArithmeticOverflow,
                resource.as_str(),
                "resource counter addition overflowed",
            )
        })?;
        self.check(resource, sum)?;
        Ok(sum)
    }

    /// Multiply counters without overflow, then enforce the resource limit.
    pub fn checked_mul(
        &self,
        resource: ResourceKind,
        lhs: usize,
        rhs: usize,
    ) -> Result<usize, Diagnostic> {
        let product = lhs.checked_mul(rhs).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticCode::ArithmeticOverflow,
                resource.as_str(),
                "resource counter multiplication overflowed",
            )
        })?;
        self.check(resource, product)?;
        Ok(product)
    }
}

/// Incremental parser budget to meter values before building large structures.
///
/// Call `record` before allocating each structured value; callers must also
/// validate the actual input format, identifiers, and semantics. This counter
/// is not a JSON/XML parser and cannot validate bytes by itself.
#[derive(Clone, Debug)]
pub struct ParseBudget {
    limits: Limits,
    visited: usize,
}

impl ParseBudget {
    /// Build an empty counter, rejecting an invalid limit configuration.
    pub fn new(limits: Limits) -> Result<Self, Diagnostic> {
        limits.validate()?;
        Ok(Self { limits, visited: 0 })
    }

    /// Charge one or more values observed at a given one-based depth.
    pub fn record(&mut self, depth: usize, count: usize) -> Result<(), Diagnostic> {
        if depth == 0 {
            return Err(Diagnostic::new(
                DiagnosticCode::MalformedStructure,
                "parse_depth",
                "parser value depth must be one-based",
            ));
        }
        self.limits.check(ResourceKind::ParseDepth, depth)?;
        let next = self
            .limits
            .checked_add(ResourceKind::ParseTokens, self.visited, count)?;
        self.visited = next;
        Ok(())
    }

    /// Number of values charged so far.
    #[must_use]
    pub const fn visited(&self) -> usize {
        self.visited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_ceiled() {
        let limits = Limits::default();
        assert!(limits.validate().is_ok());
        for resource in ResourceKind::ALL {
            assert!(limits.get(resource) <= resource.ceiling());
            assert!(limits.check(resource, limits.get(resource)).is_ok());
            assert!(matches!(
                limits.check(resource, limits.get(resource) + 1),
                Err(Diagnostic {
                    code: DiagnosticCode::ResourceLimitExceeded,
                    ..
                })
            ));
        }
    }

    #[test]
    fn zero_and_above_ceiling_are_invalid() {
        let mut limits = Limits::default();
        limits.max_graph_nodes = 0;
        assert!(matches!(
            limits.validate(),
            Err(Diagnostic {
                code: DiagnosticCode::InvalidLimit,
                ..
            })
        ));
        limits.max_graph_nodes = ResourceKind::GraphNodes.ceiling() + 1;
        assert!(matches!(
            limits.validate(),
            Err(Diagnostic {
                code: DiagnosticCode::InvalidLimit,
                ..
            })
        ));
    }

    #[test]
    fn overflow_is_not_a_zero_or_saturated_count() {
        let limits = Limits::default();
        assert!(matches!(
            limits.checked_add(ResourceKind::GraphEdges, usize::MAX, 1),
            Err(Diagnostic {
                code: DiagnosticCode::ArithmeticOverflow,
                ..
            })
        ));
        assert!(matches!(
            limits.checked_mul(ResourceKind::GraphNodes, usize::MAX, 2),
            Err(Diagnostic {
                code: DiagnosticCode::ArithmeticOverflow,
                ..
            })
        ));
    }

    #[test]
    fn parser_budget_rejects_nesting_and_does_not_advance_after_failure() {
        let limits = Limits {
            max_parse_depth: 3,
            max_parse_tokens: 2,
            ..Limits::default()
        };
        let result = ParseBudget::new(limits);
        assert!(result.is_ok());
        if let Ok(mut budget) = result {
            assert!(matches!(
                budget.record(0, 1),
                Err(Diagnostic {
                    code: DiagnosticCode::MalformedStructure,
                    ..
                })
            ));
            assert!(budget.record(1, 1).is_ok());
            assert!(matches!(
                budget.record(4, 1),
                Err(Diagnostic {
                    code: DiagnosticCode::ResourceLimitExceeded,
                    ..
                })
            ));
            assert_eq!(budget.visited(), 1);
            assert!(budget.record(2, 1).is_ok());
            assert!(budget.record(2, 1).is_err());
            assert_eq!(budget.visited(), 2);
        }
    }

    #[test]
    fn limits_reject_attack_like_count_sequence() {
        let limits = Limits {
            max_parse_tokens: 1024,
            ..Limits::default()
        };
        let mut budget = match ParseBudget::new(limits) {
            Ok(b) => b,
            Err(d) => panic!("unexpected invalid fixture: {d}"),
        };
        let mut state = 0x9e37_79b9_u32;
        let mut accepted = 0_usize;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let n = (state as usize % 7) + 1;
            if budget.record(1, n).is_ok() {
                accepted += n;
            }
            assert!(budget.visited() <= 1024);
        }
        assert_eq!(accepted, budget.visited());
    }
}
