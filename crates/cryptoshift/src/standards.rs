//! Pinned FIPS algorithm identifiers and separately sourced CNSA 2.0 edition.
//!
//! Recognition of a published parameter set is neither module validation,
//! protocol interoperability, CNSA applicability, nor migration authorization.

use crate::{Diagnostic, DiagnosticCode};

/// Immutable catalog revision for FOSS-430.
pub const STANDARDS_CATALOG_VERSION: u16 = 1;

/// Exact published document editions. Errata or later revisions are not
/// silently adopted by this catalog.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StandardEdition {
    /// NIST FIPS 203 published August 13, 2024.
    Fips203_2024,
    /// NIST FIPS 204 published August 13, 2024.
    Fips204_2024,
    /// NIST FIPS 205 published August 13, 2024.
    Fips205_2024,
    /// NSA CNSA Suite 2.0 cybersecurity advisory, September 2022 v1.0.
    Cnsa20_2022v1,
}

impl StandardEdition {
    /// Stable edition identifier for signed/external provenance crosswalks.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Fips203_2024 => "NIST-FIPS-203:2024-08-13",
            Self::Fips204_2024 => "NIST-FIPS-204:2024-08-13",
            Self::Fips205_2024 => "NIST-FIPS-205:2024-08-13",
            Self::Cnsa20_2022v1 => "NSA-CNSA-2.0:2022-v1.0",
        }
    }

    /// Authoritative publication landing page, not live-fetched at runtime.
    #[must_use]
    pub const fn source_url(self) -> &'static str {
        match self {
            Self::Fips203_2024 => "https://csrc.nist.gov/pubs/fips/203/final",
            Self::Fips204_2024 => "https://csrc.nist.gov/pubs/fips/204/final",
            Self::Fips205_2024 => "https://csrc.nist.gov/pubs/fips/205/final",
            Self::Cnsa20_2022v1 => {
                "https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/nsa-releases-future-quantum-resistant-qr-algorithm-requirements-for-national-se/"
            }
        }
    }

    /// Exact, case-sensitive supported edition lookup.
    pub fn parse_exact(value: &str) -> Result<Self, Diagnostic> {
        match value {
            "NIST-FIPS-203:2024-08-13" => Ok(Self::Fips203_2024),
            "NIST-FIPS-204:2024-08-13" => Ok(Self::Fips204_2024),
            "NIST-FIPS-205:2024-08-13" => Ok(Self::Fips205_2024),
            "NSA-CNSA-2.0:2022-v1.0" => Ok(Self::Cnsa20_2022v1),
            _ => Err(Diagnostic::new(
                DiagnosticCode::UnsupportedSchemaVersion,
                "standards_edition",
                "unrecognized or unreviewed standards edition",
            )),
        }
    }
}

/// Cryptographic operation family; a signature cannot substitute for a KEM.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AlgorithmRole {
    /// Key encapsulation/establishment algorithm.
    KeyEncapsulation,
    /// Digital-signature algorithm.
    Signature,
}

/// NIST security *category*, not bits of effective application security.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SecurityCategory {
    /// NIST security category one.
    One = 1,
    /// NIST security category three.
    Three = 3,
    /// NIST security category five.
    Five = 5,
}

/// Exact FIPS 203/204/205 parameter-set identifiers.
///
/// No Kyber/Dilithium/SPHINCS+ aliases, custom suites or vendor marketing
/// names are silently normalized into official identifiers.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KnownAlgorithm {
    /// FIPS 203 ML-KEM, NIST category one.
    MlKem512,
    /// FIPS 203 ML-KEM, NIST category three.
    MlKem768,
    /// FIPS 203 ML-KEM, NIST category five.
    MlKem1024,
    /// FIPS 204 ML-DSA, NIST category one.
    MlDsa44,
    /// FIPS 204 ML-DSA, NIST category three.
    MlDsa65,
    /// FIPS 204 ML-DSA, NIST category five.
    MlDsa87,
    /// FIPS 205 SHA2 parameter set 128s.
    SlhDsaSha2_128s,
    /// FIPS 205 SHA2 parameter set 128f.
    SlhDsaSha2_128f,
    /// FIPS 205 SHA2 parameter set 192s.
    SlhDsaSha2_192s,
    /// FIPS 205 SHA2 parameter set 192f.
    SlhDsaSha2_192f,
    /// FIPS 205 SHA2 parameter set 256s.
    SlhDsaSha2_256s,
    /// FIPS 205 SHA2 parameter set 256f.
    SlhDsaSha2_256f,
    /// FIPS 205 SHAKE parameter set 128s.
    SlhDsaShake128s,
    /// FIPS 205 SHAKE parameter set 128f.
    SlhDsaShake128f,
    /// FIPS 205 SHAKE parameter set 192s.
    SlhDsaShake192s,
    /// FIPS 205 SHAKE parameter set 192f.
    SlhDsaShake192f,
    /// FIPS 205 SHAKE parameter set 256s.
    SlhDsaShake256s,
    /// FIPS 205 SHAKE parameter set 256f.
    SlhDsaShake256f,
}

impl KnownAlgorithm {
    /// All 18 pinned FIPS parameter-set identifiers in stable catalog order.
    pub const ALL: [Self; 18] = [
        Self::MlKem512,
        Self::MlKem768,
        Self::MlKem1024,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
        Self::SlhDsaSha2_128s,
        Self::SlhDsaSha2_128f,
        Self::SlhDsaSha2_192s,
        Self::SlhDsaSha2_192f,
        Self::SlhDsaSha2_256s,
        Self::SlhDsaSha2_256f,
        Self::SlhDsaShake128s,
        Self::SlhDsaShake128f,
        Self::SlhDsaShake192s,
        Self::SlhDsaShake192f,
        Self::SlhDsaShake256s,
        Self::SlhDsaShake256f,
    ];

    /// Normative, case-sensitive FIPS parameter-set ID.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Self::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Self::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Self::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Self::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            Self::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Self::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            Self::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            Self::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            Self::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            Self::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Self::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Identity-preserving exact parser. Unknown/aliases are rejected.
    pub fn parse_exact(value: &str) -> Result<Self, Diagnostic> {
        Self::ALL
            .iter()
            .copied()
            .find(|known| known.id() == value)
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCode::InvalidReference,
                    "algorithm_id",
                    "unsupported or unrecognized exact FIPS parameter-set identifier",
                )
            })
    }

    /// FIPS document containing the parameter set.
    #[must_use]
    pub const fn standard(self) -> StandardEdition {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => StandardEdition::Fips203_2024,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => StandardEdition::Fips204_2024,
            _ => StandardEdition::Fips205_2024,
        }
    }

    /// Valid cryptographic role for the exact parameter set.
    #[must_use]
    pub const fn role(self) -> AlgorithmRole {
        match self.standard() {
            StandardEdition::Fips203_2024 => AlgorithmRole::KeyEncapsulation,
            _ => AlgorithmRole::Signature,
        }
    }

    /// NIST security category associated with the exact parameter set.
    #[must_use]
    pub const fn category(self) -> SecurityCategory {
        match self {
            Self::MlKem512
            | Self::MlDsa44
            | Self::SlhDsaSha2_128s
            | Self::SlhDsaSha2_128f
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f => SecurityCategory::One,
            Self::MlKem768
            | Self::MlDsa65
            | Self::SlhDsaSha2_192s
            | Self::SlhDsaSha2_192f
            | Self::SlhDsaShake192s
            | Self::SlhDsaShake192f => SecurityCategory::Three,
            _ => SecurityCategory::Five,
        }
    }

    /// Whether this selected *asymmetric* parameter set belongs to the
    /// general-purpose CNSA 2.0 subset represented by this contract.
    ///
    /// A true result establishes neither overall CNSA compliance nor the
    /// applicability of CNSA to a particular system or protocol.
    #[must_use]
    pub const fn cnsa20_general_purpose(self) -> bool {
        matches!(self, Self::MlKem1024 | Self::MlDsa87)
    }
}
