use super::{
    CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES, ElectricalPolicy, ElectricalReview,
    SchematicDocument, SimulationEvidence, check_schematic, electrical_policy_json_schema,
    electrical_review_json_schema, schematic_json_schema, simulation_evidence_json_schema,
    validate_simulation_evidence,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;

const MAX_REQUIREMENTS: usize = 1_000;
const MAX_RISKS: usize = 1_000;
const MAX_EVIDENCE_REFS: usize = 10_000;
const AI_REVIEW_PLAN_SOURCE_MAX_BYTES: u64 = 4 * 1024 * 1024;
// The deterministic runner reserves one byte while serializing its report,
// then publishes one final newline; the retained report is therefore bounded
// by the full shared 128 MiB limit.
const AI_REVIEW_REPORT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const AI_REVIEW_NATIVE_KICAD_ERC_REPORT_MAX_BYTES: u64 = 32 * 1024 * 1024;
const SIGNATURE_DOMAIN: &str = "pcbex-ai-schematic-approval-v1";
const SESSION_SIGNATURE_DOMAIN: &str = "pcbex-ai-schematic-approval-session-v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequirement {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalPolicy {
    pub require_simulation_evidence: bool,
}

/// Exact bytes and the digest of one retained artifact.
///
/// Paths are intentionally not part of this identity.  A path is an
/// operational location, while the bytes and digest are what the approval
/// must cryptographically bind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactIdentity {
    pub bytes: u64,
    pub sha256: String,
}

/// The deterministic pipeline inputs and retained report bound to a review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicPipelineIdentity {
    pub plan_source: ExactArtifactIdentity,
    pub plan_sha256: String,
    pub report: ExactArtifactIdentity,
    pub run_sha256: String,
}

/// The retained native KiCad ERC report and the deterministic native run that
/// produced it.  The report identity is deliberately separate from the
/// deterministic-pipeline report: native ERC is an additional, independently
/// reproducible evidence source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKicadErcIdentity {
    pub schema_version: u32,
    pub report: ExactArtifactIdentity,
    pub run_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeKicadErcIdentityWire {
    schema_version: u32,
    report: ExactArtifactIdentity,
    run_sha256: String,
}

impl<'de> Deserialize<'de> for NativeKicadErcIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NativeKicadErcIdentityWire::deserialize(deserializer)?;
        if !matches!(wire.schema_version, 1 | 2) {
            return Err(D::Error::custom(format!(
                "unsupported native KiCad ERC identity schema version {}",
                wire.schema_version
            )));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            report: wire.report,
            run_sha256: wire.run_sha256,
        })
    }
}

/// Artifact identities covered by an AI schematic review request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewArtifactBinding {
    pub schema_version: u32,
    pub generated_schematic: ExactArtifactIdentity,
    pub pipeline: DeterministicPipelineIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_kicad_erc: Option<NativeKicadErcIdentity>,
}

#[derive(Default)]
enum NativeKicadErcField {
    #[default]
    Missing,
    Null,
    Identity(NativeKicadErcIdentity),
}

impl<'de> Deserialize<'de> for NativeKicadErcField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NativeKicadErcFieldVisitor;

        impl<'de> Visitor<'de> for NativeKicadErcFieldVisitor {
            type Value = NativeKicadErcField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a native KiCad ERC identity object")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(NativeKicadErcField::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(NativeKicadErcField::Null)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                NativeKicadErcIdentity::deserialize(deserializer).map(NativeKicadErcField::Identity)
            }
        }

        deserializer.deserialize_option(NativeKicadErcFieldVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiReviewArtifactBindingWire {
    schema_version: u32,
    generated_schematic: ExactArtifactIdentity,
    pipeline: DeterministicPipelineIdentity,
    #[serde(default)]
    native_kicad_erc: NativeKicadErcField,
}

impl<'de> Deserialize<'de> for AiReviewArtifactBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AiReviewArtifactBindingWire::deserialize(deserializer)?;
        let native_kicad_erc = match (wire.schema_version, wire.native_kicad_erc) {
            (1, NativeKicadErcField::Missing) => None,
            (1, NativeKicadErcField::Null | NativeKicadErcField::Identity(_)) => {
                return Err(D::Error::custom(
                    "AI review artifact binding schema version 1 must not contain native_kicad_erc",
                ));
            }
            (2, NativeKicadErcField::Identity(identity)) if identity.schema_version == 1 => {
                Some(identity)
            }
            (2, NativeKicadErcField::Identity(identity)) => {
                return Err(D::Error::custom(format!(
                    "AI review artifact binding schema version 2 requires native KiCad ERC identity schema version 1, got {}",
                    identity.schema_version
                )));
            }
            (2, NativeKicadErcField::Missing | NativeKicadErcField::Null) => {
                return Err(D::Error::custom(
                    "AI review artifact binding schema version 2 requires native_kicad_erc",
                ));
            }
            (3, NativeKicadErcField::Identity(identity)) if identity.schema_version == 2 => {
                Some(identity)
            }
            (3, NativeKicadErcField::Identity(identity)) => {
                return Err(D::Error::custom(format!(
                    "AI review artifact binding schema version 3 requires native KiCad ERC identity schema version 2, got {}",
                    identity.schema_version
                )));
            }
            (3, NativeKicadErcField::Missing | NativeKicadErcField::Null) => {
                return Err(D::Error::custom(
                    "AI review artifact binding schema version 3 requires native_kicad_erc",
                ));
            }
            (version, _) => {
                return Err(D::Error::custom(format!(
                    "unsupported AI review artifact binding schema version {version}"
                )));
            }
        };
        Ok(Self {
            schema_version: wire.schema_version,
            generated_schematic: wire.generated_schematic,
            pipeline: wire.pipeline,
            native_kicad_erc,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewRequest {
    pub schema_version: u32,
    pub request_sha256: String,
    pub schematic: SchematicDocument,
    pub electrical_policy: ElectricalPolicy,
    pub electrical_review: ElectricalReview,
    pub electrical_review_sha256: String,
    pub simulation_evidence: Vec<SimulationEvidence>,
    pub requirements: Vec<AiRequirement>,
    pub evidence_ids: Vec<String>,
    pub approval_policy: AiApprovalPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<AiReviewArtifactBinding>,
}

#[derive(Default)]
enum ArtifactBindingField {
    #[default]
    Missing,
    Null,
    Binding(Box<AiReviewArtifactBinding>),
}

impl<'de> Deserialize<'de> for ArtifactBindingField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ArtifactBindingFieldVisitor;

        impl<'de> Visitor<'de> for ArtifactBindingFieldVisitor {
            type Value = ArtifactBindingField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an AI review artifact binding object")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ArtifactBindingField::Null)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ArtifactBindingField::Null)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                AiReviewArtifactBinding::deserialize(deserializer)
                    .map(Box::new)
                    .map(ArtifactBindingField::Binding)
            }
        }

        deserializer.deserialize_option(ArtifactBindingFieldVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiReviewRequestWire {
    schema_version: u32,
    request_sha256: String,
    schematic: SchematicDocument,
    electrical_policy: ElectricalPolicy,
    electrical_review: ElectricalReview,
    electrical_review_sha256: String,
    simulation_evidence: Vec<SimulationEvidence>,
    requirements: Vec<AiRequirement>,
    evidence_ids: Vec<String>,
    approval_policy: AiApprovalPolicy,
    #[serde(default)]
    artifact_binding: ArtifactBindingField,
}

impl<'de> Deserialize<'de> for AiReviewRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AiReviewRequestWire::deserialize(deserializer)?;
        let artifact_binding = match wire.artifact_binding {
            ArtifactBindingField::Missing => None,
            ArtifactBindingField::Binding(binding) => Some(*binding),
            ArtifactBindingField::Null => {
                return Err(D::Error::custom(
                    "AI review request artifact_binding must be an object when present",
                ));
            }
        };
        Ok(Self {
            schema_version: wire.schema_version,
            request_sha256: wire.request_sha256,
            schematic: wire.schematic,
            electrical_policy: wire.electrical_policy,
            electrical_review: wire.electrical_review,
            electrical_review_sha256: wire.electrical_review_sha256,
            simulation_evidence: wire.simulation_evidence,
            requirements: wire.requirements,
            evidence_ids: wire.evidence_ids,
            approval_policy: wire.approval_policy,
            artifact_binding,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiReviewDecision {
    Approve,
    Reject,
    NeedsHuman,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiRequirementStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiRiskSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiModelIdentity {
    pub provider: String,
    pub model: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequirementAssessment {
    pub id: String,
    pub status: AiRequirementStatus,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRisk {
    pub id: String,
    pub severity: AiRiskSeverity,
    pub title: String,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewResponse {
    pub schema_version: u32,
    pub request_sha256: String,
    pub model: AiModelIdentity,
    pub decision: AiReviewDecision,
    pub summary: String,
    pub requirements: Vec<AiRequirementAssessment>,
    pub risks: Vec<AiRisk>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAiApproval {
    pub schema_version: u32,
    pub request_sha256: String,
    pub response_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_sha256: Option<String>,
    pub approved: bool,
    pub gate_failures: Vec<String>,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ApprovalPayload<'a> {
    domain: &'static str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    approved: bool,
    gate_failures: &'a [String],
    signer_id: &'a str,
}

#[derive(Serialize)]
struct SessionApprovalPayload<'a> {
    domain: &'static str,
    session_sha256: &'a str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    approved: bool,
    gate_failures: &'a [String],
    signer_id: &'a str,
}

pub fn build_ai_review_request(
    schematic: SchematicDocument,
    policy: &ElectricalPolicy,
    electrical_review: ElectricalReview,
    electrical_review_sha256: String,
    mut simulation_evidence: Vec<SimulationEvidence>,
    mut requirements: Vec<AiRequirement>,
    require_simulation_evidence: bool,
) -> Result<AiReviewRequest, String> {
    validate_sha256(&electrical_review_sha256, "electrical review SHA-256")?;
    let recomputed = check_schematic(&schematic, policy)?;
    if recomputed != electrical_review {
        return Err(
            "electrical review does not match a fresh review of the supplied schematic and policy"
                .into(),
        );
    }
    validate_requirements(&requirements)?;
    requirements.sort_by(|left, right| left.id.cmp(&right.id));

    if simulation_evidence.len() > MAX_REQUIREMENTS {
        return Err(format!(
            "AI review exceeds the {MAX_REQUIREMENTS} simulation-evidence limit"
        ));
    }
    let mut simulation_ids = BTreeSet::new();
    for evidence in &simulation_evidence {
        validate_simulation_evidence(evidence)?;
        if evidence.schematic_sha256 != electrical_review.schematic_sha256 {
            return Err(format!(
                "simulation evidence {} is bound to a different schematic",
                evidence.id
            ));
        }
        if evidence.electrical_review_sha256 != electrical_review_sha256 {
            return Err(format!(
                "simulation evidence {} is bound to a different electrical review",
                evidence.id
            ));
        }
        if !simulation_ids.insert(evidence.id.clone()) {
            return Err(format!("duplicate simulation evidence id {}", evidence.id));
        }
    }
    simulation_evidence.sort_by(|left, right| left.id.cmp(&right.id));

    let evidence_ids = expected_evidence_ids(&schematic, &electrical_review, &simulation_evidence);
    let mut request = AiReviewRequest {
        schema_version: 1,
        request_sha256: String::new(),
        schematic,
        electrical_policy: policy.clone(),
        electrical_review,
        electrical_review_sha256,
        simulation_evidence,
        requirements,
        evidence_ids,
        approval_policy: AiApprovalPolicy {
            require_simulation_evidence,
        },
        artifact_binding: None,
    };
    request.request_sha256 = request_body_sha256(&request)?;
    Ok(request)
}

/// Add an exact generated-schematic and deterministic-pipeline binding to a
/// valid v1 request, producing a v2 request with a fresh body digest.
///
/// The generic `Borrow` parameter accepts either an owned binding or a shared
/// reference while always cloning it into the returned request.
pub fn bind_ai_review_request<B>(
    request: &AiReviewRequest,
    binding: B,
) -> Result<AiReviewRequest, String>
where
    B: Borrow<AiReviewArtifactBinding>,
{
    if request.schema_version != 1 || request.artifact_binding.is_some() {
        return Err("only an unbound AI review request schema version 1 can be bound".into());
    }
    ai_review_request_sha256(request)?;
    let binding = binding.borrow();
    if binding.schema_version != 1 || binding.native_kicad_erc.is_some() {
        return Err(
            "legacy AI review binding requires artifact binding schema version 1 without native evidence"
                .into(),
        );
    }
    validate_artifact_binding(binding)?;

    let mut bound = request.clone();
    bound.schema_version = 2;
    bound.artifact_binding = Some(binding.clone());
    bound.request_sha256.clear();
    bound.request_sha256 = request_body_sha256(&bound)?;
    Ok(bound)
}

/// Add an exact native KiCad ERC identity to a valid v2 request, producing a
/// v3 request with a fresh body digest.  The legacy binder intentionally
/// remains v1 -> v2 only so callers cannot silently upgrade a request without
/// supplying the native evidence identity.
pub fn bind_native_kicad_erc_to_ai_review_request<B>(
    request: &AiReviewRequest,
    native_kicad_erc: B,
) -> Result<AiReviewRequest, String>
where
    B: Borrow<NativeKicadErcIdentity>,
{
    if request.schema_version != 2 {
        return Err(
            "only an AI review request schema version 2 can be bound to native KiCad ERC".into(),
        );
    }
    let binding = request
        .artifact_binding
        .as_ref()
        .ok_or_else(|| "schema version 2 requires an artifact binding".to_owned())?;
    if binding.schema_version != 1 || binding.native_kicad_erc.is_some() {
        return Err(
            "native KiCad ERC binding requires an artifact binding schema version 1 without native evidence"
                .into(),
        );
    }
    ai_review_request_sha256(request)?;
    let native_kicad_erc = native_kicad_erc.borrow();
    validate_native_kicad_erc_identity(native_kicad_erc)?;
    if native_kicad_erc.schema_version != 1 {
        return Err(
            "native KiCad ERC request schema version 3 requires native identity schema version 1"
                .into(),
        );
    }

    let mut bound = request.clone();
    let mut binding = binding.clone();
    binding.schema_version = 2;
    binding.native_kicad_erc = Some(native_kicad_erc.clone());
    bound.schema_version = 3;
    bound.artifact_binding = Some(binding);
    bound.request_sha256.clear();
    bound.request_sha256 = request_body_sha256(&bound)?;
    Ok(bound)
}

/// Add a native KiCad ERC warning-policy identity to a valid v2 request,
/// producing a v4 request with a fresh body digest.
///
/// The v2 base request is intentional: a caller must choose whether it is
/// binding the legacy error-only native evidence (identity v1/request v3) or
/// the warning-policy evidence (identity v2/request v4).  In particular, a
/// v3 request can never be silently upgraded or downgraded by this helper.
pub fn bind_native_kicad_erc_warning_policy_to_ai_review_request<B>(
    request: &AiReviewRequest,
    native_kicad_erc: B,
) -> Result<AiReviewRequest, String>
where
    B: Borrow<NativeKicadErcIdentity>,
{
    if request.schema_version != 2 {
        return Err(
            "only an AI review request schema version 2 can be bound to native KiCad ERC warning-policy evidence"
                .into(),
        );
    }
    let binding = request
        .artifact_binding
        .as_ref()
        .ok_or_else(|| "schema version 2 requires an artifact binding".to_owned())?;
    if binding.schema_version != 1 || binding.native_kicad_erc.is_some() {
        return Err(
            "native KiCad ERC warning-policy binding requires an artifact binding schema version 1 without native evidence"
                .into(),
        );
    }
    ai_review_request_sha256(request)?;
    let native_kicad_erc = native_kicad_erc.borrow();
    validate_native_kicad_erc_identity(native_kicad_erc)?;
    if native_kicad_erc.schema_version != 2 {
        return Err(
            "native KiCad ERC warning-policy request schema version 4 requires native identity schema version 2"
                .into(),
        );
    }

    let mut bound = request.clone();
    let mut binding = binding.clone();
    binding.schema_version = 3;
    binding.native_kicad_erc = Some(native_kicad_erc.clone());
    bound.schema_version = 4;
    bound.artifact_binding = Some(binding);
    bound.request_sha256.clear();
    bound.request_sha256 = request_body_sha256(&bound)?;
    Ok(bound)
}

pub fn parse_ai_review_response(source: &str) -> Result<AiReviewResponse, String> {
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("invalid AI review response: {error}"))?;
    if !value
        .get("model")
        .and_then(Value::as_object)
        .is_some_and(|model| model.contains_key("version"))
    {
        return Err("AI review response model.version is required".into());
    }
    serde_json::from_value(value).map_err(|error| format!("invalid AI review response: {error}"))
}

pub fn ai_review_request_sha256(request: &AiReviewRequest) -> Result<String, String> {
    match request.schema_version {
        1 if request.artifact_binding.is_some() => {
            return Err(
                "AI review request schema version 1 must not contain an artifact binding".into(),
            );
        }
        1 => {}
        2 if request.artifact_binding.is_none() => {
            return Err("AI review request schema version 2 requires an artifact binding".into());
        }
        2 => {
            let binding = request.artifact_binding.as_ref().unwrap();
            if binding.schema_version != 1 {
                return Err(
                    "AI review request schema version 2 requires artifact binding schema version 1"
                        .into(),
                );
            }
            validate_artifact_binding(binding)?;
        }
        3 if request.artifact_binding.is_none() => {
            return Err("AI review request schema version 3 requires an artifact binding".into());
        }
        3 => {
            let binding = request.artifact_binding.as_ref().unwrap();
            if binding.schema_version != 2 {
                return Err(
                    "AI review request schema version 3 requires artifact binding schema version 2"
                        .into(),
                );
            }
            validate_artifact_binding(binding)?;
        }
        4 if request.artifact_binding.is_none() => {
            return Err("AI review request schema version 4 requires an artifact binding".into());
        }
        4 => {
            let binding = request.artifact_binding.as_ref().unwrap();
            if binding.schema_version != 3 {
                return Err(
                    "AI review request schema version 4 requires artifact binding schema version 3"
                        .into(),
                );
            }
            validate_artifact_binding(binding)?;
        }
        version => {
            return Err(format!(
                "unsupported AI review request schema version {version}"
            ));
        }
    }
    validate_request_contents(request)?;
    let expected = request_body_sha256(request)?;
    if request.request_sha256 != expected {
        return Err("AI review request SHA-256 does not match its normalized content".into());
    }
    Ok(expected)
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    description: &str,
    maximum_bytes: u64,
) -> Result<(), String> {
    if identity.bytes == 0 {
        return Err(format!("{description} byte count must be positive"));
    }
    if identity.bytes > maximum_bytes {
        return Err(format!(
            "{description} byte count exceeds the {maximum_bytes}-byte limit"
        ));
    }
    validate_sha256(&identity.sha256, &format!("{description} SHA-256"))
}

fn validate_artifact_binding(binding: &AiReviewArtifactBinding) -> Result<(), String> {
    validate_artifact_identity(
        &binding.generated_schematic,
        "generated schematic artifact",
        CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES as u64,
    )?;
    validate_artifact_identity(
        &binding.pipeline.plan_source,
        "pipeline plan source",
        AI_REVIEW_PLAN_SOURCE_MAX_BYTES,
    )?;
    validate_sha256(&binding.pipeline.plan_sha256, "pipeline plan SHA-256")?;
    validate_artifact_identity(
        &binding.pipeline.report,
        "pipeline report",
        AI_REVIEW_REPORT_MAX_BYTES,
    )?;
    validate_sha256(&binding.pipeline.run_sha256, "pipeline run SHA-256")?;
    match binding.schema_version {
        1 if binding.native_kicad_erc.is_none() => Ok(()),
        1 => Err(
            "AI review artifact binding schema version 1 must not contain native_kicad_erc".into(),
        ),
        2 => binding
            .native_kicad_erc
            .as_ref()
            .ok_or_else(|| {
                "AI review artifact binding schema version 2 requires native_kicad_erc".into()
            })
            .and_then(|identity| {
                validate_native_kicad_erc_identity(identity)?;
                if identity.schema_version != 1 {
                    return Err(
                        "AI review artifact binding schema version 2 requires native KiCad ERC identity schema version 1".into(),
                    );
                }
                Ok(())
            }),
        3 => binding
            .native_kicad_erc
            .as_ref()
            .ok_or_else(|| {
                "AI review artifact binding schema version 3 requires native_kicad_erc".into()
            })
            .and_then(|identity| {
                validate_native_kicad_erc_identity(identity)?;
                if identity.schema_version != 2 {
                    return Err(
                        "AI review artifact binding schema version 3 requires native KiCad ERC identity schema version 2".into(),
                    );
                }
                Ok(())
            }),
        version => Err(format!(
            "unsupported AI review artifact binding schema version {version}"
        )),
    }
}

fn validate_native_kicad_erc_identity(identity: &NativeKicadErcIdentity) -> Result<(), String> {
    if !matches!(identity.schema_version, 1 | 2) {
        return Err(format!(
            "unsupported native KiCad ERC identity schema version {}",
            identity.schema_version
        ));
    }
    validate_artifact_identity(
        &identity.report,
        "native KiCad ERC report",
        AI_REVIEW_NATIVE_KICAD_ERC_REPORT_MAX_BYTES,
    )?;
    validate_sha256(&identity.run_sha256, "native KiCad ERC run SHA-256")
}

fn validate_request_contents(request: &AiReviewRequest) -> Result<(), String> {
    validate_sha256(
        &request.electrical_review_sha256,
        "electrical review SHA-256",
    )?;
    validate_requirements(&request.requirements)?;
    if request
        .requirements
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err("AI review requirements must be sorted by unique id".into());
    }
    let recomputed = check_schematic(&request.schematic, &request.electrical_policy)?;
    if recomputed != request.electrical_review {
        return Err(
            "AI review embeds an electrical result that does not match its schematic and policy"
                .into(),
        );
    }
    let mut simulation_ids = BTreeSet::new();
    for evidence in &request.simulation_evidence {
        validate_simulation_evidence(evidence)?;
        if evidence.schematic_sha256 != request.electrical_review.schematic_sha256
            || evidence.electrical_review_sha256 != request.electrical_review_sha256
        {
            return Err(format!(
                "simulation evidence {} is not bound to this review",
                evidence.id
            ));
        }
        if !simulation_ids.insert(evidence.id.as_str()) {
            return Err(format!("duplicate simulation evidence id {}", evidence.id));
        }
    }
    if request
        .simulation_evidence
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err("simulation evidence must be sorted by unique id".into());
    }
    let expected = expected_evidence_ids(
        &request.schematic,
        &request.electrical_review,
        &request.simulation_evidence,
    );
    if request.evidence_ids != expected {
        return Err("AI review evidence identifiers do not match embedded evidence".into());
    }
    Ok(())
}

fn expected_evidence_ids(
    schematic: &SchematicDocument,
    electrical_review: &ElectricalReview,
    simulation_evidence: &[SimulationEvidence],
) -> Vec<String> {
    let mut evidence_ids = BTreeSet::from(["electrical-review".to_string()]);
    for symbol in &schematic.symbols {
        evidence_ids.insert(format!("symbol:{}", symbol.uuid));
    }
    for net in &schematic.nets {
        evidence_ids.insert(format!("net:{}", net.id));
    }
    for finding in &electrical_review.findings {
        evidence_ids.insert(format!("electrical-finding:{}", finding.id));
    }
    for evidence in simulation_evidence {
        evidence_ids.insert(format!("simulation:{}", evidence.id));
        for assertion in &evidence.assertions {
            evidence_ids.insert(format!(
                "simulation-assertion:{}:{}",
                evidence.id, assertion.id
            ));
        }
    }
    evidence_ids.into_iter().collect()
}

pub fn sign_ai_review(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedAiApproval, String> {
    validate_nonblank(signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let gate_failures = evaluate_ai_review(request, response, &request_sha256)?;
    let response_bytes = serde_json::to_vec(response)
        .map_err(|error| format!("serializing AI review response: {error}"))?;
    let response_sha256 = hex_digest(&response_bytes);
    let approved = gate_failures.is_empty();
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = approval_payload_bytes(
        &request_sha256,
        &response_sha256,
        approved,
        &gate_failures,
        signer_id,
    )?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedAiApproval {
        schema_version: 1,
        request_sha256,
        response_sha256,
        session_sha256: None,
        approved,
        gate_failures,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn sign_ai_review_for_session(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    session_sha256: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedAiApproval, String> {
    validate_sha256(session_sha256, "AI review session SHA-256")?;
    validate_nonblank(signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let gate_failures = evaluate_ai_review(request, response, &request_sha256)?;
    let response_sha256 = hex_digest(
        &serde_json::to_vec(response)
            .map_err(|error| format!("serializing AI review response: {error}"))?,
    );
    let approved = gate_failures.is_empty();
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = session_approval_payload_bytes(
        session_sha256,
        &request_sha256,
        &response_sha256,
        approved,
        &gate_failures,
        signer_id,
    )?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedAiApproval {
        schema_version: 2,
        request_sha256,
        response_sha256,
        session_sha256: Some(session_sha256.into()),
        approved,
        gate_failures,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn approval_public_key(secret_key: &[u8; 32]) -> String {
    hex_encode(
        &SigningKey::from_bytes(secret_key)
            .verifying_key()
            .to_bytes(),
    )
}

pub fn verify_signed_ai_approval(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    match (approval.schema_version, approval.session_sha256.is_some()) {
        (1, false) => {}
        (2, true) => {
            return Err(
                "signed AI approval schema version 2 requires its bound review session".into(),
            );
        }
        (version, _) => {
            return Err(format!(
                "unsupported signed AI approval schema version {version}"
            ));
        }
    }
    verify_signed_ai_approval_inner(approval, request, response, trusted_public_key, None)
}

pub fn verify_session_signed_ai_approval(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
    session_sha256: &str,
) -> Result<(), String> {
    validate_sha256(session_sha256, "AI review session SHA-256")?;
    if approval.schema_version != 2 || approval.session_sha256.as_deref() != Some(session_sha256) {
        return Err("signed AI approval is not bound to the supplied review session".into());
    }
    verify_signed_ai_approval_inner(
        approval,
        request,
        response,
        trusted_public_key,
        Some(session_sha256),
    )
}

fn verify_signed_ai_approval_inner(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
    session_sha256: Option<&str>,
) -> Result<(), String> {
    if approval.algorithm != "ed25519" {
        return Err(format!(
            "unsupported approval signature algorithm {}",
            approval.algorithm
        ));
    }
    validate_nonblank(&approval.signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let response_sha256 = hex_digest(
        &serde_json::to_vec(response)
            .map_err(|error| format!("serializing AI review response: {error}"))?,
    );
    if approval.request_sha256 != request_sha256 || approval.response_sha256 != response_sha256 {
        return Err("signed approval content digests do not match the supplied documents".into());
    }
    let expected_failures = evaluate_ai_review(request, response, &request_sha256)?;
    if approval.gate_failures != expected_failures
        || approval.approved != expected_failures.is_empty()
    {
        return Err("signed approval gate result does not match fresh evaluation".into());
    }
    let public_key = hex_decode_array::<32>(&approval.public_key, "approval public key")?;
    if &public_key != trusted_public_key {
        return Err("approval public key does not match the trusted public key".into());
    }
    let signature = hex_decode_array::<64>(&approval.signature, "approval signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid approval public key: {error}"))?;
    let signature = Signature::from_bytes(&signature);
    let payload = if let Some(session_sha256) = session_sha256 {
        session_approval_payload_bytes(
            session_sha256,
            &request_sha256,
            &response_sha256,
            approval.approved,
            &approval.gate_failures,
            &approval.signer_id,
        )?
    } else {
        approval_payload_bytes(
            &request_sha256,
            &response_sha256,
            approval.approved,
            &approval.gate_failures,
            &approval.signer_id,
        )?
    };
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid AI approval signature: {error}"))
}

fn evaluate_ai_review(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    request_sha256: &str,
) -> Result<Vec<String>, String> {
    if response.schema_version != 1 {
        return Err(format!(
            "unsupported AI review response schema version {}",
            response.schema_version
        ));
    }
    if response.request_sha256 != request_sha256 {
        return Err("AI review response is bound to a different request".into());
    }
    validate_nonblank(&response.model.provider, "AI provider")?;
    validate_nonblank(&response.model.model, "AI model")?;
    if response
        .model
        .version
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("AI model version must not be blank when present".into());
    }
    validate_nonblank(&response.summary, "AI review summary")?;
    if response.risks.len() > MAX_RISKS {
        return Err(format!("AI review exceeds the {MAX_RISKS} risk limit"));
    }
    let valid_evidence = request
        .evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required_ids = request
        .requirements
        .iter()
        .map(|requirement| requirement.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut assessed_ids = BTreeSet::new();
    for assessment in &response.requirements {
        if !required_ids.contains(assessment.id.as_str()) {
            return Err(format!(
                "AI response assesses unknown requirement {}",
                assessment.id
            ));
        }
        if !assessed_ids.insert(assessment.id.as_str()) {
            return Err(format!(
                "AI response repeats requirement assessment {}",
                assessment.id
            ));
        }
        validate_nonblank(&assessment.rationale, "AI requirement rationale")?;
        validate_evidence_refs(&assessment.evidence_refs, &valid_evidence)?;
    }
    if assessed_ids != required_ids {
        return Err("AI response must assess every requested requirement exactly once".into());
    }
    let mut risk_ids = BTreeSet::new();
    for risk in &response.risks {
        validate_nonblank(&risk.id, "AI risk id")?;
        validate_nonblank(&risk.title, "AI risk title")?;
        validate_nonblank(&risk.rationale, "AI risk rationale")?;
        if !risk_ids.insert(risk.id.as_str()) {
            return Err(format!("AI response repeats risk {}", risk.id));
        }
        validate_evidence_refs(&risk.evidence_refs, &valid_evidence)?;
    }

    let mut failures = Vec::new();
    if !request.electrical_review.approved {
        failures.push("electrical_review_rejected".into());
    }
    if request.approval_policy.require_simulation_evidence && request.simulation_evidence.is_empty()
    {
        failures.push("simulation_evidence_required".into());
    }
    for evidence in &request.simulation_evidence {
        if !evidence.passed {
            failures.push(format!("simulation_evidence_failed:{}", evidence.id));
        }
    }
    match response.decision {
        AiReviewDecision::Approve => {}
        AiReviewDecision::Reject => failures.push("ai_decision_reject".into()),
        AiReviewDecision::NeedsHuman => failures.push("ai_decision_needs_human".into()),
    }
    for assessment in &response.requirements {
        match assessment.status {
            AiRequirementStatus::Pass => {}
            AiRequirementStatus::Fail => {
                failures.push(format!("requirement_failed:{}", assessment.id));
            }
            AiRequirementStatus::Unknown => {
                failures.push(format!("requirement_unknown:{}", assessment.id));
            }
        }
    }
    for risk in &response.risks {
        if risk.severity >= AiRiskSeverity::Error {
            failures.push(format!(
                "risk_{}:{}",
                risk_severity_name(risk.severity),
                risk.id
            ));
        }
    }
    Ok(failures)
}

fn validate_requirements(requirements: &[AiRequirement]) -> Result<(), String> {
    if requirements.is_empty() {
        return Err("AI review requires at least one explicit requirement".into());
    }
    if requirements.len() > MAX_REQUIREMENTS {
        return Err(format!(
            "AI review exceeds the {MAX_REQUIREMENTS} requirement limit"
        ));
    }
    let mut ids = BTreeSet::new();
    for requirement in requirements {
        validate_nonblank(&requirement.id, "AI requirement id")?;
        validate_nonblank(&requirement.text, "AI requirement text")?;
        if !ids.insert(requirement.id.as_str()) {
            return Err(format!("duplicate AI requirement id {}", requirement.id));
        }
    }
    Ok(())
}

fn validate_evidence_refs(refs: &[String], valid: &BTreeSet<&str>) -> Result<(), String> {
    if refs.is_empty() {
        return Err("AI assessments and risks must cite at least one evidence identifier".into());
    }
    if refs.len() > MAX_EVIDENCE_REFS {
        return Err(format!(
            "AI review exceeds the {MAX_EVIDENCE_REFS} evidence-reference limit"
        ));
    }
    let mut seen = BTreeSet::new();
    for reference in refs {
        if !valid.contains(reference.as_str()) {
            return Err(format!(
                "AI response references unknown evidence {reference}"
            ));
        }
        if !seen.insert(reference.as_str()) {
            return Err(format!(
                "AI response repeats evidence reference {reference}"
            ));
        }
    }
    Ok(())
}

fn approval_payload_bytes(
    request_sha256: &str,
    response_sha256: &str,
    approved: bool,
    gate_failures: &[String],
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ApprovalPayload {
        domain: SIGNATURE_DOMAIN,
        request_sha256,
        response_sha256,
        approved,
        gate_failures,
        signer_id,
    })
    .map_err(|error| format!("serializing approval signature payload: {error}"))
}

fn session_approval_payload_bytes(
    session_sha256: &str,
    request_sha256: &str,
    response_sha256: &str,
    approved: bool,
    gate_failures: &[String],
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SessionApprovalPayload {
        domain: SESSION_SIGNATURE_DOMAIN,
        session_sha256,
        request_sha256,
        response_sha256,
        approved,
        gate_failures,
        signer_id,
    })
    .map_err(|error| format!("serializing session approval signature payload: {error}"))
}

fn request_body_sha256(request: &AiReviewRequest) -> Result<String, String> {
    let mut body = request.clone();
    body.request_sha256.clear();
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| format!("serializing AI review request: {error}"))?;
    Ok(hex_digest(&bytes))
}

fn validate_nonblank(value: &str, description: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{description} must not be blank"))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str, description: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        Err(format!(
            "{description} must be 64 lowercase hexadecimal digits"
        ))
    } else {
        Ok(())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str, description: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(format!(
            "{description} must be {} hexadecimal digits",
            N * 2
        ));
    }
    let mut result = [0_u8; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{description} is not hexadecimal"))?;
    }
    Ok(result)
}

fn risk_severity_name(severity: AiRiskSeverity) -> &'static str {
    match severity {
        AiRiskSeverity::Info => "info",
        AiRiskSeverity::Warning => "warning",
        AiRiskSeverity::Error => "error",
        AiRiskSeverity::Critical => "critical",
    }
}

fn string_schema() -> Value {
    json!({"type": "string", "minLength": 1})
}

pub fn ai_review_request_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-review-request-v4.json",
        "title": "pcbex AI schematic review request",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "schematic", "electrical_policy",
            "electrical_review",
            "electrical_review_sha256", "simulation_evidence", "requirements",
            "evidence_ids", "approval_policy"
        ],
        "properties": {
            "schema_version": {"enum": [1, 2, 3, 4]},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "schematic": schematic_json_schema(),
            "electrical_policy": electrical_policy_json_schema(),
            "electrical_review": electrical_review_json_schema(),
            "electrical_review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "simulation_evidence": {
                "type": "array",
                "maxItems": MAX_REQUIREMENTS,
                "items": simulation_evidence_json_schema()
            },
            "requirements": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_REQUIREMENTS,
                "items": {"$ref": "#/$defs/requirement"}
            },
            "evidence_ids": {
                "type": "array",
                "items": string_schema(),
                "uniqueItems": true
            },
            "approval_policy": {"$ref": "#/$defs/policy"},
            "artifact_binding": {"$ref": "#/$defs/artifact_binding"}
        },
        "allOf": [
            {
                "if": {"properties": {"schema_version": {"const": 1}}},
                "then": {"not": {"required": ["artifact_binding"]}}
            },
            {
                "if": {"properties": {"schema_version": {"const": 2}}},
                "then": {
                    "required": ["artifact_binding"],
                    "properties": {
                        "artifact_binding": {
                            "properties": {"schema_version": {"const": 1}}
                        }
                    }
                }
            },
            {
                "if": {"properties": {"schema_version": {"const": 3}}},
                "then": {
                    "required": ["artifact_binding"],
                    "properties": {
                        "artifact_binding": {
                            "properties": {"schema_version": {"const": 2}}
                        }
                    }
                }
            },
            {
                "if": {"properties": {"schema_version": {"const": 4}}},
                "then": {
                    "required": ["artifact_binding"],
                    "properties": {
                        "artifact_binding": {
                            "properties": {"schema_version": {"const": 3}}
                        }
                    }
                }
            }
        ],
        "$defs": {
            "requirement": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "text"],
                "properties": {"id": string_schema(), "text": string_schema()}
            },
            "policy": {
                "type": "object",
                "additionalProperties": false,
                "required": ["require_simulation_evidence"],
                "properties": {"require_simulation_evidence": {"type": "boolean"}}
            },
            "exact_artifact_identity": {
                "type": "object",
                "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "pipeline": {
                "type": "object",
                "additionalProperties": false,
                "required": ["plan_source", "plan_sha256", "report", "run_sha256"],
                "properties": {
                    "plan_source": {
                        "allOf": [
                            {"$ref": "#/$defs/exact_artifact_identity"},
                            {"properties": {"bytes": {
                                "maximum": AI_REVIEW_PLAN_SOURCE_MAX_BYTES
                            }}}
                        ]
                    },
                    "plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "report": {
                        "allOf": [
                            {"$ref": "#/$defs/exact_artifact_identity"},
                            {"properties": {"bytes": {
                                "maximum": AI_REVIEW_REPORT_MAX_BYTES
                            }}}
                        ]
                    },
                    "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "artifact_binding": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version", "generated_schematic", "pipeline"],
                "properties": {
                    "schema_version": {"enum": [1, 2, 3]},
                    "generated_schematic": {
                        "allOf": [
                            {"$ref": "#/$defs/exact_artifact_identity"},
                            {"properties": {"bytes": {
                                "maximum": CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES
                            }}}
                        ]
                    },
                    "pipeline": {"$ref": "#/$defs/pipeline"},
                    "native_kicad_erc": {"$ref": "#/$defs/native_kicad_erc"}
                },
                "allOf": [
                    {
                        "if": {"properties": {"schema_version": {"const": 1}}},
                        "then": {"not": {"required": ["native_kicad_erc"]}}
                    },
                    {
                        "if": {"properties": {"schema_version": {"const": 2}}},
                        "then": {
                            "required": ["native_kicad_erc"],
                            "properties": {
                                "native_kicad_erc": {
                                    "properties": {"schema_version": {"const": 1}}
                                }
                            }
                        }
                    },
                    {
                        "if": {"properties": {"schema_version": {"const": 3}}},
                        "then": {
                            "required": ["native_kicad_erc"],
                            "properties": {
                                "native_kicad_erc": {
                                    "properties": {"schema_version": {"const": 2}}
                                }
                            }
                        }
                    }
                ]
            },
            "native_kicad_erc": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version", "report", "run_sha256"],
                "properties": {
                    "schema_version": {"enum": [1, 2]},
                    "report": {
                        "allOf": [
                            {"$ref": "#/$defs/exact_artifact_identity"},
                            {"properties": {"bytes": {
                                "maximum": AI_REVIEW_NATIVE_KICAD_ERC_REPORT_MAX_BYTES
                            }}}
                        ]
                    },
                    "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            }
        }
    })
}

pub fn ai_review_response_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-review-response-v1.json",
        "title": "pcbex AI schematic review response",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "model", "decision", "summary",
            "requirements", "risks"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "model": {"$ref": "#/$defs/model"},
            "decision": {"enum": ["approve", "reject", "needs_human"]},
            "summary": string_schema(),
            "requirements": {
                "type": "array",
                "maxItems": MAX_REQUIREMENTS,
                "items": {"$ref": "#/$defs/assessment"}
            },
            "risks": {
                "type": "array",
                "maxItems": MAX_RISKS,
                "items": {"$ref": "#/$defs/risk"}
            }
        },
        "$defs": {
            "model": {
                "type": "object",
                "additionalProperties": false,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": string_schema(),
                    "model": string_schema(),
                    "version": {
                        "anyOf": [
                            {"type": "string", "minLength": 1},
                            {"type": "null"}
                        ]
                    }
                }
            },
            "assessment": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "status", "rationale", "evidence_refs"],
                "properties": {
                    "id": string_schema(),
                    "status": {"enum": ["pass", "fail", "unknown"]},
                    "rationale": string_schema(),
                    "evidence_refs": {
                        "type": "array", "minItems": 1, "maxItems": MAX_EVIDENCE_REFS,
                        "uniqueItems": true, "items": string_schema()
                    }
                }
            },
            "risk": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "severity", "title", "rationale", "evidence_refs"],
                "properties": {
                    "id": string_schema(),
                    "severity": {"enum": ["info", "warning", "error", "critical"]},
                    "title": string_schema(),
                    "rationale": string_schema(),
                    "evidence_refs": {
                        "type": "array", "minItems": 1, "maxItems": MAX_EVIDENCE_REFS,
                        "uniqueItems": true, "items": string_schema()
                    }
                }
            }
        }
    })
}

pub fn signed_ai_approval_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-ai-approval-v2.json",
        "title": "pcbex signed AI schematic approval",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "response_sha256", "approved",
            "gate_failures", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"enum": [1, 2]},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "session_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "approved": {"type": "boolean"},
            "gate_failures": {"type": "array", "items": string_schema()},
            "signer_id": string_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        },
        "allOf": [
            {
                "if": {"properties": {"schema_version": {"const": 2}}},
                "then": {"required": ["session_sha256"]},
                "else": {"not": {"required": ["session_sha256"]}}
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_schematic;

    fn approved_request() -> AiReviewRequest {
        let mut schematic =
            import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap();
        for symbol in &mut schematic.symbols {
            symbol.dnp = true;
        }
        let policy = ElectricalPolicy::default();
        let review = check_schematic(&schematic, &policy).unwrap();
        build_ai_review_request(
            schematic,
            &policy,
            review,
            "a".repeat(64),
            Vec::new(),
            vec![AiRequirement {
                id: "power".into(),
                text: "Power inputs are intentional".into(),
            }],
            false,
        )
        .unwrap()
    }

    fn response(request: &AiReviewRequest) -> AiReviewResponse {
        AiReviewResponse {
            schema_version: 1,
            request_sha256: ai_review_request_sha256(request).unwrap(),
            model: AiModelIdentity {
                provider: "test".into(),
                model: "reviewer".into(),
                version: Some("1".into()),
            },
            decision: AiReviewDecision::Approve,
            summary: "All supplied requirements and evidence pass.".into(),
            requirements: vec![AiRequirementAssessment {
                id: "power".into(),
                status: AiRequirementStatus::Pass,
                rationale: "Bound to the deterministic review.".into(),
                evidence_refs: vec!["electrical-review".into()],
            }],
            risks: Vec::new(),
        }
    }

    fn artifact_binding() -> AiReviewArtifactBinding {
        AiReviewArtifactBinding {
            schema_version: 1,
            generated_schematic: ExactArtifactIdentity {
                bytes: 101,
                sha256: "b".repeat(64),
            },
            pipeline: DeterministicPipelineIdentity {
                plan_source: ExactArtifactIdentity {
                    bytes: 202,
                    sha256: "c".repeat(64),
                },
                plan_sha256: "d".repeat(64),
                report: ExactArtifactIdentity {
                    bytes: 303,
                    sha256: "e".repeat(64),
                },
                run_sha256: "f".repeat(64),
            },
            native_kicad_erc: None,
        }
    }

    fn native_kicad_erc_identity() -> NativeKicadErcIdentity {
        NativeKicadErcIdentity {
            schema_version: 1,
            report: ExactArtifactIdentity {
                bytes: 404,
                sha256: "1".repeat(64),
            },
            run_sha256: "2".repeat(64),
        }
    }

    fn native_kicad_erc_warning_policy_identity() -> NativeKicadErcIdentity {
        NativeKicadErcIdentity {
            schema_version: 2,
            report: ExactArtifactIdentity {
                bytes: 505,
                sha256: "3".repeat(64),
            },
            run_sha256: "4".repeat(64),
        }
    }

    #[test]
    fn v1_request_serialization_and_hash_are_unchanged_without_binding() {
        let request = approved_request();
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(
            !String::from_utf8(encoded.clone())
                .unwrap()
                .contains("artifact_binding")
        );
        assert_eq!(
            ai_review_request_sha256(&request).unwrap(),
            request.request_sha256
        );
        let reparsed: AiReviewRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(reparsed, request);
        assert_eq!(
            ai_review_request_sha256(&reparsed).unwrap(),
            request.request_sha256
        );
        assert_eq!(
            request.request_sha256,
            "520d9fe0e09ace52d8b6d873746195d1bff464babf12732025b182cdeb835f79"
        );
    }

    #[test]
    fn binds_v1_request_to_deterministic_artifact_identities() {
        let request = approved_request();
        let binding = artifact_binding();
        let bound = bind_ai_review_request(&request, &binding).unwrap();
        assert_eq!(bound.schema_version, 2);
        assert_eq!(bound.artifact_binding, Some(binding.clone()));
        assert_ne!(bound.request_sha256, request.request_sha256);
        assert_eq!(
            bound.request_sha256,
            "90580c5ede53b42a1bf1acade6dcf09759ac55144c371f6fc4623c4c19c169b8"
        );
        assert_eq!(
            bound.request_sha256,
            ai_review_request_sha256(&bound).unwrap()
        );
        assert!(
            serde_json::to_string(&bound)
                .unwrap()
                .contains("artifact_binding")
        );
        assert_eq!(
            bound,
            bind_ai_review_request(&request, binding.clone()).unwrap()
        );
    }

    #[test]
    fn binds_v2_request_to_native_kicad_erc_v3() {
        let request = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let native = native_kicad_erc_identity();
        let bound = bind_native_kicad_erc_to_ai_review_request(&request, &native).unwrap();

        assert_eq!(bound.schema_version, 3);
        assert_eq!(bound.artifact_binding.as_ref().unwrap().schema_version, 2);
        assert_eq!(
            bound.artifact_binding.as_ref().unwrap().native_kicad_erc,
            Some(native.clone())
        );
        assert_eq!(
            bound.request_sha256,
            ai_review_request_sha256(&bound).unwrap()
        );

        let encoded = serde_json::to_vec(&bound).unwrap();
        let reparsed: AiReviewRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(reparsed, bound);
        assert_eq!(
            ai_review_request_sha256(&reparsed).unwrap(),
            bound.request_sha256
        );
    }

    #[test]
    fn binds_v2_request_to_warning_policy_native_kicad_erc_v4() {
        let request_v2 = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let native = native_kicad_erc_warning_policy_identity();
        let bound = bind_native_kicad_erc_warning_policy_to_ai_review_request(&request_v2, &native)
            .unwrap();

        assert_eq!(bound.schema_version, 4);
        assert_eq!(bound.artifact_binding.as_ref().unwrap().schema_version, 3);
        assert_eq!(
            bound.artifact_binding.as_ref().unwrap().native_kicad_erc,
            Some(native.clone())
        );
        assert_eq!(
            bound.request_sha256,
            ai_review_request_sha256(&bound).unwrap()
        );

        let encoded = serde_json::to_vec(&bound).unwrap();
        let reparsed: AiReviewRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(reparsed, bound);
        assert_eq!(
            ai_review_request_sha256(&reparsed).unwrap(),
            bound.request_sha256
        );

        // The identity-v1 binder cannot consume warning-policy evidence.
        assert!(bind_native_kicad_erc_to_ai_review_request(&request_v2, &native).is_err());
        // A warning-policy binding starts at the unbound v2 request and cannot
        // be applied again to an already-bound v3/v4 request.
        assert!(
            bind_native_kicad_erc_warning_policy_to_ai_review_request(&bound, &native).is_err()
        );
        let request_v3 =
            bind_native_kicad_erc_to_ai_review_request(&request_v2, native_kicad_erc_identity())
                .unwrap();
        assert!(
            bind_native_kicad_erc_warning_policy_to_ai_review_request(&request_v3, &native)
                .is_err()
        );
    }

    #[test]
    fn native_binding_version_mixes_and_missing_or_null_evidence_fail_closed() {
        let request_v1 = approved_request();
        let binding_v1 = artifact_binding();
        let native = native_kicad_erc_identity();

        let mut request_with_native_v1 = request_v1.clone();
        let mut binding_with_native_v1 = binding_v1.clone();
        binding_with_native_v1.native_kicad_erc = Some(native.clone());
        request_with_native_v1.artifact_binding = Some(binding_with_native_v1);
        assert!(ai_review_request_sha256(&request_with_native_v1).is_err());

        let request_v2 = bind_ai_review_request(&request_v1, binding_v1).unwrap();
        let mut request_v2_with_native_binding = request_v2.clone();
        request_v2_with_native_binding
            .artifact_binding
            .as_mut()
            .unwrap()
            .schema_version = 2;
        request_v2_with_native_binding.request_sha256 =
            request_body_sha256(&request_v2_with_native_binding).unwrap();
        assert!(ai_review_request_sha256(&request_v2_with_native_binding).is_err());

        let mut request_v3_missing_binding = request_v2.clone();
        request_v3_missing_binding.schema_version = 3;
        request_v3_missing_binding.request_sha256 =
            request_body_sha256(&request_v3_missing_binding).unwrap();
        assert!(ai_review_request_sha256(&request_v3_missing_binding).is_err());

        let mut request_v3_missing_native =
            bind_native_kicad_erc_to_ai_review_request(&request_v2, &native).unwrap();
        request_v3_missing_native
            .artifact_binding
            .as_mut()
            .unwrap()
            .native_kicad_erc = None;
        request_v3_missing_native.request_sha256 =
            request_body_sha256(&request_v3_missing_native).unwrap();
        assert!(ai_review_request_sha256(&request_v3_missing_native).is_err());

        let mut json_v3 = serde_json::to_value(
            bind_native_kicad_erc_to_ai_review_request(&request_v2, &native).unwrap(),
        )
        .unwrap();
        json_v3["artifact_binding"]["native_kicad_erc"] = Value::Null;
        assert!(serde_json::from_value::<AiReviewRequest>(json_v3).is_err());
    }

    #[test]
    fn native_identity_versions_are_closed_to_their_binding_and_request_versions() {
        let request_v2 = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let native_v1 = native_kicad_erc_identity();
        let native_v2 = native_kicad_erc_warning_policy_identity();
        let request_v3 =
            bind_native_kicad_erc_to_ai_review_request(&request_v2, &native_v1).unwrap();
        let request_v4 =
            bind_native_kicad_erc_warning_policy_to_ai_review_request(&request_v2, &native_v2)
                .unwrap();

        // A binding schema v2 is exclusively identity v1; identity v2 cannot
        // be mixed into the legacy request-v3 wire.
        let mut mixed_v3 = serde_json::to_value(&request_v3).unwrap();
        mixed_v3["artifact_binding"]["native_kicad_erc"]["schema_version"] = json!(2);
        assert!(serde_json::from_value::<AiReviewRequest>(mixed_v3).is_err());

        // Conversely, binding schema v3 is exclusively identity v2; identity
        // v1 is a downgrade and is rejected at the closed wire boundary.
        let mut mixed_v4 = serde_json::to_value(&request_v4).unwrap();
        mixed_v4["artifact_binding"]["native_kicad_erc"]["schema_version"] = json!(1);
        assert!(serde_json::from_value::<AiReviewRequest>(mixed_v4).is_err());

        // Struct-level downgrade attempts are rejected even if their body
        // digest is recomputed by the caller.
        let mut downgraded_v3 = request_v3.clone();
        downgraded_v3.schema_version = 4;
        downgraded_v3.artifact_binding = Some(AiReviewArtifactBinding {
            schema_version: 3,
            native_kicad_erc: Some(native_v1),
            ..request_v3.artifact_binding.clone().unwrap()
        });
        downgraded_v3.request_sha256 = request_body_sha256(&downgraded_v3).unwrap();
        assert!(ai_review_request_sha256(&downgraded_v3).is_err());

        let mut downgraded_v4 = request_v4.clone();
        downgraded_v4.schema_version = 3;
        downgraded_v4.artifact_binding = Some(AiReviewArtifactBinding {
            schema_version: 2,
            native_kicad_erc: Some(native_v2),
            ..request_v4.artifact_binding.clone().unwrap()
        });
        downgraded_v4.request_sha256 = request_body_sha256(&downgraded_v4).unwrap();
        assert!(ai_review_request_sha256(&downgraded_v4).is_err());

        let mut unknown_identity = serde_json::to_value(native_kicad_erc_identity()).unwrap();
        unknown_identity["schema_version"] = json!(3);
        assert!(serde_json::from_value::<NativeKicadErcIdentity>(unknown_identity).is_err());
    }

    #[test]
    fn native_binding_unknown_fields_and_size_limits_fail_closed() {
        let request_v2 = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let native = native_kicad_erc_identity();
        let mut unknown = serde_json::to_value(&native).unwrap();
        unknown["unknown"] = json!(true);
        assert!(serde_json::from_value::<NativeKicadErcIdentity>(unknown).is_err());

        let mut unknown_binding = serde_json::to_value(&request_v2).unwrap();
        unknown_binding["artifact_binding"]["native_kicad_erc"] =
            serde_json::to_value(&native).unwrap();
        unknown_binding["artifact_binding"]["native_kicad_erc"]["unknown"] = json!(true);
        unknown_binding["schema_version"] = json!(3);
        assert!(serde_json::from_value::<AiReviewRequest>(unknown_binding).is_err());

        let mut at_limit = native.clone();
        at_limit.report.bytes = AI_REVIEW_NATIVE_KICAD_ERC_REPORT_MAX_BYTES;
        assert!(bind_native_kicad_erc_to_ai_review_request(&request_v2, &at_limit).is_ok());

        let mut too_large = at_limit;
        too_large.report.bytes += 1;
        assert!(bind_native_kicad_erc_to_ai_review_request(&request_v2, &too_large).is_err());

        let schema = ai_review_request_json_schema();
        assert_eq!(
            schema["$id"],
            json!("https://github.com/penguin425/pcbex/schemas/ai-review-request-v4.json")
        );
        assert_eq!(
            schema["properties"]["schema_version"]["enum"],
            json!([1, 2, 3, 4])
        );
        assert_eq!(
            schema["$defs"]["artifact_binding"]["properties"]["schema_version"]["enum"],
            json!([1, 2, 3])
        );
        assert_eq!(
            schema["$defs"]["native_kicad_erc"]["properties"]["schema_version"]["enum"],
            json!([1, 2])
        );
        assert_eq!(
            schema["$defs"]["native_kicad_erc"]["properties"]["report"]["allOf"][1]["properties"]["bytes"]
                ["maximum"],
            json!(AI_REVIEW_NATIVE_KICAD_ERC_REPORT_MAX_BYTES)
        );
    }

    #[test]
    fn request_binding_presence_is_conditional_on_request_schema() {
        let request = approved_request();
        let binding = artifact_binding();

        let mut unexpected = request.clone();
        unexpected.artifact_binding = Some(binding.clone());
        assert!(ai_review_request_sha256(&unexpected).is_err());

        let mut missing = bind_ai_review_request(&request, &binding).unwrap();
        missing.artifact_binding = None;
        missing.request_sha256 = request_body_sha256(&missing).unwrap();
        assert!(ai_review_request_sha256(&missing).is_err());

        let mut unsupported = request;
        unsupported.schema_version = 3;
        assert!(ai_review_request_sha256(&unsupported).is_err());

        let mut unsupported_v4 = bind_ai_review_request(&approved_request(), binding).unwrap();
        unsupported_v4.schema_version = 4;
        unsupported_v4.request_sha256 = request_body_sha256(&unsupported_v4).unwrap();
        assert!(ai_review_request_sha256(&unsupported_v4).is_err());
    }

    #[test]
    fn malformed_artifact_binding_and_unknown_fields_fail_closed() {
        let request = approved_request();
        let binding = artifact_binding();

        let mut zero_bytes = binding.clone();
        zero_bytes.generated_schematic.bytes = 0;
        assert!(bind_ai_review_request(&request, zero_bytes).is_err());

        let mut uppercase_hash = binding.clone();
        uppercase_hash.pipeline.plan_sha256 = "A".repeat(64);
        assert!(bind_ai_review_request(&request, uppercase_hash).is_err());

        let mut bad_binding_schema = binding.clone();
        bad_binding_schema.schema_version = 2;
        assert!(bind_ai_review_request(&request, bad_binding_schema).is_err());

        let mut native_binding = binding.clone();
        native_binding.schema_version = 2;
        native_binding.native_kicad_erc = Some(native_kicad_erc_identity());
        assert!(bind_ai_review_request(&request, native_binding).is_err());

        let mut unknown = serde_json::to_value(binding).unwrap();
        unknown["pipeline"]["unknown"] = json!(true);
        assert!(serde_json::from_value::<AiReviewArtifactBinding>(unknown).is_err());

        let mut request_unknown = serde_json::to_value(request).unwrap();
        request_unknown["artifact_binding"] = json!({
            "schema_version": 1,
            "generated_schematic": {
                "bytes": 1,
                "sha256": "a".repeat(64),
                "unknown": true
            },
            "pipeline": {
                "plan_source": {"bytes": 1, "sha256": "b".repeat(64)},
                "plan_sha256": "c".repeat(64),
                "report": {"bytes": 1, "sha256": "d".repeat(64)},
                "run_sha256": "e".repeat(64)
            }
        });
        request_unknown["schema_version"] = json!(2);
        assert!(serde_json::from_value::<AiReviewRequest>(request_unknown).is_err());
    }

    #[test]
    fn artifact_binding_size_limits_are_fail_closed_at_the_boundary() {
        let request = approved_request();
        let mut at_limit = artifact_binding();
        at_limit.generated_schematic.bytes = CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES as u64;
        at_limit.pipeline.plan_source.bytes = AI_REVIEW_PLAN_SOURCE_MAX_BYTES;
        at_limit.pipeline.report.bytes = AI_REVIEW_REPORT_MAX_BYTES;
        assert!(bind_ai_review_request(&request, &at_limit).is_ok());

        let mut too_large = at_limit.clone();
        too_large.generated_schematic.bytes += 1;
        assert!(bind_ai_review_request(&request, &too_large).is_err());

        let mut too_large = at_limit.clone();
        too_large.pipeline.plan_source.bytes += 1;
        assert!(bind_ai_review_request(&request, &too_large).is_err());

        let mut too_large = at_limit;
        too_large.pipeline.report.bytes += 1;
        assert!(bind_ai_review_request(&request, &too_large).is_err());

        let schema = ai_review_request_json_schema();
        assert_eq!(
            schema["$defs"]["artifact_binding"]["properties"]["generated_schematic"]["allOf"][1]["properties"]
                ["bytes"]["maximum"],
            json!(CIRCUIT_KICAD_SCHEMATIC_MAX_OUTPUT_BYTES)
        );
        assert_eq!(
            schema["$defs"]["pipeline"]["properties"]["plan_source"]["allOf"][1]["properties"]["bytes"]
                ["maximum"],
            json!(AI_REVIEW_PLAN_SOURCE_MAX_BYTES)
        );
        assert_eq!(
            schema["$defs"]["pipeline"]["properties"]["report"]["allOf"][1]["properties"]["bytes"]
                ["maximum"],
            json!(AI_REVIEW_REPORT_MAX_BYTES)
        );
    }

    #[test]
    fn explicit_null_and_duplicate_artifact_bindings_are_rejected_on_deserialization() {
        let mut v1 = serde_json::to_value(approved_request()).unwrap();
        v1["artifact_binding"] = Value::Null;
        assert!(serde_json::from_value::<AiReviewRequest>(v1).is_err());

        let bound = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let mut v2 = serde_json::to_value(&bound).unwrap();
        v2["artifact_binding"] = Value::Null;
        assert!(serde_json::from_value::<AiReviewRequest>(v2).is_err());

        let source = serde_json::to_string(&bound).unwrap();
        let duplicate = format!(
            "{},\"artifact_binding\":{}}}",
            source.trim_end_matches('}'),
            serde_json::to_string(bound.artifact_binding.as_ref().unwrap()).unwrap()
        );
        assert!(serde_json::from_str::<AiReviewRequest>(&duplicate).is_err());

        let nested_duplicate = source.replacen("\"bytes\":101", "\"bytes\":101,\"bytes\":102", 1);
        assert!(serde_json::from_str::<AiReviewRequest>(&nested_duplicate).is_err());
    }

    #[test]
    fn signed_approval_envelopes_cover_bound_requests_without_schema_changes() {
        let request = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let response = response(&request);
        let public_key = SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes();

        let approval = sign_ai_review(&request, &response, "ci", &[17; 32]).unwrap();
        assert_eq!(approval.schema_version, 1);
        verify_signed_ai_approval(&approval, &request, &response, &public_key).unwrap();

        let session = "1".repeat(64);
        let session_approval =
            sign_ai_review_for_session(&request, &response, &session, "ci", &[17; 32]).unwrap();
        assert_eq!(session_approval.schema_version, 2);
        verify_session_signed_ai_approval(
            &session_approval,
            &request,
            &response,
            &public_key,
            &session,
        )
        .unwrap();
    }

    #[test]
    fn tampering_bound_artifact_identity_invalidates_request_and_signature() {
        let request = bind_ai_review_request(&approved_request(), artifact_binding()).unwrap();
        let response = response(&request);
        let approval = sign_ai_review(&request, &response, "ci", &[18; 32]).unwrap();
        let public_key = SigningKey::from_bytes(&[18; 32]).verifying_key().to_bytes();

        let mut tampered = request.clone();
        tampered
            .artifact_binding
            .as_mut()
            .unwrap()
            .generated_schematic
            .sha256 = "0".repeat(64);
        tampered.request_sha256 = request_body_sha256(&tampered).unwrap();
        assert!(ai_review_request_sha256(&tampered).is_ok());
        assert!(verify_signed_ai_approval(&approval, &tampered, &response, &public_key).is_err());

        let mut forged_digest = request;
        forged_digest.request_sha256.replace_range(0..1, "0");
        assert!(ai_review_request_sha256(&forged_digest).is_err());
    }

    #[test]
    fn signs_and_strictly_verifies_approved_reviews() {
        let request = approved_request();
        let response = response(&request);
        let approval = sign_ai_review(&request, &response, "ci", &[7; 32]).unwrap();
        assert!(approval.approved);
        assert!(approval.gate_failures.is_empty());
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        verify_signed_ai_approval(&approval, &request, &response, &public_key).unwrap();
        let untrusted_key = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        assert!(verify_signed_ai_approval(&approval, &request, &response, &untrusted_key).is_err());
        assert_eq!(
            approval,
            sign_ai_review(&request, &response, "ci", &[7; 32]).unwrap()
        );
    }

    #[test]
    fn session_signatures_cannot_be_replayed_or_downgraded() {
        let request = approved_request();
        let response = response(&request);
        let session = "d".repeat(64);
        let approval =
            sign_ai_review_for_session(&request, &response, &session, "ci", &[7; 32]).unwrap();
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        verify_session_signed_ai_approval(&approval, &request, &response, &public_key, &session)
            .unwrap();
        assert!(
            verify_session_signed_ai_approval(
                &approval,
                &request,
                &response,
                &public_key,
                &"e".repeat(64),
            )
            .is_err()
        );
        assert!(verify_signed_ai_approval(&approval, &request, &response, &public_key).is_err());
    }

    #[test]
    fn signs_rejections_when_ai_or_requirement_does_not_approve() {
        let request = approved_request();
        let mut response = response(&request);
        response.decision = AiReviewDecision::NeedsHuman;
        response.requirements[0].status = AiRequirementStatus::Unknown;
        let approval = sign_ai_review(&request, &response, "ci", &[8; 32]).unwrap();
        assert!(!approval.approved);
        assert_eq!(
            approval.gate_failures,
            ["ai_decision_needs_human", "requirement_unknown:power"]
        );
        let public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        verify_signed_ai_approval(&approval, &request, &response, &public_key).unwrap();
    }

    #[test]
    fn rejects_missing_assessments_unknown_evidence_and_tampering() {
        let request = approved_request();
        let mut missing_version = serde_json::to_value(response(&request)).unwrap();
        missing_version["model"]
            .as_object_mut()
            .unwrap()
            .remove("version");
        assert!(
            parse_ai_review_response(&serde_json::to_string(&missing_version).unwrap()).is_err()
        );

        let mut invalid = response(&request);
        invalid.requirements.clear();
        assert!(sign_ai_review(&request, &invalid, "ci", &[9; 32]).is_err());

        let mut invalid = response(&request);
        invalid.requirements[0].evidence_refs = vec!["invented".into()];
        assert!(sign_ai_review(&request, &invalid, "ci", &[9; 32]).is_err());

        let response = response(&request);
        let mut approval = sign_ai_review(&request, &response, "ci", &[9; 32]).unwrap();
        approval.signature.replace_range(0..2, "00");
        let public_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        assert!(verify_signed_ai_approval(&approval, &request, &response, &public_key).is_err());

        let mut forged_request = request.clone();
        forged_request.electrical_review.policy_id = "forged".into();
        assert!(ai_review_request_sha256(&forged_request).is_err());
    }

    #[test]
    fn schemas_are_closed() {
        for schema in [
            ai_review_request_json_schema(),
            ai_review_response_json_schema(),
            signed_ai_approval_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
            for definition in schema["$defs"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, value)| value)
            {
                if definition["type"] == "object" {
                    assert_eq!(definition["additionalProperties"], false);
                }
            }
        }
    }
}
