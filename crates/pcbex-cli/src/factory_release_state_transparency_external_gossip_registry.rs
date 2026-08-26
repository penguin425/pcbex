//! Authority-governed organization eligibility for factory-release external gossip.
//!
//! The v1.493 boundary leaves every v1.491 and v1.492 wire document unchanged.
//! It adds an independently pinned generation-zero registry and retains each
//! authority-signed admission, suspension, or permanent revocation. v1.494
//! preserves those artifacts while adding dual-signed authority rotation and
//! typed mixed-history verification in the same selected ledger. v1.495 adds
//! root-authorized threshold governance, locks out root-only mutations after
//! activation, and replays all three event types from the pinned genesis.
//! v1.496 preserves every earlier artifact while adding state-bound successor
//! governance and old-and-new quorum rotation in the same generation chain.
//! v1.497 adds prospective-root-signed successor governance and a dual-quorum
//! transition that atomically replaces the registry root and active governance.
//! v1.498 exposes that five-event chain as a portable, bounded history and
//! independently audits every exact artifact from empty genesis without
//! trusting a copied final registry snapshot.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_state_transparency_external_gossip_quorum::{
    FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
    factory_release_state_transparency_external_gossip_quorum_policy_sha256,
};
use crate::factory_release_state_transparency_external_gossip_trust::{
    FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
    FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
    factory_release_state_transparency_external_gossip_observer_trust_state_sha256,
    factory_release_state_transparency_external_gossip_trust_report_json_schema,
    parse_factory_release_state_transparency_external_gossip_trust_report,
    render_factory_release_state_transparency_external_gossip_trust_report,
};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION: u32 =
    1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCOPE: &str =
    "factory-release-state-transparency-external-gossip-organization-registry-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-transition-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-governance-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_SCOPE:
    &str = "signed-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-organization-registry-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION:
    u32 = 1;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES: u64 =
    256 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES:
    u64 = 16 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES:
    u64 = 16 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_BYTES:
    u64 = 32 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES:
    u64 = 128 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES:
    u64 = 256 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES:
    u64 = 256 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_REPORT_BYTES: u64 =
    128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_REPORT_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_REPORT_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_REPORT_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_REPORT_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT_REPORT_BYTES:
    u64 = 128 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS:
    usize = 4_096;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION: u64 =
    4_096;

const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const TRANSITION_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-external-gossip-organization-registry-transition-v1";
const AUTHORITY_KEY_ROTATION_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1";
const GOVERNANCE_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-external-gossip-organization-registry-governance-v1";
const THRESHOLD_TRANSITION_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1";
const GOVERNANCE_ROTATION_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1";
const GOVERNED_AUTHORITY_KEY_ROTATION_DOMAIN: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1";
const MAXIMUM_GOVERNANCE_AUTHORITIES: usize = 100;
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-report:v1\0";
const AUTHORITY_ROTATION_REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-report:v1\0";
const THRESHOLD_GOVERNANCE_REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-report:v1\0";
const GOVERNANCE_ROTATION_REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-report:v1\0";
const GOVERNED_AUTHORITY_ROTATION_REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-report:v1\0";
const TRANSITION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-transition-filename:v1\0";
const AUTHORITY_KEY_ROTATION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-filename:v1\0";
const THRESHOLD_TRANSITION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-filename:v1\0";
const GOVERNANCE_ROTATION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-filename:v1\0";
const GOVERNED_AUTHORITY_KEY_ROTATION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-filename:v1\0";
const REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-report-filename:v1\0";
const AUTHORITY_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-report-filename:v1\0";
const THRESHOLD_GOVERNANCE_REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-report-filename:v1\0";
const GOVERNANCE_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-report-filename:v1\0";
const GOVERNED_AUTHORITY_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-report-filename:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipOrganizationStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipObserverAdmission {
    pub(crate) observer_id: String,
    pub(crate) observer_trust_state_sha256: String,
    pub(crate) admitted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryEntry {
    pub(crate) organization_id: String,
    pub(crate) status: FactoryReleaseStateTransparencyExternalGossipOrganizationStatus,
    pub(crate) status_since_unix: u64,
    pub(crate) status_reason_sha256: String,
    pub(crate) observers: Vec<FactoryReleaseStateTransparencyExternalGossipObserverAdmission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
    pub(crate) schema_version: u32,
    pub(crate) registry_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) authority_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_governance_sha256: Option<String>,
    pub(crate) last_transition_sha256: Option<String>,
    pub(crate) last_updated_at_unix: Option<u64>,
    pub(crate) organizations:
        Vec<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction {
    AdmitObserver,
    SuspendOrganization,
    RevokeOrganization,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition
{
    pub(crate) schema_version: u32,
    pub(crate) transition_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_transition_sha256: Option<String>,
    pub(crate) action: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    pub(crate) organization_id: String,
    pub(crate) observer_id: Option<String>,
    pub(crate) observer_trust_state_sha256: Option<String>,
    pub(crate) reason_sha256: String,
    pub(crate) effective_at_unix: u64,
    pub(crate) authority_public_key: String,
    pub(crate) algorithm: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation
{
    pub(crate) schema_version: u32,
    pub(crate) rotation_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_transition_sha256: Option<String>,
    pub(crate) old_public_key: String,
    pub(crate) new_public_key: String,
    pub(crate) rotated_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) old_signature: String,
    pub(crate) new_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
    pub(crate) authority_id: String,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance
{
    pub(crate) schema_version: u32,
    pub(crate) governance_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) registry_generation: u64,
    pub(crate) registry_state_sha256: String,
    pub(crate) registry_authority_public_key: String,
    pub(crate) minimum_approvals: u32,
    pub(crate) authorities:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority>,
    pub(crate) issued_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval {
    pub(crate) authority_id: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition
{
    pub(crate) schema_version: u32,
    pub(crate) transition_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_transition_sha256: Option<String>,
    pub(crate) governance_sha256: String,
    pub(crate) governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) action: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    pub(crate) organization_id: String,
    pub(crate) observer_id: Option<String>,
    pub(crate) observer_trust_state_sha256: Option<String>,
    pub(crate) reason_sha256: String,
    pub(crate) effective_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) approvals:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation
{
    pub(crate) schema_version: u32,
    pub(crate) rotation_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_transition_sha256: Option<String>,
    pub(crate) old_governance_sha256: String,
    pub(crate) old_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) new_governance_sha256: String,
    pub(crate) new_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) rotated_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) old_approvals:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>,
    pub(crate) new_approvals:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation
{
    pub(crate) schema_version: u32,
    pub(crate) rotation_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) registry_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_transition_sha256: Option<String>,
    pub(crate) old_public_key: String,
    pub(crate) new_public_key: String,
    pub(crate) old_governance_sha256: String,
    pub(crate) old_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) new_governance_sha256: String,
    pub(crate) new_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) rotated_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) old_approvals:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>,
    pub(crate) new_approvals:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryTransitionEvidence {
    pub(crate) artifact: ExactArtifactIdentity,
    pub(crate) transition:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence {
    OrganizationTransition {
        artifact: ExactArtifactIdentity,
        transition:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
    },
    AuthorityKeyRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence
{
    OrganizationTransition {
        artifact: ExactArtifactIdentity,
        transition:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
    },
    AuthorityKeyRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    },
    ThresholdTransition {
        artifact: ExactArtifactIdentity,
        transition:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence
{
    OrganizationTransition {
        artifact: ExactArtifactIdentity,
        transition:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
    },
    AuthorityKeyRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    },
    ThresholdTransition {
        artifact: ExactArtifactIdentity,
        transition:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition>,
    },
    GovernanceRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence
{
    OrganizationTransition {
        artifact: ExactArtifactIdentity,
        transition:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
    },
    AuthorityKeyRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    },
    ThresholdTransition {
        artifact: ExactArtifactIdentity,
        transition:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition>,
    },
    GovernanceRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation>,
    },
    GovernedAuthorityKeyRotation {
        artifact: ExactArtifactIdentity,
        rotation:
            Box<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation>,
    },
}

pub(crate) type FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent =
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory {
    pub(crate) schema_version: u32,
    pub(crate) initial_registry_artifact: ExactArtifactIdentity,
    pub(crate) initial_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) events:
        Vec<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind {
    OrganizationTransition,
    AuthorityKeyRotation,
    ThresholdTransition,
    GovernanceRotation,
    GovernedAuthorityKeyRotation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditEntry
{
    pub(crate) index: u64,
    pub(crate) kind:
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) artifact: ExactArtifactIdentity,
    pub(crate) event_sha256: String,
    pub(crate) resulting_registry_sha256: String,
    pub(crate) authority_public_key: String,
    pub(crate) active_governance_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport
{
    pub(crate) schema_version: u32,
    pub(crate) registry_id: String,
    pub(crate) initial_registry_artifact: ExactArtifactIdentity,
    pub(crate) initial_registry_sha256: String,
    pub(crate) event_count: u64,
    pub(crate) entries:
        Vec<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditEntry>,
    pub(crate) final_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) final_registry_sha256: String,
    pub(crate) chain_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) registry_genesis_pin_matched: bool,
    pub(crate) complete_registry_history_verified: bool,
    pub(crate) registry_authority_signatures_verified: bool,
    pub(crate) registry_generation_chain_verified: bool,
    pub(crate) registry_digest_chain_verified: bool,
    pub(crate) registry_timestamps_monotonic: bool,
    pub(crate) registry_authority_role_separation_verified: bool,
    pub(crate) current_observer_trust_admissions_verified: bool,
    pub(crate) selected_observer_organizations_active: bool,
    pub(crate) registry_effective_before_quorum_evaluation_verified: bool,
    pub(crate) selected_ledger_latest_registry_verified: bool,
    pub(crate) selected_ledger_observer_trust_report_verified: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_registry_bound_report_committed: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) registry_genesis_artifact: ExactArtifactIdentity,
    pub(crate) registry_genesis_sha256: String,
    pub(crate) registry_genesis: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) registry_transition_count: u32,
    pub(crate) registry_transitions:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryTransitionEvidence>,
    pub(crate) current_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) current_registry_sha256: String,
    pub(crate) observer_trust_report_artifact: ExactArtifactIdentity,
    pub(crate) observer_trust_report:
        FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport
{
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) registry_genesis_pin_matched: bool,
    pub(crate) complete_registry_history_verified: bool,
    pub(crate) registry_authority_transition_signatures_verified: bool,
    pub(crate) registry_authority_rotation_dual_signatures_verified: bool,
    pub(crate) registry_authority_successor_possession_verified: bool,
    pub(crate) registry_authority_key_history_unique: bool,
    pub(crate) registry_generation_chain_verified: bool,
    pub(crate) registry_digest_chain_verified: bool,
    pub(crate) registry_timestamps_monotonic: bool,
    pub(crate) registry_authority_role_separation_verified: bool,
    pub(crate) current_observer_trust_admissions_verified: bool,
    pub(crate) selected_observer_organizations_active: bool,
    pub(crate) registry_effective_before_quorum_evaluation_verified: bool,
    pub(crate) selected_ledger_latest_registry_verified: bool,
    pub(crate) selected_ledger_observer_trust_report_verified: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_registry_bound_report_committed: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) authority_threshold_governance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) registry_genesis_artifact: ExactArtifactIdentity,
    pub(crate) registry_genesis_sha256: String,
    pub(crate) registry_genesis: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) registry_history_event_count: u32,
    pub(crate) registry_authority_rotation_count: u32,
    pub(crate) registry_history_events:
        Vec<FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence>,
    pub(crate) current_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) current_registry_sha256: String,
    pub(crate) observer_trust_report_artifact: ExactArtifactIdentity,
    pub(crate) observer_trust_report:
        FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport
{
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) registry_genesis_pin_matched: bool,
    pub(crate) complete_registry_history_verified: bool,
    pub(crate) registry_authority_transition_signatures_verified: bool,
    pub(crate) registry_authority_rotation_dual_signatures_verified: bool,
    pub(crate) registry_authority_successor_possession_verified: bool,
    pub(crate) registry_authority_key_history_unique: bool,
    pub(crate) governance_root_signature_verified: bool,
    pub(crate) governance_authority_identities_unique: bool,
    pub(crate) governance_authority_keys_unique: bool,
    pub(crate) governance_threshold_approvals_verified: bool,
    pub(crate) root_only_registry_mutations_locked_out: bool,
    pub(crate) registry_generation_chain_verified: bool,
    pub(crate) registry_digest_chain_verified: bool,
    pub(crate) registry_timestamps_monotonic: bool,
    pub(crate) registry_authority_role_separation_verified: bool,
    pub(crate) current_observer_trust_admissions_verified: bool,
    pub(crate) selected_observer_organizations_active: bool,
    pub(crate) registry_effective_before_quorum_evaluation_verified: bool,
    pub(crate) selected_ledger_latest_registry_verified: bool,
    pub(crate) selected_ledger_observer_trust_report_verified: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_registry_bound_report_committed: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) authority_threshold_governance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) registry_genesis_artifact: ExactArtifactIdentity,
    pub(crate) registry_genesis_sha256: String,
    pub(crate) registry_genesis: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) registry_history_event_count: u32,
    pub(crate) registry_authority_rotation_count: u32,
    pub(crate) registry_threshold_transition_count: u32,
    pub(crate) registry_history_events: Vec<
        FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence,
    >,
    pub(crate) active_governance_sha256: String,
    pub(crate) active_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) current_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) current_registry_sha256: String,
    pub(crate) observer_trust_report_artifact: ExactArtifactIdentity,
    pub(crate) observer_trust_report:
        FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport
{
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) registry_genesis_pin_matched: bool,
    pub(crate) complete_registry_history_verified: bool,
    pub(crate) registry_authority_transition_signatures_verified: bool,
    pub(crate) registry_authority_rotation_dual_signatures_verified: bool,
    pub(crate) registry_authority_successor_possession_verified: bool,
    pub(crate) registry_authority_key_history_unique: bool,
    pub(crate) governance_root_signatures_verified: bool,
    pub(crate) governance_authority_identities_unique: bool,
    pub(crate) governance_authority_keys_unique: bool,
    pub(crate) governance_threshold_approvals_verified: bool,
    pub(crate) governance_rotation_old_quorum_verified: bool,
    pub(crate) governance_rotation_new_quorum_verified: bool,
    pub(crate) successor_governance_state_binding_verified: bool,
    pub(crate) root_only_registry_mutations_locked_out: bool,
    pub(crate) registry_generation_chain_verified: bool,
    pub(crate) registry_digest_chain_verified: bool,
    pub(crate) registry_timestamps_monotonic: bool,
    pub(crate) registry_authority_role_separation_verified: bool,
    pub(crate) current_observer_trust_admissions_verified: bool,
    pub(crate) selected_observer_organizations_active: bool,
    pub(crate) registry_effective_before_quorum_evaluation_verified: bool,
    pub(crate) selected_ledger_latest_registry_verified: bool,
    pub(crate) selected_ledger_observer_trust_report_verified: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_registry_bound_report_committed: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) authority_threshold_governance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_governance_control_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) registry_genesis_artifact: ExactArtifactIdentity,
    pub(crate) registry_genesis_sha256: String,
    pub(crate) registry_genesis: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) registry_history_event_count: u32,
    pub(crate) registry_authority_rotation_count: u32,
    pub(crate) registry_threshold_transition_count: u32,
    pub(crate) registry_governance_rotation_count: u32,
    pub(crate) registry_history_events: Vec<
        FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence,
    >,
    pub(crate) active_governance_sha256: String,
    pub(crate) active_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) current_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) current_registry_sha256: String,
    pub(crate) observer_trust_report_artifact: ExactArtifactIdentity,
    pub(crate) observer_trust_report:
        FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport
{
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) registry_genesis_pin_matched: bool,
    pub(crate) complete_registry_history_verified: bool,
    pub(crate) registry_authority_transition_signatures_verified: bool,
    pub(crate) registry_authority_rotation_dual_signatures_verified: bool,
    pub(crate) registry_authority_successor_possession_verified: bool,
    pub(crate) registry_authority_key_history_unique: bool,
    pub(crate) governance_root_signatures_verified: bool,
    pub(crate) governance_authority_identities_unique: bool,
    pub(crate) governance_authority_keys_unique: bool,
    pub(crate) governance_threshold_approvals_verified: bool,
    pub(crate) governance_rotation_old_quorum_verified: bool,
    pub(crate) governance_rotation_new_quorum_verified: bool,
    pub(crate) successor_governance_state_binding_verified: bool,
    pub(crate) governed_authority_rotation_old_quorum_verified: bool,
    pub(crate) governed_authority_rotation_new_quorum_verified: bool,
    pub(crate) successor_registry_root_possession_verified: bool,
    pub(crate) registry_root_and_governance_rotated_atomically: bool,
    pub(crate) root_only_registry_mutations_locked_out: bool,
    pub(crate) registry_generation_chain_verified: bool,
    pub(crate) registry_digest_chain_verified: bool,
    pub(crate) registry_timestamps_monotonic: bool,
    pub(crate) registry_authority_role_separation_verified: bool,
    pub(crate) current_observer_trust_admissions_verified: bool,
    pub(crate) selected_observer_organizations_active: bool,
    pub(crate) registry_effective_before_quorum_evaluation_verified: bool,
    pub(crate) selected_ledger_latest_registry_verified: bool,
    pub(crate) selected_ledger_observer_trust_report_verified: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_registry_bound_report_committed: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) authority_threshold_governance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_governance_control_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) registry_genesis_artifact: ExactArtifactIdentity,
    pub(crate) registry_genesis_sha256: String,
    pub(crate) registry_genesis: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) registry_history_event_count: u32,
    pub(crate) registry_authority_rotation_count: u32,
    pub(crate) registry_threshold_transition_count: u32,
    pub(crate) registry_governance_rotation_count: u32,
    pub(crate) registry_governed_authority_rotation_count: u32,
    pub(crate) registry_history_events: Vec<
        FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence,
    >,
    pub(crate) active_governance_sha256: String,
    pub(crate) active_governance:
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    pub(crate) current_registry: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    pub(crate) current_registry_sha256: String,
    pub(crate) observer_trust_report_artifact: ExactArtifactIdentity,
    pub(crate) observer_trust_report:
        FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct TransitionPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    transition_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    action: &'a FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &'a str,
    observer_id: Option<&'a str>,
    observer_trust_state_sha256: Option<&'a str>,
    reason_sha256: &'a str,
    effective_at_unix: u64,
    authority_public_key: &'a str,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct AuthorityKeyRotationPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    rotation_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct GovernancePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    governance_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    registry_generation: u64,
    registry_state_sha256: &'a str,
    registry_authority_public_key: &'a str,
    minimum_approvals: u32,
    authorities: &'a [FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority],
    issued_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct ThresholdTransitionPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    transition_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    governance_sha256: &'a str,
    action: &'a FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &'a str,
    observer_id: Option<&'a str>,
    observer_trust_state_sha256: Option<&'a str>,
    reason_sha256: &'a str,
    effective_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct GovernanceRotationPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    rotation_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_governance_sha256: &'a str,
    new_governance_sha256: &'a str,
    rotated_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct GovernedAuthorityKeyRotationPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    rotation_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    old_governance_sha256: &'a str,
    new_governance_sha256: &'a str,
    rotated_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct TransitionFilenameContext<'a> {
    registry_genesis_sha256: &'a str,
    base_observer_quorum_policy_sha256: &'a str,
    registry_id: &'a str,
}

#[derive(Serialize)]
struct ReportFilenameContext<'a> {
    observer_trust_binding_sha256: &'a str,
    registry_genesis_sha256: &'a str,
    current_registry_sha256: &'a str,
    registry_generation: u64,
}

pub(crate) fn new_factory_release_state_transparency_external_gossip_organization_registry(
    base_policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    expected_base_policy_sha256: &str,
    registry_id: &str,
    authority_public_key: &[u8; 32],
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    let actual =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(base_policy)?;
    if actual != expected_base_policy_sha256 {
        return Err(
            "factory release transparency external gossip registry base observer policy pin does not match"
                .into(),
        );
    }
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    let authority_public_key = hex::encode(authority_public_key);
    validate_nonweak_public_key(
        &authority_public_key,
        "factory release transparency external gossip registry authority public key",
    )?;
    if base_policy
        .trusted_observers
        .iter()
        .any(|observer| observer.public_key == authority_public_key)
    {
        return Err(
            "factory release transparency external gossip registry authority key must be role-disjoint from every observer key"
                .into(),
        );
    }
    let registry = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        registry_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCOPE.into(),
        base_observer_quorum_policy_sha256: actual,
        policy_id: base_policy.policy_id.clone(),
        registry_id: registry_id.into(),
        generation: 0,
        authority_public_key,
        active_governance_sha256: None,
        last_transition_sha256: None,
        last_updated_at_unix: None,
        organizations: Vec::new(),
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&registry)?;
    Ok(registry)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    authority_secret_key: &[u8; 32],
    action: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&FactoryReleaseStateTransparencyExternalGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition, String>
{
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "factory release transparency external gossip registry with active governance rejects root-only transitions"
                .into(),
        );
    }
    validate_slug(
        organization_id,
        "factory release transparency external gossip registry organization id",
    )?;
    validate_digest(
        reason_sha256,
        "factory release transparency external gossip registry transition reason SHA-256",
    )?;
    if effective_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry transition time is outside its bound"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| effective_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip registry transition timestamps must be monotonic"
                .into(),
        );
    }
    let authority = SigningKey::from_bytes(authority_secret_key);
    let authority_public_key = hex::encode(authority.verifying_key().to_bytes());
    if authority_public_key != registry.authority_public_key {
        return Err(
            "factory release transparency external gossip registry authority key does not match the current registry"
                .into(),
        );
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(registry, &action, organization_id, observer_trust_state)?;
    let to_generation = registry
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip registry generation is exhausted"
                .to_string()
        })?;
    let payload = transition_payload(
        registry,
        to_generation,
        &action,
        organization_id,
        observer_id.as_deref(),
        observer_trust_state_sha256.as_deref(),
        reason_sha256,
        effective_at_unix,
    )?;
    let transition =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            transition_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
            policy_id: registry.policy_id.clone(),
            registry_id: registry.registry_id.clone(),
            from_generation: registry.generation,
            to_generation,
            previous_transition_sha256: registry.last_transition_sha256.clone(),
            action,
            organization_id: organization_id.into(),
            observer_id,
            observer_trust_state_sha256,
            reason_sha256: reason_sha256.into(),
            effective_at_unix,
            authority_public_key,
            algorithm: "ed25519".into(),
            signature: hex::encode(authority.sign(&payload).to_bytes()),
        };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
        &transition,
    )?;
    Ok(transition)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "factory release transparency external gossip registry with active governance rejects root-only transitions"
                .into(),
        );
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
        transition,
    )?;
    let expected_generation = registry.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip registry generation overflow".to_string()
    })?;
    if transition.base_observer_quorum_policy_sha256 != registry.base_observer_quorum_policy_sha256
        || transition.policy_id != registry.policy_id
        || transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.to_generation != expected_generation
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.authority_public_key != registry.authority_public_key
    {
        return Err(
            "factory release transparency external gossip registry transition does not extend the selected state"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| transition.effective_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip registry transition timestamps must be monotonic"
                .into(),
        );
    }
    let payload = transition_payload(
        registry,
        transition.to_generation,
        &transition.action,
        &transition.organization_id,
        transition.observer_id.as_deref(),
        transition.observer_trust_state_sha256.as_deref(),
        &transition.reason_sha256,
        transition.effective_at_unix,
    )?;
    let public_key = decode_hex::<32>(
        &transition.authority_public_key,
        "factory release transparency external gossip registry authority public key",
    )?;
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &transition.signature,
        "factory release transparency external gossip registry authority signature",
    )?);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip registry authority public key: {error}"
            )
        })?
        .verify_strict(&payload, &signature)
        .map_err(|_| {
            "factory release transparency external gossip registry transition signature verification failed"
                .to_string()
        })?;

    let mut organizations = registry.organizations.clone();
    apply_action(&mut organizations, transition)?;
    let next = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: registry.schema_version,
        registry_scope: registry.registry_scope.clone(),
        base_observer_quorum_policy_sha256: registry
            .base_observer_quorum_policy_sha256
            .clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_organization_registry_transition_sha256(
                transition,
            )?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&next)?;
    Ok(next)
}

pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    old_authority_secret_key: &[u8; 32],
    new_authority_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    String,
> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "factory release transparency external gossip registry with active governance rejects root-only authority rotation"
                .into(),
        );
    }
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry authority rotation time is outside its bound"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip registry authority rotation timestamps must be monotonic"
                .into(),
        );
    }
    let old_authority = SigningKey::from_bytes(old_authority_secret_key);
    let new_authority = SigningKey::from_bytes(new_authority_secret_key);
    let old_public_key = hex::encode(old_authority.verifying_key().to_bytes());
    let new_public_key = hex::encode(new_authority.verifying_key().to_bytes());
    validate_nonweak_public_key(
        &old_public_key,
        "old factory release transparency external gossip registry authority public key",
    )?;
    validate_nonweak_public_key(
        &new_public_key,
        "new factory release transparency external gossip registry authority public key",
    )?;
    if old_public_key != registry.authority_public_key {
        return Err(
            "old factory release transparency external gossip registry authority key does not match the current registry"
                .into(),
        );
    }
    if new_public_key == old_public_key {
        return Err(
            "new factory release transparency external gossip registry authority key must differ from the current key"
                .into(),
        );
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip registry generation is exhausted"
                .to_string()
        })?;
    let payload = authority_key_rotation_payload(
        registry,
        to_generation,
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            rotation_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
            policy_id: registry.policy_id.clone(),
            registry_id: registry.registry_id.clone(),
            from_generation: registry.generation,
            to_generation,
            previous_transition_sha256: registry.last_transition_sha256.clone(),
            old_public_key,
            new_public_key,
            rotated_at_unix,
            algorithm: "ed25519".into(),
            old_signature: hex::encode(old_authority.sign(&payload).to_bytes()),
            new_signature: hex::encode(new_authority.sign(&payload).to_bytes()),
        };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "factory release transparency external gossip registry with active governance rejects root-only authority rotation"
                .into(),
        );
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
        rotation,
    )?;
    let expected_generation = registry.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip registry generation overflow".to_string()
    })?;
    if rotation.base_observer_quorum_policy_sha256 != registry.base_observer_quorum_policy_sha256
        || rotation.policy_id != registry.policy_id
        || rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_public_key != registry.authority_public_key
        || rotation.new_public_key == registry.authority_public_key
    {
        return Err(
            "factory release transparency external gossip registry authority rotation does not extend the selected state"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip registry authority rotation timestamps must be monotonic"
                .into(),
        );
    }
    let payload = authority_key_rotation_payload(
        registry,
        rotation.to_generation,
        &rotation.old_public_key,
        &rotation.new_public_key,
        rotation.rotated_at_unix,
    )?;
    for (public_key, signature, label) in [
        (
            &rotation.old_public_key,
            &rotation.old_signature,
            "old factory release transparency external gossip registry authority rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new factory release transparency external gossip registry authority rotation",
        ),
    ] {
        let public_key = decode_hex::<32>(public_key, label)?;
        let signature = Signature::from_bytes(&decode_hex::<64>(signature, label)?);
        VerifyingKey::from_bytes(&public_key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let next = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: registry.schema_version,
        registry_scope: registry.registry_scope.clone(),
        base_observer_quorum_policy_sha256: registry
            .base_observer_quorum_policy_sha256
            .clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: rotation.new_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&next)?;
    Ok(next)
}

pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance, String>
{
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "factory release transparency external gossip registry already has active governance"
                .into(),
        );
    }
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "factory release transparency external gossip registry governance minimum approvals must be between 2 and 100"
                .into(),
        );
    }
    if issued_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry governance issue time is outside its bound"
                .into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err(
            "factory release transparency external gossip registry governance has fewer authorities than its threshold"
                .into(),
        );
    }
    let signing_key = SigningKey::from_bytes(registry_authority_secret_key);
    let registry_authority_public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if registry_authority_public_key != registry.authority_public_key {
        return Err(
            "factory release transparency external gossip registry governance signer does not match retained authority"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip registry governance predates retained state"
                .into(),
        );
    }
    let payload = governance_payload(
        &registry.base_observer_quorum_policy_sha256,
        &registry.policy_id,
        &registry.registry_id,
        registry.generation,
        &factory_release_state_transparency_external_gossip_organization_registry_sha256(registry)?,
        &registry_authority_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            governance_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
            policy_id: registry.policy_id.clone(),
            registry_id: registry.registry_id.clone(),
            registry_generation: registry.generation,
            registry_state_sha256:
                factory_release_state_transparency_external_gossip_organization_registry_sha256(
                    registry,
                )?,
            registry_authority_public_key,
            minimum_approvals,
            authorities,
            issued_at_unix,
            algorithm: "ed25519".into(),
            signature: hex::encode(signing_key.sign(&payload).to_bytes()),
        };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &governance,
    )?;
    Ok(governance)
}

pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_successor_governance(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance, String>
{
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_none() {
        return Err(
            "factory release transparency external gossip successor governance requires retained active governance"
                .into(),
        );
    }
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "factory release transparency external gossip registry governance minimum approvals must be between 2 and 100"
                .into(),
        );
    }
    if issued_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry governance issue time is outside its bound"
                .into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err(
            "factory release transparency external gossip registry governance has fewer authorities than its threshold"
                .into(),
        );
    }
    let signing_key = SigningKey::from_bytes(registry_authority_secret_key);
    let registry_authority_public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if registry_authority_public_key != registry.authority_public_key {
        return Err(
            "factory release transparency external gossip successor governance signer does not match retained authority"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip successor governance predates retained state"
                .into(),
        );
    }
    let registry_state_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(registry)?;
    let payload = governance_payload(
        &registry.base_observer_quorum_policy_sha256,
        &registry.policy_id,
        &registry.registry_id,
        registry.generation,
        &registry_state_sha256,
        &registry_authority_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            governance_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
            policy_id: registry.policy_id.clone(),
            registry_id: registry.registry_id.clone(),
            registry_generation: registry.generation,
            registry_state_sha256,
            registry_authority_public_key,
            minimum_approvals,
            authorities,
            issued_at_unix,
            algorithm: "ed25519".into(),
            signature: hex::encode(signing_key.sign(&payload).to_bytes()),
        };
    validate_successor_governance_for_registry(registry, &governance)?;
    Ok(governance)
}

pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_successor_root_governance(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    successor_registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance, String>
{
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_none() {
        return Err(
            "factory release transparency external gossip successor-root governance requires retained active governance"
                .into(),
        );
    }
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "factory release transparency external gossip registry governance minimum approvals must be between 2 and 100"
                .into(),
        );
    }
    if issued_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry governance issue time is outside its bound"
                .into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err(
            "factory release transparency external gossip registry governance has fewer authorities than its threshold"
                .into(),
        );
    }
    let signing_key = SigningKey::from_bytes(successor_registry_authority_secret_key);
    let registry_authority_public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if registry_authority_public_key == registry.authority_public_key {
        return Err(
            "factory release transparency external gossip successor governance root must differ from retained registry root"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip successor-root governance predates retained state"
                .into(),
        );
    }
    let registry_state_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(registry)?;
    let payload = governance_payload(
        &registry.base_observer_quorum_policy_sha256,
        &registry.policy_id,
        &registry.registry_id,
        registry.generation,
        &registry_state_sha256,
        &registry_authority_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            governance_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
            policy_id: registry.policy_id.clone(),
            registry_id: registry.registry_id.clone(),
            registry_generation: registry.generation,
            registry_state_sha256,
            registry_authority_public_key,
            minimum_approvals,
            authorities,
            issued_at_unix,
            algorithm: "ed25519".into(),
            signature: hex::encode(signing_key.sign(&payload).to_bytes()),
        };
    validate_successor_root_governance_for_registry(registry, &governance)?;
    Ok(governance)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    signers: &[(String, [u8; 32])],
    action: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&FactoryReleaseStateTransparencyExternalGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
    String,
> {
    validate_governance_for_registry(registry, governance)?;
    validate_slug(
        organization_id,
        "factory release transparency external gossip registry organization id",
    )?;
    validate_digest(
        reason_sha256,
        "factory release transparency external gossip registry threshold transition reason SHA-256",
    )?;
    if effective_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry threshold transition time is outside its bound"
                .into(),
        );
    }
    if effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| effective_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip registry threshold transition timestamps must be monotonic"
                .into(),
        );
    }
    if signers.len() < governance.minimum_approvals as usize
        || signers.len() > governance.authorities.len()
    {
        return Err(
            "factory release transparency external gossip registry threshold transition does not satisfy its threshold"
                .into(),
        );
    }
    let governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            governance,
        )?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err(
            "factory release transparency external gossip registry governance does not match retained active governance"
                .into(),
        );
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(registry, &action, organization_id, observer_trust_state)?;
    let to_generation = registry
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip registry generation is exhausted"
                .to_string()
        })?;
    let payload = threshold_transition_payload(
        registry,
        to_generation,
        &governance_sha256,
        &action,
        organization_id,
        observer_id.as_deref(),
        observer_trust_state_sha256.as_deref(),
        reason_sha256,
        effective_at_unix,
    )?;
    let mut seen_ids = HashSet::new();
    let mut seen_keys = HashSet::new();
    let mut approvals = Vec::with_capacity(signers.len());
    for (authority_id, secret_key) in signers {
        if !seen_ids.insert(authority_id.as_str()) {
            return Err(
                "duplicate factory release transparency external gossip registry governance authority identity"
                    .into(),
            );
        }
        let signing_key = SigningKey::from_bytes(secret_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        if !seen_keys.insert(public_key.clone()) {
            return Err(
                "duplicate factory release transparency external gossip registry governance authority key"
                    .into(),
            );
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.as_str().cmp(authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                format!(
                    "untrusted factory release transparency external gossip registry governance authority {authority_id:?}"
                )
            })?;
        if trusted.public_key != public_key {
            return Err(format!(
                "factory release transparency external gossip registry governance authority {authority_id:?} key does not match governance"
            ));
        }
        approvals.push(
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval {
                authority_id: authority_id.clone(),
                public_key,
                signature: hex::encode(signing_key.sign(&payload).to_bytes()),
            },
        );
    }
    approvals.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    let transition = SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        transition_scope: SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_SCOPE.into(),
        base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        governance_sha256,
        governance: governance.clone(),
        action,
        organization_id: organization_id.into(),
        observer_id,
        observer_trust_state_sha256,
        reason_sha256: reason_sha256.into(),
        effective_at_unix,
        algorithm: "ed25519".into(),
        approvals,
    };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
        &transition,
    )?;
    Ok(transition)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
        transition,
    )?;
    let governance = &transition.governance;
    validate_governance_for_registry(registry, governance)?;
    let governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            governance,
        )?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err(
            "factory release transparency external gossip registry governance does not match retained active governance"
                .into(),
        );
    }
    let expected_generation = registry.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip registry generation overflow".to_string()
    })?;
    if transition.base_observer_quorum_policy_sha256 != registry.base_observer_quorum_policy_sha256
        || transition.policy_id != registry.policy_id
        || transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.to_generation != expected_generation
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.governance_sha256 != governance_sha256
    {
        return Err(
            "factory release transparency external gossip registry threshold transition does not extend the selected state"
                .into(),
        );
    }
    if transition.effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| transition.effective_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip registry threshold transition timestamps must be monotonic"
                .into(),
        );
    }
    if transition.approvals.len() < governance.minimum_approvals as usize
        || transition.approvals.len() > governance.authorities.len()
    {
        return Err(
            "factory release transparency external gossip registry threshold transition has an invalid approval count"
                .into(),
        );
    }
    let payload = threshold_transition_payload(
        registry,
        transition.to_generation,
        &transition.governance_sha256,
        &transition.action,
        &transition.organization_id,
        transition.observer_id.as_deref(),
        transition.observer_trust_state_sha256.as_deref(),
        &transition.reason_sha256,
        transition.effective_at_unix,
    )?;
    let mut previous_id: Option<&String> = None;
    let mut seen_keys = HashSet::new();
    for approval in &transition.approvals {
        if previous_id.is_some_and(|id| id >= &approval.authority_id) {
            return Err(
                "factory release transparency external gossip registry threshold approvals must be unique and ordered"
                    .into(),
            );
        }
        previous_id = Some(&approval.authority_id);
        if !seen_keys.insert(approval.public_key.as_str()) {
            return Err(
                "factory release transparency external gossip registry threshold approvals require distinct keys"
                    .into(),
            );
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.cmp(&approval.authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                "untrusted factory release transparency external gossip registry threshold approval"
                    .to_string()
            })?;
        if trusted.public_key != approval.public_key {
            return Err(
                "factory release transparency external gossip registry threshold approval key substitution"
                    .into(),
            );
        }
        let public_key = decode_hex::<32>(
            &approval.public_key,
            "factory release transparency external gossip registry governance approval public key",
        )?;
        let signature = Signature::from_bytes(&decode_hex::<64>(
            &approval.signature,
            "factory release transparency external gossip registry governance approval signature",
        )?);
        VerifyingKey::from_bytes(&public_key)
            .map_err(|error| format!("invalid governance approval public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| {
                "factory release transparency external gossip registry threshold approval verification failed"
                    .to_string()
            })?;
    }
    let compatibility_transition =
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition {
            schema_version: transition.schema_version,
            transition_scope:
                SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE
                    .into(),
            base_observer_quorum_policy_sha256: transition
                .base_observer_quorum_policy_sha256
                .clone(),
            policy_id: transition.policy_id.clone(),
            registry_id: transition.registry_id.clone(),
            from_generation: transition.from_generation,
            to_generation: transition.to_generation,
            previous_transition_sha256: transition.previous_transition_sha256.clone(),
            action: transition.action.clone(),
            organization_id: transition.organization_id.clone(),
            observer_id: transition.observer_id.clone(),
            observer_trust_state_sha256: transition.observer_trust_state_sha256.clone(),
            reason_sha256: transition.reason_sha256.clone(),
            effective_at_unix: transition.effective_at_unix,
            authority_public_key: registry.authority_public_key.clone(),
            algorithm: "ed25519".into(),
            signature: "00".repeat(64),
        };
    let mut organizations = registry.organizations.clone();
    apply_action(&mut organizations, &compatibility_transition)?;
    let next = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: registry.schema_version,
        registry_scope: registry.registry_scope.clone(),
        base_observer_quorum_policy_sha256: registry
            .base_observer_quorum_policy_sha256
            .clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: Some(governance_sha256),
        last_transition_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_sha256(
                transition,
            )?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    old_governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    new_governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    old_signers: &[(String, [u8; 32])],
    new_signers: &[(String, [u8; 32])],
    rotated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
    String,
> {
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_governance_for_registry(registry, new_governance)?;
    if old_governance.minimum_approvals == new_governance.minimum_approvals
        && old_governance.authorities == new_governance.authorities
    {
        return Err(
            "factory release transparency external gossip successor governance must change its threshold or authorities"
                .into(),
        );
    }
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            new_governance,
        )?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str()) {
        return Err(
            "factory release transparency external gossip old governance does not match retained active governance"
                .into(),
        );
    }
    if old_governance_sha256 == new_governance_sha256 {
        return Err(
            "factory release transparency external gossip successor governance must differ".into(),
        );
    }
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip governance rotation time is outside its bound"
                .into(),
        );
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotated_at_unix < new_governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| new_governance.issued_at_unix < last || rotated_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip governance rotation timestamps must be monotonic"
                .into(),
        );
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip registry generation is exhausted"
                .to_string()
        })?;
    let payload = governance_rotation_payload(
        registry,
        to_generation,
        &old_governance_sha256,
        &new_governance_sha256,
        rotated_at_unix,
    )?;
    let rotation = SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        rotation_scope: SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_SCOPE.into(),
        base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        old_governance_sha256,
        old_governance: old_governance.clone(),
        new_governance_sha256,
        new_governance: new_governance.clone(),
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_approvals: sign_governance_approvals(old_governance, old_signers, &payload, "old")?,
        new_approvals: sign_governance_approvals(new_governance, new_signers, &payload, "new")?,
    };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
        rotation,
    )?;
    let old_governance = &rotation.old_governance;
    let new_governance = &rotation.new_governance;
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_governance_for_registry(registry, new_governance)?;
    if old_governance.minimum_approvals == new_governance.minimum_approvals
        && old_governance.authorities == new_governance.authorities
    {
        return Err(
            "factory release transparency external gossip successor governance must change its threshold or authorities"
                .into(),
        );
    }
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            new_governance,
        )?;
    let expected_generation = registry.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip registry generation overflow".to_string()
    })?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str())
        || rotation.base_observer_quorum_policy_sha256
            != registry.base_observer_quorum_policy_sha256
        || rotation.policy_id != registry.policy_id
        || rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_governance_sha256 != old_governance_sha256
        || rotation.new_governance_sha256 != new_governance_sha256
    {
        return Err(
            "factory release transparency external gossip governance rotation does not extend the selected state"
                .into(),
        );
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotation.rotated_at_unix < new_governance.issued_at_unix
        || registry.last_updated_at_unix.is_some_and(|last| {
            new_governance.issued_at_unix < last || rotation.rotated_at_unix < last
        })
    {
        return Err(
            "factory release transparency external gossip governance rotation timestamps must be monotonic"
                .into(),
        );
    }
    let payload = governance_rotation_payload(
        registry,
        rotation.to_generation,
        &rotation.old_governance_sha256,
        &rotation.new_governance_sha256,
        rotation.rotated_at_unix,
    )?;
    verify_governance_approvals(old_governance, &rotation.old_approvals, &payload, "old")?;
    verify_governance_approvals(new_governance, &rotation.new_approvals, &payload, "new")?;
    let next = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: registry.schema_version,
        registry_scope: registry.registry_scope.clone(),
        base_observer_quorum_policy_sha256: registry
            .base_observer_quorum_policy_sha256
            .clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: Some(new_governance_sha256),
        last_transition_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    old_governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    new_governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    old_signers: &[(String, [u8; 32])],
    new_signers: &[(String, [u8; 32])],
    rotated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
    String,
>{
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_root_governance_for_registry(registry, new_governance)?;
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            new_governance,
        )?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str()) {
        return Err(
            "factory release transparency external gossip old governance does not match retained active governance"
                .into(),
        );
    }
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip governed authority rotation time is outside its bound"
                .into(),
        );
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotated_at_unix < new_governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| new_governance.issued_at_unix < last || rotated_at_unix < last)
    {
        return Err(
            "factory release transparency external gossip governed authority rotation timestamps must be monotonic"
                .into(),
        );
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip registry generation is exhausted"
                .to_string()
        })?;
    let payload = governed_authority_key_rotation_payload(
        registry,
        to_generation,
        &registry.authority_public_key,
        &new_governance.registry_authority_public_key,
        &old_governance_sha256,
        &new_governance_sha256,
        rotated_at_unix,
    )?;
    let rotation = SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        rotation_scope: SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_SCOPE.into(),
        base_observer_quorum_policy_sha256: registry.base_observer_quorum_policy_sha256.clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        old_public_key: registry.authority_public_key.clone(),
        new_public_key: new_governance.registry_authority_public_key.clone(),
        old_governance_sha256,
        old_governance: old_governance.clone(),
        new_governance_sha256,
        new_governance: new_governance.clone(),
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_approvals: sign_governance_approvals(old_governance, old_signers, &payload, "old")?,
        new_approvals: sign_governance_approvals(new_governance, new_signers, &payload, "new")?,
    };
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
        rotation,
    )?;
    let old_governance = &rotation.old_governance;
    let new_governance = &rotation.new_governance;
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_root_governance_for_registry(registry, new_governance)?;
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            new_governance,
        )?;
    let expected_generation = registry.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip registry generation overflow".to_string()
    })?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str())
        || rotation.base_observer_quorum_policy_sha256
            != registry.base_observer_quorum_policy_sha256
        || rotation.policy_id != registry.policy_id
        || rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_public_key != registry.authority_public_key
        || rotation.new_public_key != new_governance.registry_authority_public_key
        || rotation.old_governance_sha256 != old_governance_sha256
        || rotation.new_governance_sha256 != new_governance_sha256
    {
        return Err(
            "factory release transparency external gossip governed authority rotation does not extend the selected state"
                .into(),
        );
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotation.rotated_at_unix < new_governance.issued_at_unix
        || registry.last_updated_at_unix.is_some_and(|last| {
            new_governance.issued_at_unix < last || rotation.rotated_at_unix < last
        })
    {
        return Err(
            "factory release transparency external gossip governed authority rotation timestamps must be monotonic"
                .into(),
        );
    }
    let payload = governed_authority_key_rotation_payload(
        registry,
        rotation.to_generation,
        &rotation.old_public_key,
        &rotation.new_public_key,
        &rotation.old_governance_sha256,
        &rotation.new_governance_sha256,
        rotation.rotated_at_unix,
    )?;
    verify_governance_approvals(old_governance, &rotation.old_approvals, &payload, "old")?;
    verify_governance_approvals(new_governance, &rotation.new_approvals, &payload, "new")?;
    let next = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry {
        schema_version: registry.schema_version,
        registry_scope: registry.registry_scope.clone(),
        base_observer_quorum_policy_sha256: registry
            .base_observer_quorum_policy_sha256
            .clone(),
        policy_id: registry.policy_id.clone(),
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: rotation.new_public_key.clone(),
        active_governance_sha256: Some(new_governance_sha256),
        last_transition_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_factory_release_state_transparency_external_gossip_organization_registry(&next)?;
    Ok(next)
}

pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_organization_registry(
    registry_genesis_source: &[u8],
    expected_registry_genesis_sha256: &str,
    registry_transition_sources: &[Vec<u8>],
    observer_trust_report_source: &[u8],
    selected_ledger_latest_registry_verified: bool,
    selected_ledger_observer_trust_report_verified: bool,
) -> Result<FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport, String> {
    if !selected_ledger_latest_registry_verified {
        return Err(
            "factory release transparency external gossip registry verification requires the latest selected-ledger registry"
                .into(),
        );
    }
    if !selected_ledger_observer_trust_report_verified {
        return Err(
            "factory release transparency external gossip registry verification requires the exact selected-ledger observer trust report"
                .into(),
        );
    }
    if registry_transition_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its transition bound"
                .into(),
        );
    }
    let registry_genesis =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            registry_genesis_source,
        )?;
    if registry_genesis.generation != 0 {
        return Err(
            "factory release transparency external gossip registry genesis must be generation zero"
                .into(),
        );
    }
    let actual_registry_genesis_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &registry_genesis,
        )?;
    if actual_registry_genesis_sha256 != expected_registry_genesis_sha256 {
        return Err(
            "factory release transparency external gossip registry genesis pin does not match"
                .into(),
        );
    }
    let mut current_registry = registry_genesis.clone();
    let mut transition_evidence = Vec::with_capacity(registry_transition_sources.len());
    for source in registry_transition_sources {
        let transition = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(source)?;
        current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &current_registry,
            &transition,
        )?;
        transition_evidence.push(
            FactoryReleaseStateTransparencyExternalGossipRegistryTransitionEvidence {
                artifact: exact_identity(source),
                transition,
            },
        );
    }
    let observer_trust_report =
        parse_factory_release_state_transparency_external_gossip_trust_report(
            observer_trust_report_source,
        )?;
    if observer_trust_report.base_observer_quorum_policy_sha256
        != current_registry.base_observer_quorum_policy_sha256
        || observer_trust_report.base_observer_quorum_policy.policy_id != current_registry.policy_id
    {
        return Err(
            "factory release transparency external gossip registry does not bind the observer trust report base policy"
                .into(),
        );
    }
    if current_registry
        .last_updated_at_unix
        .is_some_and(|updated| updated > observer_trust_report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry is newer than the observer trust quorum evaluation"
                .into(),
        );
    }
    validate_registry_authority_role_separation(&current_registry, &observer_trust_report)?;
    validate_selected_member_admissions(&current_registry, &observer_trust_report)?;

    let registry_transition_count = u32::try_from(transition_evidence.len()).map_err(|_| {
        "factory release transparency external gossip registry transition count overflow"
            .to_string()
    })?;
    let current_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &current_registry,
        )?;
    let mut report = FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        verification_scope:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_VERIFICATION_SCOPE.into(),
        status: if observer_trust_report.quorum_met {
            "verified"
        } else {
            "insufficient_organizations"
        }
        .into(),
        registry_genesis_pin_matched: true,
        complete_registry_history_verified: true,
        registry_authority_signatures_verified: true,
        registry_generation_chain_verified: true,
        registry_digest_chain_verified: true,
        registry_timestamps_monotonic: true,
        registry_authority_role_separation_verified: true,
        current_observer_trust_admissions_verified: true,
        selected_observer_organizations_active: true,
        registry_effective_before_quorum_evaluation_verified: true,
        selected_ledger_latest_registry_verified: true,
        selected_ledger_observer_trust_report_verified: true,
        selected_ledger_latest_observer_rotations_verified: true,
        selected_ledger_registry_bound_report_committed: false,
        selected_ledger_rollback_resistance_verified: false,
        global_non_equivocation_verified: false,
        trusted_time_verified: false,
        independent_organization_operation_verified: false,
        factory_legal_identity_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        quorum_met: observer_trust_report.quorum_met,
        registry_genesis_artifact: exact_identity(registry_genesis_source),
        registry_genesis_sha256: actual_registry_genesis_sha256,
        registry_genesis,
        registry_transition_count,
        registry_transitions: transition_evidence,
        current_registry,
        current_registry_sha256,
        observer_trust_report_artifact: exact_identity(observer_trust_report_source),
        evaluated_at_unix: observer_trust_report.evaluated_at_unix,
        observer_trust_report,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = registry_report_binding(&report)?;
    validate_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_organization_registry_authority_rotation(
    registry_genesis_source: &[u8],
    expected_registry_genesis_sha256: &str,
    registry_history_sources: &[Vec<u8>],
    observer_trust_report_source: &[u8],
    selected_ledger_latest_registry_verified: bool,
    selected_ledger_observer_trust_report_verified: bool,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
    String,
> {
    if !selected_ledger_latest_registry_verified {
        return Err(
            "factory release transparency external gossip registry authority-rotation verification requires the latest selected-ledger registry"
                .into(),
        );
    }
    if !selected_ledger_observer_trust_report_verified {
        return Err(
            "factory release transparency external gossip registry authority-rotation verification requires the exact selected-ledger observer trust report"
                .into(),
        );
    }
    if registry_history_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its event bound"
                .into(),
        );
    }
    let registry_genesis =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            registry_genesis_source,
        )?;
    if registry_genesis.generation != 0 {
        return Err(
            "factory release transparency external gossip registry genesis must be generation zero"
                .into(),
        );
    }
    let actual_registry_genesis_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &registry_genesis,
        )?;
    if actual_registry_genesis_sha256 != expected_registry_genesis_sha256 {
        return Err(
            "factory release transparency external gossip registry genesis pin does not match"
                .into(),
        );
    }
    let mut current_registry = registry_genesis.clone();
    let mut history_evidence = Vec::with_capacity(registry_history_sources.len());
    let mut authority_keys = vec![registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    for source in registry_history_sources {
        let evidence =
            parse_factory_release_state_transparency_external_gossip_registry_history_event(
                source,
            )?;
        match &evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::OrganizationTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current_registry,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::AuthorityKeyRotation {
                rotation,
                ..
            } => {
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current_registry,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
        }
        history_evidence.push(evidence);
    }
    let observer_trust_report =
        parse_factory_release_state_transparency_external_gossip_trust_report(
            observer_trust_report_source,
        )?;
    if observer_trust_report.base_observer_quorum_policy_sha256
        != current_registry.base_observer_quorum_policy_sha256
        || observer_trust_report.base_observer_quorum_policy.policy_id != current_registry.policy_id
    {
        return Err(
            "factory release transparency external gossip registry does not bind the observer trust report base policy"
                .into(),
        );
    }
    if current_registry
        .last_updated_at_unix
        .is_some_and(|updated| updated > observer_trust_report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry is newer than the observer trust quorum evaluation"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(&authority_keys, &observer_trust_report)?;
    validate_selected_member_admissions(&current_registry, &observer_trust_report)?;

    let registry_history_event_count = u32::try_from(history_evidence.len()).map_err(|_| {
        "factory release transparency external gossip registry history event count overflow"
            .to_string()
    })?;
    let current_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &current_registry,
        )?;
    let mut report =
        FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
            verification_scope:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_VERIFICATION_SCOPE
                    .into(),
            status: if observer_trust_report.quorum_met {
                "verified"
            } else {
                "insufficient_organizations"
            }
            .into(),
            registry_genesis_pin_matched: true,
            complete_registry_history_verified: true,
            registry_authority_transition_signatures_verified: true,
            registry_authority_rotation_dual_signatures_verified: true,
            registry_authority_successor_possession_verified: true,
            registry_authority_key_history_unique: true,
            registry_generation_chain_verified: true,
            registry_digest_chain_verified: true,
            registry_timestamps_monotonic: true,
            registry_authority_role_separation_verified: true,
            current_observer_trust_admissions_verified: true,
            selected_observer_organizations_active: true,
            registry_effective_before_quorum_evaluation_verified: true,
            selected_ledger_latest_registry_verified: true,
            selected_ledger_observer_trust_report_verified: true,
            selected_ledger_latest_observer_rotations_verified: true,
            selected_ledger_registry_bound_report_committed: false,
            selected_ledger_rollback_resistance_verified: false,
            authority_threshold_governance_verified: false,
            global_non_equivocation_verified: false,
            trusted_time_verified: false,
            independent_organization_operation_verified: false,
            factory_legal_identity_verified: false,
            capacity_reserved: false,
            order_placed: false,
            payment_performed: false,
            exactly_once_execution_verified: false,
            quorum_met: observer_trust_report.quorum_met,
            registry_genesis_artifact: exact_identity(registry_genesis_source),
            registry_genesis_sha256: actual_registry_genesis_sha256,
            registry_genesis,
            registry_history_event_count,
            registry_authority_rotation_count: authority_rotation_count,
            registry_history_events: history_evidence,
            current_registry,
            current_registry_sha256,
            observer_trust_report_artifact: exact_identity(observer_trust_report_source),
            evaluated_at_unix: observer_trust_report.evaluated_at_unix,
            observer_trust_report,
            binding_sha256: String::new(),
        };
    report.binding_sha256 = authority_rotation_registry_report_binding(&report)?;
    validate_authority_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_organization_registry_threshold_governance(
    registry_genesis_source: &[u8],
    expected_registry_genesis_sha256: &str,
    registry_history_sources: &[Vec<u8>],
    observer_trust_report_source: &[u8],
    selected_ledger_latest_registry_verified: bool,
    selected_ledger_observer_trust_report_verified: bool,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
    String,
> {
    if !selected_ledger_latest_registry_verified {
        return Err(
            "factory release transparency external gossip registry threshold-governance verification requires the latest selected-ledger registry"
                .into(),
        );
    }
    if !selected_ledger_observer_trust_report_verified {
        return Err(
            "factory release transparency external gossip registry threshold-governance verification requires the exact selected-ledger observer trust report"
                .into(),
        );
    }
    if registry_history_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its event bound"
                .into(),
        );
    }
    let registry_genesis =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            registry_genesis_source,
        )?;
    if registry_genesis.generation != 0 {
        return Err(
            "factory release transparency external gossip registry genesis must be generation zero"
                .into(),
        );
    }
    let actual_registry_genesis_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &registry_genesis,
        )?;
    if actual_registry_genesis_sha256 != expected_registry_genesis_sha256 {
        return Err(
            "factory release transparency external gossip registry genesis pin does not match"
                .into(),
        );
    }
    let mut current_registry = registry_genesis.clone();
    let mut history_evidence = Vec::with_capacity(registry_history_sources.len());
    let mut authority_keys = vec![registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    let mut threshold_transition_count = 0_u32;
    let mut active_governance = None;
    for source in registry_history_sources {
        let evidence = parse_factory_release_state_transparency_external_gossip_registry_threshold_governance_history_event(source)?;
        match &evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::OrganizationTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current_registry,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::AuthorityKeyRotation {
                rotation,
                ..
            } => {
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current_registry,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::ThresholdTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current_registry,
                    transition,
                )?;
                active_governance = Some(transition.governance.clone());
                threshold_transition_count = threshold_transition_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
        }
        history_evidence.push(evidence);
    }
    let active_governance = active_governance.ok_or_else(|| {
        "factory release transparency external gossip registry history has no threshold-governed transition"
            .to_string()
    })?;
    let active_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &active_governance,
        )?;
    if current_registry.active_governance_sha256.as_deref()
        != Some(active_governance_sha256.as_str())
    {
        return Err(
            "factory release transparency external gossip registry active governance is inconsistent"
                .into(),
        );
    }
    let observer_trust_report =
        parse_factory_release_state_transparency_external_gossip_trust_report(
            observer_trust_report_source,
        )?;
    if observer_trust_report.base_observer_quorum_policy_sha256
        != current_registry.base_observer_quorum_policy_sha256
        || observer_trust_report.base_observer_quorum_policy.policy_id != current_registry.policy_id
    {
        return Err(
            "factory release transparency external gossip registry does not bind the observer trust report base policy"
                .into(),
        );
    }
    if current_registry
        .last_updated_at_unix
        .is_some_and(|updated| updated > observer_trust_report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry is newer than the observer trust quorum evaluation"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(&authority_keys, &observer_trust_report)?;
    validate_governance_authority_role_separation(
        &active_governance,
        &authority_keys,
        &observer_trust_report,
    )?;
    validate_selected_member_admissions(&current_registry, &observer_trust_report)?;

    let registry_history_event_count = u32::try_from(history_evidence.len()).map_err(|_| {
        "factory release transparency external gossip registry history event count overflow"
            .to_string()
    })?;
    let current_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &current_registry,
        )?;
    let mut report = FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_VERIFICATION_SCOPE.into(),
        status: if observer_trust_report.quorum_met { "verified" } else { "insufficient_organizations" }.into(),
        registry_genesis_pin_matched: true,
        complete_registry_history_verified: true,
        registry_authority_transition_signatures_verified: true,
        registry_authority_rotation_dual_signatures_verified: true,
        registry_authority_successor_possession_verified: true,
        registry_authority_key_history_unique: true,
        governance_root_signature_verified: true,
        governance_authority_identities_unique: true,
        governance_authority_keys_unique: true,
        governance_threshold_approvals_verified: true,
        root_only_registry_mutations_locked_out: true,
        registry_generation_chain_verified: true,
        registry_digest_chain_verified: true,
        registry_timestamps_monotonic: true,
        registry_authority_role_separation_verified: true,
        current_observer_trust_admissions_verified: true,
        selected_observer_organizations_active: true,
        registry_effective_before_quorum_evaluation_verified: true,
        selected_ledger_latest_registry_verified: true,
        selected_ledger_observer_trust_report_verified: true,
        selected_ledger_latest_observer_rotations_verified: true,
        selected_ledger_registry_bound_report_committed: false,
        selected_ledger_rollback_resistance_verified: false,
        authority_threshold_governance_verified: true,
        global_non_equivocation_verified: false,
        trusted_time_verified: false,
        independent_organization_operation_verified: false,
        factory_legal_identity_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        quorum_met: observer_trust_report.quorum_met,
        registry_genesis_artifact: exact_identity(registry_genesis_source),
        registry_genesis_sha256: actual_registry_genesis_sha256,
        registry_genesis,
        registry_history_event_count,
        registry_authority_rotation_count: authority_rotation_count,
        registry_threshold_transition_count: threshold_transition_count,
        registry_history_events: history_evidence,
        active_governance_sha256,
        active_governance,
        current_registry,
        current_registry_sha256,
        observer_trust_report_artifact: exact_identity(observer_trust_report_source),
        evaluated_at_unix: observer_trust_report.evaluated_at_unix,
        observer_trust_report,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = threshold_governance_registry_report_binding(&report)?;
    validate_threshold_governance_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_organization_registry_governance_rotation(
    registry_genesis_source: &[u8],
    expected_registry_genesis_sha256: &str,
    registry_history_sources: &[Vec<u8>],
    observer_trust_report_source: &[u8],
    selected_ledger_latest_registry_verified: bool,
    selected_ledger_observer_trust_report_verified: bool,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
    String,
> {
    if !selected_ledger_latest_registry_verified {
        return Err(
            "factory release transparency external gossip registry governance-rotation verification requires the latest selected-ledger registry"
                .into(),
        );
    }
    if !selected_ledger_observer_trust_report_verified {
        return Err(
            "factory release transparency external gossip registry governance-rotation verification requires the exact selected-ledger observer trust report"
                .into(),
        );
    }
    if registry_history_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its event bound"
                .into(),
        );
    }
    let registry_genesis =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            registry_genesis_source,
        )?;
    if registry_genesis.generation != 0 {
        return Err(
            "factory release transparency external gossip registry genesis must be generation zero"
                .into(),
        );
    }
    let actual_registry_genesis_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &registry_genesis,
        )?;
    if actual_registry_genesis_sha256 != expected_registry_genesis_sha256 {
        return Err(
            "factory release transparency external gossip registry genesis pin does not match"
                .into(),
        );
    }
    let mut current_registry = registry_genesis.clone();
    let mut history_evidence = Vec::with_capacity(registry_history_sources.len());
    let mut authority_keys = vec![registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    let mut threshold_transition_count = 0_u32;
    let mut governance_rotation_count = 0_u32;
    let mut active_governance = None;
    let mut governance_history = Vec::new();
    let mut governance_hashes = HashSet::new();
    for source in registry_history_sources {
        let evidence = parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_history_event(source)?;
        match &evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::OrganizationTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current_registry,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::AuthorityKeyRotation {
                rotation,
                ..
            } => {
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current_registry,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::ThresholdTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current_registry,
                    transition,
                )?;
                let governance_sha256 =
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                        &transition.governance,
                    )?;
                if governance_hashes.insert(governance_sha256) {
                    governance_history.push(transition.governance.clone());
                }
                active_governance = Some(transition.governance.clone());
                threshold_transition_count = threshold_transition_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::GovernanceRotation {
                rotation,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    &current_registry,
                    rotation,
                )?;
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governance_rotation_count = governance_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry governance rotation count overflow"
                        .to_string()
                })?;
            }
        }
        history_evidence.push(evidence);
    }
    if governance_rotation_count == 0 {
        return Err(
            "factory release transparency external gossip registry history has no governance rotation"
                .into(),
        );
    }
    let active_governance = active_governance.ok_or_else(|| {
        "factory release transparency external gossip registry history has no active governance"
            .to_string()
    })?;
    let active_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &active_governance,
        )?;
    if current_registry.active_governance_sha256.as_deref()
        != Some(active_governance_sha256.as_str())
    {
        return Err(
            "factory release transparency external gossip registry active governance is inconsistent"
                .into(),
        );
    }
    let observer_trust_report =
        parse_factory_release_state_transparency_external_gossip_trust_report(
            observer_trust_report_source,
        )?;
    if observer_trust_report.base_observer_quorum_policy_sha256
        != current_registry.base_observer_quorum_policy_sha256
        || observer_trust_report.base_observer_quorum_policy.policy_id != current_registry.policy_id
    {
        return Err(
            "factory release transparency external gossip registry does not bind the observer trust report base policy"
                .into(),
        );
    }
    if current_registry
        .last_updated_at_unix
        .is_some_and(|updated| updated > observer_trust_report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry is newer than the observer trust quorum evaluation"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(&authority_keys, &observer_trust_report)?;
    for governance in &governance_history {
        validate_governance_authority_role_separation(
            governance,
            &authority_keys,
            &observer_trust_report,
        )?;
    }
    validate_selected_member_admissions(&current_registry, &observer_trust_report)?;

    let registry_history_event_count = u32::try_from(history_evidence.len()).map_err(|_| {
        "factory release transparency external gossip registry history event count overflow"
            .to_string()
    })?;
    let current_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &current_registry,
        )?;
    let mut report = FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_VERIFICATION_SCOPE.into(),
        status: if observer_trust_report.quorum_met { "verified" } else { "insufficient_organizations" }.into(),
        registry_genesis_pin_matched: true,
        complete_registry_history_verified: true,
        registry_authority_transition_signatures_verified: true,
        registry_authority_rotation_dual_signatures_verified: true,
        registry_authority_successor_possession_verified: true,
        registry_authority_key_history_unique: true,
        governance_root_signatures_verified: true,
        governance_authority_identities_unique: true,
        governance_authority_keys_unique: true,
        governance_threshold_approvals_verified: true,
        governance_rotation_old_quorum_verified: true,
        governance_rotation_new_quorum_verified: true,
        successor_governance_state_binding_verified: true,
        root_only_registry_mutations_locked_out: true,
        registry_generation_chain_verified: true,
        registry_digest_chain_verified: true,
        registry_timestamps_monotonic: true,
        registry_authority_role_separation_verified: true,
        current_observer_trust_admissions_verified: true,
        selected_observer_organizations_active: true,
        registry_effective_before_quorum_evaluation_verified: true,
        selected_ledger_latest_registry_verified: true,
        selected_ledger_observer_trust_report_verified: true,
        selected_ledger_latest_observer_rotations_verified: true,
        selected_ledger_registry_bound_report_committed: false,
        selected_ledger_rollback_resistance_verified: false,
        authority_threshold_governance_verified: true,
        global_non_equivocation_verified: false,
        trusted_time_verified: false,
        independent_governance_control_verified: false,
        independent_organization_operation_verified: false,
        factory_legal_identity_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        quorum_met: observer_trust_report.quorum_met,
        registry_genesis_artifact: exact_identity(registry_genesis_source),
        registry_genesis_sha256: actual_registry_genesis_sha256,
        registry_genesis,
        registry_history_event_count,
        registry_authority_rotation_count: authority_rotation_count,
        registry_threshold_transition_count: threshold_transition_count,
        registry_governance_rotation_count: governance_rotation_count,
        registry_history_events: history_evidence,
        active_governance_sha256,
        active_governance,
        current_registry,
        current_registry_sha256,
        observer_trust_report_artifact: exact_identity(observer_trust_report_source),
        evaluated_at_unix: observer_trust_report.evaluated_at_unix,
        observer_trust_report,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = governance_rotation_registry_report_binding(&report)?;
    validate_governance_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_organization_registry_governed_authority_rotation(
    registry_genesis_source: &[u8],
    expected_registry_genesis_sha256: &str,
    registry_history_sources: &[Vec<u8>],
    observer_trust_report_source: &[u8],
    selected_ledger_latest_registry_verified: bool,
    selected_ledger_observer_trust_report_verified: bool,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
    String,
>{
    if !selected_ledger_latest_registry_verified {
        return Err(
            "factory release transparency external gossip registry governed-authority-rotation verification requires the latest selected-ledger registry"
                .into(),
        );
    }
    if !selected_ledger_observer_trust_report_verified {
        return Err(
            "factory release transparency external gossip registry governed-authority-rotation verification requires the exact selected-ledger observer trust report"
                .into(),
        );
    }
    if registry_history_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its event bound"
                .into(),
        );
    }
    let registry_genesis =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            registry_genesis_source,
        )?;
    if registry_genesis.generation != 0 {
        return Err(
            "factory release transparency external gossip registry genesis must be generation zero"
                .into(),
        );
    }
    let actual_registry_genesis_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &registry_genesis,
        )?;
    if actual_registry_genesis_sha256 != expected_registry_genesis_sha256 {
        return Err(
            "factory release transparency external gossip registry genesis pin does not match"
                .into(),
        );
    }
    let mut current_registry = registry_genesis.clone();
    let mut history_evidence = Vec::with_capacity(registry_history_sources.len());
    let mut authority_keys = vec![registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    let mut threshold_transition_count = 0_u32;
    let mut governance_rotation_count = 0_u32;
    let mut governed_authority_rotation_count = 0_u32;
    let mut active_governance = None;
    let mut governance_history = Vec::new();
    let mut governance_hashes = HashSet::new();
    for source in registry_history_sources {
        let evidence = parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_history_event(source)?;
        match &evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::OrganizationTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current_registry,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::AuthorityKeyRotation {
                rotation,
                ..
            } => {
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current_registry,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::ThresholdTransition {
                transition,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current_registry,
                    transition,
                )?;
                let governance_sha256 =
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                        &transition.governance,
                    )?;
                if governance_hashes.insert(governance_sha256) {
                    governance_history.push(transition.governance.clone());
                }
                active_governance = Some(transition.governance.clone());
                threshold_transition_count = threshold_transition_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernanceRotation {
                rotation,
                ..
            } => {
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    &current_registry,
                    rotation,
                )?;
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governance_rotation_count = governance_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry governance rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernedAuthorityKeyRotation {
                rotation,
                ..
            } => {
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip governed registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current_registry = apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                    &current_registry,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governed_authority_rotation_count = governed_authority_rotation_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        "factory release transparency external gossip governed authority rotation count overflow"
                            .to_string()
                    })?;
            }
        }
        history_evidence.push(evidence);
    }
    if governed_authority_rotation_count == 0 {
        return Err(
            "factory release transparency external gossip registry history has no governed authority rotation"
                .into(),
        );
    }
    let active_governance = active_governance.ok_or_else(|| {
        "factory release transparency external gossip registry history has no active governance"
            .to_string()
    })?;
    let active_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &active_governance,
        )?;
    if current_registry.active_governance_sha256.as_deref()
        != Some(active_governance_sha256.as_str())
        || current_registry.authority_public_key != active_governance.registry_authority_public_key
    {
        return Err(
            "factory release transparency external gossip registry active root and governance are inconsistent"
                .into(),
        );
    }
    let observer_trust_report =
        parse_factory_release_state_transparency_external_gossip_trust_report(
            observer_trust_report_source,
        )?;
    if observer_trust_report.base_observer_quorum_policy_sha256
        != current_registry.base_observer_quorum_policy_sha256
        || observer_trust_report.base_observer_quorum_policy.policy_id != current_registry.policy_id
    {
        return Err(
            "factory release transparency external gossip registry does not bind the observer trust report base policy"
                .into(),
        );
    }
    if current_registry
        .last_updated_at_unix
        .is_some_and(|updated| updated > observer_trust_report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry is newer than the observer trust quorum evaluation"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(&authority_keys, &observer_trust_report)?;
    for governance in &governance_history {
        validate_governance_authority_role_separation(
            governance,
            &authority_keys,
            &observer_trust_report,
        )?;
    }
    validate_selected_member_admissions(&current_registry, &observer_trust_report)?;

    let registry_history_event_count = u32::try_from(history_evidence.len()).map_err(|_| {
        "factory release transparency external gossip registry history event count overflow"
            .to_string()
    })?;
    let current_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &current_registry,
        )?;
    let mut report = FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_VERIFICATION_SCOPE.into(),
        status: if observer_trust_report.quorum_met { "verified" } else { "insufficient_organizations" }.into(),
        registry_genesis_pin_matched: true,
        complete_registry_history_verified: true,
        registry_authority_transition_signatures_verified: true,
        registry_authority_rotation_dual_signatures_verified: true,
        registry_authority_successor_possession_verified: true,
        registry_authority_key_history_unique: true,
        governance_root_signatures_verified: true,
        governance_authority_identities_unique: true,
        governance_authority_keys_unique: true,
        governance_threshold_approvals_verified: true,
        governance_rotation_old_quorum_verified: true,
        governance_rotation_new_quorum_verified: true,
        successor_governance_state_binding_verified: true,
        governed_authority_rotation_old_quorum_verified: true,
        governed_authority_rotation_new_quorum_verified: true,
        successor_registry_root_possession_verified: true,
        registry_root_and_governance_rotated_atomically: true,
        root_only_registry_mutations_locked_out: true,
        registry_generation_chain_verified: true,
        registry_digest_chain_verified: true,
        registry_timestamps_monotonic: true,
        registry_authority_role_separation_verified: true,
        current_observer_trust_admissions_verified: true,
        selected_observer_organizations_active: true,
        registry_effective_before_quorum_evaluation_verified: true,
        selected_ledger_latest_registry_verified: true,
        selected_ledger_observer_trust_report_verified: true,
        selected_ledger_latest_observer_rotations_verified: true,
        selected_ledger_registry_bound_report_committed: false,
        selected_ledger_rollback_resistance_verified: false,
        authority_threshold_governance_verified: true,
        global_non_equivocation_verified: false,
        trusted_time_verified: false,
        independent_governance_control_verified: false,
        independent_organization_operation_verified: false,
        factory_legal_identity_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        quorum_met: observer_trust_report.quorum_met,
        registry_genesis_artifact: exact_identity(registry_genesis_source),
        registry_genesis_sha256: actual_registry_genesis_sha256,
        registry_genesis,
        registry_history_event_count,
        registry_authority_rotation_count: authority_rotation_count,
        registry_threshold_transition_count: threshold_transition_count,
        registry_governance_rotation_count: governance_rotation_count,
        registry_governed_authority_rotation_count: governed_authority_rotation_count,
        registry_history_events: history_evidence,
        active_governance_sha256,
        active_governance,
        current_registry,
        current_registry_sha256,
        observer_trust_report_artifact: exact_identity(observer_trust_report_source),
        evaluated_at_unix: observer_trust_report.evaluated_at_unix,
        observer_trust_report,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = governed_authority_rotation_registry_report_binding(&report)?;
    validate_governed_authority_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_organization_registry(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
) -> Result<Vec<u8>, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    render_bounded(
        registry,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip organization registry",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_organization_registry(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry, String> {
    let registry = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip organization registry",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry(&registry)?;
    Ok(registry)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
        transition,
    )?;
    render_bounded(
        transition,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
        "signed factory release transparency external gossip organization registry transition",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
    source: &[u8],
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition, String>
{
    let transition = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
        "signed factory release transparency external gossip organization registry transition",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
        &transition,
    )?;
    Ok(transition)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry authority key rotation",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
    String,
> {
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry authority key rotation",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    render_bounded(
        governance,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_BYTES,
        "signed factory release transparency external gossip organization registry governance",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
    source: &[u8],
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance, String>
{
    let governance = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_BYTES,
        "signed factory release transparency external gossip organization registry governance",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &governance,
    )?;
    Ok(governance)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
        transition,
    )?;
    render_bounded(
        transition,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
        "signed factory release transparency external gossip organization registry threshold transition",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
    String,
> {
    let transition = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
        "signed factory release transparency external gossip organization registry threshold transition",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
        &transition,
    )?;
    Ok(transition)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry governance rotation",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
    String,
> {
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry governance rotation",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry governed authority key rotation",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
    source: &[u8],
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
    String,
>{
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip organization registry governed authority key rotation",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_history_event(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence, String> {
    if let Ok(transition) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::OrganizationTransition {
                artifact: exact_identity(source),
                transition,
            },
        );
    }
    let rotation = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(source)
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip registry history event: {error}"
            )
        })?;
    Ok(
        FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::AuthorityKeyRotation {
            artifact: exact_identity(source),
            rotation,
        },
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_threshold_governance_history_event(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence,
    String,
> {
    if let Ok(transition) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::OrganizationTransition {
                artifact: exact_identity(source),
                transition,
            },
        );
    }
    if let Ok(rotation) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::AuthorityKeyRotation {
                artifact: exact_identity(source),
                rotation,
            },
        );
    }
    let transition = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(source)
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip registry threshold-governance history event: {error}"
            )
        })?;
    Ok(
        FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::ThresholdTransition {
            artifact: exact_identity(source),
            transition: Box::new(transition),
        },
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_history_event(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence,
    String,
> {
    if let Ok(transition) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::OrganizationTransition {
                artifact: exact_identity(source),
                transition,
            },
        );
    }
    if let Ok(rotation) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::AuthorityKeyRotation {
                artifact: exact_identity(source),
                rotation,
            },
        );
    }
    if let Ok(transition) = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(source) {
        return Ok(
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::ThresholdTransition {
                artifact: exact_identity(source),
                transition: Box::new(transition),
            },
        );
    }
    let rotation = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(source)
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip registry governance-rotation history event: {error}"
            )
        })?;
    Ok(
        FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::GovernanceRotation {
            artifact: exact_identity(source),
            rotation: Box::new(rotation),
        },
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_history_event(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence,
    String,
>{
    if let Ok(evidence) =
        parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_history_event(
            source,
        )
    {
        return Ok(match evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            } => FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            },
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            } => FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            },
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::ThresholdTransition {
                artifact,
                transition,
            } => FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::ThresholdTransition {
                artifact,
                transition,
            },
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::GovernanceRotation {
                artifact,
                rotation,
            } => FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernanceRotation {
                artifact,
                rotation,
            },
        });
    }
    let rotation = parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(source)
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip registry governed-authority-rotation history event: {error}"
            )
        })?;
    Ok(
        FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernedAuthorityKeyRotation {
            artifact: exact_identity(source),
            rotation: Box::new(rotation),
        },
    )
}

pub(crate) fn build_factory_release_state_transparency_external_gossip_organization_registry_history(
    initial_registry_source: &[u8],
    event_sources: &[Vec<u8>],
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory, String> {
    if event_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "factory release transparency external gossip registry history exceeds its event bound"
                .into(),
        );
    }
    let initial_registry =
        parse_factory_release_state_transparency_external_gossip_organization_registry(
            initial_registry_source,
        )?;
    let mut events = Vec::with_capacity(event_sources.len());
    for source in event_sources {
        events.push(
            parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_history_event(
                source,
            )?,
        );
    }
    let history = FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory {
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION,
        initial_registry_artifact: exact_identity(initial_registry_source),
        initial_registry,
        events,
    };
    audit_factory_release_state_transparency_external_gossip_organization_registry_history(
        &history,
    )?;
    Ok(history)
}

pub(crate) fn audit_factory_release_state_transparency_external_gossip_organization_registry_history(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    String,
> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history(
        history,
    )?;
    let initial_registry_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &history.initial_registry,
        )?;
    if history.initial_registry_artifact != exact_identity(&initial_registry_source) {
        return Err(
            "factory release transparency external gossip registry history genesis artifact identity is invalid"
                .into(),
        );
    }
    let initial_registry_sha256 =
        factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &history.initial_registry,
        )?;
    let mut current = history.initial_registry.clone();
    let mut authority_keys = HashSet::from([current.authority_public_key.clone()]);
    let mut governance_history = Vec::new();
    let mut entries = Vec::with_capacity(history.events.len());
    for (index, event) in history.events.iter().enumerate() {
        let from_generation = current.generation;
        let (kind, artifact, event_sha256, next) = match event {
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition {
                artifact,
                transition,
            } => (
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::OrganizationTransition,
                artifact.clone(),
                signed_factory_release_state_transparency_external_gossip_organization_registry_transition_sha256(
                    transition,
                )?,
                apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current,
                    transition,
                )?,
            ),
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                if !authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry history reuses a historical root key"
                            .into(),
                    );
                }
                (
                    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::AuthorityKeyRotation,
                    artifact.clone(),
                    signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_sha256(
                        rotation,
                    )?,
                    apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                        &current,
                        rotation,
                    )?,
                )
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::ThresholdTransition {
                artifact,
                transition,
            } => {
                governance_history.push(&transition.governance);
                (
                    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::ThresholdTransition,
                    artifact.clone(),
                    signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_sha256(
                        transition,
                    )?,
                    apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                        &current,
                        transition,
                    )?,
                )
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernanceRotation {
                artifact,
                rotation,
            } => {
                governance_history.extend([&rotation.old_governance, &rotation.new_governance]);
                (
                    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::GovernanceRotation,
                    artifact.clone(),
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_sha256(
                        rotation,
                    )?,
                    apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                        &current,
                        rotation,
                    )?,
                )
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernedAuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                if !authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry history reuses a historical root key"
                            .into(),
                    );
                }
                governance_history.extend([&rotation.old_governance, &rotation.new_governance]);
                (
                    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::GovernedAuthorityKeyRotation,
                    artifact.clone(),
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_sha256(
                        rotation,
                    )?,
                    apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                        &current,
                        rotation,
                    )?,
                )
            }
        };
        if next.last_transition_sha256.as_deref() != Some(event_sha256.as_str()) {
            return Err(
                "factory release transparency external gossip registry history event digest does not bind its resulting state"
                    .into(),
            );
        }
        entries.push(
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditEntry {
                index: u64::try_from(index).map_err(|_| {
                    "factory release transparency external gossip registry history index overflow"
                        .to_string()
                })?,
                kind,
                from_generation,
                to_generation: next.generation,
                artifact,
                event_sha256,
                resulting_registry_sha256:
                    factory_release_state_transparency_external_gossip_organization_registry_sha256(
                        &next,
                    )?,
                authority_public_key: next.authority_public_key.clone(),
                active_governance_sha256: next.active_governance_sha256.clone(),
            },
        );
        current = next;
    }
    for governance in governance_history {
        for authority in &governance.authorities {
            if authority_keys.contains(&authority.public_key) {
                return Err(
                    "factory release transparency external gossip registry history reuses a root key as a governance authority key"
                        .into(),
                );
            }
        }
    }
    let report =
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport {
            schema_version:
                FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION,
            registry_id: current.registry_id.clone(),
            initial_registry_artifact: history.initial_registry_artifact.clone(),
            initial_registry_sha256,
            event_count: u64::try_from(entries.len()).map_err(|_| {
                "factory release transparency external gossip registry history event count overflow"
                    .to_string()
            })?,
            entries,
            final_registry_sha256:
                factory_release_state_transparency_external_gossip_organization_registry_sha256(
                    &current,
                )?,
            final_registry: current,
            chain_valid: true,
        };
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_organization_registry_history(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
) -> Result<Vec<u8>, String> {
    audit_factory_release_state_transparency_external_gossip_organization_registry_history(
        history,
    )?;
    render_bounded(
        history,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_BYTES,
        "factory release transparency external gossip organization registry history",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_organization_registry_history(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory, String> {
    let history = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_BYTES,
        "factory release transparency external gossip organization registry history",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry_history(
        &history,
    )?;
    Ok(history)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
    report: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
) -> Result<Vec<u8>, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT_REPORT_BYTES,
        "factory release transparency external gossip organization registry history audit report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT_REPORT_BYTES,
        "factory release transparency external gossip organization registry history audit report",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_sha256(
    report: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
) -> Result<String, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
        report,
    )?;
    normalized_sha256(
        report,
        "factory release transparency external gossip organization registry history audit report",
    )
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_registry_report(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_registry_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_REPORT_BYTES,
        "factory release transparency external gossip organization registry verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_REPORT_BYTES,
        "factory release transparency external gossip organization registry verification report",
    )?;
    validate_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_registry_authority_rotation_report(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_authority_rotation_registry_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry authority-rotation verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_authority_rotation_report(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry authority-rotation verification report",
    )?;
    validate_authority_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_registry_threshold_governance_report(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_threshold_governance_registry_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_REPORT_BYTES,
        "factory release transparency external gossip organization registry threshold-governance verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_threshold_governance_report(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_REPORT_BYTES,
        "factory release transparency external gossip organization registry threshold-governance verification report",
    )?;
    validate_threshold_governance_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_registry_governance_rotation_report(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_governance_rotation_registry_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry governance-rotation verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_report(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry governance-rotation verification report",
    )?;
    validate_governance_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_report(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_governed_authority_rotation_registry_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry governed-authority-rotation verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_report(
    source: &[u8],
) -> Result<
    FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
    String,
>{
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_REPORT_BYTES,
        "factory release transparency external gossip organization registry governed-authority-rotation verification report",
    )?;
    validate_governed_authority_rotation_registry_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_external_gossip_organization_registry_sha256(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
) -> Result<String, String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    normalized_sha256(
        registry,
        "factory release transparency external gossip organization registry",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_transition_sha256(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
        transition,
    )?;
    normalized_sha256(
        transition,
        "signed factory release transparency external gossip organization registry transition",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_sha256(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
        rotation,
    )?;
    normalized_sha256(
        rotation,
        "signed factory release transparency external gossip organization registry authority key rotation",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    normalized_sha256(
        governance,
        "signed factory release transparency external gossip organization registry governance",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_sha256(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
        transition,
    )?;
    normalized_sha256(
        transition,
        "signed factory release transparency external gossip organization registry threshold transition",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_sha256(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
        rotation,
    )?;
    normalized_sha256(
        rotation,
        "signed factory release transparency external gossip organization registry governance rotation",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_sha256(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
        rotation,
    )?;
    normalized_sha256(
        rotation,
        "signed factory release transparency external gossip organization registry governed authority key rotation",
    )
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_transition_filename(
    registry_genesis_sha256: &str,
    base_policy_sha256: &str,
    registry_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip registry base policy SHA-256",
    )?;
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION)
        .contains(&generation)
    {
        return Err(
            "factory release transparency external gossip registry transition generation is outside its bound"
                .into(),
        );
    }
    let context = TransitionFilenameContext {
        registry_genesis_sha256,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        registry_id,
    };
    let digest = domain_hash(
        TRANSITION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry transition filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-transition-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_authority_key_rotation_filename(
    registry_genesis_sha256: &str,
    base_policy_sha256: &str,
    registry_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip base policy SHA-256",
    )?;
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if generation == 0
        || generation > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "factory release transparency external gossip registry authority rotation generation is outside its bound"
                .into(),
        );
    }
    let context = TransitionFilenameContext {
        registry_genesis_sha256,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        registry_id,
    };
    let digest = domain_hash(
        AUTHORITY_KEY_ROTATION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry authority rotation filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_threshold_transition_filename(
    registry_genesis_sha256: &str,
    base_policy_sha256: &str,
    registry_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip base policy SHA-256",
    )?;
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if generation == 0
        || generation > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "factory release transparency external gossip registry threshold transition generation is outside its bound"
                .into(),
        );
    }
    let context = TransitionFilenameContext {
        registry_genesis_sha256,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        registry_id,
    };
    let digest = domain_hash(
        THRESHOLD_TRANSITION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry threshold transition filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governance_rotation_filename(
    registry_genesis_sha256: &str,
    base_policy_sha256: &str,
    registry_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip base policy SHA-256",
    )?;
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if generation == 0
        || generation > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "factory release transparency external gossip registry governance rotation generation is outside its bound"
                .into(),
        );
    }
    let context = TransitionFilenameContext {
        registry_genesis_sha256,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        registry_id,
    };
    let digest = domain_hash(
        GOVERNANCE_ROTATION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry governance rotation filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governed_authority_key_rotation_filename(
    registry_genesis_sha256: &str,
    base_policy_sha256: &str,
    registry_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip base policy SHA-256",
    )?;
    validate_slug(
        registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if generation == 0
        || generation > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "factory release transparency external gossip registry governed authority rotation generation is outside its bound"
                .into(),
        );
    }
    let context = TransitionFilenameContext {
        registry_genesis_sha256,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        registry_id,
    };
    let digest = domain_hash(
        GOVERNED_AUTHORITY_KEY_ROTATION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip governed authority rotation filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport,
) -> Result<String, String> {
    validate_registry_report_shape(report)?;
    let context = ReportFilenameContext {
        observer_trust_binding_sha256: &report.observer_trust_report.binding_sha256,
        registry_genesis_sha256: &report.registry_genesis_sha256,
        current_registry_sha256: &report.current_registry_sha256,
        registry_generation: report.current_registry.generation,
    };
    let digest = domain_hash(
        REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-v1-{}-{:04}-{}.json",
        report.observer_trust_report.quorum_report.idempotency_key,
        report.current_registry.generation,
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_authority_rotation_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
) -> Result<String, String> {
    validate_authority_rotation_registry_report_shape(report)?;
    let context = ReportFilenameContext {
        observer_trust_binding_sha256: &report.observer_trust_report.binding_sha256,
        registry_genesis_sha256: &report.registry_genesis_sha256,
        current_registry_sha256: &report.current_registry_sha256,
        registry_generation: report.current_registry.generation,
    };
    let digest = domain_hash(
        AUTHORITY_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry authority-rotation report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-v1-{}-{:04}-{}.json",
        report.observer_trust_report.quorum_report.idempotency_key,
        report.current_registry.generation,
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_threshold_governance_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
) -> Result<String, String> {
    validate_threshold_governance_registry_report_shape(report)?;
    let context = ReportFilenameContext {
        observer_trust_binding_sha256: &report.observer_trust_report.binding_sha256,
        registry_genesis_sha256: &report.registry_genesis_sha256,
        current_registry_sha256: &report.current_registry_sha256,
        registry_generation: report.current_registry.generation,
    };
    let digest = domain_hash(
        THRESHOLD_GOVERNANCE_REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry threshold-governance report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-v1-{}-{:04}-{}.json",
        report.observer_trust_report.quorum_report.idempotency_key,
        report.current_registry.generation,
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governance_rotation_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
) -> Result<String, String> {
    validate_governance_rotation_registry_report_shape(report)?;
    let context = ReportFilenameContext {
        observer_trust_binding_sha256: &report.observer_trust_report.binding_sha256,
        registry_genesis_sha256: &report.registry_genesis_sha256,
        current_registry_sha256: &report.current_registry_sha256,
        registry_generation: report.current_registry.generation,
    };
    let digest = domain_hash(
        GOVERNANCE_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip registry governance-rotation report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1-{}-{:04}-{}.json",
        report.observer_trust_report.quorum_report.idempotency_key,
        report.current_registry.generation,
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
) -> Result<String, String> {
    validate_governed_authority_rotation_registry_report_shape(report)?;
    let context = ReportFilenameContext {
        observer_trust_binding_sha256: &report.observer_trust_report.binding_sha256,
        registry_genesis_sha256: &report.registry_genesis_sha256,
        current_registry_sha256: &report.current_registry_sha256,
        registry_generation: report.current_registry.generation,
    };
    let digest = domain_hash(
        GOVERNED_AUTHORITY_ROTATION_REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip governed-authority-rotation report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-v1-{}-{:04}-{}.json",
        report.observer_trust_report.quorum_report.idempotency_key,
        report.current_registry.generation,
        &digest[..32]
    ))
}

pub(crate) fn validate_factory_release_state_transparency_external_gossip_organization_registry(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
) -> Result<(), String> {
    if registry.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || registry.registry_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCOPE
    {
        return Err(
            "unsupported factory release transparency external gossip organization registry".into(),
        );
    }
    validate_digest(
        &registry.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry base policy SHA-256",
    )?;
    validate_slug(
        &registry.policy_id,
        "factory release transparency external gossip observer policy id",
    )?;
    validate_slug(
        &registry.registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    validate_nonweak_public_key(
        &registry.authority_public_key,
        "factory release transparency external gossip registry authority public key",
    )?;
    if let Some(governance_sha256) = &registry.active_governance_sha256 {
        validate_digest(
            governance_sha256,
            "factory release transparency external gossip registry active governance SHA-256",
        )?;
    }
    if registry.generation
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "factory release transparency external gossip registry generation exceeds its bound"
                .into(),
        );
    }
    match (
        registry.generation,
        &registry.last_transition_sha256,
        registry.last_updated_at_unix,
    ) {
        (0, None, None)
            if registry.organizations.is_empty() && registry.active_governance_sha256.is_none() => {
        }
        (0, _, _) => {
            return Err(
                "factory release transparency external gossip registry genesis must be empty and unadvanced"
                    .into(),
            );
        }
        (_, Some(digest), Some(updated)) => {
            validate_digest(
                digest,
                "factory release transparency external gossip registry last transition SHA-256",
            )?;
            if updated > MAX_TIMESTAMP {
                return Err(
                    "factory release transparency external gossip registry update time is outside its bound"
                        .into(),
                );
            }
        }
        _ => {
            return Err(
                "advanced factory release transparency external gossip registry requires complete transition evidence"
                    .into(),
            );
        }
    }
    if registry.organizations.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
    {
        return Err(
            "factory release transparency external gossip registry organization count exceeds its bound"
                .into(),
        );
    }
    let mut previous_organization = None;
    let mut observer_count = 0_usize;
    for organization in &registry.organizations {
        validate_slug(
            &organization.organization_id,
            "factory release transparency external gossip registry organization id",
        )?;
        validate_digest(
            &organization.status_reason_sha256,
            "factory release transparency external gossip organization status reason SHA-256",
        )?;
        if organization.status_since_unix > MAX_TIMESTAMP
            || registry
                .last_updated_at_unix
                .is_some_and(|updated| organization.status_since_unix > updated)
        {
            return Err(
                "factory release transparency external gossip organization status time exceeds registry state"
                    .into(),
            );
        }
        if previous_organization
            .is_some_and(|previous: &String| previous >= &organization.organization_id)
        {
            return Err(
                "factory release transparency external gossip registry organizations must be unique and ordered"
                    .into(),
            );
        }
        previous_organization = Some(&organization.organization_id);
        if organization.observers.is_empty() {
            return Err(
                "factory release transparency external gossip registry organizations require an admitted observer"
                    .into(),
            );
        }
        observer_count = observer_count
            .checked_add(organization.observers.len())
            .ok_or_else(|| {
                "factory release transparency external gossip registry observer count overflow"
                    .to_string()
            })?;
        let mut previous_observer = None;
        for observer in &organization.observers {
            validate_observer_slug(
                &observer.observer_id,
                "admitted factory release transparency external gossip observer id",
            )?;
            validate_digest(
                &observer.observer_trust_state_sha256,
                "admitted factory release transparency external gossip observer trust-state SHA-256",
            )?;
            if observer.admitted_at_unix > MAX_TIMESTAMP
                || registry
                    .last_updated_at_unix
                    .is_some_and(|updated| observer.admitted_at_unix > updated)
            {
                return Err(
                    "factory release transparency external gossip observer admission time exceeds registry state"
                        .into(),
                );
            }
            if previous_observer.is_some_and(|previous: &String| previous >= &observer.observer_id)
            {
                return Err(
                    "admitted factory release transparency external gossip observers must be unique and ordered"
                        .into(),
                );
            }
            previous_observer = Some(&observer.observer_id);
        }
    }
    if observer_count > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS {
        return Err(
            "factory release transparency external gossip registry observer count exceeds its bound"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_factory_release_state_transparency_external_gossip_organization_registry_history(
    history: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
) -> Result<(), String> {
    if history.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION
        || history.events.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
    {
        return Err(
            "invalid factory release transparency external gossip organization registry history invariants"
                .into(),
        );
    }
    validate_factory_release_state_transparency_external_gossip_organization_registry(
        &history.initial_registry,
    )?;
    if history.initial_registry.generation != 0 {
        return Err(
            "factory release transparency external gossip organization registry history must begin at empty generation-zero genesis"
                .into(),
        );
    }
    let initial_registry_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &history.initial_registry,
        )?;
    validate_artifact_identity(
        &history.initial_registry_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry history genesis artifact",
    )?;
    if history.initial_registry_artifact != exact_identity(&initial_registry_source) {
        return Err(
            "factory release transparency external gossip registry history genesis artifact identity is invalid"
                .into(),
        );
    }
    for event in &history.events {
        match event {
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                    "factory release transparency external gossip registry history transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry history transition artifact identity is invalid"
                            .into(),
                    );
                }
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry history authority-rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry history authority-rotation artifact identity is invalid"
                            .into(),
                    );
                }
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::ThresholdTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
                    "factory release transparency external gossip registry history threshold-transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry history threshold-transition artifact identity is invalid"
                            .into(),
                    );
                }
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernanceRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
                    "factory release transparency external gossip registry history governance-rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry history governance-rotation artifact identity is invalid"
                            .into(),
                    );
                }
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernedAuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry history governed-authority-rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry history governed-authority-rotation artifact identity is invalid"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
    report: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryAuditReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION
        || !report.chain_valid
        || report.entries.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.event_count != report.entries.len() as u64
    {
        return Err(
            "invalid factory release transparency external gossip registry history audit invariants"
                .into(),
        );
    }
    validate_slug(
        &report.registry_id,
        "factory release transparency external gossip registry history audit registry id",
    )?;
    validate_artifact_identity(
        &report.initial_registry_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry history audit genesis artifact",
    )?;
    validate_digest(
        &report.initial_registry_sha256,
        "factory release transparency external gossip registry history audit genesis SHA-256",
    )?;
    validate_factory_release_state_transparency_external_gossip_organization_registry(
        &report.final_registry,
    )?;
    validate_digest(
        &report.final_registry_sha256,
        "factory release transparency external gossip registry history audit final registry SHA-256",
    )?;
    if report.final_registry.registry_id != report.registry_id
        || report.final_registry.generation != report.event_count
        || factory_release_state_transparency_external_gossip_organization_registry_sha256(
            &report.final_registry,
        )? != report.final_registry_sha256
    {
        return Err(
            "factory release transparency external gossip registry history audit final state is inconsistent"
                .into(),
        );
    }
    let mut expected_generation = 0_u64;
    for (index, entry) in report.entries.iter().enumerate() {
        if entry.index != index as u64
            || entry.from_generation != expected_generation
            || entry.to_generation
                != expected_generation.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry history audit generation overflow"
                        .to_string()
                })?
        {
            return Err(
                "factory release transparency external gossip registry history audit entries are not contiguous"
                    .into(),
            );
        }
        let artifact_maximum = match entry.kind {
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::OrganizationTransition => {
                MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::AuthorityKeyRotation => {
                MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::ThresholdTransition => {
                MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::GovernanceRotation => {
                MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES
            }
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::GovernedAuthorityKeyRotation => {
                MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES
            }
        };
        validate_artifact_identity(
            &entry.artifact,
            artifact_maximum,
            "factory release transparency external gossip registry history audit event artifact",
        )?;
        validate_digest(
            &entry.event_sha256,
            "factory release transparency external gossip registry history audit event SHA-256",
        )?;
        validate_digest(
            &entry.resulting_registry_sha256,
            "factory release transparency external gossip registry history audit resulting registry SHA-256",
        )?;
        validate_nonweak_public_key(
            &entry.authority_public_key,
            "factory release transparency external gossip registry history audit root key",
        )?;
        if let Some(governance_sha256) = &entry.active_governance_sha256 {
            validate_digest(
                governance_sha256,
                "factory release transparency external gossip registry history audit active governance SHA-256",
            )?;
        }
        expected_generation = entry.to_generation;
    }
    if let Some(last) = report.entries.last() {
        if last.resulting_registry_sha256 != report.final_registry_sha256
            || last.authority_public_key != report.final_registry.authority_public_key
            || last.active_governance_sha256 != report.final_registry.active_governance_sha256
        {
            return Err(
                "factory release transparency external gossip registry history audit final entry does not bind the final registry"
                    .into(),
            );
        }
    } else {
        let final_source =
            render_factory_release_state_transparency_external_gossip_organization_registry(
                &report.final_registry,
            )?;
        if report.final_registry_sha256 != report.initial_registry_sha256
            || exact_identity(&final_source) != report.initial_registry_artifact
        {
            return Err(
                "empty factory release transparency external gossip registry history audit does not bind its genesis"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    if transition.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || transition.transition_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
        || transition.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "invalid factory release transparency external gossip registry transition invariants"
                .into(),
        );
    }
    validate_digest(
        &transition.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry base policy SHA-256",
    )?;
    validate_slug(
        &transition.policy_id,
        "factory release transparency external gossip observer policy id",
    )?;
    validate_slug(
        &transition.registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    validate_slug(
        &transition.organization_id,
        "factory release transparency external gossip registry organization id",
    )?;
    validate_digest(
        &transition.reason_sha256,
        "factory release transparency external gossip registry transition reason SHA-256",
    )?;
    if transition.effective_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry transition time is outside its bound"
                .into(),
        );
    }
    if let Some(digest) = &transition.previous_transition_sha256 {
        validate_digest(
            digest,
            "previous factory release transparency external gossip registry transition SHA-256",
        )?;
    }
    if (transition.from_generation == 0) != transition.previous_transition_sha256.is_none() {
        return Err(
            "factory release transparency external gossip registry transition chain reference is inconsistent"
                .into(),
        );
    }
    match transition.action {
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver => {
            validate_observer_slug(
                transition.observer_id.as_deref().ok_or_else(|| {
                    "factory release transparency external gossip observer admission requires an observer id"
                        .to_string()
                })?,
                "admitted factory release transparency external gossip observer id",
            )?;
            validate_digest(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "factory release transparency external gossip observer admission requires a trust-state SHA-256"
                            .to_string()
                    })?,
                "admitted factory release transparency external gossip observer trust-state SHA-256",
            )?;
        }
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization
        | FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::RevokeOrganization => {
            if transition.observer_id.is_some()
                || transition.observer_trust_state_sha256.is_some()
            {
                return Err(
                    "factory release transparency external gossip organization status transition cannot bind an observer"
                        .into(),
                );
            }
        }
    }
    validate_nonweak_public_key(
        &transition.authority_public_key,
        "factory release transparency external gossip registry authority public key",
    )?;
    decode_hex::<64>(
        &transition.signature,
        "factory release transparency external gossip registry authority signature",
    )?;
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || rotation.rotation_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_SCOPE
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err(
            "invalid factory release transparency external gossip registry authority rotation invariants"
                .into(),
        );
    }
    validate_digest(
        &rotation.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry base policy SHA-256",
    )?;
    validate_slug(
        &rotation.policy_id,
        "factory release transparency external gossip observer policy id",
    )?;
    validate_slug(
        &rotation.registry_id,
        "factory release transparency external gossip organization registry id",
    )?;
    if rotation.rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip registry authority rotation time is outside its bound"
                .into(),
        );
    }
    if let Some(digest) = &rotation.previous_transition_sha256 {
        validate_digest(
            digest,
            "previous factory release transparency external gossip registry history event SHA-256",
        )?;
    }
    if (rotation.from_generation == 0) != rotation.previous_transition_sha256.is_none() {
        return Err(
            "factory release transparency external gossip registry authority rotation chain reference is inconsistent"
                .into(),
        );
    }
    validate_nonweak_public_key(
        &rotation.old_public_key,
        "old factory release transparency external gossip registry authority public key",
    )?;
    validate_nonweak_public_key(
        &rotation.new_public_key,
        "new factory release transparency external gossip registry authority public key",
    )?;
    decode_hex::<64>(
        &rotation.old_signature,
        "old factory release transparency external gossip registry authority rotation signature",
    )?;
    decode_hex::<64>(
        &rotation.new_signature,
        "new factory release transparency external gossip registry authority rotation signature",
    )?;
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    if governance.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || governance.governance_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE
        || governance.algorithm != "ed25519"
        || !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&governance.minimum_approvals)
        || governance.authorities.len() < governance.minimum_approvals as usize
        || governance.issued_at_unix > MAX_TIMESTAMP
        || governance.registry_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
    {
        return Err(
            "invalid factory release transparency external gossip registry governance invariants"
                .into(),
        );
    }
    validate_digest(
        &governance.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry governance base policy SHA-256",
    )?;
    validate_slug(
        &governance.policy_id,
        "factory release transparency external gossip registry governance policy id",
    )?;
    validate_slug(
        &governance.registry_id,
        "factory release transparency external gossip registry governance registry id",
    )?;
    validate_digest(
        &governance.registry_state_sha256,
        "factory release transparency external gossip registry governance state SHA-256",
    )?;
    validate_nonweak_public_key(
        &governance.registry_authority_public_key,
        "factory release transparency external gossip registry governance root public key",
    )?;
    validate_governance_authorities(&governance.authorities)?;
    decode_hex::<64>(
        &governance.signature,
        "factory release transparency external gossip registry governance root signature",
    )?;
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryThresholdTransition,
) -> Result<(), String> {
    if transition.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || transition.transition_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_SCOPE
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
        || transition.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || transition.effective_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "invalid factory release transparency external gossip registry threshold transition invariants"
                .into(),
        );
    }
    validate_digest(
        &transition.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry threshold transition base policy SHA-256",
    )?;
    validate_slug(
        &transition.policy_id,
        "factory release transparency external gossip registry threshold transition policy id",
    )?;
    validate_slug(
        &transition.registry_id,
        "factory release transparency external gossip registry threshold transition registry id",
    )?;
    validate_slug(
        &transition.organization_id,
        "factory release transparency external gossip registry threshold transition organization id",
    )?;
    validate_digest(
        &transition.reason_sha256,
        "factory release transparency external gossip registry threshold transition reason SHA-256",
    )?;
    validate_digest(
        &transition.governance_sha256,
        "factory release transparency external gossip registry governance SHA-256",
    )?;
    if let Some(previous) = &transition.previous_transition_sha256 {
        validate_digest(
            previous,
            "previous factory release transparency external gossip registry threshold transition SHA-256",
        )?;
    }
    if (transition.from_generation == 0) != transition.previous_transition_sha256.is_none() {
        return Err(
            "factory release transparency external gossip registry threshold transition chain reference is inconsistent"
                .into(),
        );
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &transition.governance,
    )?;
    let actual_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &transition.governance,
        )?;
    if transition.governance_sha256 != actual_governance_sha256
        || transition.base_observer_quorum_policy_sha256
            != transition.governance.base_observer_quorum_policy_sha256
        || transition.policy_id != transition.governance.policy_id
        || transition.registry_id != transition.governance.registry_id
        || transition.effective_at_unix < transition.governance.issued_at_unix
    {
        return Err(
            "factory release transparency external gossip registry threshold transition does not bind its governance"
                .into(),
        );
    }
    match transition.action {
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver => {
            validate_observer_slug(
                transition.observer_id.as_deref().ok_or_else(|| {
                    "factory release transparency external gossip threshold admission requires an observer id"
                        .to_string()
                })?,
                "admitted factory release transparency external gossip observer id",
            )?;
            validate_digest(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "factory release transparency external gossip threshold admission requires a trust-state SHA-256"
                            .to_string()
                    })?,
                "admitted factory release transparency external gossip observer trust-state SHA-256",
            )?;
        }
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization
        | FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::RevokeOrganization => {
            if transition.observer_id.is_some()
                || transition.observer_trust_state_sha256.is_some()
            {
                return Err(
                    "factory release transparency external gossip threshold status transition cannot bind an observer"
                        .into(),
                );
            }
        }
    }
    if transition.approvals.len() < transition.governance.minimum_approvals as usize
        || transition.approvals.len() > transition.governance.authorities.len()
    {
        return Err(
            "factory release transparency external gossip registry threshold transition approval count is invalid"
                .into(),
        );
    }
    let mut previous_id: Option<&String> = None;
    let mut public_keys = HashSet::new();
    for approval in &transition.approvals {
        validate_slug(
            &approval.authority_id,
            "factory release transparency external gossip registry governance approval authority id",
        )?;
        validate_nonweak_public_key(
            &approval.public_key,
            "factory release transparency external gossip registry governance approval public key",
        )?;
        decode_hex::<64>(
            &approval.signature,
            "factory release transparency external gossip registry governance approval signature",
        )?;
        if previous_id.is_some_and(|previous| previous >= &approval.authority_id)
            || !public_keys.insert(approval.public_key.as_str())
        {
            return Err(
                "factory release transparency external gossip registry threshold approvals require ordered distinct identities and keys"
                    .into(),
            );
        }
        previous_id = Some(&approval.authority_id);
    }
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernanceRotation,
) -> Result<(), String> {
    if rotation.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || rotation.rotation_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_SCOPE
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.rotated_at_unix > MAX_TIMESTAMP
        || rotation.old_governance_sha256 == rotation.new_governance_sha256
    {
        return Err(
            "invalid factory release transparency external gossip registry governance rotation invariants"
                .into(),
        );
    }
    validate_digest(
        &rotation.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry governance rotation base policy SHA-256",
    )?;
    validate_slug(
        &rotation.policy_id,
        "factory release transparency external gossip registry governance rotation policy id",
    )?;
    validate_slug(
        &rotation.registry_id,
        "factory release transparency external gossip registry governance rotation registry id",
    )?;
    validate_digest(
        &rotation.old_governance_sha256,
        "old factory release transparency external gossip registry governance SHA-256",
    )?;
    validate_digest(
        &rotation.new_governance_sha256,
        "new factory release transparency external gossip registry governance SHA-256",
    )?;
    if let Some(previous) = &rotation.previous_transition_sha256 {
        validate_digest(
            previous,
            "previous factory release transparency external gossip registry governance rotation SHA-256",
        )?;
    }
    if (rotation.from_generation == 0) != rotation.previous_transition_sha256.is_none() {
        return Err(
            "factory release transparency external gossip registry governance rotation chain reference is inconsistent"
                .into(),
        );
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &rotation.old_governance,
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &rotation.new_governance,
    )?;
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &rotation.old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &rotation.new_governance,
        )?;
    if rotation.old_governance_sha256 != old_governance_sha256
        || rotation.new_governance_sha256 != new_governance_sha256
        || rotation.base_observer_quorum_policy_sha256
            != rotation.old_governance.base_observer_quorum_policy_sha256
        || rotation.base_observer_quorum_policy_sha256
            != rotation.new_governance.base_observer_quorum_policy_sha256
        || rotation.policy_id != rotation.old_governance.policy_id
        || rotation.policy_id != rotation.new_governance.policy_id
        || rotation.registry_id != rotation.old_governance.registry_id
        || rotation.registry_id != rotation.new_governance.registry_id
        || rotation.old_governance.registry_authority_public_key
            != rotation.new_governance.registry_authority_public_key
        || rotation.new_governance.registry_generation != rotation.from_generation
        || rotation.new_governance.issued_at_unix < rotation.old_governance.issued_at_unix
        || rotation.rotated_at_unix < rotation.new_governance.issued_at_unix
        || (rotation.old_governance.minimum_approvals == rotation.new_governance.minimum_approvals
            && rotation.old_governance.authorities == rotation.new_governance.authorities)
    {
        return Err(
            "factory release transparency external gossip registry governance rotation does not bind distinct compatible governance"
                .into(),
        );
    }
    validate_governance_approval_shape(&rotation.old_approvals, &rotation.old_governance, "old")?;
    validate_governance_approval_shape(&rotation.new_approvals, &rotation.new_governance, "new")?;
    Ok(())
}

pub(crate) fn validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || rotation.rotation_scope
            != SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_SCOPE
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.rotated_at_unix > MAX_TIMESTAMP
        || rotation.old_public_key == rotation.new_public_key
        || rotation.old_governance_sha256 == rotation.new_governance_sha256
    {
        return Err(
            "invalid factory release transparency external gossip registry governed authority rotation invariants"
                .into(),
        );
    }
    validate_digest(
        &rotation.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip registry governed authority rotation base policy SHA-256",
    )?;
    validate_slug(
        &rotation.policy_id,
        "factory release transparency external gossip registry governed authority rotation policy id",
    )?;
    validate_slug(
        &rotation.registry_id,
        "factory release transparency external gossip registry governed authority rotation registry id",
    )?;
    validate_nonweak_public_key(
        &rotation.old_public_key,
        "old factory release transparency external gossip governed registry authority public key",
    )?;
    validate_nonweak_public_key(
        &rotation.new_public_key,
        "new factory release transparency external gossip governed registry authority public key",
    )?;
    validate_digest(
        &rotation.old_governance_sha256,
        "old factory release transparency external gossip registry governance SHA-256",
    )?;
    validate_digest(
        &rotation.new_governance_sha256,
        "new factory release transparency external gossip registry governance SHA-256",
    )?;
    if let Some(previous) = &rotation.previous_transition_sha256 {
        validate_digest(
            previous,
            "previous factory release transparency external gossip governed authority rotation SHA-256",
        )?;
    }
    if (rotation.from_generation == 0) != rotation.previous_transition_sha256.is_none() {
        return Err(
            "factory release transparency external gossip governed authority rotation chain reference is inconsistent"
                .into(),
        );
    }
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &rotation.old_governance,
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &rotation.new_governance,
    )?;
    let old_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &rotation.old_governance,
        )?;
    let new_governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            &rotation.new_governance,
        )?;
    if rotation.old_governance_sha256 != old_governance_sha256
        || rotation.new_governance_sha256 != new_governance_sha256
        || rotation.base_observer_quorum_policy_sha256
            != rotation.old_governance.base_observer_quorum_policy_sha256
        || rotation.base_observer_quorum_policy_sha256
            != rotation.new_governance.base_observer_quorum_policy_sha256
        || rotation.policy_id != rotation.old_governance.policy_id
        || rotation.policy_id != rotation.new_governance.policy_id
        || rotation.registry_id != rotation.old_governance.registry_id
        || rotation.registry_id != rotation.new_governance.registry_id
        || rotation.old_public_key != rotation.old_governance.registry_authority_public_key
        || rotation.new_public_key != rotation.new_governance.registry_authority_public_key
        || rotation.new_governance.registry_generation != rotation.from_generation
        || rotation.new_governance.issued_at_unix < rotation.old_governance.issued_at_unix
        || rotation.rotated_at_unix < rotation.new_governance.issued_at_unix
    {
        return Err(
            "factory release transparency external gossip governed authority rotation does not bind compatible roots and governance"
                .into(),
        );
    }
    validate_governance_approval_shape(&rotation.old_approvals, &rotation.old_governance, "old")?;
    validate_governance_approval_shape(&rotation.new_approvals, &rotation.new_governance, "new")?;
    Ok(())
}

fn validate_governance_approval_shape(
    approvals: &[FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval],
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    label: &str,
) -> Result<(), String> {
    if approvals.len() < governance.minimum_approvals as usize
        || approvals.len() > governance.authorities.len()
    {
        return Err(format!(
            "factory release transparency external gossip registry {label} governance rotation approval count is invalid"
        ));
    }
    let mut previous_id: Option<&String> = None;
    let mut public_keys = HashSet::new();
    for approval in approvals {
        validate_slug(
            &approval.authority_id,
            "factory release transparency external gossip registry governance rotation authority id",
        )?;
        validate_nonweak_public_key(
            &approval.public_key,
            "factory release transparency external gossip registry governance rotation public key",
        )?;
        decode_hex::<64>(
            &approval.signature,
            "factory release transparency external gossip registry governance rotation signature",
        )?;
        if previous_id.is_some_and(|previous| previous >= &approval.authority_id)
            || !public_keys.insert(approval.public_key.as_str())
        {
            return Err(format!(
                "factory release transparency external gossip registry {label} governance rotation approvals require ordered distinct identities and keys"
            ));
        }
        previous_id = Some(&approval.authority_id);
    }
    Ok(())
}

fn validate_governance_authorities(
    authorities: &[FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority],
) -> Result<(), String> {
    if authorities.len() < 2 || authorities.len() > MAXIMUM_GOVERNANCE_AUTHORITIES {
        return Err(
            "factory release transparency external gossip registry governance requires 2 to 100 authorities"
                .into(),
        );
    }
    let mut previous_id: Option<&String> = None;
    let mut public_keys = HashSet::new();
    for authority in authorities {
        validate_slug(
            &authority.authority_id,
            "factory release transparency external gossip registry governance authority id",
        )?;
        validate_nonweak_public_key(
            &authority.public_key,
            "factory release transparency external gossip registry governance authority public key",
        )?;
        if previous_id.is_some_and(|previous| previous >= &authority.authority_id)
            || !public_keys.insert(authority.public_key.as_str())
        {
            return Err(
                "factory release transparency external gossip registry governance authorities require ordered distinct identities and keys"
                    .into(),
            );
        }
        previous_id = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_governance_for_registry(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    if governance.base_observer_quorum_policy_sha256 != registry.base_observer_quorum_policy_sha256
        || governance.policy_id != registry.policy_id
        || governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key != registry.authority_public_key
    {
        return Err(
            "factory release transparency external gossip registry governance does not match retained root trust"
                .into(),
        );
    }
    let governance_sha256 =
        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
            governance,
        )?;
    if let Some(active) = &registry.active_governance_sha256 {
        if active != &governance_sha256 {
            return Err(
                "factory release transparency external gossip registry governance does not match retained active governance"
                    .into(),
            );
        }
    } else if governance.registry_generation != registry.generation
        || governance.registry_state_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                registry,
            )?
    {
        return Err(
            "factory release transparency external gossip registry governance does not bind the activation state"
                .into(),
        );
    }
    verify_governance_root_signature(governance)
}

fn validate_successor_governance_for_registry(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    if registry.active_governance_sha256.is_none()
        || governance.base_observer_quorum_policy_sha256
            != registry.base_observer_quorum_policy_sha256
        || governance.policy_id != registry.policy_id
        || governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key != registry.authority_public_key
        || governance.registry_generation != registry.generation
        || governance.registry_state_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                registry,
            )?
    {
        return Err(
            "factory release transparency external gossip successor governance does not bind the selected active-governance state"
                .into(),
        );
    }
    verify_governance_root_signature(governance)
}

fn validate_successor_root_governance_for_registry(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_factory_release_state_transparency_external_gossip_organization_registry(registry)?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    if registry.active_governance_sha256.is_none()
        || governance.base_observer_quorum_policy_sha256
            != registry.base_observer_quorum_policy_sha256
        || governance.policy_id != registry.policy_id
        || governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key == registry.authority_public_key
        || governance.registry_generation != registry.generation
        || governance.registry_state_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                registry,
            )?
    {
        return Err(
            "factory release transparency external gossip successor-root governance does not bind a distinct root to the selected active-governance state"
                .into(),
        );
    }
    verify_governance_root_signature(governance)
}

fn verify_governance_root_signature(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    let payload = governance_payload(
        &governance.base_observer_quorum_policy_sha256,
        &governance.policy_id,
        &governance.registry_id,
        governance.registry_generation,
        &governance.registry_state_sha256,
        &governance.registry_authority_public_key,
        governance.minimum_approvals,
        &governance.authorities,
        governance.issued_at_unix,
    )?;
    let public_key = decode_hex::<32>(
        &governance.registry_authority_public_key,
        "factory release transparency external gossip registry governance root public key",
    )?;
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &governance.signature,
        "factory release transparency external gossip registry governance root signature",
    )?);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid registry governance root public key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| {
            "factory release transparency external gossip registry governance root signature verification failed"
                .to_string()
        })
}

fn sign_governance_approvals(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    signers: &[(String, [u8; 32])],
    payload: &[u8],
    label: &str,
) -> Result<Vec<FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval>, String> {
    if signers.len() < governance.minimum_approvals as usize
        || signers.len() > governance.authorities.len()
    {
        return Err(format!(
            "factory release transparency external gossip registry {label} governance rotation does not satisfy its threshold"
        ));
    }
    let mut seen_ids = HashSet::new();
    let mut seen_keys = HashSet::new();
    let mut approvals = Vec::with_capacity(signers.len());
    for (authority_id, secret_key) in signers {
        if !seen_ids.insert(authority_id.as_str()) {
            return Err(format!(
                "duplicate factory release transparency external gossip registry {label} governance authority identity"
            ));
        }
        let signing_key = SigningKey::from_bytes(secret_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        if !seen_keys.insert(public_key.clone()) {
            return Err(format!(
                "duplicate factory release transparency external gossip registry {label} governance authority key"
            ));
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.as_str().cmp(authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                format!(
                    "untrusted factory release transparency external gossip registry {label} governance authority {authority_id:?}"
                )
            })?;
        if trusted.public_key != public_key {
            return Err(format!(
                "factory release transparency external gossip registry {label} governance authority {authority_id:?} key does not match governance"
            ));
        }
        approvals.push(
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval {
                authority_id: authority_id.clone(),
                public_key,
                signature: hex::encode(signing_key.sign(payload).to_bytes()),
            },
        );
    }
    approvals.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_approval_shape(&approvals, governance, label)?;
    Ok(approvals)
}

fn verify_governance_approvals(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    approvals: &[FactoryReleaseStateTransparencyExternalGossipRegistryThresholdApproval],
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    validate_governance_approval_shape(approvals, governance, label)?;
    for approval in approvals {
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.cmp(&approval.authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                format!(
                    "untrusted factory release transparency external gossip registry {label} governance rotation approval"
                )
            })?;
        if trusted.public_key != approval.public_key {
            return Err(format!(
                "factory release transparency external gossip registry {label} governance rotation approval key substitution"
            ));
        }
        let public_key = decode_hex::<32>(
            &approval.public_key,
            "factory release transparency external gossip registry governance rotation approval public key",
        )?;
        let signature = Signature::from_bytes(&decode_hex::<64>(
            &approval.signature,
            "factory release transparency external gossip registry governance rotation approval signature",
        )?);
        VerifyingKey::from_bytes(&public_key)
            .map_err(|error| format!("invalid governance rotation approval public key: {error}"))?
            .verify_strict(payload, &signature)
            .map_err(|_| {
                format!(
                    "factory release transparency external gossip registry {label} governance rotation approval verification failed"
                )
            })?;
    }
    Ok(())
}

fn transition_observer_binding(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    action: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&FactoryReleaseStateTransparencyExternalGossipObserverTrustState>,
) -> Result<(Option<String>, Option<String>), String> {
    match action {
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver => {
            let state = observer_trust_state.ok_or_else(|| {
                "factory release transparency external gossip observer admission requires the current trust state"
                    .to_string()
            })?;
            let digest =
                factory_release_state_transparency_external_gossip_observer_trust_state_sha256(
                    state,
                )?;
            if state.base_observer_quorum_policy_sha256
                != registry.base_observer_quorum_policy_sha256
                || state.policy_id != registry.policy_id
                || state.organization_id != organization_id
            {
                return Err(
                    "factory release transparency external gossip observer trust does not match the registry admission target"
                        .into(),
                );
            }
            Ok((Some(state.observer_id.clone()), Some(digest)))
        }
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization
        | FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::RevokeOrganization => {
            if observer_trust_state.is_some() {
                return Err(
                    "factory release transparency external gossip organization status transition cannot include observer trust"
                        .into(),
                );
            }
            Ok((None, None))
        }
    }
}

fn apply_action(
    organizations: &mut Vec<FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryEntry>,
    transition: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    let organization_index = organizations
        .binary_search_by(|entry| entry.organization_id.cmp(&transition.organization_id));
    match transition.action {
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver => {
            let observer = FactoryReleaseStateTransparencyExternalGossipObserverAdmission {
                observer_id: transition.observer_id.clone().ok_or_else(|| {
                    "factory release transparency external gossip observer admission is incomplete"
                        .to_string()
                })?,
                observer_trust_state_sha256: transition
                    .observer_trust_state_sha256
                    .clone()
                    .ok_or_else(|| {
                        "factory release transparency external gossip observer admission is incomplete"
                            .to_string()
                    })?,
                admitted_at_unix: transition.effective_at_unix,
            };
            match organization_index {
                Ok(index) => {
                    let organization = &mut organizations[index];
                    if organization.status
                        != FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Active
                    {
                        return Err(
                            "cannot admit a factory release transparency external gossip observer to a non-active organization"
                                .into(),
                        );
                    }
                    match organization
                        .observers
                        .binary_search_by(|entry| entry.observer_id.cmp(&observer.observer_id))
                    {
                        Ok(index) => {
                            if organization.observers[index].observer_trust_state_sha256
                                == observer.observer_trust_state_sha256
                            {
                                return Err(
                                    "exact factory release transparency external gossip observer trust state is already admitted"
                                        .into(),
                                );
                            }
                            organization.observers[index] = observer;
                        }
                        Err(index) => organization.observers.insert(index, observer),
                    }
                }
                Err(index) => organizations.insert(
                    index,
                    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryEntry {
                        organization_id: transition.organization_id.clone(),
                        status:
                            FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Active,
                        status_since_unix: transition.effective_at_unix,
                        status_reason_sha256: transition.reason_sha256.clone(),
                        observers: vec![observer],
                    },
                ),
            }
        }
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization => {
            let organization = organization_index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| {
                    "cannot suspend a factory release transparency external gossip organization that is not admitted"
                        .to_string()
                })?;
            if organization.status
                != FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Active
            {
                return Err(
                    "only an active factory release transparency external gossip organization can be suspended"
                        .into(),
                );
            }
            organization.status =
                FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Suspended;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::RevokeOrganization => {
            let organization = organization_index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| {
                    "cannot revoke a factory release transparency external gossip organization that is not admitted"
                        .to_string()
                })?;
            if organization.status
                == FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Revoked
            {
                return Err(
                    "factory release transparency external gossip organization is already permanently revoked"
                        .into(),
                );
            }
            organization.status =
                FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Revoked;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transition_payload(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    to_generation: u64,
    action: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_id: Option<&str>,
    observer_trust_state_sha256: Option<&str>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&TransitionPayload {
        domain: TRANSITION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        transition_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE,
        base_observer_quorum_policy_sha256: &registry.base_observer_quorum_policy_sha256,
        policy_id: &registry.policy_id,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        action,
        organization_id,
        observer_id,
        observer_trust_state_sha256,
        reason_sha256,
        effective_at_unix,
        authority_public_key: &registry.authority_public_key,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip registry transition payload: {error}"
        )
    })
}

fn authority_key_rotation_payload(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    to_generation: u64,
    old_public_key: &str,
    new_public_key: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AuthorityKeyRotationPayload {
        domain: AUTHORITY_KEY_ROTATION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        rotation_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_SCOPE,
        base_observer_quorum_policy_sha256: &registry.base_observer_quorum_policy_sha256,
        policy_id: &registry.policy_id,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        old_public_key,
        new_public_key,
        rotated_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip registry authority rotation payload: {error}"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn governance_payload(
    base_observer_quorum_policy_sha256: &str,
    policy_id: &str,
    registry_id: &str,
    registry_generation: u64,
    registry_state_sha256: &str,
    registry_authority_public_key: &str,
    minimum_approvals: u32,
    authorities: &[FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority],
    issued_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernancePayload {
        domain: GOVERNANCE_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        governance_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE,
        base_observer_quorum_policy_sha256,
        policy_id,
        registry_id,
        registry_generation,
        registry_state_sha256,
        registry_authority_public_key,
        minimum_approvals,
        authorities,
        issued_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip registry governance payload: {error}"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn threshold_transition_payload(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    to_generation: u64,
    governance_sha256: &str,
    action: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_id: Option<&str>,
    observer_trust_state_sha256: Option<&str>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ThresholdTransitionPayload {
        domain: THRESHOLD_TRANSITION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        transition_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_SCOPE,
        base_observer_quorum_policy_sha256: &registry.base_observer_quorum_policy_sha256,
        policy_id: &registry.policy_id,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        governance_sha256,
        action,
        organization_id,
        observer_id,
        observer_trust_state_sha256,
        reason_sha256,
        effective_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip registry threshold transition payload: {error}"
        )
    })
}

fn governance_rotation_payload(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    to_generation: u64,
    old_governance_sha256: &str,
    new_governance_sha256: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernanceRotationPayload {
        domain: GOVERNANCE_ROTATION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        rotation_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_SCOPE,
        base_observer_quorum_policy_sha256: &registry.base_observer_quorum_policy_sha256,
        policy_id: &registry.policy_id,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip registry governance rotation payload: {error}"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn governed_authority_key_rotation_payload(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    to_generation: u64,
    old_public_key: &str,
    new_public_key: &str,
    old_governance_sha256: &str,
    new_governance_sha256: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernedAuthorityKeyRotationPayload {
        domain: GOVERNED_AUTHORITY_KEY_ROTATION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION,
        rotation_scope:
            SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_SCOPE,
        base_observer_quorum_policy_sha256: &registry.base_observer_quorum_policy_sha256,
        policy_id: &registry.policy_id,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        old_public_key,
        new_public_key,
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip governed authority rotation payload: {error}"
        )
    })
}

fn validate_registry_authority_role_separation(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    observer_trust_report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    validate_registry_authority_key_role_separation(
        &registry.authority_public_key,
        observer_trust_report,
    )
}

fn validate_registry_authority_history_role_separation(
    authority_keys: &[String],
    observer_trust_report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    for authority in authority_keys {
        validate_registry_authority_key_role_separation(authority, observer_trust_report)?;
    }
    Ok(())
}

fn validate_governance_authority_role_separation(
    governance: &SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryGovernance,
    registry_authority_keys: &[String],
    observer_trust_report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        governance,
    )?;
    for authority in &governance.authorities {
        if registry_authority_keys.contains(&authority.public_key) {
            return Err(
                "factory release transparency external gossip registry governance authority key is not role-disjoint from registry authority history"
                    .into(),
            );
        }
        validate_registry_authority_key_role_separation(
            &authority.public_key,
            observer_trust_report,
        )?;
    }
    Ok(())
}

fn validate_registry_authority_key_role_separation(
    authority: &str,
    observer_trust_report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    for observer in &observer_trust_report.observer_trust {
        if observer.initial_public_key == authority
            || observer.current_trust_state.current_public_key == authority
            || observer.rotations.iter().any(|evidence| {
                evidence.rotation.old_public_key == authority
                    || evidence.rotation.new_public_key == authority
            })
        {
            return Err(
                "factory release transparency external gossip registry authority key is not role-disjoint from observer trust history"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_selected_member_admissions(
    registry: &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistry,
    observer_trust_report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    for member in &observer_trust_report.quorum_report.members {
        let organization = registry
            .organizations
            .binary_search_by(|entry| entry.organization_id.cmp(&member.organization_id))
            .ok()
            .map(|index| &registry.organizations[index])
            .ok_or_else(|| {
                format!(
                    "factory release transparency external gossip organization {} is not admitted",
                    member.organization_id
                )
            })?;
        if organization.status
            != FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Active
        {
            return Err(format!(
                "factory release transparency external gossip organization {} is not active",
                member.organization_id
            ));
        }
        let trust = observer_trust_report
            .observer_trust
            .iter()
            .find(|candidate| {
                candidate.organization_id == member.organization_id
                    && candidate.observer_id == member.observer_id
            })
            .ok_or_else(|| {
                "factory release transparency external gossip quorum member lacks current observer trust"
                    .to_string()
            })?;
        if trust.current_trust_state.current_public_key != member.observer_public_key {
            return Err(
                "factory release transparency external gossip quorum member key is not current"
                    .into(),
            );
        }
        let admitted = organization.observers.iter().any(|observer| {
            observer.observer_id == member.observer_id
                && observer.observer_trust_state_sha256 == trust.current_trust_state_sha256
        });
        if !admitted {
            return Err(format!(
                "factory release transparency external gossip observer {}/{} does not match an admitted current trust state",
                member.organization_id, member.observer_id
            ));
        }
    }
    Ok(())
}

fn validate_registry_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_VERIFICATION_SCOPE
        || !report.registry_genesis_pin_matched
        || !report.complete_registry_history_verified
        || !report.registry_authority_signatures_verified
        || !report.registry_generation_chain_verified
        || !report.registry_digest_chain_verified
        || !report.registry_timestamps_monotonic
        || !report.registry_authority_role_separation_verified
        || !report.current_observer_trust_admissions_verified
        || !report.selected_observer_organizations_active
        || !report.registry_effective_before_quorum_evaluation_verified
        || !report.selected_ledger_latest_registry_verified
        || !report.selected_ledger_observer_trust_report_verified
        || !report.selected_ledger_latest_observer_rotations_verified
        || report.selected_ledger_registry_bound_report_committed
        || report.selected_ledger_rollback_resistance_verified
        || report.global_non_equivocation_verified
        || report.trusted_time_verified
        || report.independent_organization_operation_verified
        || report.factory_legal_identity_verified
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
        || report.quorum_met != report.observer_trust_report.quorum_met
        || report.evaluated_at_unix != report.observer_trust_report.evaluated_at_unix
        || report.selected_ledger_latest_observer_rotations_verified
            != report
                .observer_trust_report
                .selected_ledger_latest_observer_rotations_verified
    {
        return Err(
            "invalid factory release transparency external gossip registry report invariants"
                .into(),
        );
    }
    let expected_status = if report.quorum_met {
        "verified"
    } else {
        "insufficient_organizations"
    };
    if report.status != expected_status
        || report.observer_trust_report.status != expected_status
        || usize::try_from(report.registry_transition_count).ok()
            != Some(report.registry_transitions.len())
        || report.registry_transitions.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.current_registry.generation != u64::from(report.registry_transition_count)
    {
        return Err(
            "factory release transparency external gossip registry report state is inconsistent"
                .into(),
        );
    }
    validate_digest(
        &report.registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        &report.current_registry_sha256,
        "factory release transparency external gossip current registry SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip registry report binding SHA-256",
    )?;
    validate_artifact_identity(
        &report.registry_genesis_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry genesis artifact",
    )?;
    validate_artifact_identity(
        &report.observer_trust_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust report artifact",
    )?;
    Ok(())
}

fn validate_registry_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport,
) -> Result<(), String> {
    validate_registry_report_shape(report)?;
    let genesis_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &report.registry_genesis,
        )?;
    if report.registry_genesis.generation != 0
        || report.registry_genesis_artifact != exact_identity(&genesis_source)
        || report.registry_genesis_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &report.registry_genesis,
            )?
    {
        return Err(
            "factory release transparency external gossip registry report genesis binding is invalid"
                .into(),
        );
    }
    let mut current = report.registry_genesis.clone();
    for evidence in &report.registry_transitions {
        let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &evidence.transition,
        )?;
        validate_artifact_identity(
            &evidence.artifact,
            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
            "factory release transparency external gossip registry transition artifact",
        )?;
        if evidence.artifact != exact_identity(&source) {
            return Err(
                "factory release transparency external gossip registry transition artifact identity is invalid"
                    .into(),
            );
        }
        current = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &current,
            &evidence.transition,
        )?;
    }
    if current != report.current_registry
        || report.current_registry_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &current,
            )?
    {
        return Err(
            "factory release transparency external gossip registry report does not reproduce its current registry"
                .into(),
        );
    }
    let trust_source = render_factory_release_state_transparency_external_gossip_trust_report(
        &report.observer_trust_report,
    )?;
    if report.observer_trust_report_artifact != exact_identity(&trust_source)
        || report.registry_genesis.base_observer_quorum_policy_sha256
            != report
                .observer_trust_report
                .base_observer_quorum_policy_sha256
        || report.registry_genesis.policy_id
            != report
                .observer_trust_report
                .base_observer_quorum_policy
                .policy_id
        || report
            .current_registry
            .last_updated_at_unix
            .is_some_and(|updated| updated > report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry report observer trust binding is invalid"
                .into(),
        );
    }
    validate_registry_authority_role_separation(
        &report.current_registry,
        &report.observer_trust_report,
    )?;
    validate_selected_member_admissions(&report.current_registry, &report.observer_trust_report)?;
    if registry_report_binding(report)? != report.binding_sha256 {
        return Err(
            "factory release transparency external gossip registry report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn validate_authority_rotation_registry_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_VERIFICATION_SCOPE
        || !report.registry_genesis_pin_matched
        || !report.complete_registry_history_verified
        || !report.registry_authority_transition_signatures_verified
        || !report.registry_authority_rotation_dual_signatures_verified
        || !report.registry_authority_successor_possession_verified
        || !report.registry_authority_key_history_unique
        || !report.registry_generation_chain_verified
        || !report.registry_digest_chain_verified
        || !report.registry_timestamps_monotonic
        || !report.registry_authority_role_separation_verified
        || !report.current_observer_trust_admissions_verified
        || !report.selected_observer_organizations_active
        || !report.registry_effective_before_quorum_evaluation_verified
        || !report.selected_ledger_latest_registry_verified
        || !report.selected_ledger_observer_trust_report_verified
        || !report.selected_ledger_latest_observer_rotations_verified
        || report.selected_ledger_registry_bound_report_committed
        || report.selected_ledger_rollback_resistance_verified
        || report.authority_threshold_governance_verified
        || report.global_non_equivocation_verified
        || report.trusted_time_verified
        || report.independent_organization_operation_verified
        || report.factory_legal_identity_verified
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
        || report.quorum_met != report.observer_trust_report.quorum_met
        || report.evaluated_at_unix != report.observer_trust_report.evaluated_at_unix
        || report.selected_ledger_latest_observer_rotations_verified
            != report
                .observer_trust_report
                .selected_ledger_latest_observer_rotations_verified
    {
        return Err(
            "invalid factory release transparency external gossip registry authority-rotation report invariants"
                .into(),
        );
    }
    let expected_status = if report.quorum_met {
        "verified"
    } else {
        "insufficient_organizations"
    };
    if report.status != expected_status
        || report.observer_trust_report.status != expected_status
        || usize::try_from(report.registry_history_event_count).ok()
            != Some(report.registry_history_events.len())
        || report.registry_history_events.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.current_registry.generation != u64::from(report.registry_history_event_count)
        || report.registry_authority_rotation_count > report.registry_history_event_count
    {
        return Err(
            "factory release transparency external gossip registry authority-rotation report state is inconsistent"
                .into(),
        );
    }
    validate_digest(
        &report.registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        &report.current_registry_sha256,
        "factory release transparency external gossip current registry SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip registry authority-rotation report binding SHA-256",
    )?;
    validate_artifact_identity(
        &report.registry_genesis_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry genesis artifact",
    )?;
    validate_artifact_identity(
        &report.observer_trust_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust report artifact",
    )?;
    Ok(())
}

fn validate_authority_rotation_registry_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
) -> Result<(), String> {
    validate_authority_rotation_registry_report_shape(report)?;
    let genesis_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &report.registry_genesis,
        )?;
    if report.registry_genesis.generation != 0
        || report.registry_genesis_artifact != exact_identity(&genesis_source)
        || report.registry_genesis_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &report.registry_genesis,
            )?
    {
        return Err(
            "factory release transparency external gossip registry authority-rotation report genesis binding is invalid"
                .into(),
        );
    }
    let mut current = report.registry_genesis.clone();
    let mut authority_keys = vec![report.registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([report.registry_genesis.authority_public_key.clone()]);
    let mut rotation_count = 0_u32;
    for evidence in &report.registry_history_events {
        match evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                    "factory release transparency external gossip registry transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry authority rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation artifact identity is invalid"
                            .into(),
                    );
                }
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                rotation_count = rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
        }
    }
    if rotation_count != report.registry_authority_rotation_count
        || current != report.current_registry
        || report.current_registry_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &current,
            )?
    {
        return Err(
            "factory release transparency external gossip registry authority-rotation report does not reproduce its current registry"
                .into(),
        );
    }
    let trust_source = render_factory_release_state_transparency_external_gossip_trust_report(
        &report.observer_trust_report,
    )?;
    if report.observer_trust_report_artifact != exact_identity(&trust_source)
        || report.registry_genesis.base_observer_quorum_policy_sha256
            != report
                .observer_trust_report
                .base_observer_quorum_policy_sha256
        || report.registry_genesis.policy_id
            != report
                .observer_trust_report
                .base_observer_quorum_policy
                .policy_id
        || report
            .current_registry
            .last_updated_at_unix
            .is_some_and(|updated| updated > report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry authority-rotation report observer trust binding is invalid"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(
        &authority_keys,
        &report.observer_trust_report,
    )?;
    validate_selected_member_admissions(&report.current_registry, &report.observer_trust_report)?;
    if authority_rotation_registry_report_binding(report)? != report.binding_sha256 {
        return Err(
            "factory release transparency external gossip registry authority-rotation report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn validate_threshold_governance_registry_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_VERIFICATION_SCOPE
        || !report.registry_genesis_pin_matched
        || !report.complete_registry_history_verified
        || !report.registry_authority_transition_signatures_verified
        || !report.registry_authority_rotation_dual_signatures_verified
        || !report.registry_authority_successor_possession_verified
        || !report.registry_authority_key_history_unique
        || !report.governance_root_signature_verified
        || !report.governance_authority_identities_unique
        || !report.governance_authority_keys_unique
        || !report.governance_threshold_approvals_verified
        || !report.root_only_registry_mutations_locked_out
        || !report.registry_generation_chain_verified
        || !report.registry_digest_chain_verified
        || !report.registry_timestamps_monotonic
        || !report.registry_authority_role_separation_verified
        || !report.current_observer_trust_admissions_verified
        || !report.selected_observer_organizations_active
        || !report.registry_effective_before_quorum_evaluation_verified
        || !report.selected_ledger_latest_registry_verified
        || !report.selected_ledger_observer_trust_report_verified
        || !report.selected_ledger_latest_observer_rotations_verified
        || report.selected_ledger_registry_bound_report_committed
        || report.selected_ledger_rollback_resistance_verified
        || !report.authority_threshold_governance_verified
        || report.global_non_equivocation_verified
        || report.trusted_time_verified
        || report.independent_organization_operation_verified
        || report.factory_legal_identity_verified
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
        || report.quorum_met != report.observer_trust_report.quorum_met
        || report.evaluated_at_unix != report.observer_trust_report.evaluated_at_unix
        || report.selected_ledger_latest_observer_rotations_verified
            != report
                .observer_trust_report
                .selected_ledger_latest_observer_rotations_verified
    {
        return Err(
            "invalid factory release transparency external gossip registry threshold-governance report invariants"
                .into(),
        );
    }
    let expected_status = if report.quorum_met {
        "verified"
    } else {
        "insufficient_organizations"
    };
    if report.status != expected_status
        || report.observer_trust_report.status != expected_status
        || usize::try_from(report.registry_history_event_count).ok()
            != Some(report.registry_history_events.len())
        || report.registry_history_events.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.current_registry.generation != u64::from(report.registry_history_event_count)
        || report.registry_authority_rotation_count > report.registry_history_event_count
        || report.registry_threshold_transition_count == 0
        || report.registry_threshold_transition_count > report.registry_history_event_count
        || report
            .registry_authority_rotation_count
            .checked_add(report.registry_threshold_transition_count)
            .is_none_or(|count| count > report.registry_history_event_count)
        || report.current_registry.active_governance_sha256.as_deref()
            != Some(report.active_governance_sha256.as_str())
    {
        return Err(
            "factory release transparency external gossip registry threshold-governance report state is inconsistent"
                .into(),
        );
    }
    validate_digest(
        &report.registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        &report.current_registry_sha256,
        "factory release transparency external gossip current registry SHA-256",
    )?;
    validate_digest(
        &report.active_governance_sha256,
        "factory release transparency external gossip active registry governance SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip registry threshold-governance report binding SHA-256",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &report.active_governance,
    )?;
    validate_artifact_identity(
        &report.registry_genesis_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry genesis artifact",
    )?;
    validate_artifact_identity(
        &report.observer_trust_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust report artifact",
    )?;
    Ok(())
}

fn validate_threshold_governance_registry_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
) -> Result<(), String> {
    validate_threshold_governance_registry_report_shape(report)?;
    let genesis_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &report.registry_genesis,
        )?;
    if report.registry_genesis.generation != 0
        || report.registry_genesis_artifact != exact_identity(&genesis_source)
        || report.registry_genesis_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &report.registry_genesis,
            )?
    {
        return Err(
            "factory release transparency external gossip registry threshold-governance report genesis binding is invalid"
                .into(),
        );
    }
    let mut current = report.registry_genesis.clone();
    let mut authority_keys = vec![report.registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([report.registry_genesis.authority_public_key.clone()]);
    let mut rotation_count = 0_u32;
    let mut threshold_count = 0_u32;
    let mut active_governance = None;
    for evidence in &report.registry_history_events {
        match evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                    "factory release transparency external gossip registry transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry authority rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation artifact identity is invalid"
                            .into(),
                    );
                }
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                rotation_count = rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::ThresholdTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
                    "factory release transparency external gossip registry threshold transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry threshold transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current,
                    transition,
                )?;
                active_governance = Some(transition.governance.clone());
                threshold_count = threshold_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
        }
    }
    if rotation_count != report.registry_authority_rotation_count
        || threshold_count != report.registry_threshold_transition_count
        || active_governance.as_ref() != Some(&report.active_governance)
        || report.active_governance_sha256
            != signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                &report.active_governance,
            )?
        || current != report.current_registry
        || report.current_registry_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &current,
            )?
    {
        return Err(
            "factory release transparency external gossip registry threshold-governance report does not reproduce its current registry"
                .into(),
        );
    }
    let trust_source = render_factory_release_state_transparency_external_gossip_trust_report(
        &report.observer_trust_report,
    )?;
    if report.observer_trust_report_artifact != exact_identity(&trust_source)
        || report.registry_genesis.base_observer_quorum_policy_sha256
            != report
                .observer_trust_report
                .base_observer_quorum_policy_sha256
        || report.registry_genesis.policy_id
            != report
                .observer_trust_report
                .base_observer_quorum_policy
                .policy_id
        || report
            .current_registry
            .last_updated_at_unix
            .is_some_and(|updated| updated > report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry threshold-governance report observer trust binding is invalid"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(
        &authority_keys,
        &report.observer_trust_report,
    )?;
    validate_governance_authority_role_separation(
        &report.active_governance,
        &authority_keys,
        &report.observer_trust_report,
    )?;
    validate_selected_member_admissions(&report.current_registry, &report.observer_trust_report)?;
    if threshold_governance_registry_report_binding(report)? != report.binding_sha256 {
        return Err(
            "factory release transparency external gossip registry threshold-governance report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn validate_governance_rotation_registry_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_VERIFICATION_SCOPE
        || !report.registry_genesis_pin_matched
        || !report.complete_registry_history_verified
        || !report.registry_authority_transition_signatures_verified
        || !report.registry_authority_rotation_dual_signatures_verified
        || !report.registry_authority_successor_possession_verified
        || !report.registry_authority_key_history_unique
        || !report.governance_root_signatures_verified
        || !report.governance_authority_identities_unique
        || !report.governance_authority_keys_unique
        || !report.governance_threshold_approvals_verified
        || !report.governance_rotation_old_quorum_verified
        || !report.governance_rotation_new_quorum_verified
        || !report.successor_governance_state_binding_verified
        || !report.root_only_registry_mutations_locked_out
        || !report.registry_generation_chain_verified
        || !report.registry_digest_chain_verified
        || !report.registry_timestamps_monotonic
        || !report.registry_authority_role_separation_verified
        || !report.current_observer_trust_admissions_verified
        || !report.selected_observer_organizations_active
        || !report.registry_effective_before_quorum_evaluation_verified
        || !report.selected_ledger_latest_registry_verified
        || !report.selected_ledger_observer_trust_report_verified
        || !report.selected_ledger_latest_observer_rotations_verified
        || report.selected_ledger_registry_bound_report_committed
        || report.selected_ledger_rollback_resistance_verified
        || !report.authority_threshold_governance_verified
        || report.global_non_equivocation_verified
        || report.trusted_time_verified
        || report.independent_governance_control_verified
        || report.independent_organization_operation_verified
        || report.factory_legal_identity_verified
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
        || report.quorum_met != report.observer_trust_report.quorum_met
        || report.evaluated_at_unix != report.observer_trust_report.evaluated_at_unix
        || report.selected_ledger_latest_observer_rotations_verified
            != report
                .observer_trust_report
                .selected_ledger_latest_observer_rotations_verified
    {
        return Err(
            "invalid factory release transparency external gossip registry governance-rotation report invariants"
                .into(),
        );
    }
    let expected_status = if report.quorum_met {
        "verified"
    } else {
        "insufficient_organizations"
    };
    let governed_event_count = report
        .registry_authority_rotation_count
        .checked_add(report.registry_threshold_transition_count)
        .and_then(|count| count.checked_add(report.registry_governance_rotation_count));
    if report.status != expected_status
        || report.observer_trust_report.status != expected_status
        || usize::try_from(report.registry_history_event_count).ok()
            != Some(report.registry_history_events.len())
        || report.registry_history_events.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.current_registry.generation != u64::from(report.registry_history_event_count)
        || report.registry_authority_rotation_count > report.registry_history_event_count
        || report.registry_threshold_transition_count == 0
        || report.registry_threshold_transition_count > report.registry_history_event_count
        || report.registry_governance_rotation_count == 0
        || report.registry_governance_rotation_count > report.registry_history_event_count
        || governed_event_count.is_none_or(|count| count > report.registry_history_event_count)
        || report.current_registry.active_governance_sha256.as_deref()
            != Some(report.active_governance_sha256.as_str())
    {
        return Err(
            "factory release transparency external gossip registry governance-rotation report state is inconsistent"
                .into(),
        );
    }
    validate_digest(
        &report.registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        &report.current_registry_sha256,
        "factory release transparency external gossip current registry SHA-256",
    )?;
    validate_digest(
        &report.active_governance_sha256,
        "factory release transparency external gossip active registry governance SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip registry governance-rotation report binding SHA-256",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &report.active_governance,
    )?;
    validate_artifact_identity(
        &report.registry_genesis_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry genesis artifact",
    )?;
    validate_artifact_identity(
        &report.observer_trust_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust report artifact",
    )?;
    Ok(())
}

fn validate_governance_rotation_registry_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
) -> Result<(), String> {
    validate_governance_rotation_registry_report_shape(report)?;
    let genesis_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &report.registry_genesis,
        )?;
    if report.registry_genesis.generation != 0
        || report.registry_genesis_artifact != exact_identity(&genesis_source)
        || report.registry_genesis_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &report.registry_genesis,
            )?
    {
        return Err(
            "factory release transparency external gossip registry governance-rotation report genesis binding is invalid"
                .into(),
        );
    }
    let mut current = report.registry_genesis.clone();
    let mut authority_keys = vec![report.registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([report.registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    let mut threshold_transition_count = 0_u32;
    let mut governance_rotation_count = 0_u32;
    let mut active_governance = None;
    let mut governance_history = Vec::new();
    let mut governance_hashes = HashSet::new();
    for evidence in &report.registry_history_events {
        match evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                    "factory release transparency external gossip registry transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry authority rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation artifact identity is invalid"
                            .into(),
                    );
                }
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::ThresholdTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
                    "factory release transparency external gossip registry threshold transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry threshold transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current,
                    transition,
                )?;
                let governance_sha256 =
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                        &transition.governance,
                    )?;
                if governance_hashes.insert(governance_sha256) {
                    governance_history.push(transition.governance.clone());
                }
                active_governance = Some(transition.governance.clone());
                threshold_transition_count = threshold_transition_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::GovernanceRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
                    "factory release transparency external gossip registry governance rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry governance rotation artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    &current,
                    rotation,
                )?;
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governance_rotation_count = governance_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry governance rotation count overflow"
                        .to_string()
                })?;
            }
        }
    }
    if authority_rotation_count != report.registry_authority_rotation_count
        || threshold_transition_count != report.registry_threshold_transition_count
        || governance_rotation_count != report.registry_governance_rotation_count
        || active_governance.as_ref() != Some(&report.active_governance)
        || report.active_governance_sha256
            != signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                &report.active_governance,
            )?
        || current != report.current_registry
        || report.current_registry_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &current,
            )?
    {
        return Err(
            "factory release transparency external gossip registry governance-rotation report does not reproduce its current registry"
                .into(),
        );
    }
    let trust_source = render_factory_release_state_transparency_external_gossip_trust_report(
        &report.observer_trust_report,
    )?;
    if report.observer_trust_report_artifact != exact_identity(&trust_source)
        || report.registry_genesis.base_observer_quorum_policy_sha256
            != report
                .observer_trust_report
                .base_observer_quorum_policy_sha256
        || report.registry_genesis.policy_id
            != report
                .observer_trust_report
                .base_observer_quorum_policy
                .policy_id
        || report
            .current_registry
            .last_updated_at_unix
            .is_some_and(|updated| updated > report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip registry governance-rotation report observer trust binding is invalid"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(
        &authority_keys,
        &report.observer_trust_report,
    )?;
    for governance in &governance_history {
        validate_governance_authority_role_separation(
            governance,
            &authority_keys,
            &report.observer_trust_report,
        )?;
    }
    validate_selected_member_admissions(&report.current_registry, &report.observer_trust_report)?;
    if governance_rotation_registry_report_binding(report)? != report.binding_sha256 {
        return Err(
            "factory release transparency external gossip registry governance-rotation report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn validate_governed_authority_rotation_registry_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
) -> Result<(), String> {
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_VERIFICATION_SCOPE
        || !report.registry_genesis_pin_matched
        || !report.complete_registry_history_verified
        || !report.registry_authority_transition_signatures_verified
        || !report.registry_authority_rotation_dual_signatures_verified
        || !report.registry_authority_successor_possession_verified
        || !report.registry_authority_key_history_unique
        || !report.governance_root_signatures_verified
        || !report.governance_authority_identities_unique
        || !report.governance_authority_keys_unique
        || !report.governance_threshold_approvals_verified
        || !report.governance_rotation_old_quorum_verified
        || !report.governance_rotation_new_quorum_verified
        || !report.successor_governance_state_binding_verified
        || !report.governed_authority_rotation_old_quorum_verified
        || !report.governed_authority_rotation_new_quorum_verified
        || !report.successor_registry_root_possession_verified
        || !report.registry_root_and_governance_rotated_atomically
        || !report.root_only_registry_mutations_locked_out
        || !report.registry_generation_chain_verified
        || !report.registry_digest_chain_verified
        || !report.registry_timestamps_monotonic
        || !report.registry_authority_role_separation_verified
        || !report.current_observer_trust_admissions_verified
        || !report.selected_observer_organizations_active
        || !report.registry_effective_before_quorum_evaluation_verified
        || !report.selected_ledger_latest_registry_verified
        || !report.selected_ledger_observer_trust_report_verified
        || !report.selected_ledger_latest_observer_rotations_verified
        || report.selected_ledger_registry_bound_report_committed
        || report.selected_ledger_rollback_resistance_verified
        || !report.authority_threshold_governance_verified
        || report.global_non_equivocation_verified
        || report.trusted_time_verified
        || report.independent_governance_control_verified
        || report.independent_organization_operation_verified
        || report.factory_legal_identity_verified
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
        || report.quorum_met != report.observer_trust_report.quorum_met
        || report.evaluated_at_unix != report.observer_trust_report.evaluated_at_unix
        || report.selected_ledger_latest_observer_rotations_verified
            != report
                .observer_trust_report
                .selected_ledger_latest_observer_rotations_verified
    {
        return Err(
            "invalid factory release transparency external gossip registry governed-authority-rotation report invariants"
                .into(),
        );
    }
    let expected_status = if report.quorum_met {
        "verified"
    } else {
        "insufficient_organizations"
    };
    let governed_event_count = report
        .registry_authority_rotation_count
        .checked_add(report.registry_threshold_transition_count)
        .and_then(|count| count.checked_add(report.registry_governance_rotation_count))
        .and_then(|count| count.checked_add(report.registry_governed_authority_rotation_count));
    if report.status != expected_status
        || report.observer_trust_report.status != expected_status
        || usize::try_from(report.registry_history_event_count).ok()
            != Some(report.registry_history_events.len())
        || report.registry_history_events.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        || report.current_registry.generation != u64::from(report.registry_history_event_count)
        || report.registry_authority_rotation_count > report.registry_history_event_count
        || report.registry_threshold_transition_count == 0
        || report.registry_threshold_transition_count > report.registry_history_event_count
        || report.registry_governance_rotation_count > report.registry_history_event_count
        || report.registry_governed_authority_rotation_count == 0
        || report.registry_governed_authority_rotation_count > report.registry_history_event_count
        || governed_event_count.is_none_or(|count| count > report.registry_history_event_count)
        || report.current_registry.active_governance_sha256.as_deref()
            != Some(report.active_governance_sha256.as_str())
        || report.current_registry.authority_public_key
            != report.active_governance.registry_authority_public_key
    {
        return Err(
            "factory release transparency external gossip registry governed-authority-rotation report state is inconsistent"
                .into(),
        );
    }
    validate_digest(
        &report.registry_genesis_sha256,
        "factory release transparency external gossip registry genesis SHA-256",
    )?;
    validate_digest(
        &report.current_registry_sha256,
        "factory release transparency external gossip current registry SHA-256",
    )?;
    validate_digest(
        &report.active_governance_sha256,
        "factory release transparency external gossip active registry governance SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip governed-authority-rotation report binding SHA-256",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(
        &report.active_governance,
    )?;
    validate_artifact_identity(
        &report.registry_genesis_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES,
        "factory release transparency external gossip registry genesis artifact",
    )?;
    validate_artifact_identity(
        &report.observer_trust_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust report artifact",
    )?;
    Ok(())
}

fn validate_governed_authority_rotation_registry_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
) -> Result<(), String> {
    validate_governed_authority_rotation_registry_report_shape(report)?;
    let genesis_source =
        render_factory_release_state_transparency_external_gossip_organization_registry(
            &report.registry_genesis,
        )?;
    if report.registry_genesis.generation != 0
        || report.registry_genesis_artifact != exact_identity(&genesis_source)
        || report.registry_genesis_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &report.registry_genesis,
            )?
    {
        return Err(
            "factory release transparency external gossip governed-authority-rotation report genesis binding is invalid"
                .into(),
        );
    }
    let mut current = report.registry_genesis.clone();
    let mut authority_keys = vec![report.registry_genesis.authority_public_key.clone()];
    let mut historical_authority_keys =
        HashSet::from([report.registry_genesis.authority_public_key.clone()]);
    let mut authority_rotation_count = 0_u32;
    let mut threshold_transition_count = 0_u32;
    let mut governance_rotation_count = 0_u32;
    let mut governed_authority_rotation_count = 0_u32;
    let mut active_governance = None;
    let mut governance_history = Vec::new();
    let mut governance_hashes = HashSet::new();
    for evidence in &report.registry_history_events {
        match evidence {
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::OrganizationTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                    "factory release transparency external gossip registry transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &current,
                    transition,
                )?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::AuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip registry authority rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation artifact identity is invalid"
                            .into(),
                    );
                }
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip registry authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                    &current,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                authority_rotation_count = authority_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry authority rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::ThresholdTransition {
                artifact,
                transition,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    transition,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
                    "factory release transparency external gossip registry threshold transition artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry threshold transition artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                    &current,
                    transition,
                )?;
                let governance_sha256 =
                    signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                        &transition.governance,
                    )?;
                if governance_hashes.insert(governance_sha256) {
                    governance_history.push(transition.governance.clone());
                }
                active_governance = Some(transition.governance.clone());
                threshold_transition_count = threshold_transition_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry threshold transition count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernanceRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
                    "factory release transparency external gossip registry governance rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip registry governance rotation artifact identity is invalid"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                    &current,
                    rotation,
                )?;
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governance_rotation_count = governance_rotation_count.checked_add(1).ok_or_else(|| {
                    "factory release transparency external gossip registry governance rotation count overflow"
                        .to_string()
                })?;
            }
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernedAuthorityKeyRotation {
                artifact,
                rotation,
            } => {
                let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                    rotation,
                )?;
                validate_artifact_identity(
                    artifact,
                    MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES,
                    "factory release transparency external gossip governed authority rotation artifact",
                )?;
                if *artifact != exact_identity(&source) {
                    return Err(
                        "factory release transparency external gossip governed authority rotation artifact identity is invalid"
                            .into(),
                    );
                }
                if !historical_authority_keys.insert(rotation.new_public_key.clone()) {
                    return Err(
                        "factory release transparency external gossip governed authority rotation reuses a historical key"
                            .into(),
                    );
                }
                current = apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                    &current,
                    rotation,
                )?;
                authority_keys.push(rotation.new_public_key.clone());
                for governance in [&rotation.old_governance, &rotation.new_governance] {
                    let governance_sha256 =
                        signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                            governance,
                        )?;
                    if governance_hashes.insert(governance_sha256) {
                        governance_history.push(governance.clone());
                    }
                }
                active_governance = Some(rotation.new_governance.clone());
                governed_authority_rotation_count = governed_authority_rotation_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        "factory release transparency external gossip governed authority rotation count overflow"
                            .to_string()
                    })?;
            }
        }
    }
    if authority_rotation_count != report.registry_authority_rotation_count
        || threshold_transition_count != report.registry_threshold_transition_count
        || governance_rotation_count != report.registry_governance_rotation_count
        || governed_authority_rotation_count
            != report.registry_governed_authority_rotation_count
        || active_governance.as_ref() != Some(&report.active_governance)
        || report.active_governance_sha256
            != signed_factory_release_state_transparency_external_gossip_organization_registry_governance_sha256(
                &report.active_governance,
            )?
        || current != report.current_registry
        || report.current_registry.authority_public_key
            != report.active_governance.registry_authority_public_key
        || report.current_registry_sha256
            != factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &current,
            )?
    {
        return Err(
            "factory release transparency external gossip governed-authority-rotation report does not reproduce its current registry"
                .into(),
        );
    }
    let trust_source = render_factory_release_state_transparency_external_gossip_trust_report(
        &report.observer_trust_report,
    )?;
    if report.observer_trust_report_artifact != exact_identity(&trust_source)
        || report.registry_genesis.base_observer_quorum_policy_sha256
            != report
                .observer_trust_report
                .base_observer_quorum_policy_sha256
        || report.registry_genesis.policy_id
            != report
                .observer_trust_report
                .base_observer_quorum_policy
                .policy_id
        || report
            .current_registry
            .last_updated_at_unix
            .is_some_and(|updated| updated > report.evaluated_at_unix)
    {
        return Err(
            "factory release transparency external gossip governed-authority-rotation report observer trust binding is invalid"
                .into(),
        );
    }
    validate_registry_authority_history_role_separation(
        &authority_keys,
        &report.observer_trust_report,
    )?;
    for governance in &governance_history {
        validate_governance_authority_role_separation(
            governance,
            &authority_keys,
            &report.observer_trust_report,
        )?;
    }
    validate_selected_member_admissions(&report.current_registry, &report.observer_trust_report)?;
    if governed_authority_rotation_registry_report_binding(report)? != report.binding_sha256 {
        return Err(
            "factory release transparency external gossip governed-authority-rotation report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn registry_report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryVerificationReport,
) -> Result<String, String> {
    let mut bound = report.clone();
    bound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &bound,
        "factory release transparency external gossip registry report binding",
    )
}

fn authority_rotation_registry_report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryAuthorityRotationVerificationReport,
) -> Result<String, String> {
    let mut bound = report.clone();
    bound.binding_sha256.clear();
    domain_hash(
        AUTHORITY_ROTATION_REPORT_BINDING_DOMAIN,
        &bound,
        "factory release transparency external gossip registry authority-rotation report binding",
    )
}

fn threshold_governance_registry_report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceVerificationReport,
) -> Result<String, String> {
    let mut bound = report.clone();
    bound.binding_sha256.clear();
    domain_hash(
        THRESHOLD_GOVERNANCE_REPORT_BINDING_DOMAIN,
        &bound,
        "factory release transparency external gossip registry threshold-governance report binding",
    )
}

fn governance_rotation_registry_report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationVerificationReport,
) -> Result<String, String> {
    let mut bound = report.clone();
    bound.binding_sha256.clear();
    domain_hash(
        GOVERNANCE_ROTATION_REPORT_BINDING_DOMAIN,
        &bound,
        "factory release transparency external gossip registry governance-rotation report binding",
    )
}

fn governed_authority_rotation_registry_report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationVerificationReport,
) -> Result<String, String> {
    let mut bound = report.clone();
    bound.binding_sha256.clear();
    domain_hash(
        GOVERNED_AUTHORITY_ROTATION_REPORT_BINDING_DOMAIN,
        &bound,
        "factory release transparency external gossip governed-authority-rotation report binding",
    )
}

fn normalized_sha256(value: &impl Serialize, label: &str) -> Result<String, String> {
    let source =
        serde_json::to_vec(value).map_err(|error| format!("serializing {label}: {error}"))?;
    Ok(sha256(&source))
}

fn render_bounded(value: &impl Serialize, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut source =
        serde_json::to_vec_pretty(value).map_err(|error| format!("rendering {label}: {error}"))?;
    source.push(b'\n');
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(source)
}

fn parse_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    source: &[u8],
    maximum: u64,
    label: &str,
) -> Result<T, String> {
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} must contain 1 to {maximum} bytes"));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid {label} JSON: {error:#}"))?;
    let value: T =
        serde_json::from_slice(source).map_err(|error| format!("invalid {label} JSON: {error}"))?;
    if render_bounded(&value, maximum, label)? != source {
        return Err(format!("{label} is not canonical pretty JSON"));
    }
    Ok(value)
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: sha256(source),
    }
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum {
        return Err(format!("{label} byte count is outside its bound"));
    }
    validate_digest(&identity.sha256, &format!("{label} SHA-256"))
}

fn domain_hash(domain: &[u8], value: &impl Serialize, label: &str) -> Result<String, String> {
    let source =
        serde_json::to_vec(value).map_err(|error| format!("serializing {label}: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(source);
    Ok(hex::encode(hash.finalize()))
}

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' => index != 0,
            _ => false,
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_observer_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' | b'_' => index != 0,
            _ => false,
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    Ok(())
}

fn validate_nonweak_public_key(value: &str, label: &str) -> Result<(), String> {
    let bytes = decode_hex::<32>(value, label)?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid {label}: {error}"))?;
    if key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "{label} must contain exactly {N} lowercase hexadecimal bytes"
        ));
    }
    hex::decode(value)
        .map_err(|error| format!("invalid {label}: {error}"))?
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

fn observer_slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    })
}

fn artifact_schema(maximum: u64) -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
            "sha256": digest_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_organization_registry_json_schema()
-> Value {
    let admission = json!({
        "type": "object", "additionalProperties": false,
        "required": ["observer_id", "observer_trust_state_sha256", "admitted_at_unix"],
        "properties": {
            "observer_id": observer_slug_schema(),
            "observer_trust_state_sha256": digest_schema(),
            "admitted_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}
        }
    });
    let organization = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "organization_id", "status", "status_since_unix",
            "status_reason_sha256", "observers"
        ],
        "properties": {
            "organization_id": slug_schema(),
            "status": {"enum": ["active", "suspended", "revoked"]},
            "status_since_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "status_reason_sha256": digest_schema(),
            "observers": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
                "items": admission
            }
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-v1.json",
        "title": "pcbex factory-release transparency external-gossip organization registry",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "generation", "authority_public_key",
            "last_transition_sha256", "last_updated_at_unix", "organizations"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "authority_public_key": digest_schema(),
            "active_governance_sha256": digest_schema(),
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "last_updated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}
                ]
            },
            "organizations": {
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
                "items": organization
            }
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-transition-v1.json",
        "title": "Signed pcbex factory-release transparency external-gossip organization registry transition",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "transition_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "action", "organization_id", "observer_id",
            "observer_trust_state_sha256", "reason_sha256", "effective_at_unix",
            "authority_public_key", "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "transition_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "action": {"enum": ["admit_observer", "suspend_organization", "revoke_organization"]},
            "organization_id": slug_schema(),
            "observer_id": {"oneOf": [{"type": "null"}, observer_slug_schema()]},
            "observer_trust_state_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "reason_sha256": digest_schema(),
            "effective_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "authority_public_key": digest_schema(),
            "algorithm": {"const": "ed25519"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1.json",
        "title": "Dual-signed pcbex factory-release transparency external-gossip organization registry authority key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rotation_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_public_key", "new_public_key",
            "rotated_at_unix", "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "rotation_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": digest_schema(),
            "new_public_key": digest_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema()
-> Value {
    let authority = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": digest_schema()
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-governance-v1.json",
        "title": "Root-signed pcbex factory-release transparency external-gossip organization registry threshold governance",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "governance_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "registry_generation", "registry_state_sha256",
            "registry_authority_public_key", "minimum_approvals", "authorities",
            "issued_at_unix", "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "governance_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "registry_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_state_sha256": digest_schema(),
            "registry_authority_public_key": digest_schema(),
            "minimum_approvals": {
                "type": "integer", "minimum": 2,
                "maximum": MAXIMUM_GOVERNANCE_AUTHORITIES
            },
            "authorities": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": authority
            },
            "issued_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_json_schema()
-> Value {
    let approval = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key", "signature"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": digest_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1.json",
        "title": "Threshold-approved pcbex factory-release transparency external-gossip organization registry transition",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "transition_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "governance_sha256", "governance",
            "action", "organization_id", "observer_id", "observer_trust_state_sha256",
            "reason_sha256", "effective_at_unix", "algorithm", "approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "transition_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "governance_sha256": digest_schema(),
            "governance": signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema(),
            "action": {"enum": ["admit_observer", "suspend_organization", "revoke_organization"]},
            "organization_id": slug_schema(),
            "observer_id": {"oneOf": [{"type": "null"}, observer_slug_schema()]},
            "observer_trust_state_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "reason_sha256": digest_schema(),
            "effective_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": approval
            }
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_json_schema()
-> Value {
    let approval = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key", "signature"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": digest_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    });
    let governance = signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1.json",
        "title": "Old-and-new quorum-approved pcbex factory-release transparency external-gossip organization registry governance rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rotation_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_governance_sha256", "old_governance",
            "new_governance_sha256", "new_governance", "rotated_at_unix", "algorithm",
            "old_approvals", "new_approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "rotation_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_transition_sha256": digest_schema(),
            "old_governance_sha256": digest_schema(),
            "old_governance": governance.clone(),
            "new_governance_sha256": digest_schema(),
            "new_governance": governance,
            "rotated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "old_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": approval.clone()
            },
            "new_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": approval
            }
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_json_schema()
-> Value {
    let approval = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key", "signature"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": digest_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    });
    let governance = signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1.json",
        "title": "Dual-quorum governed pcbex factory-release transparency external-gossip organization registry root rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rotation_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_public_key", "new_public_key",
            "old_governance_sha256", "old_governance", "new_governance_sha256",
            "new_governance", "rotated_at_unix", "algorithm", "old_approvals",
            "new_approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "rotation_scope": {"const": SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "registry_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_transition_sha256": digest_schema(),
            "old_public_key": digest_schema(),
            "new_public_key": digest_schema(),
            "old_governance_sha256": digest_schema(),
            "old_governance": governance.clone(),
            "new_governance_sha256": digest_schema(),
            "new_governance": governance,
            "rotated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "old_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": approval.clone()
            },
            "new_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": approval
            }
        }
    })
}

fn factory_release_state_transparency_external_gossip_organization_registry_complete_history_event_json_schema()
-> Value {
    json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "transition"],
                "properties": {
                    "kind": {"const": "organization_transition"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES),
                    "transition": signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "rotation"],
                "properties": {
                    "kind": {"const": "authority_key_rotation"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES),
                    "rotation": signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_json_schema()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "transition"],
                "properties": {
                    "kind": {"const": "threshold_transition"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES),
                    "transition": signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_json_schema()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "rotation"],
                "properties": {
                    "kind": {"const": "governance_rotation"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES),
                    "rotation": signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_json_schema()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "rotation"],
                "properties": {
                    "kind": {"const": "governed_authority_key_rotation"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES),
                    "rotation": signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_json_schema()
                }
            }
        ]
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_organization_registry_history_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-history-v1.json",
        "title": "Complete pcbex factory-release transparency external-gossip organization registry history",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "initial_registry_artifact", "initial_registry", "events"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION},
            "initial_registry_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES),
            "initial_registry": factory_release_state_transparency_external_gossip_organization_registry_json_schema(),
            "events": {
                "type": "array", "minItems": 0,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS,
                "items": factory_release_state_transparency_external_gossip_organization_registry_complete_history_event_json_schema()
            }
        }
    })
}

fn factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
    kind: &str,
    artifact_maximum: u64,
) -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "index", "kind", "from_generation", "to_generation", "artifact",
            "event_sha256", "resulting_registry_sha256", "authority_public_key",
            "active_governance_sha256"
        ],
        "properties": {
            "index": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS - 1
            },
            "kind": {"const": kind},
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "artifact": artifact_schema(artifact_maximum),
            "event_sha256": digest_schema(),
            "resulting_registry_sha256": digest_schema(),
            "authority_public_key": digest_schema(),
            "active_governance_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-history-audit-v1.json",
        "title": "Verified pcbex factory-release transparency external-gossip organization registry history audit",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "initial_registry_artifact",
            "initial_registry_sha256", "event_count", "entries", "final_registry",
            "final_registry_sha256", "chain_valid"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_SCHEMA_VERSION},
            "registry_id": slug_schema(),
            "initial_registry_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES),
            "initial_registry_sha256": digest_schema(),
            "event_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "entries": {
                "type": "array", "minItems": 0,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS,
                "items": {
                    "oneOf": [
                        factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
                            "organization_transition",
                            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES,
                        ),
                        factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
                            "authority_key_rotation",
                            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES,
                        ),
                        factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
                            "threshold_transition",
                            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES,
                        ),
                        factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
                            "governance_rotation",
                            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES,
                        ),
                        factory_release_state_transparency_external_gossip_organization_registry_history_audit_entry_json_schema(
                            "governed_authority_key_rotation",
                            MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES,
                        )
                    ]
                }
            },
            "final_registry": factory_release_state_transparency_external_gossip_organization_registry_json_schema(),
            "final_registry_sha256": digest_schema(),
            "chain_valid": {"const": true}
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_report_json_schema()
-> Value {
    let registry =
        factory_release_state_transparency_external_gossip_organization_registry_json_schema();
    let transition = signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema();
    let transition_evidence = json!({
        "type": "object", "additionalProperties": false,
        "required": ["artifact", "transition"],
        "properties": {
            "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES),
            "transition": transition
        }
    });
    let true_value = json!({"const": true});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-verification-report-v1.json",
        "title": "pcbex factory-release transparency external-gossip organization registry verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status",
            "registry_genesis_pin_matched", "complete_registry_history_verified",
            "registry_authority_signatures_verified", "registry_generation_chain_verified",
            "registry_digest_chain_verified", "registry_timestamps_monotonic",
            "registry_authority_role_separation_verified",
            "current_observer_trust_admissions_verified",
            "selected_observer_organizations_active",
            "registry_effective_before_quorum_evaluation_verified",
            "selected_ledger_latest_registry_verified",
            "selected_ledger_observer_trust_report_verified",
            "selected_ledger_latest_observer_rotations_verified",
            "selected_ledger_registry_bound_report_committed",
            "selected_ledger_rollback_resistance_verified", "global_non_equivocation_verified",
            "trusted_time_verified", "independent_organization_operation_verified",
            "factory_legal_identity_verified", "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "quorum_met",
            "registry_genesis_artifact", "registry_genesis_sha256", "registry_genesis",
            "registry_transition_count", "registry_transitions", "current_registry",
            "current_registry_sha256", "observer_trust_report_artifact",
            "observer_trust_report", "evaluated_at_unix", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_VERIFICATION_SCOPE},
            "status": {"enum": ["verified", "insufficient_organizations"]},
            "registry_genesis_pin_matched": true_value.clone(),
            "complete_registry_history_verified": true_value.clone(),
            "registry_authority_signatures_verified": true_value.clone(),
            "registry_generation_chain_verified": true_value.clone(),
            "registry_digest_chain_verified": true_value.clone(),
            "registry_timestamps_monotonic": true_value.clone(),
            "registry_authority_role_separation_verified": true_value.clone(),
            "current_observer_trust_admissions_verified": true_value.clone(),
            "selected_observer_organizations_active": true_value.clone(),
            "registry_effective_before_quorum_evaluation_verified": true_value.clone(),
            "selected_ledger_latest_registry_verified": true_value.clone(),
            "selected_ledger_observer_trust_report_verified": true_value.clone(),
            "selected_ledger_latest_observer_rotations_verified": true_value,
            "selected_ledger_registry_bound_report_committed": false_value.clone(),
            "selected_ledger_rollback_resistance_verified": false_value.clone(),
            "global_non_equivocation_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "independent_organization_operation_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "quorum_met": {"type": "boolean"},
            "registry_genesis_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES),
            "registry_genesis_sha256": digest_schema(),
            "registry_genesis": registry.clone(),
            "registry_transition_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_transitions": {
                "type": "array", "minItems": 0,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS,
                "items": transition_evidence
            },
            "current_registry": registry,
            "current_registry_sha256": digest_schema(),
            "observer_trust_report_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES),
            "observer_trust_report": factory_release_state_transparency_external_gossip_trust_report_json_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "binding_sha256": digest_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_authority_rotation_report_json_schema()
-> Value {
    let registry =
        factory_release_state_transparency_external_gossip_organization_registry_json_schema();
    let transition = signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema();
    let rotation = signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_json_schema();
    let history_event = json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "transition"],
                "properties": {
                    "kind": {"const": "organization_transition"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES),
                    "transition": transition
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "rotation"],
                "properties": {
                    "kind": {"const": "authority_key_rotation"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES),
                    "rotation": rotation
                }
            }
        ]
    });
    let true_value = json!({"const": true});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-verification-report-v1.json",
        "title": "pcbex factory-release transparency external-gossip organization registry authority-rotation verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status",
            "registry_genesis_pin_matched", "complete_registry_history_verified",
            "registry_authority_transition_signatures_verified",
            "registry_authority_rotation_dual_signatures_verified",
            "registry_authority_successor_possession_verified",
            "registry_authority_key_history_unique", "registry_generation_chain_verified",
            "registry_digest_chain_verified", "registry_timestamps_monotonic",
            "registry_authority_role_separation_verified",
            "current_observer_trust_admissions_verified",
            "selected_observer_organizations_active",
            "registry_effective_before_quorum_evaluation_verified",
            "selected_ledger_latest_registry_verified",
            "selected_ledger_observer_trust_report_verified",
            "selected_ledger_latest_observer_rotations_verified",
            "selected_ledger_registry_bound_report_committed",
            "selected_ledger_rollback_resistance_verified",
            "authority_threshold_governance_verified", "global_non_equivocation_verified",
            "trusted_time_verified", "independent_organization_operation_verified",
            "factory_legal_identity_verified", "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "quorum_met",
            "registry_genesis_artifact", "registry_genesis_sha256", "registry_genesis",
            "registry_history_event_count", "registry_authority_rotation_count",
            "registry_history_events", "current_registry", "current_registry_sha256",
            "observer_trust_report_artifact", "observer_trust_report",
            "evaluated_at_unix", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION_VERIFICATION_SCOPE},
            "status": {"enum": ["verified", "insufficient_organizations"]},
            "registry_genesis_pin_matched": true_value.clone(),
            "complete_registry_history_verified": true_value.clone(),
            "registry_authority_transition_signatures_verified": true_value.clone(),
            "registry_authority_rotation_dual_signatures_verified": true_value.clone(),
            "registry_authority_successor_possession_verified": true_value.clone(),
            "registry_authority_key_history_unique": true_value.clone(),
            "registry_generation_chain_verified": true_value.clone(),
            "registry_digest_chain_verified": true_value.clone(),
            "registry_timestamps_monotonic": true_value.clone(),
            "registry_authority_role_separation_verified": true_value.clone(),
            "current_observer_trust_admissions_verified": true_value.clone(),
            "selected_observer_organizations_active": true_value.clone(),
            "registry_effective_before_quorum_evaluation_verified": true_value.clone(),
            "selected_ledger_latest_registry_verified": true_value.clone(),
            "selected_ledger_observer_trust_report_verified": true_value.clone(),
            "selected_ledger_latest_observer_rotations_verified": true_value,
            "selected_ledger_registry_bound_report_committed": false_value.clone(),
            "selected_ledger_rollback_resistance_verified": false_value.clone(),
            "authority_threshold_governance_verified": false_value.clone(),
            "global_non_equivocation_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "independent_organization_operation_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "quorum_met": {"type": "boolean"},
            "registry_genesis_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES),
            "registry_genesis_sha256": digest_schema(),
            "registry_genesis": registry.clone(),
            "registry_history_event_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_authority_rotation_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_history_events": {
                "type": "array", "minItems": 0,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS,
                "items": history_event
            },
            "current_registry": registry,
            "current_registry_sha256": digest_schema(),
            "observer_trust_report_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES),
            "observer_trust_report": factory_release_state_transparency_external_gossip_trust_report_json_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "binding_sha256": digest_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_threshold_governance_report_json_schema()
-> Value {
    let registry =
        factory_release_state_transparency_external_gossip_organization_registry_json_schema();
    let transition = signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema();
    let rotation = signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_json_schema();
    let threshold_transition = signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_json_schema();
    let governance = signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema();
    let history_event = json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "transition"],
                "properties": {
                    "kind": {"const": "organization_transition"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITION_BYTES),
                    "transition": transition
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "rotation"],
                "properties": {
                    "kind": {"const": "authority_key_rotation"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_KEY_ROTATION_BYTES),
                    "rotation": rotation
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "artifact", "transition"],
                "properties": {
                    "kind": {"const": "threshold_transition"},
                    "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_TRANSITION_BYTES),
                    "transition": threshold_transition
                }
            }
        ]
    });
    let true_value = json!({"const": true});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-verification-report-v1.json",
        "title": "pcbex factory-release transparency external-gossip organization registry threshold-governance verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status",
            "registry_genesis_pin_matched", "complete_registry_history_verified",
            "registry_authority_transition_signatures_verified",
            "registry_authority_rotation_dual_signatures_verified",
            "registry_authority_successor_possession_verified",
            "registry_authority_key_history_unique", "governance_root_signature_verified",
            "governance_authority_identities_unique", "governance_authority_keys_unique",
            "governance_threshold_approvals_verified", "root_only_registry_mutations_locked_out",
            "registry_generation_chain_verified", "registry_digest_chain_verified",
            "registry_timestamps_monotonic", "registry_authority_role_separation_verified",
            "current_observer_trust_admissions_verified", "selected_observer_organizations_active",
            "registry_effective_before_quorum_evaluation_verified",
            "selected_ledger_latest_registry_verified",
            "selected_ledger_observer_trust_report_verified",
            "selected_ledger_latest_observer_rotations_verified",
            "selected_ledger_registry_bound_report_committed",
            "selected_ledger_rollback_resistance_verified",
            "authority_threshold_governance_verified", "global_non_equivocation_verified",
            "trusted_time_verified", "independent_organization_operation_verified",
            "factory_legal_identity_verified", "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "quorum_met",
            "registry_genesis_artifact", "registry_genesis_sha256", "registry_genesis",
            "registry_history_event_count", "registry_authority_rotation_count",
            "registry_threshold_transition_count", "registry_history_events",
            "active_governance_sha256", "active_governance", "current_registry",
            "current_registry_sha256", "observer_trust_report_artifact",
            "observer_trust_report", "evaluated_at_unix", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE_VERIFICATION_SCOPE},
            "status": {"enum": ["verified", "insufficient_organizations"]},
            "registry_genesis_pin_matched": true_value.clone(),
            "complete_registry_history_verified": true_value.clone(),
            "registry_authority_transition_signatures_verified": true_value.clone(),
            "registry_authority_rotation_dual_signatures_verified": true_value.clone(),
            "registry_authority_successor_possession_verified": true_value.clone(),
            "registry_authority_key_history_unique": true_value.clone(),
            "governance_root_signature_verified": true_value.clone(),
            "governance_authority_identities_unique": true_value.clone(),
            "governance_authority_keys_unique": true_value.clone(),
            "governance_threshold_approvals_verified": true_value.clone(),
            "root_only_registry_mutations_locked_out": true_value.clone(),
            "registry_generation_chain_verified": true_value.clone(),
            "registry_digest_chain_verified": true_value.clone(),
            "registry_timestamps_monotonic": true_value.clone(),
            "registry_authority_role_separation_verified": true_value.clone(),
            "current_observer_trust_admissions_verified": true_value.clone(),
            "selected_observer_organizations_active": true_value.clone(),
            "registry_effective_before_quorum_evaluation_verified": true_value.clone(),
            "selected_ledger_latest_registry_verified": true_value.clone(),
            "selected_ledger_observer_trust_report_verified": true_value.clone(),
            "selected_ledger_latest_observer_rotations_verified": true_value.clone(),
            "selected_ledger_registry_bound_report_committed": false_value.clone(),
            "selected_ledger_rollback_resistance_verified": false_value.clone(),
            "authority_threshold_governance_verified": true_value,
            "global_non_equivocation_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "independent_organization_operation_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "quorum_met": {"type": "boolean"},
            "registry_genesis_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_BYTES),
            "registry_genesis_sha256": digest_schema(),
            "registry_genesis": registry.clone(),
            "registry_history_event_count": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_authority_rotation_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_threshold_transition_count": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
            },
            "registry_history_events": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS,
                "items": history_event
            },
            "active_governance_sha256": digest_schema(),
            "active_governance": governance,
            "current_registry": registry,
            "current_registry_sha256": digest_schema(),
            "observer_trust_report_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES),
            "observer_trust_report": factory_release_state_transparency_external_gossip_trust_report_json_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "binding_sha256": digest_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governance_rotation_report_json_schema()
-> Value {
    let mut schema =
        factory_release_state_transparency_external_gossip_registry_threshold_governance_report_json_schema();
    let object = schema
        .as_object_mut()
        .expect("threshold-governance report schema is an object");
    object.insert(
        "$id".into(),
        json!("https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-verification-report-v1.json"),
    );
    object.insert(
        "title".into(),
        json!("pcbex factory-release transparency external-gossip organization registry governance-rotation verification report"),
    );
    let required = object
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("threshold-governance report required list is an array");
    for field in required.iter_mut() {
        if field.as_str() == Some("governance_root_signature_verified") {
            *field = json!("governance_root_signatures_verified");
        }
    }
    required.extend([
        json!("governance_rotation_old_quorum_verified"),
        json!("governance_rotation_new_quorum_verified"),
        json!("successor_governance_state_binding_verified"),
        json!("independent_governance_control_verified"),
        json!("registry_governance_rotation_count"),
    ]);
    let properties = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("threshold-governance report properties are an object");
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_VERIFICATION_SCOPE}),
    );
    properties.remove("governance_root_signature_verified");
    for field in [
        "governance_root_signatures_verified",
        "governance_rotation_old_quorum_verified",
        "governance_rotation_new_quorum_verified",
        "successor_governance_state_binding_verified",
    ] {
        properties.insert(field.into(), json!({"const": true}));
    }
    properties.insert(
        "independent_governance_control_verified".into(),
        json!({"const": false}),
    );
    properties.insert(
        "registry_governance_rotation_count".into(),
        json!({
            "type": "integer", "minimum": 1,
            "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        }),
    );
    let history_variants = properties
        .get_mut("registry_history_events")
        .and_then(|events| events.get_mut("items"))
        .and_then(|items| items.get_mut("oneOf"))
        .and_then(Value::as_array_mut)
        .expect("threshold-governance history event schema has oneOf variants");
    history_variants.push(json!({
        "type": "object", "additionalProperties": false,
        "required": ["kind", "artifact", "rotation"],
        "properties": {
            "kind": {"const": "governance_rotation"},
            "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION_BYTES),
            "rotation": signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_json_schema()
        }
    }));
    schema
}

pub(crate) fn factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_report_json_schema()
-> Value {
    let mut schema =
        factory_release_state_transparency_external_gossip_registry_governance_rotation_report_json_schema();
    let object = schema
        .as_object_mut()
        .expect("governance-rotation report schema is an object");
    object.insert(
        "$id".into(),
        json!("https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-verification-report-v1.json"),
    );
    object.insert(
        "title".into(),
        json!("pcbex factory-release transparency external-gossip organization registry governed-authority-rotation verification report"),
    );
    let required = object
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("governance-rotation report required list is an array");
    required.extend([
        json!("governed_authority_rotation_old_quorum_verified"),
        json!("governed_authority_rotation_new_quorum_verified"),
        json!("successor_registry_root_possession_verified"),
        json!("registry_root_and_governance_rotated_atomically"),
        json!("registry_governed_authority_rotation_count"),
    ]);
    let properties = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("governance-rotation report properties are an object");
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_ROTATION_VERIFICATION_SCOPE}),
    );
    for field in [
        "governed_authority_rotation_old_quorum_verified",
        "governed_authority_rotation_new_quorum_verified",
        "successor_registry_root_possession_verified",
        "registry_root_and_governance_rotated_atomically",
    ] {
        properties.insert(field.into(), json!({"const": true}));
    }
    properties.insert(
        "registry_governance_rotation_count".into(),
        json!({
            "type": "integer", "minimum": 0,
            "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        }),
    );
    properties.insert(
        "registry_governed_authority_rotation_count".into(),
        json!({
            "type": "integer", "minimum": 1,
            "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        }),
    );
    let history_variants = properties
        .get_mut("registry_history_events")
        .and_then(|events| events.get_mut("items"))
        .and_then(|items| items.get_mut("oneOf"))
        .and_then(Value::as_array_mut)
        .expect("governance-rotation history event schema has oneOf variants");
    history_variants.push(json!({
        "type": "object", "additionalProperties": false,
        "required": ["kind", "artifact", "rotation"],
        "properties": {
            "kind": {"const": "governed_authority_key_rotation"},
            "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_AUTHORITY_KEY_ROTATION_BYTES),
            "rotation": signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_json_schema()
        }
    }));
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_release_state_transparency_external_gossip_quorum::{
        FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE,
        TrustedFactoryReleaseTransparencyExternalGossipObserver,
    };
    use crate::factory_release_state_transparency_external_gossip_trust::new_factory_release_state_transparency_external_gossip_observer_trust_state;

    fn public(secret: [u8; 32]) -> String {
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    fn policy() -> FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE
                .into(),
            policy_id: "registry-unit".into(),
            minimum_organizations: 2,
            maximum_receipt_age_seconds: 300,
            trusted_observers: vec![
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-a".into(),
                    observer_id: "observer-a".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([11; 32]),
                },
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-b".into(),
                    observer_id: "observer-b".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([21; 32]),
                },
            ],
        }
    }

    #[test]
    fn authority_governs_admission_suspension_and_revocation() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let admission = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_000,
        )
        .unwrap();
        let admitted = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &admission,
        )
        .unwrap();
        assert_eq!(admitted.generation, 1);
        assert_eq!(
            admitted.organizations[0].status,
            FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Active
        );
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &admitted,
                &admission,
            )
            .is_err()
        );

        let suspension = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &admitted,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"2".repeat(64),
            2_000,
        )
        .unwrap();
        let suspended = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &admitted,
            &suspension,
        )
        .unwrap();
        assert_eq!(
            suspended.organizations[0].status,
            FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Suspended
        );

        let revocation = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &suspended,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::RevokeOrganization,
            "lab-a",
            None,
            &"3".repeat(64),
            3_000,
        )
        .unwrap();
        let revoked = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &suspended,
            &revocation,
        )
        .unwrap();
        assert_eq!(
            revoked.organizations[0].status,
            FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Revoked
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &revoked,
                &[31; 32],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
                "lab-a",
                Some(&trust),
                &"4".repeat(64),
                4_000,
            )
            .and_then(|transition| {
                apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                    &revoked,
                    &transition,
                )
            })
            .is_err()
        );
    }

    #[test]
    fn transition_is_bound_to_authority_chain_and_current_trust() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &initial,
                &[32; 32],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
                "lab-a",
                Some(&trust),
                &"1".repeat(64),
                1_000,
            )
            .is_err()
        );
        let mut transition = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_000,
        )
        .unwrap();
        transition.reason_sha256 = "2".repeat(64);
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &initial,
                &transition,
            )
            .is_err()
        );
    }

    #[test]
    fn authority_rotation_requires_both_keys_and_preserves_registry_membership() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &initial,
            &[31; 32],
            &[41; 32],
            1_000,
        )
        .unwrap();
        let rotation_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &rotation,
        )
        .unwrap();
        assert!(matches!(
            parse_factory_release_state_transparency_external_gossip_registry_history_event(
                &rotation_source,
            )
            .unwrap(),
            FactoryReleaseStateTransparencyExternalGossipRegistryHistoryEventEvidence::AuthorityKeyRotation { .. }
        ));
        let rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &initial,
            &rotation,
        )
        .unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(rotated.authority_public_key, public([41; 32]));
        assert!(rotated.organizations.is_empty());

        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &rotated,
                &[31; 32],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
                "lab-a",
                Some(&trust),
                &"1".repeat(64),
                2_000,
            )
            .is_err()
        );
        let admission = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &rotated,
            &[41; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            2_000,
        )
        .unwrap();
        let admitted = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &rotated,
            &admission,
        )
        .unwrap();
        let second_rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &admitted,
            &[41; 32],
            &[51; 32],
            3_000,
        )
        .unwrap();
        let twice_rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &admitted,
            &second_rotation,
        )
        .unwrap();
        assert_eq!(twice_rotated.organizations, admitted.organizations);

        let mut tampered_old = rotation.clone();
        let replacement = if tampered_old.old_signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered_old.old_signature.replace_range(..2, replacement);
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                &initial,
                &tampered_old,
            )
            .is_err()
        );
        let mut tampered_new = rotation.clone();
        let replacement = if tampered_new.new_signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered_new.new_signature.replace_range(..2, replacement);
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                &initial,
                &tampered_new,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                &initial,
                &[31; 32],
                &[31; 32],
                1_000,
            )
            .is_err()
        );
    }

    #[test]
    fn threshold_governance_requires_distinct_keys_and_locks_out_root_only_mutation() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        assert!(
            !String::from_utf8(
                render_factory_release_state_transparency_external_gossip_organization_registry(
                    &initial,
                )
                .unwrap()
            )
            .unwrap()
            .contains("active_governance_sha256")
        );

        let governance = sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
            &initial,
            &[31; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-c".into(),
                    public_key: public([43; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-a".into(),
                    public_key: public([41; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-b".into(),
                    public_key: public([42; 32]),
                },
            ],
            1_000,
        )
        .unwrap();
        assert_eq!(governance.authorities[0].authority_id, "authority-a");
        let governance_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(&governance).unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governance(&governance_source).unwrap(),
            governance
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
                &initial,
                &[31; 32],
                2,
                vec![
                    FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                        authority_id: "authority-a".into(),
                        public_key: public([41; 32]),
                    },
                    FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                        authority_id: "authority-b".into(),
                        public_key: public([41; 32]),
                    },
                ],
                1_000,
            )
            .is_err()
        );

        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &[("authority-a".into(), [41; 32])],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
                "lab-a",
                Some(&trust),
                &"1".repeat(64),
                1_100,
            )
            .is_err()
        );
        let admission = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &governance,
            &[
                ("authority-b".into(), [42; 32]),
                ("authority-a".into(), [41; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_100,
        )
        .unwrap();
        let admission_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(&admission).unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(&admission_source).unwrap(),
            admission
        );
        assert!(matches!(
            parse_factory_release_state_transparency_external_gossip_registry_threshold_governance_history_event(&admission_source).unwrap(),
            FactoryReleaseStateTransparencyExternalGossipRegistryThresholdGovernanceHistoryEventEvidence::ThresholdTransition { .. }
        ));
        let governed = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &admission,
        )
        .unwrap();
        assert_eq!(governed.organizations.len(), 1);
        assert_eq!(
            governed.active_governance_sha256.as_deref(),
            Some(admission.governance_sha256.as_str())
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &governed,
                &[31; 32],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
                "lab-a",
                None,
                &"2".repeat(64),
                1_200,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                &governed,
                &[31; 32],
                &[51; 32],
                1_200,
            )
            .is_err()
        );
        let suspension = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &governed,
            &governance,
            &[
                ("authority-c".into(), [43; 32]),
                ("authority-a".into(), [41; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"2".repeat(64),
            1_200,
        )
        .unwrap();
        let suspended = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &governed,
            &suspension,
        )
        .unwrap();
        assert_eq!(
            suspended.organizations[0].status,
            FactoryReleaseStateTransparencyExternalGossipOrganizationStatus::Suspended
        );
        let mut tampered = suspension.clone();
        let replacement = if tampered.approvals[0].signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered.approvals[0]
            .signature
            .replace_range(..2, replacement);
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &governed,
                &tampered,
            )
            .is_err()
        );

        let root_transition = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"3".repeat(64),
            1_050,
        )
        .unwrap();
        let advanced = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &root_transition,
        )
        .unwrap();
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &advanced,
                &governance,
                &[
                    ("authority-a".into(), [41; 32]),
                    ("authority-b".into(), [42; 32]),
                ],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
                "lab-a",
                None,
                &"4".repeat(64),
                1_200,
            )
            .is_err()
        );
    }

    #[test]
    fn governance_rotation_requires_old_and_new_quorums_and_state_bound_successor() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let old_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
            &initial,
            &[31; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-a".into(),
                    public_key: public([41; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-b".into(),
                    public_key: public([42; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-c".into(),
                    public_key: public([43; 32]),
                },
            ],
            1_000,
        )
        .unwrap();
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let admission = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &old_governance,
            &[
                ("authority-a".into(), [41; 32]),
                ("authority-b".into(), [42; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_100,
        )
        .unwrap();
        let governed = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &admission,
        )
        .unwrap();
        let new_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_successor_governance(
            &governed,
            &[31; 32],
            3,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-d".into(),
                    public_key: public([44; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-e".into(),
                    public_key: public([45; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-f".into(),
                    public_key: public([46; 32]),
                },
            ],
            1_150,
        )
        .unwrap();
        assert_eq!(new_governance.registry_generation, governed.generation);
        assert_eq!(
            new_governance.registry_state_sha256,
            factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &governed,
            )
            .unwrap()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_successor_governance(
                &initial,
                &[31; 32],
                2,
                old_governance.authorities.clone(),
                1_150,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &governed,
                &old_governance,
                &new_governance,
                &[("authority-a".into(), [41; 32])],
                &[
                    ("authority-d".into(), [44; 32]),
                    ("authority-e".into(), [45; 32]),
                    ("authority-f".into(), [46; 32]),
                ],
                1_200,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &governed,
                &old_governance,
                &new_governance,
                &[
                    ("authority-a".into(), [41; 32]),
                    ("authority-b".into(), [42; 32]),
                ],
                &[
                    ("authority-d".into(), [44; 32]),
                    ("authority-e".into(), [45; 32]),
                ],
                1_200,
            )
            .is_err()
        );
        let rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
            &governed,
            &old_governance,
            &new_governance,
            &[
                ("authority-b".into(), [42; 32]),
                ("authority-a".into(), [41; 32]),
            ],
            &[
                ("authority-f".into(), [46; 32]),
                ("authority-d".into(), [44; 32]),
                ("authority-e".into(), [45; 32]),
            ],
            1_200,
        )
        .unwrap();
        let rotation_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
            &rotation,
        )
        .unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &rotation_source,
            )
            .unwrap(),
            rotation
        );
        assert!(matches!(
            parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_history_event(
                &rotation_source,
            )
            .unwrap(),
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceRotationHistoryEventEvidence::GovernanceRotation { .. }
        ));
        assert!(
            parse_factory_release_state_transparency_external_gossip_registry_threshold_governance_history_event(
                &rotation_source,
            )
            .is_err()
        );
        let rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
            &governed,
            &rotation,
        )
        .unwrap();
        assert_eq!(rotated.generation, governed.generation + 1);
        assert_eq!(rotated.organizations, governed.organizations);
        assert_eq!(
            rotated.active_governance_sha256.as_deref(),
            Some(rotation.new_governance_sha256.as_str())
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &rotated,
                &old_governance,
                &[
                    ("authority-a".into(), [41; 32]),
                    ("authority-b".into(), [42; 32]),
                ],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
                "lab-a",
                None,
                &"2".repeat(64),
                1_300,
            )
            .is_err()
        );
        let suspension = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &rotated,
            &new_governance,
            &[
                ("authority-d".into(), [44; 32]),
                ("authority-e".into(), [45; 32]),
                ("authority-f".into(), [46; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"2".repeat(64),
            1_300,
        )
        .unwrap();
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &rotated,
                &suspension,
            )
            .is_ok()
        );
        let mut tampered_old = rotation.clone();
        tampered_old.old_approvals[0]
            .signature
            .replace_range(..2, "00");
        if tampered_old.old_approvals[0].signature == rotation.old_approvals[0].signature {
            tampered_old.old_approvals[0]
                .signature
                .replace_range(..2, "ff");
        }
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &governed,
                &tampered_old,
            )
            .is_err()
        );
        let mut tampered_new = rotation.clone();
        tampered_new.new_approvals[0]
            .signature
            .replace_range(..2, "00");
        if tampered_new.new_approvals[0].signature == rotation.new_approvals[0].signature {
            tampered_new.new_approvals[0]
                .signature
                .replace_range(..2, "ff");
        }
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &governed,
                &tampered_new,
            )
            .is_err()
        );
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &rotated,
                &rotation,
            )
            .is_err()
        );
    }

    #[test]
    fn governed_authority_rotation_requires_two_quorums_and_a_distinct_successor_root() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let old_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
            &initial,
            &[31; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-a".into(),
                    public_key: public([41; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-b".into(),
                    public_key: public([42; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-c".into(),
                    public_key: public([43; 32]),
                },
            ],
            1_000,
        )
        .unwrap();
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let admission = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &old_governance,
            &[
                ("authority-a".into(), [41; 32]),
                ("authority-b".into(), [42; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_100,
        )
        .unwrap();
        let governed = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &initial,
            &admission,
        )
        .unwrap();

        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_successor_root_governance(
                &governed,
                &[31; 32],
                2,
                old_governance.authorities.clone(),
                1_150,
            )
            .is_err()
        );
        let new_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_successor_root_governance(
            &governed,
            &[51; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-d".into(),
                    public_key: public([44; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-e".into(),
                    public_key: public([45; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-f".into(),
                    public_key: public([46; 32]),
                },
            ],
            1_150,
        )
        .unwrap();
        assert_eq!(new_governance.registry_generation, governed.generation);
        assert_eq!(
            new_governance.registry_state_sha256,
            factory_release_state_transparency_external_gossip_organization_registry_sha256(
                &governed,
            )
            .unwrap()
        );
        assert_ne!(
            new_governance.registry_authority_public_key,
            governed.authority_public_key
        );

        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old_governance,
                &new_governance,
                &[("authority-a".into(), [41; 32])],
                &[
                    ("authority-d".into(), [44; 32]),
                    ("authority-e".into(), [45; 32]),
                ],
                1_200,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old_governance,
                &new_governance,
                &[
                    ("authority-a".into(), [41; 32]),
                    ("authority-b".into(), [42; 32]),
                ],
                &[("authority-d".into(), [44; 32])],
                1_200,
            )
            .is_err()
        );
        let rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &governed,
            &old_governance,
            &new_governance,
            &[
                ("authority-b".into(), [42; 32]),
                ("authority-a".into(), [41; 32]),
            ],
            &[
                ("authority-e".into(), [45; 32]),
                ("authority-d".into(), [44; 32]),
            ],
            1_200,
        )
        .unwrap();
        let rotation_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &rotation,
        )
        .unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &rotation_source,
            )
            .unwrap(),
            rotation
        );
        assert!(matches!(
            parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_history_event(
                &rotation_source,
            )
            .unwrap(),
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernedAuthorityRotationHistoryEventEvidence::GovernedAuthorityKeyRotation { .. }
        ));
        assert!(
            parse_factory_release_state_transparency_external_gossip_registry_governance_rotation_history_event(
                &rotation_source,
            )
            .is_err()
        );

        let rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &governed,
            &rotation,
        )
        .unwrap();
        assert_eq!(rotated.generation, governed.generation + 1);
        assert_eq!(rotated.organizations, governed.organizations);
        assert_eq!(rotated.authority_public_key, rotation.new_public_key);
        assert_eq!(
            rotated.active_governance_sha256.as_deref(),
            Some(rotation.new_governance_sha256.as_str())
        );

        let suspension = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &rotated,
            &new_governance,
            &[
                ("authority-d".into(), [44; 32]),
                ("authority-e".into(), [45; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"2".repeat(64),
            1_300,
        )
        .unwrap();
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &rotated,
                &suspension,
            )
            .is_ok()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &rotated,
                &old_governance,
                &[
                    ("authority-a".into(), [41; 32]),
                    ("authority-b".into(), [42; 32]),
                ],
                FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
                "lab-a",
                None,
                &"3".repeat(64),
                1_300,
            )
            .is_err()
        );

        let mut tampered_old = rotation.clone();
        tampered_old.old_approvals[0]
            .signature
            .replace_range(..2, "00");
        if tampered_old.old_approvals[0].signature == rotation.old_approvals[0].signature {
            tampered_old.old_approvals[0]
                .signature
                .replace_range(..2, "ff");
        }
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &tampered_old,
            )
            .is_err()
        );
        let mut tampered_new = rotation.clone();
        tampered_new.new_approvals[0]
            .signature
            .replace_range(..2, "00");
        if tampered_new.new_approvals[0].signature == rotation.new_approvals[0].signature {
            tampered_new.new_approvals[0]
                .signature
                .replace_range(..2, "ff");
        }
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &tampered_new,
            )
            .is_err()
        );
        assert!(
            apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &rotated,
                &rotation,
            )
            .is_err()
        );
    }

    #[test]
    fn complete_history_audit_replays_all_five_event_kinds_from_exact_genesis() {
        let policy = policy();
        let policy_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_organization_registry(
            &policy,
            &policy_sha,
            "production-observers",
            &SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let trust = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &policy,
            &policy_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let legacy_transition = sign_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &[31; 32],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::AdmitObserver,
            "lab-a",
            Some(&trust),
            &"1".repeat(64),
            1_000,
        )
        .unwrap();
        let admitted = apply_factory_release_state_transparency_external_gossip_organization_registry_transition(
            &initial,
            &legacy_transition,
        )
        .unwrap();
        let root_rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &admitted,
            &[31; 32],
            &[32; 32],
            2_000,
        )
        .unwrap();
        let root_rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
            &admitted,
            &root_rotation,
        )
        .unwrap();
        let old_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_governance(
            &root_rotated,
            &[32; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-a".into(),
                    public_key: public([41; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-b".into(),
                    public_key: public([42; 32]),
                },
            ],
            2_100,
        )
        .unwrap();
        let threshold_transition = sign_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &root_rotated,
            &old_governance,
            &[
                ("authority-a".into(), [41; 32]),
                ("authority-b".into(), [42; 32]),
            ],
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryAction::SuspendOrganization,
            "lab-a",
            None,
            &"2".repeat(64),
            3_000,
        )
        .unwrap();
        let governed = apply_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
            &root_rotated,
            &threshold_transition,
        )
        .unwrap();
        let middle_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_successor_governance(
            &governed,
            &[32; 32],
            2,
            vec![
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-c".into(),
                    public_key: public([43; 32]),
                },
                FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                    authority_id: "authority-d".into(),
                    public_key: public([44; 32]),
                },
            ],
            3_100,
        )
        .unwrap();
        let governance_rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
            &governed,
            &old_governance,
            &middle_governance,
            &[
                ("authority-a".into(), [41; 32]),
                ("authority-b".into(), [42; 32]),
            ],
            &[
                ("authority-c".into(), [43; 32]),
                ("authority-d".into(), [44; 32]),
            ],
            4_000,
        )
        .unwrap();
        let governance_rotated = apply_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
            &governed,
            &governance_rotation,
        )
        .unwrap();
        let final_authorities = vec![
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                authority_id: "authority-e".into(),
                public_key: public([45; 32]),
            },
            FactoryReleaseStateTransparencyExternalGossipRegistryGovernanceAuthority {
                authority_id: "authority-f".into(),
                public_key: public([46; 32]),
            },
        ];
        let final_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_successor_root_governance(
            &governance_rotated,
            &[33; 32],
            2,
            final_authorities.clone(),
            4_100,
        )
        .unwrap();
        let governed_root_rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &governance_rotated,
            &middle_governance,
            &final_governance,
            &[
                ("authority-c".into(), [43; 32]),
                ("authority-d".into(), [44; 32]),
            ],
            &[
                ("authority-e".into(), [45; 32]),
                ("authority-f".into(), [46; 32]),
            ],
            5_000,
        )
        .unwrap();
        let expected_final = apply_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &governance_rotated,
            &governed_root_rotation,
        )
        .unwrap();
        let initial_source =
            render_factory_release_state_transparency_external_gossip_organization_registry(
                &initial,
            )
            .unwrap();
        let event_sources = vec![
            render_signed_factory_release_state_transparency_external_gossip_organization_registry_transition(
                &legacy_transition,
            )
            .unwrap(),
            render_signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation(
                &root_rotation,
            )
            .unwrap(),
            render_signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition(
                &threshold_transition,
            )
            .unwrap(),
            render_signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation(
                &governance_rotation,
            )
            .unwrap(),
            render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                &governed_root_rotation,
            )
            .unwrap(),
        ];
        let history =
            build_factory_release_state_transparency_external_gossip_organization_registry_history(
                &initial_source,
                &event_sources,
            )
            .unwrap();
        let report =
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &history,
            )
            .unwrap();
        assert_eq!(report.event_count, 5);
        assert_eq!(report.final_registry, expected_final);
        assert!(report.chain_valid);
        assert_eq!(
            report.entries[0].artifact,
            exact_identity(&event_sources[0])
        );
        assert_eq!(
            report.entries[4].kind,
            FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEventKind::GovernedAuthorityKeyRotation
        );
        let history_source = render_factory_release_state_transparency_external_gossip_organization_registry_history(
            &history,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_organization_registry_history(
                &history_source,
            )
            .unwrap(),
            history
        );
        let report_source = render_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
            &report,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
                &report_source,
            )
            .unwrap(),
            report
        );
        assert_eq!(
            factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_sha256(
                &report,
            )
            .unwrap()
            .len(),
            64
        );

        let mut reordered = history.clone();
        reordered.events.swap(0, 1);
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &reordered,
            )
            .is_err()
        );
        let mut replayed = history.clone();
        replayed.events.insert(1, replayed.events[0].clone());
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &replayed,
            )
            .is_err()
        );
        let mut omitted = history.clone();
        omitted.events.remove(1);
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &omitted,
            )
            .is_err()
        );
        let mut non_genesis = history.clone();
        non_genesis.initial_registry = expected_final;
        non_genesis.initial_registry_artifact = exact_identity(
            &render_factory_release_state_transparency_external_gossip_organization_registry(
                &non_genesis.initial_registry,
            )
            .unwrap(),
        );
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &non_genesis,
            )
            .is_err()
        );
        let mut wrong_artifact = history.clone();
        if let FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::OrganizationTransition {
            artifact,
            ..
        } = &mut wrong_artifact.events[0]
        {
            artifact.sha256 = "0".repeat(64);
        }
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &wrong_artifact,
            )
            .is_err()
        );
        let mut tampered_signature = history.clone();
        if let FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryEvent::GovernedAuthorityKeyRotation {
            artifact,
            rotation,
        } = &mut tampered_signature.events[4]
        {
            let replacement = if rotation.new_approvals[0].signature.starts_with("00") {
                "ff"
            } else {
                "00"
            };
            rotation.new_approvals[0]
                .signature
                .replace_range(..2, replacement);
            let source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
                rotation,
            )
            .unwrap();
            *artifact = exact_identity(&source);
        }
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &tampered_signature,
            )
            .is_err()
        );

        let reused_root_governance = sign_factory_release_state_transparency_external_gossip_organization_registry_successor_root_governance(
            &governance_rotated,
            &[31; 32],
            2,
            final_authorities,
            4_100,
        )
        .unwrap();
        let reused_root_rotation = sign_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &governance_rotated,
            &middle_governance,
            &reused_root_governance,
            &[
                ("authority-c".into(), [43; 32]),
                ("authority-d".into(), [44; 32]),
            ],
            &[
                ("authority-e".into(), [45; 32]),
                ("authority-f".into(), [46; 32]),
            ],
            5_000,
        )
        .unwrap();
        let reused_source = render_signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation(
            &reused_root_rotation,
        )
        .unwrap();
        let mut reused_history = history;
        reused_history.events[4] =
            parse_factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_history_event(
                &reused_source,
            )
            .unwrap();
        assert!(
            audit_factory_release_state_transparency_external_gossip_organization_registry_history(
                &reused_history,
            )
            .is_err()
        );

        let mut inconsistent_report = report;
        inconsistent_report.entries[4].resulting_registry_sha256 = "0".repeat(64);
        assert!(
            validate_factory_release_state_transparency_external_gossip_organization_registry_history_audit_report(
                &inconsistent_report,
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed_and_bounded() {
        let registry =
            factory_release_state_transparency_external_gossip_organization_registry_json_schema();
        let transition = signed_factory_release_state_transparency_external_gossip_organization_registry_transition_json_schema();
        let authority_rotation = signed_factory_release_state_transparency_external_gossip_organization_registry_authority_key_rotation_json_schema();
        let governance = signed_factory_release_state_transparency_external_gossip_organization_registry_governance_json_schema();
        let threshold_transition = signed_factory_release_state_transparency_external_gossip_organization_registry_threshold_transition_json_schema();
        let governance_rotation = signed_factory_release_state_transparency_external_gossip_organization_registry_governance_rotation_json_schema();
        let governed_authority_rotation = signed_factory_release_state_transparency_external_gossip_organization_registry_governed_authority_key_rotation_json_schema();
        let report =
            factory_release_state_transparency_external_gossip_registry_report_json_schema();
        let authority_rotation_report = factory_release_state_transparency_external_gossip_registry_authority_rotation_report_json_schema();
        let threshold_governance_report = factory_release_state_transparency_external_gossip_registry_threshold_governance_report_json_schema();
        let governance_rotation_report = factory_release_state_transparency_external_gossip_registry_governance_rotation_report_json_schema();
        let governed_authority_rotation_report = factory_release_state_transparency_external_gossip_registry_governed_authority_rotation_report_json_schema();
        let history = factory_release_state_transparency_external_gossip_organization_registry_history_json_schema();
        let history_audit = factory_release_state_transparency_external_gossip_organization_registry_history_audit_report_json_schema();
        assert_eq!(registry["additionalProperties"], false);
        assert_eq!(transition["additionalProperties"], false);
        assert_eq!(authority_rotation["additionalProperties"], false);
        assert_eq!(governance["additionalProperties"], false);
        assert_eq!(threshold_transition["additionalProperties"], false);
        assert_eq!(governance_rotation["additionalProperties"], false);
        assert_eq!(governed_authority_rotation["additionalProperties"], false);
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(authority_rotation_report["additionalProperties"], false);
        assert_eq!(threshold_governance_report["additionalProperties"], false);
        assert_eq!(governance_rotation_report["additionalProperties"], false);
        assert_eq!(
            governed_authority_rotation_report["additionalProperties"],
            false
        );
        assert_eq!(history["additionalProperties"], false);
        assert_eq!(history_audit["additionalProperties"], false);
        assert_eq!(
            registry["properties"]["organizations"]["maxItems"],
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
        );
        assert_eq!(
            report["properties"]["selected_ledger_rollback_resistance_verified"],
            json!({"const": false})
        );
        assert_eq!(
            authority_rotation_report["properties"]["registry_history_events"]["maxItems"],
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        );
        assert_eq!(
            authority_rotation_report["properties"]["authority_threshold_governance_verified"],
            json!({"const": false})
        );
        assert_eq!(
            threshold_governance_report["properties"]["authority_threshold_governance_verified"],
            json!({"const": true})
        );
        assert_eq!(
            governance_rotation_report["properties"]["governance_rotation_old_quorum_verified"],
            json!({"const": true})
        );
        assert_eq!(
            governance_rotation_report["properties"]["independent_governance_control_verified"],
            json!({"const": false})
        );
        assert_eq!(
            history["properties"]["events"]["maxItems"],
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        );
        assert_eq!(
            history_audit["properties"]["entries"]["maxItems"],
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_TRANSITIONS
        );
    }
}
