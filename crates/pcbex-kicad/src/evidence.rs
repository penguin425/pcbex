use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_ASSERTIONS: usize = 10_000;
const MAX_ARTIFACTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationAnalysisKind {
    DcOperatingPoint,
    AcSweep,
    Transient,
    SignalIntegrity,
    PowerIntegrity,
    Thermal,
    Custom,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationEngine {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationAssertion {
    pub id: String,
    pub description: String,
    pub measured: f64,
    pub unit: String,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationDeclaration {
    pub schema_version: u32,
    pub id: String,
    pub analysis: SimulationAnalysisKind,
    pub simulator: SimulationEngine,
    pub schematic_sha256: String,
    pub assertions: Vec<SimulationAssertion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationArtifact {
    pub name: String,
    pub media_type: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationAssertionResult {
    pub id: String,
    pub description: String,
    pub measured: f64,
    pub unit: String,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub passed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationEvidenceCounts {
    pub assertions: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationEvidence {
    pub schema_version: u32,
    pub id: String,
    pub analysis: SimulationAnalysisKind,
    pub simulator: SimulationEngine,
    pub schematic_sha256: String,
    pub electrical_review_sha256: String,
    pub electrical_review_approved: bool,
    pub declaration_sha256: String,
    pub passed: bool,
    pub counts: SimulationEvidenceCounts,
    pub assertions: Vec<SimulationAssertionResult>,
    pub artifacts: Vec<SimulationArtifact>,
}

pub fn parse_simulation_declaration(source: &str) -> Result<SimulationDeclaration, String> {
    let declaration: SimulationDeclaration = serde_json::from_str(source)
        .map_err(|error| format!("invalid simulation declaration: {error}"))?;
    validate_declaration(&declaration)?;
    Ok(declaration)
}

pub fn record_simulation_evidence(
    declaration: &SimulationDeclaration,
    electrical_review_sha256: &str,
    electrical_review_approved: bool,
    mut artifacts: Vec<SimulationArtifact>,
) -> Result<SimulationEvidence, String> {
    validate_declaration(declaration)?;
    validate_sha256(electrical_review_sha256, "electrical review SHA-256")?;
    if artifacts.is_empty() {
        return Err("simulation evidence requires at least one raw artifact".into());
    }
    if artifacts.len() > MAX_ARTIFACTS {
        return Err(format!(
            "simulation evidence exceeds the {MAX_ARTIFACTS} artifact limit"
        ));
    }
    let mut artifact_names = BTreeSet::new();
    for artifact in &artifacts {
        validate_nonblank(&artifact.name, "artifact name")?;
        validate_nonblank(&artifact.media_type, "artifact media type")?;
        if artifact.bytes == 0 {
            return Err(format!(
                "simulation artifact {} must not be empty",
                artifact.name
            ));
        }
        validate_sha256(&artifact.sha256, "artifact SHA-256")?;
        if !artifact_names.insert(artifact.name.clone()) {
            return Err(format!(
                "duplicate simulation artifact name {}",
                artifact.name
            ));
        }
    }
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));

    let mut assertions = declaration
        .assertions
        .iter()
        .map(|assertion| SimulationAssertionResult {
            id: assertion.id.clone(),
            description: assertion.description.clone(),
            measured: assertion.measured,
            unit: assertion.unit.clone(),
            minimum: assertion.minimum,
            maximum: assertion.maximum,
            passed: assertion
                .minimum
                .is_none_or(|minimum| assertion.measured >= minimum)
                && assertion
                    .maximum
                    .is_none_or(|maximum| assertion.measured <= maximum),
        })
        .collect::<Vec<_>>();
    assertions.sort_by(|left, right| left.id.cmp(&right.id));
    let counts = SimulationEvidenceCounts {
        assertions: assertions.len(),
        passed: assertions
            .iter()
            .filter(|assertion| assertion.passed)
            .count(),
        failed: assertions
            .iter()
            .filter(|assertion| !assertion.passed)
            .count(),
    };
    let declaration_bytes = serde_json::to_vec(declaration)
        .map_err(|error| format!("serializing simulation declaration: {error}"))?;
    Ok(SimulationEvidence {
        schema_version: 1,
        id: declaration.id.clone(),
        analysis: declaration.analysis,
        simulator: declaration.simulator.clone(),
        schematic_sha256: declaration.schematic_sha256.clone(),
        electrical_review_sha256: electrical_review_sha256.into(),
        electrical_review_approved,
        declaration_sha256: hex_digest(&declaration_bytes),
        passed: electrical_review_approved && counts.failed == 0,
        counts,
        assertions,
        artifacts,
    })
}

fn validate_declaration(declaration: &SimulationDeclaration) -> Result<(), String> {
    if declaration.schema_version != 1 {
        return Err(format!(
            "unsupported simulation declaration schema version {}",
            declaration.schema_version
        ));
    }
    validate_nonblank(&declaration.id, "simulation declaration id")?;
    validate_nonblank(&declaration.simulator.name, "simulator name")?;
    validate_nonblank(&declaration.simulator.version, "simulator version")?;
    validate_sha256(&declaration.schematic_sha256, "schematic SHA-256")?;
    if declaration.assertions.is_empty() {
        return Err("simulation declaration requires at least one assertion".into());
    }
    if declaration.assertions.len() > MAX_ASSERTIONS {
        return Err(format!(
            "simulation declaration exceeds the {MAX_ASSERTIONS} assertion limit"
        ));
    }
    let mut ids = BTreeSet::new();
    for assertion in &declaration.assertions {
        validate_nonblank(&assertion.id, "simulation assertion id")?;
        validate_nonblank(&assertion.description, "simulation assertion description")?;
        validate_nonblank(&assertion.unit, "simulation assertion unit")?;
        if !ids.insert(assertion.id.clone()) {
            return Err(format!(
                "duplicate simulation assertion id {}",
                assertion.id
            ));
        }
        if !assertion.measured.is_finite()
            || assertion.minimum.is_some_and(|value| !value.is_finite())
            || assertion.maximum.is_some_and(|value| !value.is_finite())
        {
            return Err(format!(
                "simulation assertion {} contains a non-finite value",
                assertion.id
            ));
        }
        if assertion.minimum.is_none() && assertion.maximum.is_none() {
            return Err(format!(
                "simulation assertion {} requires a minimum or maximum",
                assertion.id
            ));
        }
        if assertion
            .minimum
            .zip(assertion.maximum)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err(format!(
                "simulation assertion {} has reversed bounds",
                assertion.id
            ));
        }
    }
    Ok(())
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
        return Err(format!(
            "{description} must be 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn assertion_schema(include_passed: bool) -> Value {
    let mut required = vec!["id", "description", "measured", "unit"];
    if include_passed {
        required.extend(["minimum", "maximum"]);
        required.push("passed");
    }
    let mut properties = serde_json::Map::from_iter([
        ("id".into(), json!({"type": "string", "minLength": 1})),
        (
            "description".into(),
            json!({"type": "string", "minLength": 1}),
        ),
        ("measured".into(), json!({"type": "number"})),
        ("unit".into(), json!({"type": "string", "minLength": 1})),
        ("minimum".into(), json!({"type": ["number", "null"]})),
        ("maximum".into(), json!({"type": ["number", "null"]})),
    ]);
    if include_passed {
        properties.insert("passed".into(), json!({"type": "boolean"}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

pub fn simulation_declaration_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/simulation-declaration-v1.json",
        "title": "pcbex simulation declaration",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "analysis", "simulator", "schematic_sha256",
            "assertions"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1},
            "analysis": {"$ref": "#/$defs/analysis"},
            "simulator": {"$ref": "#/$defs/simulator"},
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "assertions": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_ASSERTIONS,
                "items": {"$ref": "#/$defs/assertion"}
            }
        },
        "$defs": {
            "analysis": {
                "enum": [
                    "dc_operating_point", "ac_sweep", "transient", "signal_integrity",
                    "power_integrity", "thermal", "custom"
                ]
            },
            "simulator": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "version"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "version": {"type": "string", "minLength": 1}
                }
            },
            "assertion": assertion_schema(false)
        }
    })
}

pub fn simulation_evidence_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/simulation-evidence-v1.json",
        "title": "pcbex bound simulation evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "analysis", "simulator", "schematic_sha256",
            "electrical_review_sha256", "electrical_review_approved",
            "declaration_sha256", "passed", "counts", "assertions", "artifacts"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1},
            "analysis": {"$ref": "#/$defs/analysis"},
            "simulator": {"$ref": "#/$defs/simulator"},
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "electrical_review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "electrical_review_approved": {"type": "boolean"},
            "declaration_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "passed": {"type": "boolean"},
            "counts": {"$ref": "#/$defs/counts"},
            "assertions": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_ASSERTIONS,
                "items": {"$ref": "#/$defs/assertion"}
            },
            "artifacts": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_ARTIFACTS,
                "items": {"$ref": "#/$defs/artifact"}
            }
        },
        "$defs": {
            "analysis": simulation_declaration_json_schema()["$defs"]["analysis"].clone(),
            "simulator": simulation_declaration_json_schema()["$defs"]["simulator"].clone(),
            "assertion": assertion_schema(true),
            "artifact": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name", "media_type", "bytes", "sha256"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "media_type": {"type": "string", "minLength": 1},
                    "bytes": {"type": "integer", "minimum": 1},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["assertions", "passed", "failed"],
                "properties": {
                    "assertions": {"type": "integer", "minimum": 1},
                    "passed": {"type": "integer", "minimum": 0},
                    "failed": {"type": "integer", "minimum": 0}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(measured: f64) -> SimulationDeclaration {
        SimulationDeclaration {
            schema_version: 1,
            id: "power-rail-dc".into(),
            analysis: SimulationAnalysisKind::DcOperatingPoint,
            simulator: SimulationEngine {
                name: "ngspice".into(),
                version: "42".into(),
            },
            schematic_sha256: "a".repeat(64),
            assertions: vec![SimulationAssertion {
                id: "vout".into(),
                description: "regulated output".into(),
                measured,
                unit: "V".into(),
                minimum: Some(3.2),
                maximum: Some(3.4),
            }],
        }
    }

    fn artifact() -> SimulationArtifact {
        SimulationArtifact {
            name: "raw.csv".into(),
            media_type: "text/csv".into(),
            bytes: 12,
            sha256: "b".repeat(64),
        }
    }

    #[test]
    fn records_bound_passing_and_failing_evidence_deterministically() {
        let passing =
            record_simulation_evidence(&declaration(3.3), &"c".repeat(64), true, vec![artifact()])
                .unwrap();
        assert!(passing.passed);
        assert_eq!(passing.counts.passed, 1);
        assert_eq!(
            passing,
            record_simulation_evidence(&declaration(3.3), &"c".repeat(64), true, vec![artifact()])
                .unwrap()
        );
        let failed =
            record_simulation_evidence(&declaration(3.5), &"c".repeat(64), true, vec![artifact()])
                .unwrap();
        assert!(!failed.passed);
        assert_eq!(failed.counts.failed, 1);
    }

    #[test]
    fn electrical_rejection_prevents_an_overall_pass() {
        let evidence =
            record_simulation_evidence(&declaration(3.3), &"c".repeat(64), false, vec![artifact()])
                .unwrap();
        assert!(!evidence.passed);
        assert_eq!(evidence.counts.failed, 0);
    }

    #[test]
    fn rejects_unbounded_duplicate_and_unverifiable_evidence() {
        let mut invalid = declaration(3.3);
        invalid.assertions[0].minimum = None;
        invalid.assertions[0].maximum = None;
        assert!(
            record_simulation_evidence(&invalid, &"c".repeat(64), true, vec![artifact()]).is_err()
        );

        let duplicate = vec![artifact(), artifact()];
        assert!(
            record_simulation_evidence(&declaration(3.3), &"c".repeat(64), true, duplicate)
                .is_err()
        );
        assert!(
            record_simulation_evidence(&declaration(3.3), &"c".repeat(64), true, Vec::new())
                .is_err()
        );
    }

    #[test]
    fn schemas_close_every_declared_object() {
        for schema in [
            simulation_declaration_json_schema(),
            simulation_evidence_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
            for definition in schema["$defs"].as_object().unwrap().values() {
                if definition["type"] == "object" {
                    assert_eq!(definition["additionalProperties"], false);
                }
            }
        }
    }
}
