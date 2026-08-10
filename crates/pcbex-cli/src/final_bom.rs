//! Closed verification that a manufacturing package is the final BOM for an
//! exact KiCad board source.

use crate::{
    factory::validate_manufacturing_package_details,
    manufacturing_limits::{
        MAX_MANIFEST_BYTES, MAX_PACKAGE_BYTES, ManufacturingLimits, validate_manufacturing_basename,
    },
    manufacturing_package::render_canonical_bom,
};
use pcbex_kicad::{MAX_MANUFACTURING_PARTS, ManufacturingPart, manufacturing_parts};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const FINAL_BOM_REPORT_SCHEMA_VERSION: u32 = 1;
pub(crate) const FINAL_BOM_SCOPE: &str = "final_bom_source_and_canonical_bom_v1";
pub(crate) const FINAL_BOM_MAX_REFERENCES: usize = 256;
pub(crate) const FINAL_BOM_MAX_FINDINGS: usize = 2;
pub(crate) const FINAL_BOM_MAX_PART_TEXT_BYTES: usize = 4096;
pub(crate) const FINAL_BOM_MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

const CANONICAL_BOM_MISMATCH_CODE: &str = "canonical_bom_mismatch";
const CANONICAL_BOM_MISMATCH_MESSAGE: &str =
    "manufacturing package bom.csv does not equal the canonical BOM regenerated from the board";
const PACKAGE_BOARD_SOURCE_MISMATCH_CODE: &str = "package_board_source_mismatch";
const PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE: &str =
    "manufacturing package input identity does not equal the supplied board";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomSourceIdentity {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomSources {
    pub(crate) board: FinalBomSourceIdentity,
    pub(crate) manufacturing_package: FinalBomSourceIdentity,
    pub(crate) manifest: FinalBomSourceIdentity,
    pub(crate) bom: FinalBomSourceIdentity,
    pub(crate) canonical_bom: FinalBomSourceIdentity,
    pub(crate) package_board_source: FinalBomSourceIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomCounts {
    pub(crate) board_parts: usize,
    pub(crate) board_in_bom_parts: usize,
    pub(crate) package_parts: u64,
    pub(crate) package_in_bom_parts: u64,
    pub(crate) findings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomPart {
    pub(crate) reference: String,
    pub(crate) value: String,
    pub(crate) footprint: String,
    pub(crate) mpn: Option<String>,
    pub(crate) layer: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomFinding {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalBomReport {
    pub(crate) schema_version: u32,
    pub(crate) scope: &'static str,
    pub(crate) engine_version: &'static str,
    pub(crate) board_basename: String,
    pub(crate) sources: FinalBomSources,
    pub(crate) counts: FinalBomCounts,
    pub(crate) in_bom_parts: Vec<FinalBomPart>,
    pub(crate) findings: Vec<FinalBomFinding>,
    pub(crate) approved: bool,
}

pub(crate) fn verify_final_bom_sources(
    board_basename: &str,
    board_source: &[u8],
    manufacturing_package: &[u8],
) -> Result<FinalBomReport, String> {
    validate_manufacturing_basename(
        board_basename,
        ManufacturingLimits::production().max_name_bytes,
        "final BOM board",
    )
    .map_err(|error| error.to_string())?;
    if board_basename
        .strip_suffix(".kicad_pcb")
        .is_none_or(str::is_empty)
    {
        return Err("final BOM board name must be one portable .kicad_pcb leaf".into());
    }
    if board_source.is_empty() || board_source.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "final BOM board must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    if manufacturing_package.is_empty() || manufacturing_package.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "final BOM manufacturing package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }

    let board_text = std::str::from_utf8(board_source)
        .map_err(|error| format!("final BOM board is not UTF-8: {error}"))?;
    let parts = manufacturing_parts(board_text)
        .map_err(|error| format!("extracting exact board manufacturing parts: {error}"))?;
    let in_bom_count = parts.iter().filter(|part| part.in_bom).count();
    if in_bom_count > FINAL_BOM_MAX_REFERENCES {
        return Err(format!(
            "final BOM board contains more than {FINAL_BOM_MAX_REFERENCES} BOM references"
        ));
    }
    let in_bom_parts = parts
        .iter()
        .filter(|part| part.in_bom)
        .map(final_bom_part)
        .collect::<Result<Vec<_>, _>>()?;
    debug_assert!(
        in_bom_parts
            .windows(2)
            .all(|pair| pair[0].reference < pair[1].reference)
    );

    let canonical_bom = render_canonical_bom(&parts)
        .map_err(|error| format!("rendering exact board canonical BOM: {error:#}"))?;
    let package = validate_manufacturing_package_details(manufacturing_package)?;

    let board_identity = identity(board_source);
    let package_board_identity = FinalBomSourceIdentity {
        bytes: package.identity.input_bytes,
        sha256: package.identity.input_sha256.clone(),
    };
    let mut findings = Vec::with_capacity(FINAL_BOM_MAX_FINDINGS);
    if board_identity != package_board_identity {
        findings.push(FinalBomFinding {
            code: PACKAGE_BOARD_SOURCE_MISMATCH_CODE.into(),
            message: PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE.into(),
        });
    }
    if canonical_bom != package.bom_bytes {
        findings.push(FinalBomFinding {
            code: CANONICAL_BOM_MISMATCH_CODE.into(),
            message: CANONICAL_BOM_MISMATCH_MESSAGE.into(),
        });
    }
    findings.sort();

    let report = FinalBomReport {
        schema_version: FINAL_BOM_REPORT_SCHEMA_VERSION,
        scope: FINAL_BOM_SCOPE,
        engine_version: env!("CARGO_PKG_VERSION"),
        board_basename: board_basename.into(),
        sources: FinalBomSources {
            board: board_identity,
            manufacturing_package: identity(manufacturing_package),
            manifest: identity(&package.manifest_bytes),
            bom: identity(&package.bom_bytes),
            canonical_bom: identity(&canonical_bom),
            package_board_source: package_board_identity,
        },
        counts: FinalBomCounts {
            board_parts: parts.len(),
            board_in_bom_parts: in_bom_count,
            package_parts: package.manifest_parts_total,
            package_in_bom_parts: package.manifest_parts_bom,
            findings: findings.len(),
        },
        in_bom_parts,
        approved: findings.is_empty(),
        findings,
    };
    validate_final_bom_report(&report)?;
    Ok(report)
}

pub(crate) fn render_final_bom_report(report: &FinalBomReport) -> Result<Vec<u8>, String> {
    validate_final_bom_report(report)?;
    let mut rendered = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("serializing final BOM report: {error}"))?;
    rendered.push(b'\n');
    if rendered.len() > FINAL_BOM_MAX_REPORT_BYTES {
        return Err(format!(
            "final BOM report exceeds {FINAL_BOM_MAX_REPORT_BYTES} bytes"
        ));
    }
    Ok(rendered)
}

fn final_bom_part(part: &ManufacturingPart) -> Result<FinalBomPart, String> {
    let result = FinalBomPart {
        reference: part.reference.clone(),
        value: part.value.clone(),
        footprint: part.footprint.clone(),
        mpn: part.mpn.clone(),
        layer: part.side.clone(),
        kind: if part.smd { "SMD" } else { "THT" }.into(),
    };
    validate_final_bom_part(&result)?;
    Ok(result)
}

fn validate_final_bom_report(report: &FinalBomReport) -> Result<(), String> {
    if report.schema_version != FINAL_BOM_REPORT_SCHEMA_VERSION
        || report.scope != FINAL_BOM_SCOPE
        || report.engine_version != env!("CARGO_PKG_VERSION")
    {
        return Err("final BOM report version, scope, or engine is invalid".into());
    }
    validate_manufacturing_basename(
        &report.board_basename,
        ManufacturingLimits::production().max_name_bytes,
        "final BOM board",
    )
    .map_err(|error| error.to_string())?;
    for (identity, maximum, label) in [
        (&report.sources.board, MAX_PACKAGE_BYTES, "board"),
        (
            &report.sources.manufacturing_package,
            MAX_PACKAGE_BYTES,
            "manufacturing package",
        ),
        (&report.sources.manifest, MAX_MANIFEST_BYTES, "manifest"),
        (&report.sources.bom, MAX_PACKAGE_BYTES, "BOM"),
        (
            &report.sources.canonical_bom,
            MAX_PACKAGE_BYTES,
            "canonical BOM",
        ),
        (
            &report.sources.package_board_source,
            MAX_PACKAGE_BYTES,
            "package board source",
        ),
    ] {
        validate_identity(identity, maximum, label)?;
    }
    if report.in_bom_parts.len() > FINAL_BOM_MAX_REFERENCES
        || report.findings.len() > FINAL_BOM_MAX_FINDINGS
        || report.counts.board_parts > MAX_MANUFACTURING_PARTS
        || report.counts.package_parts > MAX_MANUFACTURING_PARTS as u64
        || report.counts.package_in_bom_parts > MAX_MANUFACTURING_PARTS as u64
        || report.counts.board_in_bom_parts > report.counts.board_parts
        || report.counts.package_in_bom_parts > report.counts.package_parts
        || report.counts.board_in_bom_parts != report.in_bom_parts.len()
        || report.counts.findings != report.findings.len()
        || report.approved != report.findings.is_empty()
    {
        return Err("final BOM report counts or approval state are inconsistent".into());
    }
    if !report
        .in_bom_parts
        .windows(2)
        .all(|pair| pair[0].reference < pair[1].reference)
        || !report.findings.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err("final BOM report records are not strictly sorted".into());
    }
    for part in &report.in_bom_parts {
        validate_final_bom_part(part)?;
    }
    for finding in &report.findings {
        if !matches!(
            (finding.code.as_str(), finding.message.as_str()),
            (CANONICAL_BOM_MISMATCH_CODE, CANONICAL_BOM_MISMATCH_MESSAGE)
                | (
                    PACKAGE_BOARD_SOURCE_MISMATCH_CODE,
                    PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE
                )
        ) {
            return Err("final BOM report contains an unsupported finding".into());
        }
    }
    let has_canonical_mismatch = report
        .findings
        .iter()
        .any(|finding| finding.code == CANONICAL_BOM_MISMATCH_CODE);
    if (report.sources.bom == report.sources.canonical_bom) == has_canonical_mismatch {
        return Err("final BOM canonical BOM identity/finding state is inconsistent".into());
    }
    let has_source_mismatch = report
        .findings
        .iter()
        .any(|finding| finding.code == PACKAGE_BOARD_SOURCE_MISMATCH_CODE);
    if (report.sources.board == report.sources.package_board_source) == has_source_mismatch {
        return Err("final BOM board source identity/finding state is inconsistent".into());
    }
    Ok(())
}

fn validate_final_bom_part(part: &FinalBomPart) -> Result<(), String> {
    for (label, value) in [
        ("reference", part.reference.as_str()),
        ("value", part.value.as_str()),
        ("footprint", part.footprint.as_str()),
    ] {
        if value.is_empty() || value.len() > FINAL_BOM_MAX_PART_TEXT_BYTES || value.contains('\0') {
            return Err(format!(
                "final BOM part {label} must contain 1 to {FINAL_BOM_MAX_PART_TEXT_BYTES} safe UTF-8 bytes"
            ));
        }
    }
    if let Some(mpn) = part.mpn.as_deref()
        && (mpn.is_empty() || mpn.len() > FINAL_BOM_MAX_PART_TEXT_BYTES || mpn.contains('\0'))
    {
        return Err(format!(
            "final BOM part mpn must contain 1 to {FINAL_BOM_MAX_PART_TEXT_BYTES} safe UTF-8 bytes when present"
        ));
    }
    if !matches!(part.layer.as_str(), "F" | "B") || !matches!(part.kind.as_str(), "SMD" | "THT") {
        return Err("final BOM part layer or type is invalid".into());
    }
    Ok(())
}

fn validate_identity(
    identity: &FinalBomSourceIdentity,
    maximum_bytes: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0
        || identity.bytes > maximum_bytes
        || identity.sha256.len() != 64
        || !identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("final BOM report {label} identity is invalid"));
    }
    Ok(())
}

fn identity(source: &[u8]) -> FinalBomSourceIdentity {
    FinalBomSourceIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

pub(crate) fn final_bom_report_json_schema() -> Value {
    let identity = |maximum: u64| {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            }
        })
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/final-bom-report-v1.json",
        "title": "pcbex exact final BOM verification report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "scope", "engine_version", "board_basename", "sources",
            "counts", "in_bom_parts", "findings", "approved"
        ],
        "properties": {
            "schema_version": {"const": FINAL_BOM_REPORT_SCHEMA_VERSION},
            "scope": {"const": FINAL_BOM_SCOPE},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"},
            "board_basename": {"type": "string", "minLength": 11, "maxLength": 255, "pattern": "^[^\\u0000-\\u001f<>:\"/\\\\|?*]+\\.kicad_pcb$"},
            "sources": {
                "type": "object",
                "additionalProperties": false,
                "required": ["board", "manufacturing_package", "manifest", "bom", "canonical_bom", "package_board_source"],
                "properties": {
                    "board": identity(MAX_PACKAGE_BYTES),
                    "manufacturing_package": identity(MAX_PACKAGE_BYTES),
                    "manifest": identity(MAX_MANIFEST_BYTES),
                    "bom": identity(MAX_PACKAGE_BYTES),
                    "canonical_bom": identity(MAX_PACKAGE_BYTES),
                    "package_board_source": identity(MAX_PACKAGE_BYTES)
                }
            },
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["board_parts", "board_in_bom_parts", "package_parts", "package_in_bom_parts", "findings"],
                "properties": {
                    "board_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "board_in_bom_parts": {"type": "integer", "minimum": 0, "maximum": FINAL_BOM_MAX_REFERENCES},
                    "package_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "package_in_bom_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "findings": {"type": "integer", "minimum": 0, "maximum": FINAL_BOM_MAX_FINDINGS}
                }
            },
            "in_bom_parts": {
                "type": "array",
                "maxItems": FINAL_BOM_MAX_REFERENCES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["reference", "value", "footprint", "mpn", "layer", "type"],
                    "properties": {
                        "reference": {"type": "string", "minLength": 1, "maxLength": FINAL_BOM_MAX_PART_TEXT_BYTES},
                        "value": {"type": "string", "minLength": 1, "maxLength": FINAL_BOM_MAX_PART_TEXT_BYTES},
                        "footprint": {"type": "string", "minLength": 1, "maxLength": FINAL_BOM_MAX_PART_TEXT_BYTES},
                        "mpn": {
                            "anyOf": [
                                {"type": "null"},
                                {"type": "string", "minLength": 1, "maxLength": FINAL_BOM_MAX_PART_TEXT_BYTES}
                            ]
                        },
                        "layer": {"enum": ["F", "B"]},
                        "type": {"enum": ["SMD", "THT"]}
                    }
                }
            },
            "findings": {
                "type": "array",
                "maxItems": FINAL_BOM_MAX_FINDINGS,
                "uniqueItems": true,
                "items": {
                    "anyOf": [
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"const": CANONICAL_BOM_MISMATCH_CODE},
                                "message": {"const": CANONICAL_BOM_MISMATCH_MESSAGE}
                            }
                        },
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"const": PACKAGE_BOARD_SOURCE_MISMATCH_CODE},
                                "message": {"const": PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE}
                            }
                        }
                    ]
                }
            },
            "approved": {"type": "boolean"}
        },
        "allOf": [
            {
                "if": {"properties": {"approved": {"const": true}}},
                "then": {
                    "properties": {
                        "findings": {"maxItems": 0},
                        "counts": {"properties": {"findings": {"const": 0}}}
                    }
                }
            },
            {
                "if": {"properties": {"approved": {"const": false}}},
                "then": {
                    "properties": {
                        "findings": {"minItems": 1},
                        "counts": {"properties": {"findings": {"minimum": 1}}}
                    }
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_closed_and_pins_the_two_findings() {
        let schema = final_bom_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["sources"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["counts"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["in_bom_parts"]["maxItems"],
            FINAL_BOM_MAX_REFERENCES
        );
        assert_eq!(
            schema["properties"]["findings"]["maxItems"],
            FINAL_BOM_MAX_FINDINGS
        );
    }

    #[test]
    fn optional_mpn_is_null_or_one_to_4096_utf8_bytes() {
        let mut part = ManufacturingPart {
            reference: "R1".into(),
            value: "10k".into(),
            footprint: "Test:R".into(),
            x_nm: 0,
            y_nm: 0,
            rotation_mdeg: 0,
            side: "F".into(),
            mpn: None,
            in_bom: true,
            dnp: false,
            in_pos: true,
            smd: true,
        };
        assert_eq!(final_bom_part(&part).unwrap().mpn, None);
        part.mpn = Some(String::new());
        assert!(final_bom_part(&part).is_err());
        part.mpn = Some("x".repeat(FINAL_BOM_MAX_PART_TEXT_BYTES));
        assert!(final_bom_part(&part).is_ok());
        part.mpn = Some("x".repeat(FINAL_BOM_MAX_PART_TEXT_BYTES + 1));
        assert!(final_bom_part(&part).is_err());
    }

    #[test]
    fn board_basename_requires_a_nonempty_portable_stem() {
        for name in [
            ".kicad_pcb",
            "CON.kicad_pcb",
            "COM¹.kicad_pcb",
            "LPT².kicad_pcb",
        ] {
            let error = verify_final_bom_sources(name, b"board", b"package").unwrap_err();
            assert!(
                error.contains("board name") || error.contains("reserved Windows device name"),
                "{name}: {error}"
            );
        }
    }
}
