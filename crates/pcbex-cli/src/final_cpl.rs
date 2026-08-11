//! Closed verification that a manufacturing package is the final component
//! placement list for an exact KiCad board source.

use crate::{
    factory::validate_manufacturing_package_details,
    manufacturing_limits::{
        MAX_MANIFEST_BYTES, MAX_PACKAGE_BYTES, ManufacturingLimits, validate_manufacturing_basename,
    },
    manufacturing_package::render_canonical_cpl,
};
use pcbex_kicad::{MAX_MANUFACTURING_PARTS, ManufacturingPart, manufacturing_parts};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const FINAL_CPL_REPORT_SCHEMA_VERSION: u32 = 1;
pub(crate) const FINAL_CPL_SCOPE: &str = "final_cpl_source_and_canonical_placement_v1";
pub(crate) const FINAL_CPL_MAX_REFERENCES: usize = 256;
pub(crate) const FINAL_CPL_MAX_FINDINGS: usize = 2;
pub(crate) const FINAL_CPL_MAX_REFERENCE_BYTES: usize = 4096;
pub(crate) const FINAL_CPL_MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

const CANONICAL_CPL_MISMATCH_CODE: &str = "canonical_cpl_mismatch";
const CANONICAL_CPL_MISMATCH_MESSAGE: &str =
    "manufacturing package cpl.csv does not equal the canonical CPL regenerated from the board";
const PACKAGE_BOARD_SOURCE_MISMATCH_CODE: &str = "package_board_source_mismatch";
const PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE: &str =
    "manufacturing package input identity does not equal the supplied board";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplSourceIdentity {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplSources {
    pub(crate) board: FinalCplSourceIdentity,
    pub(crate) manufacturing_package: FinalCplSourceIdentity,
    pub(crate) manifest: FinalCplSourceIdentity,
    pub(crate) cpl: FinalCplSourceIdentity,
    pub(crate) canonical_cpl: FinalCplSourceIdentity,
    pub(crate) package_board_source: FinalCplSourceIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplCounts {
    pub(crate) board_parts: usize,
    pub(crate) board_in_pos_parts: usize,
    pub(crate) package_parts: u64,
    pub(crate) package_placement_parts: u64,
    pub(crate) findings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplPlacement {
    pub(crate) reference: String,
    pub(crate) x_nm: i64,
    pub(crate) y_nm: i64,
    pub(crate) rotation_mdeg: i64,
    pub(crate) layer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplFinding {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalCplReport {
    pub(crate) schema_version: u32,
    pub(crate) scope: &'static str,
    pub(crate) engine_version: &'static str,
    pub(crate) board_basename: String,
    pub(crate) sources: FinalCplSources,
    pub(crate) counts: FinalCplCounts,
    pub(crate) in_pos_parts: Vec<FinalCplPlacement>,
    pub(crate) findings: Vec<FinalCplFinding>,
    pub(crate) approved: bool,
}

pub(crate) fn verify_final_cpl_sources(
    board_basename: &str,
    board_source: &[u8],
    manufacturing_package: &[u8],
) -> Result<FinalCplReport, String> {
    validate_board_basename(board_basename)?;
    if board_source.is_empty() || board_source.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "final CPL board must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    if manufacturing_package.is_empty() || manufacturing_package.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "final CPL manufacturing package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }

    let board_text = std::str::from_utf8(board_source)
        .map_err(|error| format!("final CPL board is not UTF-8: {error}"))?;
    let parts = manufacturing_parts(board_text)
        .map_err(|error| format!("extracting exact board manufacturing parts: {error}"))?;
    let in_pos_count = parts.iter().filter(|part| part.in_pos).count();
    if in_pos_count > FINAL_CPL_MAX_REFERENCES {
        return Err(format!(
            "final CPL board contains more than {FINAL_CPL_MAX_REFERENCES} placement references"
        ));
    }
    let in_pos_parts = parts
        .iter()
        .filter(|part| part.in_pos)
        .map(final_cpl_placement)
        .collect::<Result<Vec<_>, _>>()?;
    debug_assert!(
        in_pos_parts
            .windows(2)
            .all(|pair| pair[0].reference < pair[1].reference)
    );

    let canonical_cpl = render_canonical_cpl(&parts)
        .map_err(|error| format!("rendering exact board canonical CPL: {error:#}"))?;
    let package = validate_manufacturing_package_details(manufacturing_package)?;

    let board_identity = identity(board_source);
    let package_board_identity = FinalCplSourceIdentity {
        bytes: package.identity.input_bytes,
        sha256: package.identity.input_sha256.clone(),
    };
    let mut findings = Vec::with_capacity(FINAL_CPL_MAX_FINDINGS);
    if board_identity != package_board_identity {
        findings.push(FinalCplFinding {
            code: PACKAGE_BOARD_SOURCE_MISMATCH_CODE.into(),
            message: PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE.into(),
        });
    }
    if canonical_cpl != package.cpl_bytes {
        findings.push(FinalCplFinding {
            code: CANONICAL_CPL_MISMATCH_CODE.into(),
            message: CANONICAL_CPL_MISMATCH_MESSAGE.into(),
        });
    }
    findings.sort();

    let report = FinalCplReport {
        schema_version: FINAL_CPL_REPORT_SCHEMA_VERSION,
        scope: FINAL_CPL_SCOPE,
        engine_version: env!("CARGO_PKG_VERSION"),
        board_basename: board_basename.into(),
        sources: FinalCplSources {
            board: board_identity,
            manufacturing_package: identity(manufacturing_package),
            manifest: identity(&package.manifest_bytes),
            cpl: identity(&package.cpl_bytes),
            canonical_cpl: identity(&canonical_cpl),
            package_board_source: package_board_identity,
        },
        counts: FinalCplCounts {
            board_parts: parts.len(),
            board_in_pos_parts: in_pos_count,
            package_parts: package.manifest_parts_total,
            package_placement_parts: package.manifest_parts_placement,
            findings: findings.len(),
        },
        in_pos_parts,
        approved: findings.is_empty(),
        findings,
    };
    validate_final_cpl_report(&report)?;
    Ok(report)
}

pub(crate) fn render_final_cpl_report(report: &FinalCplReport) -> Result<Vec<u8>, String> {
    validate_final_cpl_report(report)?;
    let mut rendered = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("serializing final CPL report: {error}"))?;
    rendered.push(b'\n');
    if rendered.len() > FINAL_CPL_MAX_REPORT_BYTES {
        return Err(format!(
            "final CPL report exceeds {FINAL_CPL_MAX_REPORT_BYTES} bytes"
        ));
    }
    Ok(rendered)
}

fn final_cpl_placement(part: &ManufacturingPart) -> Result<FinalCplPlacement, String> {
    let result = FinalCplPlacement {
        reference: part.reference.clone(),
        x_nm: part.x_nm,
        y_nm: part.y_nm,
        rotation_mdeg: part.rotation_mdeg,
        layer: part.side.clone(),
    };
    validate_final_cpl_placement(&result)?;
    Ok(result)
}

fn validate_final_cpl_report(report: &FinalCplReport) -> Result<(), String> {
    if report.schema_version != FINAL_CPL_REPORT_SCHEMA_VERSION
        || report.scope != FINAL_CPL_SCOPE
        || report.engine_version != env!("CARGO_PKG_VERSION")
    {
        return Err("final CPL report version, scope, or engine is invalid".into());
    }
    validate_board_basename(&report.board_basename)?;
    for (identity, maximum, label) in [
        (&report.sources.board, MAX_PACKAGE_BYTES, "board"),
        (
            &report.sources.manufacturing_package,
            MAX_PACKAGE_BYTES,
            "manufacturing package",
        ),
        (&report.sources.manifest, MAX_MANIFEST_BYTES, "manifest"),
        (&report.sources.cpl, MAX_PACKAGE_BYTES, "CPL"),
        (
            &report.sources.canonical_cpl,
            MAX_PACKAGE_BYTES,
            "canonical CPL",
        ),
        (
            &report.sources.package_board_source,
            MAX_PACKAGE_BYTES,
            "package board source",
        ),
    ] {
        validate_identity(identity, maximum, label)?;
    }
    if report.in_pos_parts.len() > FINAL_CPL_MAX_REFERENCES
        || report.findings.len() > FINAL_CPL_MAX_FINDINGS
        || report.counts.board_parts > MAX_MANUFACTURING_PARTS
        || report.counts.package_parts > MAX_MANUFACTURING_PARTS as u64
        || report.counts.package_placement_parts > MAX_MANUFACTURING_PARTS as u64
        || report.counts.board_in_pos_parts > report.counts.board_parts
        || report.counts.package_placement_parts > report.counts.package_parts
        || report.counts.board_in_pos_parts != report.in_pos_parts.len()
        || report.counts.findings != report.findings.len()
        || report.approved != report.findings.is_empty()
    {
        return Err("final CPL report counts or approval state are inconsistent".into());
    }
    if !report
        .in_pos_parts
        .windows(2)
        .all(|pair| pair[0].reference < pair[1].reference)
        || !report.findings.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err("final CPL report records are not strictly sorted".into());
    }
    for placement in &report.in_pos_parts {
        validate_final_cpl_placement(placement)?;
    }
    for finding in &report.findings {
        if !matches!(
            (finding.code.as_str(), finding.message.as_str()),
            (CANONICAL_CPL_MISMATCH_CODE, CANONICAL_CPL_MISMATCH_MESSAGE)
                | (
                    PACKAGE_BOARD_SOURCE_MISMATCH_CODE,
                    PACKAGE_BOARD_SOURCE_MISMATCH_MESSAGE
                )
        ) {
            return Err("final CPL report contains an unsupported finding".into());
        }
    }
    let has_canonical_mismatch = report
        .findings
        .iter()
        .any(|finding| finding.code == CANONICAL_CPL_MISMATCH_CODE);
    if (report.sources.cpl == report.sources.canonical_cpl) == has_canonical_mismatch {
        return Err("final CPL canonical CPL identity/finding state is inconsistent".into());
    }
    let has_source_mismatch = report
        .findings
        .iter()
        .any(|finding| finding.code == PACKAGE_BOARD_SOURCE_MISMATCH_CODE);
    if (report.sources.board == report.sources.package_board_source) == has_source_mismatch {
        return Err("final CPL board source identity/finding state is inconsistent".into());
    }
    Ok(())
}

fn validate_board_basename(board_basename: &str) -> Result<(), String> {
    validate_manufacturing_basename(
        board_basename,
        ManufacturingLimits::production().max_name_bytes,
        "final CPL board",
    )
    .map_err(|error| error.to_string())?;
    if board_basename
        .strip_suffix(".kicad_pcb")
        .is_none_or(str::is_empty)
    {
        return Err("final CPL board name must be one portable .kicad_pcb leaf".into());
    }
    Ok(())
}

fn validate_final_cpl_placement(placement: &FinalCplPlacement) -> Result<(), String> {
    if placement.reference.is_empty()
        || placement.reference.len() > FINAL_CPL_MAX_REFERENCE_BYTES
        || placement.reference.contains('\0')
    {
        return Err(format!(
            "final CPL placement reference must contain 1 to {FINAL_CPL_MAX_REFERENCE_BYTES} safe UTF-8 bytes"
        ));
    }
    if !matches!(placement.layer.as_str(), "F" | "B") {
        return Err("final CPL placement layer is invalid".into());
    }
    Ok(())
}

fn validate_identity(
    identity: &FinalCplSourceIdentity,
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
        return Err(format!("final CPL report {label} identity is invalid"));
    }
    Ok(())
}

fn identity(source: &[u8]) -> FinalCplSourceIdentity {
    FinalCplSourceIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

pub(crate) fn final_cpl_report_json_schema() -> Value {
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
        "$id": "https://github.com/penguin425/pcbex/schema/final-cpl-report-v1.json",
        "title": "pcbex exact final CPL verification report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "scope", "engine_version", "board_basename", "sources",
            "counts", "in_pos_parts", "findings", "approved"
        ],
        "properties": {
            "schema_version": {"const": FINAL_CPL_REPORT_SCHEMA_VERSION},
            "scope": {"const": FINAL_CPL_SCOPE},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"},
            "board_basename": {"type": "string", "minLength": 11, "maxLength": 255, "pattern": "^[^\\u0000-\\u001f<>:\"/\\\\|?*]+\\.kicad_pcb$"},
            "sources": {
                "type": "object",
                "additionalProperties": false,
                "required": ["board", "manufacturing_package", "manifest", "cpl", "canonical_cpl", "package_board_source"],
                "properties": {
                    "board": identity(MAX_PACKAGE_BYTES),
                    "manufacturing_package": identity(MAX_PACKAGE_BYTES),
                    "manifest": identity(MAX_MANIFEST_BYTES),
                    "cpl": identity(MAX_PACKAGE_BYTES),
                    "canonical_cpl": identity(MAX_PACKAGE_BYTES),
                    "package_board_source": identity(MAX_PACKAGE_BYTES)
                }
            },
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["board_parts", "board_in_pos_parts", "package_parts", "package_placement_parts", "findings"],
                "properties": {
                    "board_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "board_in_pos_parts": {"type": "integer", "minimum": 0, "maximum": FINAL_CPL_MAX_REFERENCES},
                    "package_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "package_placement_parts": {"type": "integer", "minimum": 0, "maximum": MAX_MANUFACTURING_PARTS},
                    "findings": {"type": "integer", "minimum": 0, "maximum": FINAL_CPL_MAX_FINDINGS}
                }
            },
            "in_pos_parts": {
                "type": "array",
                "maxItems": FINAL_CPL_MAX_REFERENCES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["reference", "x_nm", "y_nm", "rotation_mdeg", "layer"],
                    "properties": {
                        "reference": {"type": "string", "minLength": 1, "maxLength": FINAL_CPL_MAX_REFERENCE_BYTES},
                        "x_nm": {"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX},
                        "y_nm": {"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX},
                        "rotation_mdeg": {"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX},
                        "layer": {"enum": ["F", "B"]}
                    }
                }
            },
            "findings": {
                "type": "array",
                "maxItems": FINAL_CPL_MAX_FINDINGS,
                "uniqueItems": true,
                "items": {
                    "anyOf": [
                        {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"const": CANONICAL_CPL_MISMATCH_CODE},
                                "message": {"const": CANONICAL_CPL_MISMATCH_MESSAGE}
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

    fn part(reference: &str) -> ManufacturingPart {
        ManufacturingPart {
            reference: reference.into(),
            value: "10k".into(),
            footprint: "Test:R".into(),
            x_nm: 1_250_000,
            y_nm: -2_500_000,
            rotation_mdeg: 90_125,
            side: "B".into(),
            mpn: None,
            in_bom: true,
            dnp: false,
            in_pos: true,
            smd: true,
        }
    }

    #[test]
    fn schema_is_closed_and_pins_the_two_findings() {
        let schema = final_cpl_report_json_schema();
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
            schema["properties"]["in_pos_parts"]["maxItems"],
            FINAL_CPL_MAX_REFERENCES
        );
        assert_eq!(
            schema["properties"]["findings"]["maxItems"],
            FINAL_CPL_MAX_FINDINGS
        );
    }

    #[test]
    fn placement_preserves_exact_integer_coordinates_and_bounds_reference() {
        let placement = final_cpl_placement(&part("R1")).unwrap();
        assert_eq!(placement.reference, "R1");
        assert_eq!(placement.x_nm, 1_250_000);
        assert_eq!(placement.y_nm, -2_500_000);
        assert_eq!(placement.rotation_mdeg, 90_125);
        assert_eq!(placement.layer, "B");

        let mut invalid = part("");
        assert!(final_cpl_placement(&invalid).is_err());
        invalid.reference = "x".repeat(FINAL_CPL_MAX_REFERENCE_BYTES);
        assert!(final_cpl_placement(&invalid).is_ok());
        invalid.reference = "x".repeat(FINAL_CPL_MAX_REFERENCE_BYTES + 1);
        assert!(final_cpl_placement(&invalid).is_err());
    }

    #[test]
    fn board_basename_requires_a_nonempty_portable_stem() {
        for name in [
            ".kicad_pcb",
            "CON.kicad_pcb",
            "COM¹.kicad_pcb",
            "LPT².kicad_pcb",
        ] {
            let error = verify_final_cpl_sources(name, b"board", b"package").unwrap_err();
            assert!(
                error.contains("board name") || error.contains("reserved Windows device name"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn pretty_report_uses_one_trailing_lf() {
        let source = FinalCplSourceIdentity {
            bytes: 1,
            sha256: "a".repeat(64),
        };
        let report = FinalCplReport {
            schema_version: FINAL_CPL_REPORT_SCHEMA_VERSION,
            scope: FINAL_CPL_SCOPE,
            engine_version: env!("CARGO_PKG_VERSION"),
            board_basename: "board.kicad_pcb".into(),
            sources: FinalCplSources {
                board: source.clone(),
                manufacturing_package: source.clone(),
                manifest: source.clone(),
                cpl: source.clone(),
                canonical_cpl: source.clone(),
                package_board_source: source,
            },
            counts: FinalCplCounts {
                board_parts: 1,
                board_in_pos_parts: 1,
                package_parts: 1,
                package_placement_parts: 1,
                findings: 0,
            },
            in_pos_parts: vec![final_cpl_placement(&part("R1")).unwrap()],
            findings: vec![],
            approved: true,
        };
        let rendered = render_final_cpl_report(&report).unwrap();
        assert!(rendered.ends_with(b"}\n"));
        assert!(!rendered.ends_with(b"}\n\n"));
        assert!(!rendered.contains(&b'\r'));
    }
}
