//! Closed, bounded embedded KiCad footprint sources for board construction.
//!
//! A closure contains the exact `.kicad_mod` bytes needed by one circuit.  It
//! deliberately contains no paths or library search configuration, so replay
//! does not depend on the host's KiCad installation.

use super::{CircuitSpecV2, Sexp, normalize_circuit_spec_v2, parse};
use pcbex_core::Layer;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

pub const FOOTPRINT_CLOSURE_V1_SCHEMA_VERSION: u32 = 1;
pub const FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES: u64 = 96 * 1024 * 1024;
pub const FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINTS: usize = 256;
pub const FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINT_BYTES: usize = 4 * 1024 * 1024;
pub const FOOTPRINT_CLOSURE_V1_MAX_AGGREGATE_FOOTPRINT_BYTES: usize = 64 * 1024 * 1024;
pub const FOOTPRINT_CLOSURE_V1_MAX_ID_BYTES: usize = 512;
const CLOSED_JSON_MAX_ARRAY_ITEMS: usize = FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINTS;
const CLOSED_JSON_MAX_OBJECT_KEYS: usize = 16;
pub(crate) const FOOTPRINT_CLOSURE_V1_MAX_KICAD_VERSION: u32 = 20250114;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootprintClosureV1 {
    pub schema_version: u32,
    pub footprints: Vec<FootprintClosureEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootprintClosureEntryV1 {
    /// Exact identifier used by `CircuitPartV2::footprint`.
    pub id: String,
    /// UTF-8 byte length of `source`.
    pub source_bytes: u64,
    /// Lower-case SHA-256 of the exact UTF-8 `source` bytes.
    pub source_sha256: String,
    /// Exact contents of one `.kicad_mod` file.
    pub source: String,
}

/// Parse and structurally validate a bounded footprint-closure v1 document.
///
/// Circuit-specific set and pad checks are performed by
/// [`validate_footprint_closure_v1`].
pub fn parse_footprint_closure_v1(source: &str) -> Result<FootprintClosureV1, String> {
    if source.is_empty() {
        return Err("footprint closure source must not be empty".into());
    }
    if source.len() as u64 > FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES {
        return Err(format!(
            "footprint closure source exceeds {FOOTPRINT_CLOSURE_V1_MAX_SOURCE_BYTES} bytes"
        ));
    }
    let value = parse_json_value_without_duplicate_keys(source, "footprint closure")?;
    let mut closure: FootprintClosureV1 = serde_json::from_value(value)
        .map_err(|error| format!("invalid footprint closure JSON: {error}"))?;
    validate_closure_structure(&closure)?;
    closure
        .footprints
        .sort_by(|left, right| left.id.cmp(&right.id));
    Ok(closure)
}

/// Validate exact footprint inventory and pad numbers against a circuit spec.
pub fn validate_footprint_closure_v1(
    closure: &FootprintClosureV1,
    spec: &CircuitSpecV2,
) -> Result<(), String> {
    validate_closure_structure(closure)?;
    let spec = normalize_circuit_spec_v2(spec)?;
    let expected = spec
        .parts
        .iter()
        .map(|part| part.footprint.as_str())
        .collect::<BTreeSet<_>>();
    let actual = closure
        .footprints
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "footprint closure does not exactly match the circuit footprint set (missing: {missing:?}; extra: {extra:?})"
        ));
    }

    for part in &spec.parts {
        let entry = closure
            .footprints
            .iter()
            .find(|entry| entry.id == part.footprint)
            .expect("exact footprint inventory was checked");
        let root = parse_footprint_root(entry)?;
        let actual_pads = collect_pad_numbers(
            root.as_list().expect("validated footprint root is a list"),
            &entry.id,
        )?;
        let expected_pads = part
            .pins
            .iter()
            .map(|pin| pin.number.as_str())
            .collect::<BTreeSet<_>>();
        if actual_pads != expected_pads {
            let missing = expected_pads
                .difference(&actual_pads)
                .copied()
                .collect::<Vec<_>>();
            let extra = actual_pads
                .difference(&expected_pads)
                .copied()
                .collect::<Vec<_>>();
            return Err(format!(
                "footprint {} pad numbers do not exactly match circuit part {} pins (missing: {missing:?}; extra: {extra:?})",
                entry.id, part.reference
            ));
        }
    }
    Ok(())
}

pub fn footprint_closure_v1_sha256(closure: &FootprintClosureV1) -> Result<String, String> {
    validate_closure_structure(closure)?;
    let mut normalized = closure.clone();
    normalized
        .footprints
        .sort_by(|left, right| left.id.cmp(&right.id));
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| format!("unable to serialize footprint closure: {error}"))?;
    Ok(digest_hex(&bytes))
}

pub fn footprint_closure_v1_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pcbex.dev/schemas/footprint-closure-v1.schema.json",
        "title": "pcbex footprint closure v1",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "footprints"],
        "properties": {
            "schema_version": {"const": FOOTPRINT_CLOSURE_V1_SCHEMA_VERSION},
            "footprints": {
                "type": "array",
                "minItems": 1,
                "maxItems": FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINTS,
                "items": {"$ref": "#/$defs/footprint"}
            }
        },
        "$defs": {
            "footprint": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "source_bytes", "source_sha256", "source"],
                "properties": {
                    "id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": FOOTPRINT_CLOSURE_V1_MAX_ID_BYTES,
                        "pattern": "^\\S(?:[\\s\\S]*\\S)?$"
                    },
                    "source_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINT_BYTES
                    },
                    "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "source": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINT_BYTES
                    }
                }
            }
        }
    })
}

fn validate_closure_structure(closure: &FootprintClosureV1) -> Result<(), String> {
    if closure.schema_version != FOOTPRINT_CLOSURE_V1_SCHEMA_VERSION {
        return Err(format!(
            "unsupported footprint closure schema_version {}; expected {}",
            closure.schema_version, FOOTPRINT_CLOSURE_V1_SCHEMA_VERSION
        ));
    }
    if closure.footprints.is_empty() {
        return Err("footprint closure must contain at least one footprint".into());
    }
    if closure.footprints.len() > FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINTS {
        return Err(format!(
            "footprint closure contains more than {FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINTS} footprints"
        ));
    }

    let mut ids = BTreeSet::new();
    let mut aggregate = 0usize;
    for entry in &closure.footprints {
        validate_id(&entry.id)?;
        if !ids.insert(entry.id.as_str()) {
            return Err(format!(
                "footprint closure contains duplicate footprint id {}",
                entry.id
            ));
        }
        let length = entry.source.len();
        if length == 0 {
            return Err(format!("footprint {} source must not be empty", entry.id));
        }
        if length > FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINT_BYTES {
            return Err(format!(
                "footprint {} source exceeds {FOOTPRINT_CLOSURE_V1_MAX_FOOTPRINT_BYTES} bytes",
                entry.id
            ));
        }
        if entry.source_bytes != length as u64 {
            return Err(format!(
                "footprint {} source_bytes is {}, expected {}",
                entry.id, entry.source_bytes, length
            ));
        }
        validate_sha256(&entry.source_sha256, &format!("footprint {}", entry.id))?;
        let actual_sha256 = digest_hex(entry.source.as_bytes());
        if entry.source_sha256 != actual_sha256 {
            return Err(format!(
                "footprint {} source_sha256 does not match its exact source bytes",
                entry.id
            ));
        }
        aggregate = aggregate
            .checked_add(length)
            .ok_or_else(|| "footprint closure aggregate byte count overflow".to_string())?;
        if aggregate > FOOTPRINT_CLOSURE_V1_MAX_AGGREGATE_FOOTPRINT_BYTES {
            return Err(format!(
                "footprint closure embedded sources exceed {FOOTPRINT_CLOSURE_V1_MAX_AGGREGATE_FOOTPRINT_BYTES} aggregate bytes"
            ));
        }
        let root = parse_footprint_root(entry)?;
        let values = root.as_list().expect("validated footprint root is a list");
        validate_closed_footprint_source(values, &entry.id)?;
        validate_layer_references(values, &entry.id, None)?;
        collect_pad_numbers(values, &entry.id)?;
    }
    Ok(())
}

pub(crate) fn parse_footprint_root(entry: &FootprintClosureEntryV1) -> Result<Sexp, String> {
    let root = parse(&entry.source)
        .map_err(|error| format!("invalid footprint {} source: {error}", entry.id))?;
    let values = root
        .as_list()
        .ok_or_else(|| format!("footprint {} source root must be a list", entry.id))?;
    if unquoted_atom(values.first()) != Some("footprint") {
        return Err(format!(
            "footprint {} source must contain one footprint root",
            entry.id
        ));
    }
    let root_name = scalar(values.get(1))
        .ok_or_else(|| format!("footprint {} root is missing its name", entry.id))?;
    let expected_name = entry
        .id
        .rsplit_once(':')
        .map_or(entry.id.as_str(), |(_, name)| name);
    if root_name != expected_name {
        return Err(format!(
            "footprint {} root name {root_name:?} does not match {expected_name:?}",
            entry.id
        ));
    }
    Ok(root)
}

/// Validate that every footprint layer copied by the writer exists in the
/// construction layer table.  Technical layers are fixed by the writer;
/// copper layers come from the construction profile.
pub(crate) fn validate_footprint_closure_layers(
    closure: &FootprintClosureV1,
    copper_layers: &[Layer],
) -> Result<(), String> {
    for entry in &closure.footprints {
        let root = parse_footprint_root(entry)?;
        validate_layer_references(
            root.as_list().expect("validated footprint root is a list"),
            &entry.id,
            Some(copper_layers),
        )?;
    }
    Ok(())
}

fn validate_closed_footprint_source(root: &[Sexp], id: &str) -> Result<(), String> {
    let mut version_count = 0usize;
    let mut layer_count = 0usize;
    for direct in root.iter().skip(2) {
        if let Sexp::Atom(value) | Sexp::QuotedAtom(value) = direct {
            let label = if matches!(value.as_str(), "locked" | "placed") {
                "writer-owned instance flag"
            } else {
                "unsupported root scalar"
            };
            return Err(format!("footprint {id} source contains {label} {value}"));
        }
        let values = direct
            .as_list()
            .expect("all s-expression variants were handled");
        let keyword = unquoted_atom(values.first()).ok_or_else(|| {
            format!("footprint {id} source contains a root field without an unquoted keyword")
        })?;
        if !matches!(
            keyword,
            // Library metadata accepted as input but removed/replaced.
            "version"
                | "generator"
                | "generator_version"
                | "layer"
                | "property"
                | "model"
                | "uuid"
                | "tstamp"
                | "attr"
                | "descr"
                | "tags"
                // Recognized library drawings are validated but omitted by
                // board-writer v1; only pad geometry is copied.
                | "fp_text"
                | "fp_text_box"
                | "fp_line"
                | "fp_rect"
                | "fp_circle"
                | "fp_arc"
                | "fp_poly"
                | "fp_curve"
                | "pad"
        ) {
            return Err(format!(
                "footprint {id} source contains unsupported root field {keyword}"
            ));
        }
        match keyword {
            "version" => {
                version_count += 1;
                let version = if values.len() == 2 {
                    unquoted_atom(values.get(1)).and_then(|value| value.parse::<u32>().ok())
                } else {
                    None
                }
                .ok_or_else(|| {
                    format!("footprint {id} version must contain one unquoted date code")
                })?;
                if version > FOOTPRINT_CLOSURE_V1_MAX_KICAD_VERSION {
                    return Err(format!(
                        "footprint {id} version {version} is newer than supported board dialect {FOOTPRINT_CLOSURE_V1_MAX_KICAD_VERSION}"
                    ));
                }
            }
            "layer" => {
                layer_count += 1;
                if values.len() != 2 || scalar(values.get(1)) != Some("F.Cu") {
                    return Err(format!(
                        "footprint {id} library root layer must be exactly F.Cu"
                    ));
                }
            }
            "pad" => validate_pad_record(values, id)?,
            "fp_text" => validate_direct_child_fields(
                values,
                3,
                &["at", "layer", "effects", "uuid", "tstamp"],
                id,
                keyword,
            )?,
            "fp_text_box" => validate_direct_child_fields(
                values,
                2,
                &[
                    "start", "end", "pts", "angle", "stroke", "fill", "layer", "effects", "uuid",
                    "tstamp",
                ],
                id,
                keyword,
            )?,
            "fp_line" => validate_direct_child_fields(
                values,
                1,
                &["start", "end", "stroke", "layer", "uuid", "tstamp"],
                id,
                keyword,
            )?,
            "fp_rect" => validate_direct_child_fields(
                values,
                1,
                &["start", "end", "stroke", "fill", "layer", "uuid", "tstamp"],
                id,
                keyword,
            )?,
            "fp_circle" => validate_direct_child_fields(
                values,
                1,
                &["center", "end", "stroke", "fill", "layer", "uuid", "tstamp"],
                id,
                keyword,
            )?,
            "fp_arc" => validate_direct_child_fields(
                values,
                1,
                &[
                    "start", "mid", "end", "stroke", "fill", "layer", "uuid", "tstamp",
                ],
                id,
                keyword,
            )?,
            "fp_poly" | "fp_curve" => validate_direct_child_fields(
                values,
                1,
                &["pts", "stroke", "fill", "layer", "uuid", "tstamp"],
                id,
                keyword,
            )?,
            _ => {}
        }
    }
    if version_count != 1 {
        return Err(format!(
            "footprint {id} source must contain exactly one version field"
        ));
    }
    if layer_count != 1 {
        return Err(format!(
            "footprint {id} source must contain exactly one root layer field"
        ));
    }

    // These fields can override connectivity, routing, zone behavior, or
    // project/footprint-local fabrication rules in real KiCad.  They are not
    // part of closure v1, regardless of where they are nested.
    let mut stack = vec![root];
    while let Some(values) = stack.pop() {
        let keyword = scalar(values.first()).unwrap_or("");
        if matches!(
            keyword,
            "net"
                | "net_name"
                | "net_tie_pad_groups"
                | "clearance"
                | "zone_connect"
                | "zone_connection"
                | "zone_layer_connections"
                | "thermal_width"
                | "thermal_gap"
                | "thermal_bridge_width"
                | "thermal_bridge_angle"
                | "solder_mask_margin"
                | "solder_paste_margin"
                | "solder_paste_margin_ratio"
                | "solder_paste_ratio"
                | "private_layers"
                | "remove_unused_layers"
                | "keep_end_layers"
        ) {
            return Err(format!(
                "footprint {id} source contains forbidden rule or connectivity field {keyword}"
            ));
        }
        for value in values.iter().skip(1) {
            if let Some(child) = value.as_list() {
                stack.push(child);
            }
        }
    }
    Ok(())
}

fn validate_pad_record(pad: &[Sexp], id: &str) -> Result<(), String> {
    if pad.len() < 4 {
        return Err(format!(
            "footprint {id} pad header must contain number, type, and shape"
        ));
    }
    let shape = unquoted_atom(pad.get(3))
        .ok_or_else(|| format!("footprint {id} pad shape must be unquoted"))?;
    if matches!(shape, "custom" | "trapezoid") {
        return Err(format!(
            "footprint {id} {shape} pads are not supported by closure v1"
        ));
    }
    validate_direct_child_fields(
        pad,
        4,
        &[
            "at",
            "size",
            "drill",
            "layers",
            "roundrect_rratio",
            "uuid",
            "tstamp",
        ],
        id,
        "pad",
    )?;
    for child in pad.iter().skip(4).filter_map(Sexp::as_list) {
        match unquoted_atom(child.first()).expect("pad child keywords were validated") {
            "at" => validate_numeric_tuple(child, 2, 3, false, id, "pad at")?,
            "size" => validate_numeric_tuple(child, 2, 2, true, id, "pad size")?,
            "drill" => validate_pad_drill(child, id)?,
            "roundrect_rratio" => {
                validate_numeric_tuple(child, 1, 1, true, id, "pad roundrect_rratio")?;
                let ratio = parse_kicad_decimal(child.get(1))
                    .expect("roundrect ratio was validated as numeric");
                if ratio > 0.5 {
                    return Err(format!(
                        "footprint {id} pad roundrect_rratio must not exceed 0.5"
                    ));
                }
            }
            "uuid" | "tstamp" if child.len() != 2 || scalar(child.get(1)).is_none() => {
                return Err(format!(
                    "footprint {id} pad {} metadata must contain one scalar value",
                    scalar(child.first()).unwrap_or("identity")
                ));
            }
            _ => {}
        }
    }
    for required in ["at", "size", "layers"] {
        if !pad.iter().skip(4).any(|value| {
            value
                .as_list()
                .is_some_and(|values| unquoted_atom(values.first()) == Some(required))
        }) {
            return Err(format!("footprint {id} pad is missing required {required}"));
        }
    }
    let kind = unquoted_atom(pad.get(2))
        .ok_or_else(|| format!("footprint {id} pad type must be unquoted"))?;
    let has_drill = pad.iter().skip(4).any(|value| {
        value
            .as_list()
            .is_some_and(|values| unquoted_atom(values.first()) == Some("drill"))
    });
    if matches!(kind, "thru_hole" | "np_thru_hole") != has_drill {
        return Err(format!(
            "footprint {id} pad type {kind} has an invalid drill field"
        ));
    }
    if shape == "roundrect"
        && !pad.iter().skip(4).any(|value| {
            value
                .as_list()
                .is_some_and(|values| unquoted_atom(values.first()) == Some("roundrect_rratio"))
        })
    {
        return Err(format!(
            "footprint {id} roundrect pad is missing roundrect_rratio"
        ));
    }
    Ok(())
}

fn validate_numeric_tuple(
    values: &[Sexp],
    minimum_values: usize,
    maximum_values: usize,
    positive: bool,
    id: &str,
    label: &str,
) -> Result<(), String> {
    let count = values.len().saturating_sub(1);
    if count < minimum_values || count > maximum_values {
        return Err(format!(
            "footprint {id} {label} must contain {minimum_values} to {maximum_values} numeric values"
        ));
    }
    for value in values.iter().skip(1) {
        let number = parse_kicad_decimal(Some(value)).ok_or_else(|| {
            format!("footprint {id} {label} must use unquoted canonical finite decimal numbers")
        })?;
        if positive && number <= 0.0 {
            return Err(format!("footprint {id} {label} values must be positive"));
        }
    }
    Ok(())
}

fn parse_kicad_decimal(value: Option<&Sexp>) -> Option<f64> {
    let token = unquoted_atom(value)?;
    let unsigned = token.strip_prefix('-').unwrap_or(token);
    if unsigned.is_empty()
        || unsigned
            .bytes()
            .any(|byte| matches!(byte, b'e' | b'E' | b'+'))
    {
        return None;
    }
    let mut pieces = unsigned.split('.');
    let integer = pieces.next()?;
    let fraction = pieces.next();
    if pieces.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|fraction| {
            fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    token.parse::<f64>().ok().filter(|value| value.is_finite())
}

fn validate_pad_drill(values: &[Sexp], id: &str) -> Result<(), String> {
    if values.len() == 2 {
        return validate_numeric_tuple(values, 1, 1, true, id, "pad drill");
    }
    if values.len() == 4 && unquoted_atom(values.get(1)) == Some("oval") {
        let numeric = [
            Sexp::Atom("drill".into()),
            values[2].clone(),
            values[3].clone(),
        ];
        return validate_numeric_tuple(&numeric, 2, 2, true, id, "oval pad drill");
    }
    Err(format!(
        "footprint {id} pad drill must be one diameter or oval width and height"
    ))
}

fn validate_direct_child_fields(
    values: &[Sexp],
    header_len: usize,
    allowed: &[&str],
    id: &str,
    record: &str,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for child in values.iter().skip(header_len) {
        let Some(child) = child.as_list() else {
            let scalar = unquoted_atom(Some(child)).unwrap_or("");
            if record.starts_with("fp_")
                && matches!(scalar, "hide" | "locked" | "unlocked" | "knockout")
            {
                if !seen.insert(scalar) {
                    return Err(format!(
                        "footprint {id} {record} contains duplicate scalar field {scalar}"
                    ));
                }
                continue;
            }
            return Err(format!(
                "footprint {id} {record} contains unsupported scalar field {scalar}"
            ));
        };
        let keyword = unquoted_atom(child.first())
            .ok_or_else(|| format!("footprint {id} {record} child lacks an unquoted keyword"))?;
        if !allowed.contains(&keyword) {
            return Err(format!(
                "footprint {id} {record} contains unsupported child field {keyword}"
            ));
        }
        if !seen.insert(keyword) {
            return Err(format!(
                "footprint {id} {record} contains duplicate child field {keyword}"
            ));
        }
    }
    Ok(())
}

fn validate_layer_references(
    root: &[Sexp],
    id: &str,
    copper_layers: Option<&[Layer]>,
) -> Result<(), String> {
    let mut stack = vec![root];
    while let Some(values) = stack.pop() {
        let keyword = scalar(values.first()).unwrap_or("");
        if matches!(keyword, "layer" | "layers") {
            if values.len() < 2 {
                return Err(format!(
                    "footprint {id} {keyword} field must contain at least one layer name"
                ));
            }
            let mut seen = BTreeSet::new();
            for value in values.iter().skip(1) {
                let name = scalar(Some(value)).ok_or_else(|| {
                    format!("footprint {id} {keyword} field contains a non-scalar layer name")
                })?;
                if !seen.insert(name) {
                    return Err(format!(
                        "footprint {id} {keyword} field contains duplicate layer {name}"
                    ));
                }
                validate_emitted_layer_name(name, id, copper_layers)?;
            }
        }
        for value in values.iter().skip(1) {
            if let Some(child) = value.as_list() {
                stack.push(child);
            }
        }
    }
    Ok(())
}

fn validate_emitted_layer_name(
    name: &str,
    id: &str,
    copper_layers: Option<&[Layer]>,
) -> Result<(), String> {
    if matches!(name, "*.Cu" | "*.Mask" | "F&B.Cu")
        || matches!(
            name,
            "B.Paste"
                | "F.Paste"
                | "B.SilkS"
                | "F.SilkS"
                | "B.Mask"
                | "F.Mask"
                | "B.CrtYd"
                | "F.CrtYd"
                | "B.Fab"
                | "F.Fab"
        )
    {
        return Ok(());
    }
    let layer = parse_copper_layer_name(name).ok_or_else(|| {
        format!("footprint {id} references unsupported or unrendered layer {name}")
    })?;
    if copper_layers.is_some_and(|layers| !layers.contains(&layer)) {
        return Err(format!(
            "footprint {id} references copper layer {name} absent from the construction profile"
        ));
    }
    Ok(())
}

fn parse_copper_layer_name(name: &str) -> Option<Layer> {
    match name {
        "F.Cu" => Some(Layer::Front),
        "B.Cu" => Some(Layer::Back),
        _ => {
            let index = name.strip_prefix("In")?.strip_suffix(".Cu")?.parse().ok()?;
            if !(1..=30).contains(&index) {
                None
            } else {
                let layer = Layer::Inner(index);
                (layer.name() == name).then_some(layer)
            }
        }
    }
}

fn collect_pad_numbers<'a>(root: &'a [Sexp], id: &str) -> Result<BTreeSet<&'a str>, String> {
    let mut numbers = BTreeSet::new();
    let mut direct_pad_count = 0usize;
    for value in root.iter().skip(2) {
        let Some(pad) = value.as_list() else {
            continue;
        };
        if unquoted_atom(pad.first()) != Some("pad") {
            continue;
        }
        direct_pad_count = direct_pad_count
            .checked_add(1)
            .ok_or_else(|| format!("footprint {id} pad count overflow"))?;
        if direct_pad_count > 4096 {
            return Err(format!("footprint {id} contains more than 4096 pads"));
        }
        if pad.len() < 4 {
            return Err(format!(
                "footprint {id} pad header must contain number, type, and shape"
            ));
        }
        let number = scalar(pad.get(1))
            .ok_or_else(|| format!("footprint {id} pad number must be scalar"))?;
        let kind = unquoted_atom(pad.get(2))
            .ok_or_else(|| format!("footprint {id} pad {number:?} type must be unquoted"))?;
        let shape = unquoted_atom(pad.get(3))
            .ok_or_else(|| format!("footprint {id} pad {number:?} shape must be unquoted"))?;
        if !matches!(kind, "smd" | "thru_hole" | "np_thru_hole" | "connect") {
            return Err(format!(
                "footprint {id} pad {number:?} has unsupported type {kind:?}"
            ));
        }
        if !matches!(shape, "circle" | "oval" | "rect" | "roundrect") {
            return Err(format!(
                "footprint {id} pad {number:?} has unsupported shape {shape:?}"
            ));
        }
        if number.is_empty() {
            if kind != "np_thru_hole" {
                return Err(format!(
                    "footprint {id} contains an unnumbered non-NPTH pad"
                ));
            }
            continue;
        }
        if kind == "np_thru_hole" {
            return Err(format!(
                "footprint {id} numbered pad {number} must not be NPTH"
            ));
        }
        if !numbers.insert(number) {
            return Err(format!(
                "footprint {id} contains duplicate numbered pad {number}"
            ));
        }
    }

    // A nested pad is not legal footprint syntax and must not be silently
    // ignored while checking the direct pad inventory.
    let mut all_pad_count = 0usize;
    let mut stack = vec![root];
    while let Some(values) = stack.pop() {
        for value in values.iter().skip(1) {
            let Some(child) = value.as_list() else {
                continue;
            };
            if unquoted_atom(child.first()) == Some("pad") {
                all_pad_count = all_pad_count
                    .checked_add(1)
                    .ok_or_else(|| format!("footprint {id} pad count overflow"))?;
            }
            stack.push(child);
        }
    }
    if all_pad_count != direct_pad_count {
        return Err(format!("footprint {id} contains a nested pad"));
    }
    if numbers.is_empty() {
        return Err(format!(
            "footprint {id} must contain at least one numbered electrical pad"
        ));
    }
    Ok(numbers)
}

fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > FOOTPRINT_CLOSURE_V1_MAX_ID_BYTES
        || id.trim() != id
        || id.chars().any(char::is_control)
    {
        return Err(format!(
            "footprint id must contain 1 to {FOOTPRINT_CLOSURE_V1_MAX_ID_BYTES} trimmed non-control bytes"
        ));
    }
    let name = id.rsplit_once(':').map_or(id, |(_, name)| name);
    if name.is_empty() {
        return Err(format!(
            "footprint id {id:?} has an empty library item name"
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} source_sha256 must be 64 lower-case hex characters"
        ));
    }
    Ok(())
}

fn unquoted_atom(value: Option<&Sexp>) -> Option<&str> {
    match value? {
        Sexp::Atom(value) => Some(value),
        Sexp::QuotedAtom(_) | Sexp::List(_) => None,
    }
}

pub(crate) fn scalar(value: Option<&Sexp>) -> Option<&str> {
    match value? {
        Sexp::Atom(value) | Sexp::QuotedAtom(value) => Some(value),
        Sexp::List(_) => None,
    }
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn parse_json_value_without_duplicate_keys(
    source: &str,
    label: &str,
) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = deserializer
        .deserialize_any(NoDuplicateValueVisitor)
        .map_err(|error| format!("invalid {label} JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid {label} JSON: {error}"))?;
    Ok(value)
}

struct NoDuplicateValueSeed;

impl<'de> DeserializeSeed<'de> for NoDuplicateValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateValueVisitor)
    }
}

struct NoDuplicateValueVisitor;

impl<'de> Visitor<'de> for NoDuplicateValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(NoDuplicateValueSeed)? {
            if values.len() >= CLOSED_JSON_MAX_ARRAY_ITEMS {
                return Err(de::Error::custom(format!(
                    "JSON array exceeds {CLOSED_JSON_MAX_ARRAY_ITEMS} items"
                )));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= CLOSED_JSON_MAX_OBJECT_KEYS {
                return Err(de::Error::custom(format!(
                    "JSON object exceeds {CLOSED_JSON_MAX_OBJECT_KEYS} keys"
                )));
            }
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            values.insert(key, map.next_value_seed(NoDuplicateValueSeed)?);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CircuitConnectionV2, CircuitNetV2, CircuitPartV2, CircuitPinV2, CircuitPowerV2,
        ElectricalPinType,
    };

    fn footprint_source() -> String {
        "(footprint \"Test_2Pin\" (version 20240108) (generator pcbnew)\n  (layer \"F.Cu\")\n  (property \"Reference\" \"REF**\")\n  (property \"Value\" \"Test_2Pin\")\n  (model \"${KICAD9_3DMODEL_DIR}/test.step\")\n  (pad \"1\" smd rect (at -1 0) (size 1 1) (layers \"F.Cu\" \"F.Paste\" \"F.Mask\"))\n  (pad \"2\" smd rect (at 1 0) (size 1 1) (layers \"F.Cu\" \"F.Paste\" \"F.Mask\"))\n  (pad \"\" np_thru_hole circle (at 0 2) (size 0.8 0.8) (drill 0.8) (layers \"*.Cu\" \"*.Mask\"))\n)\n".into()
    }

    fn closure(source: String) -> FootprintClosureV1 {
        FootprintClosureV1 {
            schema_version: 1,
            footprints: vec![FootprintClosureEntryV1 {
                id: "TestLib:Test_2Pin".into(),
                source_bytes: source.len() as u64,
                source_sha256: digest_hex(source.as_bytes()),
                source,
            }],
        }
    }

    fn spec() -> CircuitSpecV2 {
        CircuitSpecV2 {
            schema_version: 2,
            parts: vec![CircuitPartV2 {
                reference: "R1".into(),
                lib_id: "Device:R".into(),
                value: "1k".into(),
                footprint: "TestLib:Test_2Pin".into(),
                mpn: Some("TEST-1K".into()),
                power: CircuitPowerV2 {
                    rail_voltage_uv: None,
                    max_voltage_uv: None,
                    requires_decoupling: false,
                    decoupling: false,
                },
                pins: vec![
                    CircuitPinV2 {
                        number: "1".into(),
                        name: "1".into(),
                        net: Some("A".into()),
                        electrical_type: ElectricalPinType::Passive,
                    },
                    CircuitPinV2 {
                        number: "2".into(),
                        name: "2".into(),
                        net: Some("A".into()),
                        electrical_type: ElectricalPinType::Passive,
                    },
                ],
            }],
            nets: vec![CircuitNetV2 {
                name: "A".into(),
                voltage_uv: None,
                connections: vec![
                    CircuitConnectionV2 {
                        reference: "R1".into(),
                        pin: "1".into(),
                    },
                    CircuitConnectionV2 {
                        reference: "R1".into(),
                        pin: "2".into(),
                    },
                ],
            }],
        }
    }

    #[test]
    fn accepts_exact_closed_footprint_and_safe_unnumbered_npth() {
        let closure = closure(footprint_source());
        validate_footprint_closure_v1(&closure, &spec()).unwrap();
        assert_eq!(footprint_closure_v1_sha256(&closure).unwrap().len(), 64);
    }

    #[test]
    fn parser_rejects_duplicate_json_keys() {
        let error = parse_footprint_closure_v1(
            r#"{"schema_version":1,"schema_version":1,"footprints":[]}"#,
        )
        .unwrap_err();
        assert!(error.contains("duplicate JSON object key"));
    }

    #[test]
    fn rejects_injected_net_and_mismatched_digest() {
        let injected = footprint_source().replace("(size 1 1)", "(size 1 1) (net 7 \"ATTACK\")");
        let error = validate_footprint_closure_v1(&closure(injected), &spec()).unwrap_err();
        assert!(error.contains("net"));

        let net_tie = footprint_source().replace(
            "(layer \"F.Cu\")",
            "(layer \"F.Cu\") (net_tie_pad_groups \"1,2\")",
        );
        assert!(
            validate_footprint_closure_v1(&closure(net_tie), &spec())
                .unwrap_err()
                .contains("net_tie_pad_groups")
        );

        let mut bad_digest = closure(footprint_source());
        bad_digest.footprints[0].source_sha256 = "0".repeat(64);
        assert!(
            validate_footprint_closure_v1(&bad_digest, &spec())
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn rejects_extra_missing_duplicate_and_unsafe_unnumbered_pads() {
        let extra = footprint_source().replace(
            "(pad \"2\"",
            "(pad \"3\" smd rect (at 2 0) (size 1 1) (layers \"F.Cu\"))\n  (pad \"2\"",
        );
        assert!(
            validate_footprint_closure_v1(&closure(extra), &spec())
                .unwrap_err()
                .contains("do not exactly match")
        );

        let duplicate = footprint_source().replace("(pad \"2\"", "(pad \"1\"");
        assert!(
            validate_footprint_closure_v1(&closure(duplicate), &spec())
                .unwrap_err()
                .contains("duplicate numbered pad")
        );

        let unsafe_pad = footprint_source().replace("(pad \"\" np_thru_hole", "(pad \"\" smd");
        assert!(
            validate_footprint_closure_v1(&closure(unsafe_pad), &spec())
                .unwrap_err()
                .contains("invalid drill field")
        );
    }

    #[test]
    fn rejects_unknown_roots_and_local_rule_overrides() {
        let bogus = footprint_source().replace(
            "(layer \"F.Cu\")",
            "(layer \"F.Cu\")\n  (bogus \"accepted-by-a-private-dialect\")",
        );
        assert!(
            validate_footprint_closure_v1(&closure(bogus), &spec())
                .unwrap_err()
                .contains("unsupported root field bogus")
        );

        let clearance = footprint_source().replace("(size 1 1)", "(size 1 1) (clearance 0)");
        assert!(
            validate_footprint_closure_v1(&closure(clearance), &spec())
                .unwrap_err()
                .contains("clearance")
        );

        let bogus_pad = footprint_source().replace("(size 1 1)", "(size 1 1) (bogus 1)");
        assert!(
            validate_footprint_closure_v1(&closure(bogus_pad), &spec())
                .unwrap_err()
                .contains("pad contains unsupported child field bogus")
        );

        let nested_pinfunction =
            footprint_source().replace("(size 1 1)", "(size 1 1) (pinfunction (bogus 1))");
        assert!(
            validate_footprint_closure_v1(&closure(nested_pinfunction), &spec())
                .unwrap_err()
                .contains("pad contains unsupported child field pinfunction")
        );

        let leading_plus = footprint_source().replace("(size 1 1)", "(size +1 1)");
        assert!(
            validate_footprint_closure_v1(&closure(leading_plus), &spec())
                .unwrap_err()
                .contains("unquoted canonical finite decimal")
        );

        let quoted_number = footprint_source().replace("(size 1 1)", "(size \"1\" 1)");
        assert!(
            validate_footprint_closure_v1(&closure(quoted_number), &spec())
                .unwrap_err()
                .contains("unquoted canonical finite decimal")
        );

        let bogus_graphic = footprint_source().replace(
            "(layer \"F.Cu\")",
            "(layer \"F.Cu\")\n  (fp_rect (start 0 0) (end 1 1) (bogus 1))",
        );
        assert!(
            validate_footprint_closure_v1(&closure(bogus_graphic), &spec())
                .unwrap_err()
                .contains("fp_rect contains unsupported child field bogus")
        );
    }

    #[test]
    fn rejects_unrendered_and_construction_absent_layers() {
        let unrendered = footprint_source().replacen("\"F.Paste\"", "\"Edge.Cuts\"", 1);
        assert!(
            validate_footprint_closure_v1(&closure(unrendered), &spec())
                .unwrap_err()
                .contains("unsupported or unrendered layer Edge.Cuts")
        );

        let inner = footprint_source().replacen(
            "(layers \"F.Cu\" \"F.Paste\" \"F.Mask\")",
            "(layers \"In1.Cu\" \"F.Paste\" \"F.Mask\")",
            1,
        );
        let inner_closure = closure(inner);
        validate_footprint_closure_v1(&inner_closure, &spec()).unwrap();
        assert!(
            validate_footprint_closure_layers(&inner_closure, &[Layer::Front, Layer::Back])
                .unwrap_err()
                .contains("absent from the construction profile")
        );

        for noncanonical in ["In+1.Cu", "In01.Cu", "In001.Cu"] {
            let source = footprint_source().replacen(
                "(layers \"F.Cu\" \"F.Paste\" \"F.Mask\")",
                &format!("(layers \"{noncanonical}\" \"F.Paste\" \"F.Mask\")"),
                1,
            );
            assert!(
                validate_footprint_closure_v1(&closure(source), &spec())
                    .unwrap_err()
                    .contains("unsupported or unrendered layer")
            );
        }

        let back_root = footprint_source().replace("(layer \"F.Cu\")", "(layer \"B.Cu\")");
        assert!(
            validate_footprint_closure_v1(&closure(back_root), &spec())
                .unwrap_err()
                .contains("root layer must be exactly F.Cu")
        );
    }

    #[test]
    fn rejects_newer_footprint_dialects_and_unsupported_pad_geometry() {
        let newer = footprint_source().replace("20240108", "20251028");
        assert!(
            validate_footprint_closure_v1(&closure(newer), &spec())
                .unwrap_err()
                .contains("newer than supported board dialect")
        );

        let custom = footprint_source().replace("smd rect", "smd custom");
        assert!(
            validate_footprint_closure_v1(&closure(custom), &spec())
                .unwrap_err()
                .contains("custom pads are not supported")
        );

        let trapezoid = footprint_source().replace("smd rect", "smd trapezoid");
        assert!(
            validate_footprint_closure_v1(&closure(trapezoid), &spec())
                .unwrap_err()
                .contains("trapezoid pads are not supported")
        );
    }
}
