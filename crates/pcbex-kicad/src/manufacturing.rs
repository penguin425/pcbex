//! Deterministic manufacturing metadata extracted from a KiCad PCB.
//!
//! KiCad's board parser already validates the geometry used by the router.  This
//! module intentionally keeps manufacturing metadata separate from that geometry
//! model: BOM and pick-and-place files need the original absolute coordinates,
//! values, and component properties that are not part of `pcbex-core::Footprint`.

use super::{Sexp, atom, child_values, number, parse};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_MANUFACTURING_PARTS: usize = 100_000;

/// Return the copper and standard manufacturing layers declared by a KiCad board.
///
/// KiCad's layer table is allowed to be written in any order, and its numeric
/// copper-layer IDs changed between the legacy and current file formats. Copper
/// layers are therefore ordered by their semantic names before the fixed set of
/// factory layers is appended. The table is validated strictly because a
/// malformed layer map can otherwise cause a Gerber exporter to silently write
/// the wrong file names.
pub fn manufacturing_gerber_layers(source: &str) -> Result<Vec<String>, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad document is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_pcb") {
        return Err("expected a kicad_pcb document".into());
    }

    let tables = top.iter().filter_map(|item| {
        let values = item.as_list()?;
        (atom(values.first()) == Some("layers")).then_some(values)
    });
    let mut tables = tables;
    let Some(table) = tables.next() else {
        return Err("KiCad board is missing a layers table".into());
    };
    if tables.next().is_some() {
        return Err("KiCad board contains duplicate layers tables".into());
    }

    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut copper = Vec::new();
    for entry in table.iter().skip(1) {
        let values = entry
            .as_list()
            .ok_or_else(|| "KiCad layers table contains a non-list entry".to_string())?;
        let id = atom(values.first())
            .ok_or_else(|| "KiCad layer entry is missing a numeric ID".to_string())?
            .parse::<u16>()
            .map_err(|_| "KiCad layer entry has an invalid numeric ID".to_string())?;
        if id > u8::MAX as u16 {
            return Err(format!(
                "KiCad layer ID {id} is outside the supported range"
            ));
        }
        if !ids.insert(id) {
            return Err(format!("KiCad layers table contains duplicate ID {id}"));
        }
        let name = atom(values.get(1))
            .ok_or_else(|| format!("KiCad layer ID {id} is missing a name"))?
            .to_string();
        if name.trim().is_empty() {
            return Err(format!("KiCad layer ID {id} has an empty name"));
        }
        if !names.insert(name.clone()) {
            return Err(format!("KiCad layers table contains duplicate name {name}"));
        }
        let layer_type =
            atom(values.get(2)).ok_or_else(|| format!("KiCad layer {name} is missing a type"))?;

        if let Some(stack_order) = copper_stack_order_from_name(&name) {
            if !matches!(layer_type, "signal" | "power" | "mixed" | "jumper") {
                return Err(format!(
                    "KiCad copper layer {name} has an invalid type {layer_type}"
                ));
            }
            copper.push((stack_order, name));
        } else if looks_like_copper_layer_name(&name) {
            return Err(format!(
                "KiCad layer {name} has an invalid name for a copper layer"
            ));
        }
    }

    if !names.contains("F.Cu") || !names.contains("B.Cu") {
        return Err("KiCad layers table must declare both F.Cu and B.Cu".into());
    }

    copper.sort_unstable_by_key(|(stack_order, _)| *stack_order);
    let mut output = copper.into_iter().map(|(_, name)| name).collect::<Vec<_>>();
    for standard in [
        "F.Paste",
        "B.Paste",
        "F.Mask",
        "B.Mask",
        "F.SilkS",
        "B.SilkS",
        "Edge.Cuts",
    ] {
        if !output.iter().any(|name| name == standard) {
            output.push(standard.to_string());
        }
    }
    Ok(output)
}

fn copper_stack_order_from_name(name: &str) -> Option<u16> {
    match name {
        "F.Cu" => Some(0),
        "B.Cu" => Some(31),
        _ if name.starts_with("In") && name.ends_with(".Cu") => {
            let id = name
                .strip_prefix("In")
                .and_then(|name| name.strip_suffix(".Cu"))
                .and_then(|id| id.parse::<u16>().ok())?;
            (name == format!("In{id}.Cu") && (1..=30).contains(&id)).then_some(id)
        }
        _ => None,
    }
}

fn looks_like_copper_layer_name(name: &str) -> bool {
    matches!(name, "F.Cu" | "B.Cu") || (name.starts_with("In") && name.ends_with(".Cu"))
}

/// One footprint as it should appear in manufacturing outputs.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ManufacturingPart {
    /// Schematic reference, for example `R1` or `U3`.
    pub reference: String,
    /// KiCad value/comment used to group BOM rows.
    pub value: String,
    /// Library footprint identifier.
    pub footprint: String,
    /// Absolute board X coordinate in nanometres.
    pub x_nm: i64,
    /// Absolute board Y coordinate in nanometres.
    pub y_nm: i64,
    /// Placement rotation in milli-degrees.
    pub rotation_mdeg: i64,
    /// `F` or `B`, derived from the footprint layer.
    pub side: String,
    /// Manufacturer or distributor part number, when declared on the footprint.
    pub mpn: Option<String>,
    /// Whether this footprint is included in the BOM.
    pub in_bom: bool,
    /// Whether this footprint is marked do-not-populate.
    pub dnp: bool,
    /// Whether this footprint is eligible for a pick-and-place row.
    pub in_pos: bool,
    /// Whether KiCad identifies this as a surface-mount component.
    pub smd: bool,
}

/// Parse all top-level footprints in a KiCad PCB into stable manufacturing records.
pub fn manufacturing_parts(source: &str) -> Result<Vec<ManufacturingPart>, String> {
    manufacturing_parts_with_limit(source, MAX_MANUFACTURING_PARTS)
}

fn manufacturing_parts_with_limit(
    source: &str,
    limit: usize,
) -> Result<Vec<ManufacturingPart>, String> {
    let root = parse(source)?;
    let top = root
        .as_list()
        .ok_or_else(|| "KiCad document is not an s-expression".to_string())?;
    if atom(top.first()) != Some("kicad_pcb") {
        return Err("expected a kicad_pcb document".into());
    }

    let mut references = HashSet::new();
    let mut parts = Vec::new();
    for item in top {
        let Some(xs) = item.as_list() else { continue };
        if atom(xs.first()) != Some("footprint") {
            continue;
        }
        if parts.len() >= limit {
            return Err(format!(
                "KiCad board exceeds the {limit} manufacturing part limit"
            ));
        }
        let part = parse_footprint(xs)?;
        if part.reference.is_empty() {
            return Err("KiCad footprint is missing a reference".into());
        }
        if !references.insert(part.reference.clone()) {
            return Err(format!(
                "KiCad board contains duplicate footprint reference {}",
                part.reference
            ));
        }
        parts.push(part);
    }
    parts.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok(parts)
}

fn parse_footprint(xs: &[Sexp]) -> Result<ManufacturingPart, String> {
    let properties = footprint_properties(xs);
    let footprint = atom(xs.get(1)).unwrap_or_default().to_string();
    if footprint.trim().is_empty() {
        return Err("KiCad footprint is missing a footprint identifier".into());
    }
    let reference = resolve_property(
        &properties,
        xs,
        ManufacturingProperty::Reference,
        &footprint,
    )?
    .unwrap_or_default();
    if reference.trim().is_empty() {
        return Err(format!(
            "KiCad footprint {footprint:?} is missing a reference"
        ));
    }
    if reference.contains('?') || reference.eq_ignore_ascii_case("REF**") {
        return Err(format!(
            "KiCad footprint {footprint:?} has unannotated reference {reference:?}"
        ));
    }
    let value = resolve_property(&properties, xs, ManufacturingProperty::Value, &footprint)?
        .unwrap_or_default();
    let at = child_values(xs, "at")
        .ok_or_else(|| format!("footprint {reference:?} is missing its placement"))?;
    if !(3..=4).contains(&at.len()) {
        return Err(format!(
            "footprint {reference:?} has an invalid placement arity"
        ));
    }
    let x = at
        .get(1)
        .and_then(|value| number(Some(value)))
        .ok_or_else(|| format!("footprint {reference:?} is missing a valid X coordinate"))?;
    let y = at
        .get(2)
        .and_then(|value| number(Some(value)))
        .ok_or_else(|| format!("footprint {reference:?} is missing a valid Y coordinate"))?;
    let rotation = match at.get(3) {
        Some(value) => number(Some(value))
            .ok_or_else(|| format!("footprint {reference:?} has an invalid rotation"))?,
        None => 0.0,
    };
    if !x.is_finite() || !y.is_finite() || !rotation.is_finite() {
        return Err(format!(
            "footprint {reference:?} has a non-finite placement"
        ));
    }

    let layer = child_values(xs, "layer")
        .and_then(|values| atom(values.get(1)))
        .ok_or_else(|| format!("footprint {reference:?} is missing its board side layer"))?;
    let side = match layer {
        "F.Cu" => "F",
        "B.Cu" => "B",
        _ => {
            return Err(format!(
                "footprint {reference:?} uses unsupported placement layer {layer:?}"
            ));
        }
    }
    .to_string();
    let attrs = child_values(xs, "attr");
    let attr_tokens = attrs
        .into_iter()
        .flat_map(|values| values.iter().filter_map(|value| atom(Some(value))))
        .collect::<Vec<_>>();
    let smd = attr_tokens.contains(&"smd") || has_smd_pad(xs);
    let excluded_bom = attr_tokens.contains(&"exclude_from_bom");
    let excluded_pos = attr_tokens.contains(&"exclude_from_pos_files");
    let property_dnp = resolve_property(&properties, xs, ManufacturingProperty::Dnp, &footprint)?
        .map(|value| parse_dnp(&value, &footprint))
        .transpose()?;
    let attr_dnp = attr_tokens.contains(&"dnp");
    if property_dnp == Some(false) && attr_dnp {
        return Err(format!(
            "KiCad footprint {footprint:?} has conflicting DNP declarations"
        ));
    }
    let dnp = attr_dnp || property_dnp.unwrap_or(false);
    let in_bom = !excluded_bom && !dnp;
    if in_bom && value.trim().is_empty() {
        return Err(format!(
            "KiCad footprint {reference:?} is missing a value for BOM inclusion"
        ));
    }
    let in_pos = !excluded_pos && !dnp && smd;
    let mpn = resolve_property(&properties, xs, ManufacturingProperty::Mpn, &footprint)?
        .filter(|value| !value.trim().is_empty());

    let x_nm = mm_to_nm(x).map_err(|error| {
        format!("KiCad footprint {reference:?} has an invalid X coordinate: {error}")
    })?;
    let y_nm = mm_to_nm(y).map_err(|error| {
        format!("KiCad footprint {reference:?} has an invalid Y coordinate: {error}")
    })?;
    let rotation_mdeg = mm_to_mdeg(rotation).map_err(|error| {
        format!("KiCad footprint {reference:?} has an invalid rotation: {error}")
    })?;

    Ok(ManufacturingPart {
        reference,
        value,
        footprint,
        x_nm,
        y_nm,
        rotation_mdeg,
        side,
        mpn,
        in_bom,
        dnp,
        in_pos,
        smd,
    })
}

fn footprint_properties(xs: &[Sexp]) -> Vec<(String, String)> {
    xs.iter()
        .filter_map(|item| {
            let values = item.as_list()?;
            if atom(values.first()) != Some("property") {
                return None;
            }
            let name = atom(values.get(1))?.trim().to_string();
            let value = atom(values.get(2)).unwrap_or_default().to_string();
            Some((name, value))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManufacturingProperty {
    Reference,
    Value,
    Mpn,
    Dnp,
}

impl ManufacturingProperty {
    fn label(self) -> &'static str {
        match self {
            Self::Reference => "Reference",
            Self::Value => "Value",
            Self::Mpn => "MPN",
            Self::Dnp => "DNP",
        }
    }
}

fn resolve_property(
    properties: &[(String, String)],
    xs: &[Sexp],
    kind: ManufacturingProperty,
    footprint: &str,
) -> Result<Option<String>, String> {
    let mut candidates = properties
        .iter()
        .filter(|(name, _)| property_kind(name) == Some(kind))
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    candidates.extend(legacy_texts(xs, kind));
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => Err(format!(
            "KiCad footprint {footprint:?} has duplicate {} properties",
            kind.label()
        )),
    }
}

fn legacy_texts(xs: &[Sexp], kind: ManufacturingProperty) -> Vec<String> {
    let expected = match kind {
        ManufacturingProperty::Reference => "reference",
        ManufacturingProperty::Value => "value",
        ManufacturingProperty::Mpn | ManufacturingProperty::Dnp => return Vec::new(),
    };
    xs.iter()
        .filter_map(|item| {
            let values = item.as_list()?;
            if atom(values.first()) != Some("fp_text")
                || !atom(values.get(1)).is_some_and(|value| value.eq_ignore_ascii_case(expected))
            {
                return None;
            }
            Some(atom(values.get(2)).unwrap_or_default().to_string())
        })
        .collect()
}

fn property_kind(name: &str) -> Option<ManufacturingProperty> {
    let normalized = normalize_property_name(name);
    if normalized == "reference" {
        Some(ManufacturingProperty::Reference)
    } else if normalized == "value" {
        Some(ManufacturingProperty::Value)
    } else if is_mpn_property_normalized(&normalized) {
        Some(ManufacturingProperty::Mpn)
    } else if is_dnp_property_normalized(&normalized) {
        Some(ManufacturingProperty::Dnp)
    } else {
        None
    }
}

fn normalize_property_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn parse_dnp(value: &str, footprint: &str) -> Result<bool, String> {
    match normalize_property_name(value).as_str() {
        "1" | "yes" | "true" | "dnp" | "donotpopulate" => Ok(true),
        "0" | "no" | "false" | "optional" | "notrequired" => Ok(false),
        _ => Err(format!(
            "KiCad footprint {footprint:?} has an invalid DNP property value"
        )),
    }
}

fn is_mpn_property_normalized(normalized: &str) -> bool {
    matches!(
        normalized,
        "mpn"
            | "manufacturerpart"
            | "manufacturerpartnumber"
            | "manufacturerpartno"
            | "mfrpart"
            | "mfrpartno"
            | "mfrpartnumber"
            | "partnumber"
            | "partno"
            | "lcsc"
            | "lcscpart"
            | "lcscpartnumber"
            | "jlcpcb"
            | "jlcpcbpart"
            | "jlcpcbpartnumber"
            | "digikey"
            | "digikeypart"
            | "digikeypartnumber"
    )
}

fn is_dnp_property_normalized(normalized: &str) -> bool {
    matches!(normalized, "dnp" | "donotpopulate" | "exclude")
}

fn mm_to_nm(value: f64) -> Result<i64, &'static str> {
    checked_scaled_i64(value, 1_000_000.0)
}

fn mm_to_mdeg(value: f64) -> Result<i64, &'static str> {
    checked_scaled_i64(value, 1_000.0)
}

fn checked_scaled_i64(value: f64, scale: f64) -> Result<i64, &'static str> {
    let scaled = (value * scale).round();
    if !scaled.is_finite() {
        return Err("scaled value is non-finite");
    }
    // `i64::MAX as f64` rounds up to 2^63, so the upper bound is exclusive.
    if scaled < i64::MIN as f64 || scaled >= i64::MAX as f64 {
        return Err("scaled value is outside the i64 range");
    }
    Ok(scaled as i64)
}

fn has_smd_pad(xs: &[Sexp]) -> bool {
    xs.iter().any(|item| {
        let Some(values) = item.as_list() else {
            return false;
        };
        atom(values.first()) == Some("pad") && atom(values.get(2)) == Some("smd")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_orders_four_layer_gerber_stack() {
        let pcb = r#"(kicad_pcb
          (layers
            (2 "B.Cu" signal)
            (6 "In2.Cu" mixed)
            (44 "Edge.Cuts" user)
            (0 "F.Cu" signal)
            (4 "In1.Cu" power)))"#;
        assert_eq!(
            manufacturing_gerber_layers(pcb).unwrap(),
            [
                "F.Cu",
                "In1.Cu",
                "In2.Cu",
                "B.Cu",
                "F.Paste",
                "B.Paste",
                "F.Mask",
                "B.Mask",
                "F.SilkS",
                "B.SilkS",
                "Edge.Cuts",
            ]
        );
    }

    #[test]
    fn accepts_legacy_copper_ids_but_orders_by_semantic_layer_name() {
        let pcb = r#"(kicad_pcb
          (layers
            (4 "In2.Cu" mixed)
            (31 "B.Cu" signal)
            (0 "F.Cu" signal)
            (2 "In1.Cu" power)))"#;
        assert_eq!(
            &manufacturing_gerber_layers(pcb).unwrap()[..4],
            ["F.Cu", "In1.Cu", "In2.Cu", "B.Cu"]
        );
    }

    #[test]
    fn rejects_invalid_gerber_layer_tables() {
        let cases = [
            (
                r#"(layers (0 "F.Cu" signal) (0 "F.Cu" signal) (31 "B.Cu" signal))"#,
                "duplicate ID",
            ),
            (
                r#"(layers (0 "F.Cu" signal) (31 "B.Cu" signal) (2 "F.Cu" signal))"#,
                "duplicate name",
            ),
            (
                r#"(layers (0 "F.Cu" signal) (2 "In0.Cu" signal) (31 "B.Cu" signal))"#,
                "invalid name",
            ),
            (
                r#"(layers (0 "F.Cu" user) (31 "B.Cu" signal))"#,
                "invalid type",
            ),
            (r#"(layers (0 "F.Cu" signal))"#, "both F.Cu"),
        ];
        for (table, expected) in cases {
            let pcb = format!("(kicad_pcb {table})");
            assert!(
                manufacturing_gerber_layers(&pcb)
                    .unwrap_err()
                    .contains(expected),
                "table: {table}"
            );
        }
    }

    #[test]
    fn extracts_bom_and_placement_metadata_deterministically() {
        let pcb = r#"(kicad_pcb
          (footprint "Resistor_SMD:R_0603" (layer "F.Cu") (at 12.345678 9.876543 90)
            (property "Reference" "R2") (property "Value" "10k")
            (property "LCSC" "C25804") (attr smd)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")))
          (footprint "Capacitor_SMD:C_0603" (layer "B.Cu") (at 2 3)
            (fp_text reference "C1") (fp_text value "100nF")
            (attr smd exclude_from_bom)
            (pad "1" smd rect (at 0 0) (size 1 1) (layers "B.Cu")))
        )"#;
        let parts = manufacturing_parts(pcb).unwrap();
        assert_eq!(
            parts.iter().map(|part| &part.reference).collect::<Vec<_>>(),
            [&"C1", &"R2"]
        );
        let resistor = &parts[1];
        assert_eq!(resistor.x_nm, 12_345_678);
        assert_eq!(resistor.rotation_mdeg, 90_000);
        assert_eq!(resistor.mpn.as_deref(), Some("C25804"));
        assert!(resistor.in_bom && resistor.in_pos && resistor.smd);
        assert_eq!(parts[0].side, "B");
        assert!(!parts[0].in_bom);
    }

    #[test]
    fn enforces_manufacturing_part_limit_before_parsing_next_footprint() {
        let footprint = |reference: &str| {
            format!(
                r#"(footprint "X" (layer "F.Cu") (at 0 0)
                  (property "Reference" "{reference}") (property "Value" "10k"))"#
            )
        };
        let exact = format!("(kicad_pcb {} {})", footprint("R1"), footprint("R2"));
        assert_eq!(manufacturing_parts_with_limit(&exact, 2).unwrap().len(), 2);

        let over = format!(
            "(kicad_pcb {} {} (footprint \"malformed\"))",
            footprint("R1"),
            footprint("R2")
        );
        assert_eq!(
            manufacturing_parts_with_limit(&over, 2).unwrap_err(),
            "KiCad board exceeds the 2 manufacturing part limit"
        );
    }

    #[test]
    fn rejects_missing_and_duplicate_references() {
        let missing = r#"(kicad_pcb (footprint "X" (at 0 0)))"#;
        assert!(
            manufacturing_parts(missing)
                .unwrap_err()
                .contains("missing a reference")
        );
        let duplicate = r#"(kicad_pcb
          (footprint "X" (layer "F.Cu") (at 0 0) (fp_text reference "R1") (fp_text value "10k"))
          (footprint "Y" (layer "F.Cu") (at 1 1) (fp_text reference "R1") (fp_text value "10k")))"#;
        assert!(
            manufacturing_parts(duplicate)
                .unwrap_err()
                .contains("duplicate footprint reference")
        );
    }

    #[test]
    fn normalizes_distributor_mpn_property_names() {
        let pcb = r#"(kicad_pcb
          (footprint "X" (layer "F.Cu") (at 0 0)
            (property "Reference" "R1") (property "Value" "10k")
            (property "LCSC Part #" "C123") (attr smd))
          (footprint "Y" (layer "F.Cu") (at 1 1)
            (property "Reference" "R2") (property "Value" "10k")
            (property "JLCPCB-Part_Number" "C456") (attr smd))
          (footprint "Z" (layer "F.Cu") (at 2 2)
            (property "Reference" "R3") (property "Value" "10k")
            (property "Mfr Part #" "RC0603") (attr smd)))"#;
        let parts = manufacturing_parts(pcb).unwrap();
        assert_eq!(parts[0].mpn.as_deref(), Some("C123"));
        assert_eq!(parts[1].mpn.as_deref(), Some("C456"));
        assert_eq!(parts[2].mpn.as_deref(), Some("RC0603"));
    }

    #[test]
    fn rejects_duplicate_or_conflicting_manufacturing_properties() {
        let cases = [
            (
                r#"(property "Reference" "R1") (property "reference" "R1")"#,
                "duplicate Reference properties",
            ),
            (
                r#"(property "Value" "10k") (property "Value" "20k")"#,
                "duplicate Value properties",
            ),
            (
                r#"(property "MPN" "A") (property "LCSC Part #" "B")"#,
                "duplicate MPN properties",
            ),
            (
                r#"(property "DNP" "yes") (property "Do Not Populate" "yes")"#,
                "duplicate DNP properties",
            ),
        ];
        for (properties, expected) in cases {
            let pcb = format!(
                r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
                  (property "Reference" "R1") (property "Value" "10k") {properties}))"#
            );
            assert_eq!(
                manufacturing_parts(&pcb).unwrap_err(),
                format!("KiCad footprint \"X\" has {expected}"),
                "properties: {properties}"
            );
        }
    }

    #[test]
    fn rejects_missing_manufacturing_identifiers_and_bom_value() {
        let missing_footprint = r#"(kicad_pcb (footprint (at 0 0)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(missing_footprint)
                .unwrap_err()
                .contains("missing a footprint identifier")
        );

        let missing_value = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
          (property "Reference" "R1")))"#;
        assert!(
            manufacturing_parts(missing_value)
                .unwrap_err()
                .contains("missing a value for BOM inclusion")
        );

        let excluded_without_value = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
          (property "Reference" "R1") (attr exclude_from_bom)))"#;
        assert!(manufacturing_parts(excluded_without_value).is_ok());

        let unsupported_layer = r#"(kicad_pcb (footprint "X" (layer "F.Fab") (at 0 0)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(unsupported_layer)
                .unwrap_err()
                .contains("unsupported placement layer")
        );

        for reference in ["REF**", "R?", "#PWR?"] {
            let unannotated = format!(
                r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
                  (property "Reference" "{reference}") (property "Value" "10k")))"#
            );
            assert!(
                manufacturing_parts(&unannotated)
                    .unwrap_err()
                    .contains("unannotated reference"),
                "reference: {reference}"
            );
        }
    }

    #[test]
    fn rejects_invalid_or_out_of_range_placement_values() {
        let non_finite = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at NaN 0)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(non_finite)
                .unwrap_err()
                .contains("non-finite placement")
        );

        let coordinate_overflow = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 1e20 0)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(coordinate_overflow)
                .unwrap_err()
                .contains("invalid X coordinate")
        );

        let rotation_overflow = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0 1e20)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(rotation_overflow)
                .unwrap_err()
                .contains("invalid rotation")
        );

        let malformed_rotation = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0 nope)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(malformed_rotation)
                .unwrap_err()
                .contains("invalid rotation")
        );

        let extra_placement_token = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0 90 extra)
          (property "Reference" "R1") (property "Value" "10k")))"#;
        assert!(
            manufacturing_parts(extra_placement_token)
                .unwrap_err()
                .contains("invalid placement arity")
        );
    }

    #[test]
    fn accepts_property_only_dnp_and_rejects_explicit_false_attribute_conflict() {
        let property_only = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
          (property "Reference" "R1") (property "DNP" "yes")))"#;
        let parts = manufacturing_parts(property_only).unwrap();
        assert!(parts[0].dnp);
        assert!(!parts[0].in_bom && !parts[0].in_pos);

        let punctuation = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
          (property "Reference" "R1") (property "Value" "10k")
          (property "DNP" "not_required")))"#;
        assert!(!manufacturing_parts(punctuation).unwrap()[0].dnp);

        let conflict = r#"(kicad_pcb (footprint "X" (layer "F.Cu") (at 0 0)
          (property "Reference" "R1") (property "Value" "10k")
          (property "DNP" "no") (attr dnp)))"#;
        assert!(
            manufacturing_parts(conflict)
                .unwrap_err()
                .contains("conflicting DNP declarations")
        );
    }
}
