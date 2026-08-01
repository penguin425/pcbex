//! Deterministic manufacturing metadata extracted from a KiCad PCB.
//!
//! KiCad's board parser already validates the geometry used by the router.  This
//! module intentionally keeps manufacturing metadata separate from that geometry
//! model: BOM and pick-and-place files need the original absolute coordinates,
//! values, and component properties that are not part of `pcbex-core::Footprint`.

use super::{Sexp, atom, child_values, number, parse};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
    let reference = property_value(&properties, "reference")
        .or_else(|| legacy_text(xs, "reference"))
        .unwrap_or_default();
    let value = property_value(&properties, "value")
        .or_else(|| legacy_text(xs, "value"))
        .unwrap_or_default();
    let footprint = atom(xs.get(1)).unwrap_or_default().to_string();
    let at = child_values(xs, "at");
    let x = at
        .and_then(|values| number(values.get(1)))
        .ok_or_else(|| format!("footprint {reference:?} is missing a valid X coordinate"))?;
    let y = at
        .and_then(|values| number(values.get(2)))
        .ok_or_else(|| format!("footprint {reference:?} is missing a valid Y coordinate"))?;
    let rotation = at.and_then(|values| number(values.get(3))).unwrap_or(0.0);
    if !x.is_finite() || !y.is_finite() || !rotation.is_finite() {
        return Err(format!(
            "footprint {reference:?} has a non-finite placement"
        ));
    }

    let layer = child_values(xs, "layer")
        .and_then(|values| atom(values.get(1)))
        .unwrap_or("F.Cu");
    let side = if layer.starts_with("B.") { "B" } else { "F" }.to_string();
    let attrs = child_values(xs, "attr");
    let attr_tokens = attrs
        .into_iter()
        .flat_map(|values| values.iter().filter_map(|value| atom(Some(value))))
        .collect::<Vec<_>>();
    let smd = attr_tokens.contains(&"smd") || has_smd_pad(xs);
    let excluded_bom = attr_tokens.contains(&"exclude_from_bom");
    let excluded_pos = attr_tokens.contains(&"exclude_from_pos_files");
    let property_dnp = properties
        .iter()
        .find(|(name, _)| is_dnp_property(name))
        .is_some_and(|(_, value)| is_true(value));
    let dnp = attr_tokens.contains(&"dnp") || property_dnp;
    let in_bom = !excluded_bom && !dnp;
    let in_pos = !excluded_pos && !dnp && smd;
    let mpn = properties.iter().find_map(|(name, value)| {
        is_mpn_property(name)
            .then(|| (!value.trim().is_empty()).then(|| value.clone()))
            .flatten()
    });

    Ok(ManufacturingPart {
        reference,
        value,
        footprint,
        x_nm: mm_to_nm(x),
        y_nm: mm_to_nm(y),
        rotation_mdeg: mm_to_mdeg(rotation),
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
            let name = atom(values.get(1))?.trim().to_ascii_lowercase();
            let value = atom(values.get(2)).unwrap_or_default().to_string();
            Some((name, value))
        })
        .collect()
}

fn property_value(properties: &[(String, String)], name: &str) -> Option<String> {
    properties
        .iter()
        .find(|(property, _)| property == name)
        .map(|(_, value)| value.clone())
}

fn legacy_text(xs: &[Sexp], kind: &str) -> Option<String> {
    xs.iter().find_map(|item| {
        let values = item.as_list()?;
        (atom(values.first()) == Some("fp_text") && atom(values.get(1)) == Some(kind))
            .then(|| atom(values.get(2)).unwrap_or_default().to_string())
    })
}

fn has_smd_pad(xs: &[Sexp]) -> bool {
    xs.iter().any(|item| {
        let Some(values) = item.as_list() else {
            return false;
        };
        atom(values.first()) == Some("pad") && atom(values.get(2)) == Some("smd")
    })
}

fn is_mpn_property(name: &str) -> bool {
    let normalized = name.replace([' ', '_', '-', ':'], "");
    matches!(
        normalized.as_str(),
        "mpn" | "manufacturerpartnumber" | "partnumber" | "lcsc" | "jlcpcb" | "digikey"
    )
}

fn is_dnp_property(name: &str) -> bool {
    let normalized = name.replace([' ', '_', '-', ':'], "");
    matches!(normalized.as_str(), "dnp" | "donotpopulate" | "exclude")
}

fn is_true(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "dnp"
    )
}

fn mm_to_nm(value: f64) -> i64 {
    (value * 1_000_000.0)
        .round()
        .clamp(i64::MIN as f64, i64::MAX as f64) as i64
}

fn mm_to_mdeg(value: f64) -> i64 {
    (value * 1_000.0)
        .round()
        .clamp(i64::MIN as f64, i64::MAX as f64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_missing_and_duplicate_references() {
        let missing = r#"(kicad_pcb (footprint "X" (at 0 0)))"#;
        assert!(
            manufacturing_parts(missing)
                .unwrap_err()
                .contains("missing a reference")
        );
        let duplicate = r#"(kicad_pcb
          (footprint "X" (at 0 0) (fp_text reference "R1"))
          (footprint "Y" (at 1 1) (fp_text reference "R1")))"#;
        assert!(
            manufacturing_parts(duplicate)
                .unwrap_err()
                .contains("duplicate footprint reference")
        );
    }
}
