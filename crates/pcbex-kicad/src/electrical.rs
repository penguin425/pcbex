use super::{
    ElectricalPinType, SchematicDocument, SchematicNet, SchematicPin, SchematicPinRef,
    SchematicSymbol,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::{self, Write as _},
};

pub const RULE_COVERAGE_INCOMPLETE: &str = "coverage_incomplete";
pub const RULE_DUPLICATE_REFERENCE_UNIT: &str = "duplicate_reference_unit";
pub const RULE_UNANNOTATED_REFERENCE: &str = "unannotated_reference";
pub const RULE_MISSING_FOOTPRINT: &str = "missing_footprint";
pub const RULE_NO_CONNECT_CONNECTED: &str = "no_connect_connected";
pub const RULE_PIN_TYPE_NO_CONNECT_CONNECTED: &str = "pin_type_no_connect_connected";
pub const RULE_UNCONNECTED_PIN: &str = "unconnected_pin";
pub const RULE_MULTIPLE_OUTPUT_DRIVERS: &str = "multiple_output_drivers";
pub const RULE_MULTIPLE_POWER_OUTPUTS: &str = "multiple_power_outputs";
pub const RULE_POWER_INPUT_NOT_DRIVEN: &str = "power_input_not_driven";
pub const RULE_INPUT_NOT_DRIVEN: &str = "input_not_driven";
pub const RULE_MULTIPLE_NET_NAMES: &str = "multiple_net_names";
pub const RULE_INVALID_POWER_METADATA: &str = "invalid_power_metadata";
pub const RULE_POWER_RAIL_VOLTAGE_CONFLICT: &str = "power_rail_voltage_conflict";
pub const RULE_POWER_INPUT_VOLTAGE_EXCEEDED: &str = "power_input_voltage_exceeded";
pub const RULE_MISSING_DECOUPLING_CAPACITOR: &str = "missing_decoupling_capacitor";

const RAIL_VOLTAGE_PROPERTIES: [&str; 2] = ["pcbex:rail_voltage", "rail_voltage"];
const MAX_VOLTAGE_PROPERTIES: [&str; 4] = [
    "pcbex:max_voltage",
    "pcbex:maximum_voltage",
    "max_voltage",
    "maximum_voltage",
];
const BOOLEAN_POWER_PROPERTIES: [&str; 2] = ["pcbex:requires_decoupling", "pcbex:decoupling"];

const RULES: [(&str, ElectricalSeverity); 16] = [
    (RULE_COVERAGE_INCOMPLETE, ElectricalSeverity::Error),
    (RULE_DUPLICATE_REFERENCE_UNIT, ElectricalSeverity::Error),
    (RULE_UNANNOTATED_REFERENCE, ElectricalSeverity::Error),
    (RULE_MISSING_FOOTPRINT, ElectricalSeverity::Warning),
    (RULE_NO_CONNECT_CONNECTED, ElectricalSeverity::Error),
    (
        RULE_PIN_TYPE_NO_CONNECT_CONNECTED,
        ElectricalSeverity::Error,
    ),
    (RULE_UNCONNECTED_PIN, ElectricalSeverity::Warning),
    (RULE_MULTIPLE_OUTPUT_DRIVERS, ElectricalSeverity::Error),
    (RULE_MULTIPLE_POWER_OUTPUTS, ElectricalSeverity::Error),
    (RULE_POWER_INPUT_NOT_DRIVEN, ElectricalSeverity::Error),
    (RULE_INPUT_NOT_DRIVEN, ElectricalSeverity::Warning),
    (RULE_MULTIPLE_NET_NAMES, ElectricalSeverity::Warning),
    (RULE_INVALID_POWER_METADATA, ElectricalSeverity::Error),
    (RULE_POWER_RAIL_VOLTAGE_CONFLICT, ElectricalSeverity::Error),
    (RULE_POWER_INPUT_VOLTAGE_EXCEEDED, ElectricalSeverity::Error),
    (RULE_MISSING_DECOUPLING_CAPACITOR, ElectricalSeverity::Error),
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElectricalSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalRulePolicy {
    pub enabled: bool,
    pub severity: ElectricalSeverity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalPolicy {
    pub schema_version: u32,
    pub id: String,
    #[serde(deserialize_with = "deserialize_rules")]
    pub rules: BTreeMap<String, ElectricalRulePolicy>,
}

impl Default for ElectricalPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            id: "pcbex-default-v1".into(),
            rules: RULES
                .into_iter()
                .map(|(id, severity)| {
                    (
                        id.to_string(),
                        ElectricalRulePolicy {
                            enabled: true,
                            severity,
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalSymbolRef {
    pub uuid: String,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalFinding {
    pub id: String,
    pub rule: String,
    pub severity: ElectricalSeverity,
    pub message: String,
    pub net_id: Option<u32>,
    pub symbols: Vec<ElectricalSymbolRef>,
    pub pins: Vec<SchematicPinRef>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalFindingCounts {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalReview {
    pub schema_version: u32,
    pub schematic_sha256: String,
    pub policy_sha256: String,
    pub policy_id: String,
    pub approved: bool,
    pub counts: ElectricalFindingCounts,
    pub findings: Vec<ElectricalFinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalRuleExplanation {
    pub id: String,
    pub enabled: bool,
    pub severity: ElectricalSeverity,
    pub title: String,
    pub purpose: String,
    pub trigger: String,
    pub remediation: String,
    pub finding_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalExplanationReport {
    pub schema_version: u32,
    pub schematic_sha256: String,
    pub policy_sha256: String,
    pub policy_id: String,
    pub rules: Vec<ElectricalRuleExplanation>,
}

struct PinContext<'a> {
    symbol: &'a SchematicSymbol,
    pin: &'a SchematicPin,
    pin_ref: SchematicPinRef,
}

fn deserialize_rules<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ElectricalRulePolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct RuleMapVisitor;

    impl<'de> serde::de::Visitor<'de> for RuleMapVisitor {
        type Value = BTreeMap<String, ElectricalRulePolicy>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object containing unique electrical rule identifiers")
        }

        fn visit_map<A>(self, mut values: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut rules = BTreeMap::new();
            while let Some((id, policy)) = values.next_entry::<String, ElectricalRulePolicy>()? {
                if rules.insert(id.clone(), policy).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate electrical rule {id}"
                    )));
                }
            }
            Ok(rules)
        }
    }

    deserializer.deserialize_map(RuleMapVisitor)
}

pub fn parse_electrical_policy(source: &str) -> Result<ElectricalPolicy, String> {
    let policy: ElectricalPolicy = serde_json::from_str(source)
        .map_err(|error| format!("invalid electrical policy: {error}"))?;
    effective_policy(&policy)
}

pub fn check_schematic(
    schematic: &SchematicDocument,
    policy: &ElectricalPolicy,
) -> Result<ElectricalReview, String> {
    if schematic.schema_version != 1 {
        return Err(format!(
            "unsupported schematic IR schema version {}",
            schematic.schema_version
        ));
    }
    let policy = effective_policy(policy)?;
    let schematic_bytes = serde_json::to_vec(schematic)
        .map_err(|error| format!("serializing schematic IR: {error}"))?;
    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|error| format!("serializing electrical policy: {error}"))?;
    let mut findings = Vec::new();
    let pin_contexts = pin_contexts(schematic);
    let by_net = pins_by_net(&pin_contexts);

    if !schematic.coverage.complete {
        add_finding(
            &mut findings,
            &policy,
            RULE_COVERAGE_INCOMPLETE,
            format!(
                "schematic coverage is incomplete: {}",
                schematic
                    .coverage
                    .unsupported_features
                    .iter()
                    .map(|feature| format!("{} ({})", feature.kind, feature.count))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None,
            Vec::new(),
            Vec::new(),
        );
    }

    check_symbols(schematic, &policy, &mut findings);
    for net in &schematic.nets {
        check_net(
            net,
            by_net.get(&net.id).map(Vec::as_slice).unwrap_or_default(),
            &policy,
            &mut findings,
        );
    }
    check_power_safety(schematic, &by_net, &policy, &mut findings);

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.rule.cmp(&right.rule))
            .then_with(|| left.net_id.cmp(&right.net_id))
            .then_with(|| left.id.cmp(&right.id))
    });
    let counts = ElectricalFindingCounts {
        errors: findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Error)
            .count(),
        warnings: findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Warning)
            .count(),
        info: findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Info)
            .count(),
    };
    Ok(ElectricalReview {
        schema_version: 1,
        schematic_sha256: hex_digest(&schematic_bytes),
        policy_sha256: hex_digest(&policy_bytes),
        policy_id: policy.id,
        approved: counts.errors == 0,
        counts,
        findings,
    })
}

pub fn explain_electrical_review(
    review: &ElectricalReview,
    policy: &ElectricalPolicy,
) -> Result<ElectricalExplanationReport, String> {
    if review.schema_version != 1 {
        return Err(format!(
            "unsupported electrical review schema version {}",
            review.schema_version
        ));
    }
    let policy = effective_policy(policy)?;
    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|error| format!("serializing electrical policy: {error}"))?;
    let policy_sha256 = hex_digest(&policy_bytes);
    if review.policy_id != policy.id || review.policy_sha256 != policy_sha256 {
        return Err("electrical review does not match the effective policy".into());
    }
    let rules = RULES
        .iter()
        .map(|(id, _)| {
            let setting = policy
                .rules
                .get(*id)
                .expect("effective policy contains every built-in rule");
            let (title, purpose, trigger, remediation) = rule_explanation(id);
            ElectricalRuleExplanation {
                id: (*id).to_string(),
                enabled: setting.enabled,
                severity: setting.severity,
                title: title.into(),
                purpose: purpose.into(),
                trigger: trigger.into(),
                remediation: remediation.into(),
                finding_ids: review
                    .findings
                    .iter()
                    .filter(|finding| finding.rule == *id)
                    .map(|finding| finding.id.clone())
                    .collect(),
            }
        })
        .collect();
    Ok(ElectricalExplanationReport {
        schema_version: 1,
        schematic_sha256: review.schematic_sha256.clone(),
        policy_sha256,
        policy_id: policy.id,
        rules,
    })
}

pub fn electrical_review_to_junit(
    review: &ElectricalReview,
    policy: &ElectricalPolicy,
) -> Result<String, String> {
    let explanations = explain_electrical_review(review, policy)?;
    let failures = explanations
        .rules
        .iter()
        .filter(|rule| {
            rule.finding_ids.iter().any(|id| {
                review.findings.iter().any(|finding| {
                    finding.id == *id && finding.severity == ElectricalSeverity::Error
                })
            })
        })
        .count();
    let skipped = explanations
        .rules
        .iter()
        .filter(|rule| !rule.enabled)
        .count();
    let mut xml = String::new();
    writeln!(xml, r#"<?xml version="1.0" encoding="UTF-8"?>"#).unwrap();
    writeln!(
        xml,
        r#"<testsuites name="pcbex electrical review" tests="{}" failures="{failures}" errors="0" skipped="{skipped}">"#,
        explanations.rules.len()
    )
    .unwrap();
    writeln!(
        xml,
        r#"  <testsuite name="pcbex electrical rules" tests="{}" failures="{failures}" errors="0" skipped="{skipped}">"#,
        explanations.rules.len()
    )
    .unwrap();
    writeln!(xml, "    <properties>").unwrap();
    for (name, value) in [
        ("pcbex.schema_version", review.schema_version.to_string()),
        ("pcbex.schematic_sha256", review.schematic_sha256.clone()),
        ("pcbex.policy_sha256", review.policy_sha256.clone()),
        ("pcbex.policy_id", review.policy_id.clone()),
        ("pcbex.approved", review.approved.to_string()),
    ] {
        writeln!(
            xml,
            r#"      <property name="{}" value="{}"/>"#,
            xml_escape(name),
            xml_escape(&value)
        )
        .unwrap();
    }
    writeln!(xml, "    </properties>").unwrap();

    for rule in &explanations.rules {
        writeln!(
            xml,
            r#"    <testcase classname="pcbex.electrical" name="{}">"#,
            xml_escape(&rule.id)
        )
        .unwrap();
        if !rule.enabled {
            writeln!(
                xml,
                r#"      <skipped message="disabled by electrical policy"/>"#
            )
            .unwrap();
        } else {
            let findings = review
                .findings
                .iter()
                .filter(|finding| finding.rule == rule.id)
                .collect::<Vec<_>>();
            let errors = findings
                .iter()
                .filter(|finding| finding.severity == ElectricalSeverity::Error)
                .copied()
                .collect::<Vec<_>>();
            if !errors.is_empty() {
                writeln!(
                    xml,
                    r#"      <failure type="electrical_error" message="{} error finding(s)">"#,
                    errors.len()
                )
                .unwrap();
                for finding in errors {
                    writeln!(
                        xml,
                        "        {}: {}",
                        xml_escape(&finding.id),
                        xml_escape(&finding.message)
                    )
                    .unwrap();
                }
                writeln!(xml, "      </failure>").unwrap();
            }
            let advisory = findings
                .iter()
                .filter(|finding| finding.severity != ElectricalSeverity::Error)
                .copied()
                .collect::<Vec<_>>();
            if !advisory.is_empty() {
                writeln!(xml, "      <system-out>").unwrap();
                for finding in advisory {
                    writeln!(
                        xml,
                        "        {:?} {}: {}",
                        finding.severity,
                        xml_escape(&finding.id),
                        xml_escape(&finding.message)
                    )
                    .unwrap();
                }
                writeln!(xml, "      </system-out>").unwrap();
            }
        }
        writeln!(xml, "    </testcase>").unwrap();
    }
    writeln!(xml, "  </testsuite>").unwrap();
    writeln!(xml, "</testsuites>").unwrap();
    Ok(xml)
}

pub fn electrical_review_to_sarif(
    review: &ElectricalReview,
    policy: &ElectricalPolicy,
    artifact_uri: &str,
) -> Result<Value, String> {
    if artifact_uri.trim().is_empty() {
        return Err("electrical SARIF artifact URI must not be blank".into());
    }
    let explanations = explain_electrical_review(review, policy)?;
    let rules = explanations
        .rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.purpose},
                "help": {
                    "text": format!(
                        "Trigger: {}\n\nRemediation: {}",
                        rule.trigger, rule.remediation
                    )
                },
                "defaultConfiguration": {
                    "enabled": rule.enabled,
                    "level": sarif_level(rule.severity)
                },
                "properties": {
                    "tags": ["hardware", "schematic", "electrical"]
                }
            })
        })
        .collect::<Vec<_>>();
    let mut findings = review.findings.iter().collect::<Vec<_>>();
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    let results = findings
        .into_iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule,
                "level": sarif_level(finding.severity),
                "message": {"text": finding.message},
                "partialFingerprints": {
                    "pcbexElectricalFinding/v1": finding.id
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri}
                    }
                }],
                "properties": {
                    "findingId": finding.id,
                    "netId": finding.net_id,
                    "symbols": finding.symbols,
                    "pins": finding.pins
                }
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pcbex check-schematic",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/penguin425/pcbex",
                    "rules": rules
                }
            },
            "automationDetails": {
                "id": format!("pcbex/electrical/{}/", review.policy_id)
            },
            "properties": {
                "schemaVersion": review.schema_version,
                "schematicSha256": review.schematic_sha256,
                "policySha256": review.policy_sha256,
                "policyId": review.policy_id,
                "approved": review.approved
            },
            "results": results
        }]
    }))
}

fn sarif_level(severity: ElectricalSeverity) -> &'static str {
    match severity {
        ElectricalSeverity::Info => "note",
        ElectricalSeverity::Warning => "warning",
        ElectricalSeverity::Error => "error",
    }
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn rule_explanation(rule: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match rule {
        RULE_COVERAGE_INCOMPLETE => (
            "Incomplete schematic coverage",
            "Prevent approval when unsupported KiCad constructs could hide electrical intent.",
            "The normalized schematic reports one or more unsupported features.",
            "Remove the unsupported construct or use a pcbex version that imports it completely.",
        ),
        RULE_DUPLICATE_REFERENCE_UNIT => (
            "Duplicate reference unit",
            "Keep each annotated multi-unit symbol identity unambiguous.",
            "More than one symbol uses the same reference designator and unit number.",
            "Re-annotate the duplicate or assign the correct unit number.",
        ),
        RULE_UNANNOTATED_REFERENCE => (
            "Unannotated reference",
            "Ensure every fitted component has a stable design identity.",
            "A non-DNP symbol reference still contains a question mark.",
            "Run schematic annotation and verify references before approval.",
        ),
        RULE_MISSING_FOOTPRINT => (
            "Missing footprint",
            "Ensure each on-board component can be transferred into PCB layout.",
            "A fitted on-board symbol has no footprint assignment.",
            "Assign a verified footprint or mark the symbol as off-board or DNP.",
        ),
        RULE_NO_CONNECT_CONNECTED => (
            "Connected no-connect marker",
            "Prevent intentional no-connect declarations from masking real connectivity.",
            "A pin marked no-connect belongs to an electrical net.",
            "Remove the no-connect marker or disconnect the pin from the net.",
        ),
        RULE_PIN_TYPE_NO_CONNECT_CONNECTED => (
            "Connected no-connect pin type",
            "Keep library-declared no-connect pins electrically isolated.",
            "A library pin with no-connect electrical type belongs to a net.",
            "Correct the symbol pin type or remove the electrical connection.",
        ),
        RULE_UNCONNECTED_PIN => (
            "Unmarked unconnected pin",
            "Require unused pins to be explicitly reviewed instead of silently floating.",
            "A pin has no peer connection and is not marked no-connect.",
            "Connect the pin or add an intentional no-connect marker.",
        ),
        RULE_MULTIPLE_OUTPUT_DRIVERS => (
            "Multiple output drivers",
            "Prevent ordinary actively driven outputs from contending on one net.",
            "A net contains more than one output pin.",
            "Separate the outputs or use a topology and pin types that explicitly permit sharing.",
        ),
        RULE_MULTIPLE_POWER_OUTPUTS => (
            "Multiple power outputs",
            "Prevent independent power sources from being shorted together.",
            "A net contains more than one power-output pin.",
            "Separate the rails or document the intended power-sharing topology with corrected symbols.",
        ),
        RULE_POWER_INPUT_NOT_DRIVEN => (
            "Undriven power input",
            "Ensure every power-input pin has an identified source.",
            "A net has power-input pins but no power-output pin.",
            "Connect a valid source or correct the source pin electrical type.",
        ),
        RULE_INPUT_NOT_DRIVEN => (
            "Undriven signal input",
            "Detect signal inputs that have no active driver.",
            "A net has input pins but no output or bidirectional driver.",
            "Connect a driver, add the required bias network, or correct pin electrical types.",
        ),
        RULE_MULTIPLE_NET_NAMES => (
            "Multiple net names",
            "Prevent aliasing from hiding accidental net merges.",
            "One electrical net resolves to more than one distinct label.",
            "Use one canonical name or split connections that should be separate.",
        ),
        RULE_INVALID_POWER_METADATA => (
            "Invalid power metadata",
            "Fail closed when explicit power-safety metadata is malformed or contradictory.",
            "A power voltage is invalid, aliases conflict, or a boolean marker is unrecognized.",
            "Use one supported voltage per property group and a documented boolean value.",
        ),
        RULE_POWER_RAIL_VOLTAGE_CONFLICT => (
            "Conflicting power-rail voltages",
            "Prevent rails with different nominal voltages from being shorted together.",
            "One net has labels or metadata that resolve to more than one voltage.",
            "Split the rails or correct the power-symbol and rail-voltage metadata.",
        ),
        RULE_POWER_INPUT_VOLTAGE_EXCEEDED => (
            "Power-input voltage rating exceeded",
            "Prevent a rail from exceeding a component's declared maximum input voltage.",
            "A power-input pin declares pcbex:max_voltage below its connected rail voltage.",
            "Use a compatible rail, add level conversion, or correct the component rating.",
        ),
        RULE_MISSING_DECOUPLING_CAPACITOR => (
            "Missing power decoupling capacitor",
            "Require a local bypass capacitor for explicitly marked power-sensitive devices.",
            "A pcbex:requires_decoupling symbol has a power-input net without a capacitor.",
            "Place a capacitor on the same power net and mark the part as decoupling.",
        ),
        _ => unreachable!("all effective electrical rules have explanations"),
    }
}

fn effective_policy(policy: &ElectricalPolicy) -> Result<ElectricalPolicy, String> {
    if policy.schema_version != 1 {
        return Err(format!(
            "unsupported electrical policy schema version {}",
            policy.schema_version
        ));
    }
    if policy.id.trim().is_empty() {
        return Err("electrical policy id must not be blank".into());
    }
    let known = RULES.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
    if let Some(unknown) = policy.rules.keys().find(|id| !known.contains(id.as_str())) {
        return Err(format!("unknown electrical rule {unknown}"));
    }
    let mut effective = ElectricalPolicy::default();
    effective.id.clone_from(&policy.id);
    effective.rules.extend(policy.rules.clone());
    Ok(effective)
}

fn pin_contexts(schematic: &SchematicDocument) -> Vec<PinContext<'_>> {
    schematic
        .symbols
        .iter()
        .filter(|symbol| !symbol.dnp)
        .flat_map(|symbol| {
            symbol.pins.iter().map(move |pin| PinContext {
                symbol,
                pin,
                pin_ref: SchematicPinRef {
                    symbol_uuid: symbol.uuid.clone(),
                    reference: symbol.reference.clone(),
                    unit: symbol.unit,
                    number: pin.number.clone(),
                },
            })
        })
        .collect()
}

fn pins_by_net<'a>(contexts: &'a [PinContext<'a>]) -> HashMap<u32, Vec<&'a PinContext<'a>>> {
    let mut result = HashMap::<u32, Vec<&PinContext<'_>>>::new();
    for context in contexts {
        result.entry(context.pin.net_id).or_default().push(context);
    }
    result
}

fn check_symbols(
    schematic: &SchematicDocument,
    policy: &ElectricalPolicy,
    findings: &mut Vec<ElectricalFinding>,
) {
    let mut reference_units = BTreeMap::<(&str, u32), Vec<&SchematicSymbol>>::new();
    for symbol in schematic.symbols.iter().filter(|symbol| !symbol.dnp) {
        reference_units
            .entry((&symbol.reference, symbol.unit))
            .or_default()
            .push(symbol);
        if symbol.reference.contains('?') {
            add_finding(
                findings,
                policy,
                RULE_UNANNOTATED_REFERENCE,
                format!("symbol {} is not annotated", symbol.reference),
                None,
                vec![symbol_ref(symbol)],
                Vec::new(),
            );
        }
        if symbol.on_board
            && !symbol.reference.starts_with('#')
            && symbol.footprint.as_deref().is_none_or(str::is_empty)
        {
            add_finding(
                findings,
                policy,
                RULE_MISSING_FOOTPRINT,
                format!("symbol {} has no footprint", symbol.reference),
                None,
                vec![symbol_ref(symbol)],
                Vec::new(),
            );
        }
    }
    for ((reference, unit), symbols) in reference_units {
        if symbols.len() > 1 {
            add_finding(
                findings,
                policy,
                RULE_DUPLICATE_REFERENCE_UNIT,
                format!(
                    "reference {reference} unit {unit} is used by {} symbols",
                    symbols.len()
                ),
                None,
                symbols.into_iter().map(symbol_ref).collect(),
                Vec::new(),
            );
        }
    }
}

fn check_net(
    net: &SchematicNet,
    contexts: &[&PinContext<'_>],
    policy: &ElectricalPolicy,
    findings: &mut Vec<ElectricalFinding>,
) {
    let connected = contexts.len() > 1 || !net.labels.is_empty() || net.points.len() > 1;
    let all_pins = || contexts.iter().map(|value| value.pin_ref.clone()).collect();
    let all_symbols = || {
        contexts
            .iter()
            .map(|value| symbol_ref(value.symbol))
            .collect()
    };

    for context in contexts {
        if context.pin.no_connect && connected {
            add_finding(
                findings,
                policy,
                RULE_NO_CONNECT_CONNECTED,
                format!(
                    "{} pin {} has a no-connect marker but is electrically connected",
                    context.symbol.reference, context.pin.number
                ),
                Some(net.id),
                vec![symbol_ref(context.symbol)],
                vec![context.pin_ref.clone()],
            );
        }
        if context.pin.electrical_type == ElectricalPinType::NoConnect && connected {
            add_finding(
                findings,
                policy,
                RULE_PIN_TYPE_NO_CONNECT_CONNECTED,
                format!(
                    "{} pin {} is typed no-connect but is electrically connected",
                    context.symbol.reference, context.pin.number
                ),
                Some(net.id),
                vec![symbol_ref(context.symbol)],
                vec![context.pin_ref.clone()],
            );
        }
        if !connected
            && !context.pin.no_connect
            && !matches!(
                context.pin.electrical_type,
                ElectricalPinType::Free | ElectricalPinType::NoConnect
            )
        {
            add_finding(
                findings,
                policy,
                RULE_UNCONNECTED_PIN,
                format!(
                    "{} pin {} ({}) is unconnected without a no-connect marker",
                    context.symbol.reference, context.pin.number, context.pin.name
                ),
                Some(net.id),
                vec![symbol_ref(context.symbol)],
                vec![context.pin_ref.clone()],
            );
        }
    }

    let outputs = contexts
        .iter()
        .filter(|context| context.pin.electrical_type == ElectricalPinType::Output)
        .collect::<Vec<_>>();
    if outputs.len() > 1 {
        add_finding(
            findings,
            policy,
            RULE_MULTIPLE_OUTPUT_DRIVERS,
            format!(
                "net {} has {} push-pull output drivers",
                net.name,
                outputs.len()
            ),
            Some(net.id),
            outputs
                .iter()
                .map(|context| symbol_ref(context.symbol))
                .collect(),
            outputs
                .iter()
                .map(|context| context.pin_ref.clone())
                .collect(),
        );
    }

    let power_outputs = contexts
        .iter()
        .filter(|context| context.pin.electrical_type == ElectricalPinType::PowerOutput)
        .collect::<Vec<_>>();
    if power_outputs.len() > 1 {
        add_finding(
            findings,
            policy,
            RULE_MULTIPLE_POWER_OUTPUTS,
            format!(
                "net {} has {} power-output drivers",
                net.name,
                power_outputs.len()
            ),
            Some(net.id),
            power_outputs
                .iter()
                .map(|context| symbol_ref(context.symbol))
                .collect(),
            power_outputs
                .iter()
                .map(|context| context.pin_ref.clone())
                .collect(),
        );
    }

    let has_power_input = contexts
        .iter()
        .any(|context| context.pin.electrical_type == ElectricalPinType::PowerInput);
    if has_power_input && power_outputs.is_empty() {
        add_finding(
            findings,
            policy,
            RULE_POWER_INPUT_NOT_DRIVEN,
            format!(
                "net {} has power-input pins but no power-output driver",
                net.name
            ),
            Some(net.id),
            all_symbols(),
            all_pins(),
        );
    }

    let has_input = contexts
        .iter()
        .any(|context| context.pin.electrical_type == ElectricalPinType::Input);
    let has_signal_driver = contexts.iter().any(|context| {
        matches!(
            context.pin.electrical_type,
            ElectricalPinType::Output
                | ElectricalPinType::Bidirectional
                | ElectricalPinType::TriState
                | ElectricalPinType::OpenCollector
                | ElectricalPinType::OpenEmitter
        )
    });
    if has_input && !has_signal_driver {
        add_finding(
            findings,
            policy,
            RULE_INPUT_NOT_DRIVEN,
            format!("net {} has input pins but no signal driver", net.name),
            Some(net.id),
            all_symbols(),
            all_pins(),
        );
    }

    if net.labels.len() > 1 {
        add_finding(
            findings,
            policy,
            RULE_MULTIPLE_NET_NAMES,
            format!(
                "net {} has multiple electrical names: {}",
                net.name,
                net.labels.join(", ")
            ),
            Some(net.id),
            all_symbols(),
            all_pins(),
        );
    }
}

fn check_power_safety(
    schematic: &SchematicDocument,
    by_net: &HashMap<u32, Vec<&PinContext<'_>>>,
    policy: &ElectricalPolicy,
    findings: &mut Vec<ElectricalFinding>,
) {
    for symbol in schematic.symbols.iter().filter(|symbol| !symbol.dnp) {
        let invalid = invalid_power_metadata(symbol);
        if !invalid.is_empty() {
            add_finding(
                findings,
                policy,
                RULE_INVALID_POWER_METADATA,
                format!(
                    "{} has invalid or conflicting power metadata: {}",
                    symbol.reference,
                    invalid.join(", ")
                ),
                None,
                vec![symbol_ref(symbol)],
                Vec::new(),
            );
        }
    }

    for net in &schematic.nets {
        let contexts = by_net.get(&net.id).map(Vec::as_slice).unwrap_or_default();
        let mut voltages = voltage_hints(&net.name);
        for label in &net.labels {
            voltages.extend(voltage_hints(label));
        }
        for context in contexts
            .iter()
            .filter(|context| context.pin.electrical_type == ElectricalPinType::PowerOutput)
        {
            for key in RAIL_VOLTAGE_PROPERTIES {
                if let Some(value) = property(context.symbol, key)
                    && let Some(voltage) = parse_voltage_uv(value)
                {
                    voltages.push(voltage);
                }
            }
        }
        voltages.sort_unstable();
        voltages.dedup();
        if voltages.len() > 1 {
            add_finding(
                findings,
                policy,
                RULE_POWER_RAIL_VOLTAGE_CONFLICT,
                format!(
                    "net {} has conflicting rail voltages: {}",
                    net.name,
                    voltages
                        .iter()
                        .map(|voltage| format_voltage_uv(*voltage))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Some(net.id),
                contexts
                    .iter()
                    .map(|context| symbol_ref(context.symbol))
                    .collect(),
                contexts
                    .iter()
                    .map(|context| context.pin_ref.clone())
                    .collect(),
            );
        }
        let power_inputs = contexts
            .iter()
            .filter(|context| context.pin.electrical_type == ElectricalPinType::PowerInput)
            .copied()
            .collect::<Vec<_>>();
        let decoupling_symbols = contexts
            .iter()
            .filter(|context| is_decoupling_capacitor(context.symbol))
            .map(|context| context.symbol.uuid.as_str())
            .collect::<BTreeSet<_>>();
        let mut power_inputs_by_symbol = BTreeMap::<&str, Vec<&PinContext<'_>>>::new();
        for context in &power_inputs {
            power_inputs_by_symbol
                .entry(context.symbol.uuid.as_str())
                .or_default()
                .push(context);
        }
        for inputs in power_inputs_by_symbol.values() {
            let context = inputs[0];
            let has_external_decoupling = decoupling_symbols.len() > 1
                || decoupling_symbols
                    .first()
                    .is_some_and(|uuid| *uuid != context.symbol.uuid);
            if property_truthy(context.symbol, "pcbex:requires_decoupling")
                && !has_external_decoupling
            {
                add_finding(
                    findings,
                    policy,
                    RULE_MISSING_DECOUPLING_CAPACITOR,
                    format!(
                        "{} on net {} requires a decoupling capacitor",
                        context.symbol.reference, net.name
                    ),
                    Some(net.id),
                    vec![symbol_ref(context.symbol)],
                    inputs
                        .iter()
                        .map(|candidate| candidate.pin_ref.clone())
                        .collect(),
                );
            }
        }
        let Some(rail_voltage) = voltages.iter().copied().max() else {
            continue;
        };
        for context in power_inputs {
            for key in MAX_VOLTAGE_PROPERTIES {
                let Some(value) = property(context.symbol, key) else {
                    continue;
                };
                let Some(max_voltage) = parse_voltage_uv(value) else {
                    continue;
                };
                if rail_voltage > max_voltage {
                    add_finding(
                        findings,
                        policy,
                        RULE_POWER_INPUT_VOLTAGE_EXCEEDED,
                        format!(
                            "{} pin {} is rated for at most {}, but net {} is {}",
                            context.symbol.reference,
                            context.pin.number,
                            format_voltage_uv(max_voltage),
                            net.name,
                            format_voltage_uv(rail_voltage)
                        ),
                        Some(net.id),
                        vec![symbol_ref(context.symbol)],
                        vec![context.pin_ref.clone()],
                    );
                }
                break;
            }
        }
    }
}

fn invalid_power_metadata(symbol: &SchematicSymbol) -> Vec<String> {
    let mut invalid = BTreeSet::new();
    for keys in [
        RAIL_VOLTAGE_PROPERTIES.as_slice(),
        MAX_VOLTAGE_PROPERTIES.as_slice(),
    ] {
        let mut parsed = BTreeSet::new();
        let mut matched = Vec::new();
        for (name, value) in &symbol.properties {
            if keys.iter().any(|key| name.eq_ignore_ascii_case(key)) {
                matched.push(name.as_str());
                match parse_voltage_uv(value) {
                    Some(voltage) => {
                        parsed.insert(voltage);
                    }
                    None => {
                        invalid.insert(name.clone());
                    }
                }
            }
        }
        if parsed.len() > 1 {
            invalid.extend(matched.into_iter().map(str::to_string));
        }
    }
    let rail_properties = symbol
        .properties
        .keys()
        .filter(|name| {
            RAIL_VOLTAGE_PROPERTIES
                .iter()
                .any(|key| name.eq_ignore_ascii_case(key))
        })
        .collect::<Vec<_>>();
    let power_output_nets = symbol
        .pins
        .iter()
        .filter(|pin| pin.electrical_type == ElectricalPinType::PowerOutput)
        .map(|pin| pin.net_id)
        .collect::<BTreeSet<_>>();
    if !rail_properties.is_empty() && power_output_nets.len() != 1 {
        invalid.extend(rail_properties.into_iter().cloned());
    }
    for key in BOOLEAN_POWER_PROPERTIES {
        let mut parsed = BTreeSet::new();
        let mut matched = Vec::new();
        for (name, value) in &symbol.properties {
            if name.eq_ignore_ascii_case(key) {
                matched.push(name.as_str());
                match parse_power_boolean(value) {
                    Some(value) => {
                        parsed.insert(value);
                    }
                    None => {
                        invalid.insert(name.clone());
                    }
                }
            }
        }
        if parsed.len() > 1 {
            invalid.extend(matched.into_iter().map(str::to_string));
        }
    }
    invalid.into_iter().collect()
}

fn property<'a>(symbol: &'a SchematicSymbol, wanted: &str) -> Option<&'a str> {
    symbol
        .properties
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str())
}

fn parse_power_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "required" => Some(true),
        "0" | "false" | "no" | "optional" | "not_required" | "not-required" => Some(false),
        _ => None,
    }
}

fn property_truthy(symbol: &SchematicSymbol, key: &str) -> bool {
    property(symbol, key).and_then(parse_power_boolean) == Some(true)
}

fn is_decoupling_capacitor(symbol: &SchematicSymbol) -> bool {
    let lib_id = symbol.lib_id.to_ascii_lowercase();
    let value = symbol.value.to_ascii_lowercase();
    (symbol.reference.starts_with('C')
        || lib_id.ends_with(":c")
        || lib_id.contains("capacitor")
        || value.contains("cap"))
        && property(symbol, "pcbex:decoupling")
            .is_none_or(|value| parse_power_boolean(value) == Some(true))
}

fn voltage_hints(name: &str) -> Vec<i64> {
    let mut values = Vec::new();
    let mut token = String::new();
    let mut characters = name.chars().peekable();
    while let Some(character) = characters.next() {
        let signed_number_start = matches!(character, '-' | '+')
            && characters.peek().is_some_and(|next| next.is_ascii_digit());
        if signed_number_start {
            append_voltage_hints(&token, &mut values);
            token.clear();
            token.push(character);
        } else if character.is_ascii_alphanumeric() || character == '.' {
            token.push(character);
        } else {
            append_voltage_hints(&token, &mut values);
            token.clear();
        }
    }
    append_voltage_hints(&token, &mut values);
    values
}

fn append_voltage_hints(token: &str, values: &mut Vec<i64>) {
    if token.is_empty() {
        return;
    }
    if let Some(value) = parse_voltage_uv(token) {
        values.push(value);
    }
    let upper = token.to_ascii_uppercase();
    for prefix in ["AVCC", "AVDD", "VCC", "VDD"] {
        if let Some(suffix) = upper.strip_prefix(prefix)
            && let Some(value) = parse_voltage_uv(suffix)
        {
            values.push(value);
        }
    }
}

fn parse_voltage_uv(value: &str) -> Option<i64> {
    let mut text = value.trim().to_ascii_uppercase();
    if text.starts_with('+') {
        text.remove(0);
    }
    if text.is_empty() {
        return None;
    }
    let scale = if text.ends_with("MV") {
        text.truncate(text.len() - 2);
        1_000_i64
    } else if text.ends_with('V') {
        text.truncate(text.len() - 1);
        1_000_000_i64
    } else {
        let index = text.find('V')?;
        if index == 0 || index + 1 == text.len() {
            return None;
        }
        text.replace_range(index..=index, ".");
        1_000_000_i64
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((text.as_str(), ""));
    if whole.is_empty() || !whole.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    if fraction.len() > 6 || !fraction.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    let whole = whole.parse::<i64>().ok()?.checked_mul(scale)?;
    let mut fraction_value = fraction.parse::<i64>().unwrap_or(0);
    for _ in fraction.len()..6 {
        fraction_value = fraction_value.checked_mul(10)?;
    }
    let fraction_uv = fraction_value.checked_mul(scale)?.checked_div(1_000_000)?;
    whole.checked_add(fraction_uv)
}

fn format_voltage_uv(value: i64) -> String {
    if value % 1_000_000 == 0 {
        format!("{}V", value / 1_000_000)
    } else {
        let whole = value / 1_000_000;
        let fraction = format!("{:06}", value % 1_000_000)
            .trim_end_matches('0')
            .to_string();
        format!("{whole}.{fraction}V")
    }
}

#[allow(clippy::too_many_arguments)]
fn add_finding(
    findings: &mut Vec<ElectricalFinding>,
    policy: &ElectricalPolicy,
    rule: &str,
    message: String,
    net_id: Option<u32>,
    mut symbols: Vec<ElectricalSymbolRef>,
    mut pins: Vec<SchematicPinRef>,
) {
    let Some(setting) = policy.rules.get(rule).filter(|setting| setting.enabled) else {
        return;
    };
    symbols.sort_by(|left, right| {
        left.reference
            .cmp(&right.reference)
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
    symbols.dedup();
    pins.sort();
    pins.dedup();
    let identity = serde_json::to_vec(&(rule, net_id, &symbols, &pins))
        .expect("electrical finding identity is serializable");
    findings.push(ElectricalFinding {
        id: format!("pcbex-er-{}", &hex_digest(&identity)[..16]),
        rule: rule.into(),
        severity: setting.severity,
        message,
        net_id,
        symbols,
        pins,
    });
}

fn symbol_ref(symbol: &SchematicSymbol) -> ElectricalSymbolRef {
    ElectricalSymbolRef {
        uuid: symbol.uuid.clone(),
        reference: symbol.reference.clone(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn electrical_policy_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-policy-v1.json",
        "title": "pcbex electrical approval policy",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "id", "rules"],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1},
            "rules": {
                "type": "object",
                "propertyNames": {"enum": RULES.map(|(id, _)| id)},
                "additionalProperties": {"$ref": "#/$defs/rule"}
            }
        },
        "$defs": {
            "rule": {
                "type": "object",
                "additionalProperties": false,
                "required": ["enabled", "severity"],
                "properties": {
                    "enabled": {"type": "boolean"},
                    "severity": {"enum": ["info", "warning", "error"]}
                }
            }
        }
    })
}

pub fn electrical_review_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-review-v1.json",
        "title": "pcbex deterministic electrical review",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "schematic_sha256", "policy_sha256", "policy_id",
            "approved", "counts", "findings"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_id": {"type": "string", "minLength": 1},
            "approved": {"type": "boolean"},
            "counts": {"$ref": "#/$defs/counts"},
            "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}}
        },
        "$defs": {
            "symbol": {
                "type": "object",
                "additionalProperties": false,
                "required": ["uuid", "reference"],
                "properties": {
                    "uuid": {"type": "string", "minLength": 1},
                    "reference": {"type": "string", "minLength": 1}
                }
            },
            "pin": {
                "type": "object",
                "additionalProperties": false,
                "required": ["symbol_uuid", "reference", "unit", "number"],
                "properties": {
                    "symbol_uuid": {"type": "string", "minLength": 1},
                    "reference": {"type": "string", "minLength": 1},
                    "unit": {"type": "integer", "minimum": 1},
                    "number": {"type": "string", "minLength": 1}
                }
            },
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": ["errors", "warnings", "info"],
                "properties": {
                    "errors": {"type": "integer", "minimum": 0},
                    "warnings": {"type": "integer", "minimum": 0},
                    "info": {"type": "integer", "minimum": 0}
                }
            },
            "finding": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "id", "rule", "severity", "message", "net_id", "symbols", "pins"
                ],
                "properties": {
                    "id": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"},
                    "rule": {"enum": RULES.map(|(id, _)| id)},
                    "severity": {"enum": ["info", "warning", "error"]},
                    "message": {"type": "string", "minLength": 1},
                    "net_id": {"type": ["integer", "null"], "minimum": 1},
                    "symbols": {"type": "array", "items": {"$ref": "#/$defs/symbol"}},
                    "pins": {"type": "array", "items": {"$ref": "#/$defs/pin"}}
                }
            }
        }
    })
}

pub fn electrical_explanation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-explanation-v1.json",
        "title": "pcbex electrical rule explanation report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "schematic_sha256", "policy_sha256", "policy_id", "rules"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_id": {"type": "string", "minLength": 1},
            "rules": {
                "type": "array",
                "minItems": RULES.len(),
                "maxItems": RULES.len(),
                "items": {"$ref": "#/$defs/rule"}
            }
        },
        "$defs": {
            "rule": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "id", "enabled", "severity", "title", "purpose", "trigger",
                    "remediation", "finding_ids"
                ],
                "properties": {
                    "id": {"enum": RULES.map(|(id, _)| id)},
                    "enabled": {"type": "boolean"},
                    "severity": {"enum": ["info", "warning", "error"]},
                    "title": {"type": "string", "minLength": 1},
                    "purpose": {"type": "string", "minLength": 1},
                    "trigger": {"type": "string", "minLength": 1},
                    "remediation": {"type": "string", "minLength": 1},
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"}
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SchematicUnsupportedFeature, import_schematic};

    const SOURCE: &str = include_str!("../../../examples/simple.kicad_sch");

    fn rules(schematic: &SchematicDocument) -> BTreeSet<String> {
        check_schematic(schematic, &ElectricalPolicy::default())
            .unwrap()
            .findings
            .into_iter()
            .map(|finding| finding.rule)
            .collect()
    }

    #[test]
    fn default_review_is_deterministic_and_rejects_unpowered_input() {
        let schematic = import_schematic(SOURCE).unwrap();
        let first = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let second = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        assert_eq!(first, second);
        assert!(!first.approved);
        assert!(first.counts.errors > 0);
        assert!(
            first
                .findings
                .iter()
                .any(|finding| finding.rule == RULE_POWER_INPUT_NOT_DRIVEN)
        );
    }

    #[test]
    fn policy_can_demote_or_disable_rules() {
        let schematic = import_schematic(SOURCE).unwrap();
        let mut policy = ElectricalPolicy::default();
        for setting in policy.rules.values_mut() {
            if setting.severity == ElectricalSeverity::Error {
                setting.enabled = false;
            }
        }
        let report = check_schematic(&schematic, &policy).unwrap();
        assert!(report.approved);
        assert_eq!(report.counts.errors, 0);
    }

    #[test]
    fn policy_rejects_unknown_fields_rules_and_versions() {
        assert!(parse_electrical_policy(r#"{"schema_version":1,"id":"x","extra":1}"#).is_err());
        assert!(
            parse_electrical_policy(
                r#"{"schema_version":1,"id":"x","rules":{"imaginary":{"enabled":true,"severity":"error"}}}"#
            )
            .is_err()
        );
        assert!(parse_electrical_policy(r#"{"schema_version":2,"id":"x","rules":{}}"#).is_err());
        assert!(
            parse_electrical_policy(
                r#"{"schema_version":1,"id":"x","rules":{"input_not_driven":{"enabled":true,"severity":"error"},"input_not_driven":{"enabled":false,"severity":"info"}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn checks_symbol_identity_annotation_footprint_and_coverage() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        schematic.coverage.complete = false;
        schematic
            .coverage
            .unsupported_features
            .push(SchematicUnsupportedFeature {
                kind: "sheet".into(),
                count: 1,
            });
        schematic.symbols[0].reference = "R?".into();
        schematic.symbols[0].footprint = None;
        let mut duplicate = schematic.symbols[0].clone();
        duplicate.uuid = "duplicate-reference-unit".into();
        schematic.symbols.push(duplicate);

        let detected = rules(&schematic);
        for expected in [
            RULE_COVERAGE_INCOMPLETE,
            RULE_DUPLICATE_REFERENCE_UNIT,
            RULE_UNANNOTATED_REFERENCE,
            RULE_MISSING_FOOTPRINT,
        ] {
            assert!(detected.contains(expected), "missing rule {expected}");
        }
    }

    #[test]
    fn checks_no_connects_driver_conflicts_and_net_aliases() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let signal_net = schematic
            .nets
            .iter_mut()
            .find(|net| net.name == "SIGNAL")
            .unwrap();
        signal_net.labels.push("SIGNAL_ALIAS".into());
        {
            let resistor = schematic
                .symbols
                .iter_mut()
                .find(|symbol| symbol.reference == "R1")
                .unwrap();
            resistor.pins[0].electrical_type = ElectricalPinType::Output;
            resistor.pins[0].no_connect = true;
        }
        let detected = rules(&schematic);
        for expected in [
            RULE_NO_CONNECT_CONNECTED,
            RULE_MULTIPLE_OUTPUT_DRIVERS,
            RULE_MULTIPLE_NET_NAMES,
        ] {
            assert!(detected.contains(expected), "missing rule {expected}");
        }

        let resistor = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "R1")
            .unwrap();
        resistor.pins[0].no_connect = false;
        resistor.pins[0].electrical_type = ElectricalPinType::NoConnect;
        assert!(rules(&schematic).contains(RULE_PIN_TYPE_NO_CONNECT_CONNECTED));
    }

    #[test]
    fn checks_unconnected_undriven_and_power_driver_rules() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let resistor = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "R1")
            .unwrap();
        resistor.pins[1].no_connect = false;
        let signal_net_id = resistor.pins[0].net_id;
        resistor.pins[0].electrical_type = ElectricalPinType::Input;
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .pins
            .iter_mut()
            .find(|pin| pin.net_id == signal_net_id)
            .unwrap()
            .electrical_type = ElectricalPinType::Passive;
        let detected = rules(&schematic);
        for expected in [
            RULE_UNCONNECTED_PIN,
            RULE_INPUT_NOT_DRIVEN,
            RULE_POWER_INPUT_NOT_DRIVEN,
        ] {
            assert!(detected.contains(expected), "missing rule {expected}");
        }

        let signal_pins = schematic
            .symbols
            .iter_mut()
            .flat_map(|symbol| symbol.pins.iter_mut())
            .filter(|pin| pin.net_id == signal_net_id)
            .collect::<Vec<_>>();
        for pin in signal_pins {
            pin.electrical_type = ElectricalPinType::PowerOutput;
        }
        assert!(rules(&schematic).contains(RULE_MULTIPLE_POWER_OUTPUTS));
    }

    #[test]
    fn checks_power_rail_conflicts_voltage_ratings_and_decoupling() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let power_net = schematic
            .nets
            .iter_mut()
            .find(|net| net.name == "VCC")
            .unwrap();
        power_net.name = "VCC_5V".into();
        power_net.labels.push("VCC_3V3".into());
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:max_voltage".into(), "3.3V".into());
        controller
            .properties
            .insert("pcbex:requires_decoupling".into(), "true".into());

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let detected = report
            .findings
            .iter()
            .map(|finding| finding.rule.as_str())
            .collect::<BTreeSet<_>>();
        assert!(detected.contains(RULE_POWER_RAIL_VOLTAGE_CONFLICT));
        assert!(detected.contains(RULE_POWER_INPUT_VOLTAGE_EXCEEDED));
        assert!(detected.contains(RULE_MISSING_DECOUPLING_CAPACITOR));
    }

    #[test]
    fn invalid_power_metadata_fails_closed_once_per_symbol() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        for (name, value) in [
            ("pcbex:rail_voltage", "-5V"),
            ("pcbex:max_voltage", "3.3V"),
            ("maximum_voltage", "5V"),
            ("pcbex:requires_decoupling", "mandatory"),
            ("pcbex:decoupling", "maybe"),
        ] {
            controller.properties.insert(name.into(), value.into());
        }

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RULE_INVALID_POWER_METADATA)
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        assert!(!report.approved);
        for property in [
            "pcbex:rail_voltage",
            "pcbex:max_voltage",
            "maximum_voltage",
            "pcbex:requires_decoupling",
            "pcbex:decoupling",
        ] {
            assert!(findings[0].message.contains(property));
        }
    }

    #[test]
    fn valid_false_power_metadata_is_not_rejected() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:requires_decoupling".into(), "false".into());
        controller
            .properties
            .insert("pcbex:decoupling".into(), "no".into());
        controller
            .properties
            .insert("pcbex:max_voltage".into(), "5V".into());

        assert!(!rules(&schematic).contains(RULE_INVALID_POWER_METADATA));
    }

    #[test]
    fn rail_voltage_metadata_requires_one_power_output_net() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:rail_voltage".into(), "5V".into());
        assert!(rules(&schematic).contains(RULE_INVALID_POWER_METADATA));

        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .pins
            .iter_mut()
            .find(|pin| pin.electrical_type == ElectricalPinType::Output)
            .unwrap()
            .electrical_type = ElectricalPinType::PowerOutput;
        assert!(!rules(&schematic).contains(RULE_INVALID_POWER_METADATA));

        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .pins
            .iter_mut()
            .find(|pin| pin.electrical_type == ElectricalPinType::PowerInput)
            .unwrap()
            .electrical_type = ElectricalPinType::PowerOutput;
        assert!(rules(&schematic).contains(RULE_INVALID_POWER_METADATA));
    }

    #[test]
    fn rail_voltage_metadata_applies_only_to_power_outputs() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let power_net = schematic
            .nets
            .iter_mut()
            .find(|net| net.name == "VCC")
            .unwrap();
        power_net.name = "VCC_12V".into();
        let power_net_id = power_net.id;
        let signal_net = schematic
            .nets
            .iter_mut()
            .find(|net| net.name == "SIGNAL")
            .unwrap();
        signal_net.name = "VOUT_3V3".into();
        let signal_net_id = signal_net.id;
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:rail_voltage".into(), "5V".into());
        controller
            .pins
            .iter_mut()
            .find(|pin| pin.net_id == signal_net_id)
            .unwrap()
            .electrical_type = ElectricalPinType::PowerOutput;

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let conflict_nets = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RULE_POWER_RAIL_VOLTAGE_CONFLICT)
            .filter_map(|finding| finding.net_id)
            .collect::<BTreeSet<_>>();
        assert!(conflict_nets.contains(&signal_net_id));
        assert!(!conflict_nets.contains(&power_net_id));
    }

    #[test]
    fn power_rail_conflict_is_reported_without_connected_pins() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        schematic.nets.push(SchematicNet {
            id: 99,
            name: "5V".into(),
            labels: vec!["3V3".into()],
            pins: Vec::new(),
            points: Vec::new(),
        });

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule == RULE_POWER_RAIL_VOLTAGE_CONFLICT
                && finding.net_id == Some(99)
                && finding.symbols.is_empty()
                && finding.pins.is_empty()
        }));
    }

    #[test]
    fn missing_decoupling_is_reported_without_known_rail_voltage() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let power_net = schematic
            .nets
            .iter_mut()
            .find(|net| net.name == "VCC")
            .unwrap();
        power_net.name = "POWER".into();
        power_net.labels.clear();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:requires_decoupling".into(), "true".into());

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.rule == RULE_MISSING_DECOUPLING_CAPACITOR)
                .count(),
            1
        );
    }

    #[test]
    fn missing_decoupling_is_deduplicated_per_symbol_and_net() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:requires_decoupling".into(), "true".into());
        let mut duplicate_power_pin = controller
            .pins
            .iter()
            .find(|pin| pin.electrical_type == ElectricalPinType::PowerInput)
            .unwrap()
            .clone();
        duplicate_power_pin.uuid = Some("pin-u1-power-duplicate".into());
        duplicate_power_pin.number = "3".into();
        controller.pins.push(duplicate_power_pin);
        let controller_uuid = controller.uuid.clone();

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RULE_MISSING_DECOUPLING_CAPACITOR)
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0]
                .pins
                .iter()
                .filter(|pin| pin.symbol_uuid == controller_uuid)
                .count(),
            2
        );
    }

    #[test]
    fn missing_decoupling_has_unique_findings_per_symbol_and_net() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        let controller = schematic
            .symbols
            .iter_mut()
            .find(|symbol| symbol.reference == "U1")
            .unwrap();
        controller
            .properties
            .insert("pcbex:requires_decoupling".into(), "true".into());
        let mut second_controller = controller.clone();
        second_controller.uuid = "symbol-u2".into();
        second_controller.reference = "U2".into();
        for (index, pin) in second_controller.pins.iter_mut().enumerate() {
            pin.uuid = Some(format!("pin-u2-{index}"));
        }
        schematic.symbols.push(second_controller);

        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RULE_MISSING_DECOUPLING_CAPACITOR)
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        assert!(findings.iter().all(|finding| finding.symbols.len() == 1));
    }

    #[test]
    fn power_voltage_parser_handles_common_rail_notations() {
        assert_eq!(parse_voltage_uv("5V"), Some(5_000_000));
        assert_eq!(parse_voltage_uv("+5V"), Some(5_000_000));
        assert_eq!(parse_voltage_uv("3V3"), Some(3_300_000));
        assert_eq!(parse_voltage_uv("3300mV"), Some(3_300_000));
        assert_eq!(voltage_hints("VCC_1V8"), vec![1_800_000]);
        assert_eq!(voltage_hints("VCC_3.3V"), vec![3_300_000]);
        assert_eq!(voltage_hints("3.3V"), vec![3_300_000]);
        assert_eq!(voltage_hints("+5V"), vec![5_000_000]);
        assert_eq!(voltage_hints("VCC_+5V"), vec![5_000_000]);
        assert!(voltage_hints("-5V").is_empty());
        assert!(voltage_hints("VEE_-5V").is_empty());
        assert!(voltage_hints("VCC-5V").is_empty());
        assert!(voltage_hints("POWER-5V").is_empty());
    }

    #[test]
    fn power_voltage_parser_handles_decimal_millivolts() {
        assert_eq!(parse_voltage_uv("3.3mV"), Some(3_300));
        assert_eq!(parse_voltage_uv("0.5mV"), Some(500));
        assert_eq!(parse_voltage_uv("3.333333mV"), Some(3_333));
    }

    #[test]
    fn dnp_symbols_do_not_create_findings() {
        let mut schematic = import_schematic(SOURCE).unwrap();
        for symbol in &mut schematic.symbols {
            symbol.dnp = true;
            symbol.reference = "U?".into();
            symbol.footprint = None;
        }
        let report = check_schematic(&schematic, &ElectricalPolicy::default()).unwrap();
        assert!(report.approved);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn schemas_close_every_declared_object() {
        for schema in [
            electrical_policy_json_schema(),
            electrical_review_json_schema(),
            electrical_explanation_json_schema(),
        ] {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            for definition in schema["$defs"].as_object().unwrap().values() {
                if definition["type"] == "object" {
                    assert_eq!(definition["additionalProperties"], false);
                }
            }
        }
    }

    #[test]
    fn explanations_bind_every_rule_to_the_review_and_effective_policy() {
        let schematic = import_schematic(SOURCE).unwrap();
        let mut policy = ElectricalPolicy::default();
        policy
            .rules
            .get_mut(RULE_INPUT_NOT_DRIVEN)
            .unwrap()
            .severity = ElectricalSeverity::Error;
        let review = check_schematic(&schematic, &policy).unwrap();
        let explanations = explain_electrical_review(&review, &policy).unwrap();
        assert_eq!(explanations.schema_version, 1);
        assert_eq!(explanations.schematic_sha256, review.schematic_sha256);
        assert_eq!(explanations.policy_sha256, review.policy_sha256);
        assert_eq!(explanations.rules.len(), RULES.len());
        let input = explanations
            .rules
            .iter()
            .find(|explanation| explanation.id == RULE_INPUT_NOT_DRIVEN)
            .unwrap();
        assert_eq!(input.severity, ElectricalSeverity::Error);
        assert!(!input.purpose.is_empty());
        assert_eq!(
            input.finding_ids,
            review
                .findings
                .iter()
                .filter(|finding| finding.rule == RULE_INPUT_NOT_DRIVEN)
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>()
        );

        let mismatched = ElectricalPolicy {
            id: "different-policy".into(),
            ..ElectricalPolicy::default()
        };
        assert!(explain_electrical_review(&review, &mismatched).is_err());
    }

    #[test]
    fn junit_maps_rule_outcomes_and_escapes_untrusted_text() {
        let schematic = import_schematic(SOURCE).unwrap();
        let mut policy = ElectricalPolicy::default();
        policy
            .rules
            .get_mut(RULE_MISSING_FOOTPRINT)
            .unwrap()
            .enabled = false;
        let mut review = check_schematic(&schematic, &policy).unwrap();
        review.policy_id = r#"team<&">"#.into();
        policy.id = review.policy_id.clone();
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        review.policy_sha256 = hex_digest(&policy_bytes);
        review.findings[0].message = r#"unsafe <rail> & "driver""#.into();
        let junit = electrical_review_to_junit(&review, &policy).unwrap();
        assert!(junit.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(junit.contains(r#"tests="16""#));
        assert!(junit.contains(r#"<failure type="electrical_error""#));
        assert!(junit.contains(r#"<skipped message="disabled by electrical policy"/>"#));
        assert!(junit.contains("unsafe &lt;rail&gt; &amp; &quot;driver&quot;"));
        assert!(junit.contains(r#"value="team&lt;&amp;&quot;&gt;""#));
        assert!(!junit.contains("unsafe <rail>"));
    }

    #[test]
    fn sarif_binds_rules_findings_and_schematic_identity() {
        let schematic = import_schematic(SOURCE).unwrap();
        let mut policy = ElectricalPolicy::default();
        for rule in policy.rules.values_mut() {
            rule.severity = ElectricalSeverity::Warning;
        }
        let review = check_schematic(&schematic, &policy).unwrap();
        let sarif =
            electrical_review_to_sarif(&review, &policy, "hardware/design.kicad_sch").unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            RULES.len()
        );
        assert_eq!(
            sarif["runs"][0]["properties"]["schematicSha256"],
            review.schematic_sha256
        );
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), review.findings.len());
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "hardware/design.kicad_sch"
        );
        assert!(results.iter().all(|result| {
            result["partialFingerprints"]["pcbexElectricalFinding/v1"]
                .as_str()
                .is_some_and(|value| value.starts_with("pcbex-er-"))
        }));
        assert!(results.iter().any(|result| result["level"] == "warning"));
        assert!(electrical_review_to_sarif(&review, &policy, " ").is_err());
        assert!(
            electrical_review_to_sarif(&review, &ElectricalPolicy::default(), "design.kicad_sch")
                .is_err()
        );
    }
}
