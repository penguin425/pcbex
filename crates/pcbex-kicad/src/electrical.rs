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

const RULES: [(&str, ElectricalSeverity); 12] = [
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
    format!("{:x}", Sha256::digest(bytes))
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
        assert!(junit.contains(r#"tests="12""#));
        assert!(junit.contains(r#"<failure type="electrical_error""#));
        assert!(junit.contains(r#"<skipped message="disabled by electrical policy"/>"#));
        assert!(junit.contains("unsafe &lt;rail&gt; &amp; &quot;driver&quot;"));
        assert!(junit.contains(r#"value="team&lt;&amp;&quot;&gt;""#));
        assert!(!junit.contains("unsafe <rail>"));
    }
}
