//! Deterministic, schematic-bound firmware source bundle generation.
//!
//! This module deliberately keeps the generated bundle small and boring.  The
//! source files are generated from the canonical schematic IR, then the local
//! C, C++, and Python toolchains are invoked without a shell.  Tool failures
//! are evidence in the manifest rather than errors from the generator: callers
//! decide whether a bundle with failed (or skipped) checks is acceptable.

use crate::bounded_process::{ProcessLimits, run_bounded};
use anyhow::{Context, Result, bail};
use pcbex_kicad::{SchematicDocument, SchematicSymbol};
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, MapAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[path = "firmware_build.rs"]
mod firmware_build;

#[allow(unused_imports)]
pub(crate) use firmware_build::{
    FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES, FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES,
    FRESH_FIRMWARE_BUILD_REPORT_SCHEMA_VERSION, FRESH_FIRMWARE_BUILD_SCOPE,
    FRESH_FIRMWARE_BUILD_STDERR_BYTES, FRESH_FIRMWARE_BUILD_STDOUT_BYTES,
    FreshFirmwareBuildArtifactInput, FreshFirmwareBuildBundle, FreshFirmwareBuildCheck,
    FreshFirmwareBuildFailure, FreshFirmwareBuildFileIdentity, FreshFirmwareBuildInput,
    FreshFirmwareBuildOptions, FreshFirmwareBuildProcessLimits, FreshFirmwareBuildReport,
    decode_fresh_firmware_build_report, fresh_firmware_build_report_schema,
    render_fresh_firmware_build_report, validate_fresh_firmware_build_report,
    verify_fresh_firmware_bundle_build,
};

/// The source files in a v2 firmware bundle, in canonical order.
pub(crate) const FIRMWARE_ARTIFACTS: [&str; 7] = [
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
];
pub(crate) const FIRMWARE_SCHEMA_VERSION: u32 = 2;

pub(crate) const MAX_FIRMWARE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_COMMAND_ARGUMENTS: usize = 256;
const MAX_COMMAND_TEXT: usize = 4096;
const FIRMWARE_PROCESS_STDOUT_LIMIT_BYTES: usize = 1024 * 1024;
const FIRMWARE_PROCESS_STDERR_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_ENGINE_VERSION: usize = 128;
const COMMAND_TEXT_PATTERN: &str = r"^[\u0021-\u007E](?:[\u0020-\u007E]*[\u0021-\u007E])?$";
const ENGINE_VERSION_PATTERN: &str =
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$";
const MAX_PIN_TEXT: usize = 4096;
const MAX_PIN_NUMBER: usize = 64;
const MAX_GPIO_NAME: usize = 128;
#[cfg(not(windows))]
const C_SMOKE_BINARY: &str = ".pcbex-firmware-c-smoke";
#[cfg(windows)]
const C_SMOKE_BINARY: &str = ".pcbex-firmware-c-smoke.exe";
#[cfg(not(windows))]
const CPP_SMOKE_BINARY: &str = ".pcbex-firmware-cpp-smoke";
#[cfg(windows)]
const CPP_SMOKE_BINARY: &str = ".pcbex-firmware-cpp-smoke.exe";

/// A byte and SHA-256 descriptor for one generated source file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirmwareArtifact {
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

/// Evidence for one shell-free child process invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirmwareCommandEvidence {
    pub(crate) attempted: bool,
    pub(crate) passed: bool,
    pub(crate) command: Vec<String>,
    pub(crate) exit_code: Option<i32>,
}

/// Evidence for a compile/check command and its resulting smoke test.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirmwareBuildEvidence {
    pub(crate) attempted: bool,
    pub(crate) passed: bool,
    pub(crate) command: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) smoke: FirmwareCommandEvidence,
}

/// Closed manifest written beside the seven generated source files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirmwareManifest {
    pub(crate) schema_version: u32,
    pub(crate) engine: String,
    pub(crate) engine_version: String,
    pub(crate) schematic_sha256: String,
    pub(crate) artifacts: Vec<FirmwareArtifact>,
    pub(crate) c_build: FirmwareBuildEvidence,
    pub(crate) cpp_build: FirmwareBuildEvidence,
    pub(crate) python_check: FirmwareBuildEvidence,
}

/// Toolchain choices and process deadline for bundle validation.
///
/// The command strings are executable paths, not shell snippets.  They are
/// intentionally retained as the first argv element in manifest evidence.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FirmwareBuildOptions<'a> {
    pub(crate) cc: &'a str,
    pub(crate) cxx: &'a str,
    pub(crate) python: &'a str,
    pub(crate) skip_build: bool,
    pub(crate) timeout: Duration,
    /// Permit source schematics with importer coverage gaps.  The default is
    /// false so an incomplete IR cannot silently produce firmware evidence.
    pub(crate) allow_incomplete: bool,
}

impl<'a> Default for FirmwareBuildOptions<'a> {
    fn default() -> Self {
        Self {
            cc: "cc",
            cxx: "c++",
            python: "python3",
            skip_build: false,
            timeout: Duration::from_secs(30),
            allow_incomplete: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PinAssignment {
    pin_number: String,
    pin_name: String,
    net_name: String,
    gpio: String,
    macro_name: String,
}

/// Generate a deterministic seven-source firmware bundle.
///
/// `output_dir` is a caller-owned private staging directory.  It must already
/// exist and must not itself be a symlink.  Generated tool failures are kept
/// in the returned manifest; malformed schematic/pin-map input and filesystem
/// failures remain ordinary `Err` results.
pub(crate) fn generate_firmware_bundle(
    schematic: &SchematicDocument,
    output_dir: &Path,
    mcu_reference: &str,
    pin_map: &BTreeMap<String, String>,
    options: FirmwareBuildOptions<'_>,
) -> Result<FirmwareManifest> {
    validate_staging_directory(output_dir)?;
    validate_text(mcu_reference, "MCU reference", MAX_PIN_TEXT)?;
    for (label, tool) in [
        ("C compiler", options.cc),
        ("C++ compiler", options.cxx),
        ("Python interpreter", options.python),
    ] {
        validate_tool_name(tool, label)?;
    }
    if options.timeout.is_zero() || options.timeout > Duration::from_secs(3600) {
        bail!("firmware process timeout must be between 1 and 3600 seconds");
    }
    if !schematic.coverage.complete && !options.allow_incomplete {
        bail!("schematic coverage is incomplete");
    }

    let symbol = find_mcu(schematic, mcu_reference)?;
    validate_pin_map(pin_map, symbol)?;
    let schematic_sha256 = canonical_schematic_sha256(schematic)?;
    let pins = collect_assignments(schematic, symbol, pin_map)?;
    if pins.is_empty() {
        bail!("MCU {mcu_reference} has no connected pins to generate");
    }

    // Never let stale executable or Python cache files affect the generated
    // bundle.  Existing ordinary source files are replaced only after all
    // symlink checks below have succeeded.
    remove_generated_outputs(output_dir)?;
    for name in FIRMWARE_ARTIFACTS {
        reject_symlink(&output_dir.join(name))?;
    }
    reject_symlink(&output_dir.join("manifest.json"))?;

    let generated = [
        ("pinout.h", render_pinout_header(mcu_reference, &pins)),
        ("firmware.h", render_firmware_header()),
        ("firmware.c", render_firmware_c(&pins)),
        (
            "firmware_smoke_test.c",
            render_c_smoke_test(mcu_reference, &pins),
        ),
        ("firmware.cpp", render_firmware_cpp(&pins)),
        (
            "firmware_cpp_smoke_test.cpp",
            render_cpp_smoke_test(mcu_reference, &pins),
        ),
        ("host.py", render_host_python(mcu_reference, &pins)),
    ];
    let mut generated_bytes = 0u64;
    for (name, contents) in &generated {
        let bytes = contents.len() as u64;
        if bytes == 0 || bytes > MAX_FIRMWARE_ARTIFACT_BYTES {
            bail!("generated firmware artifact {name} has an invalid byte count");
        }
        generated_bytes = generated_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("generated firmware artifact byte count overflow"))?;
        if generated_bytes > MAX_TOTAL_ARTIFACT_BYTES {
            bail!("generated firmware artifacts exceed total byte limit");
        }
    }
    // Validate only disposable copies. Compiler/interpreter tools never need
    // write access to the canonical source stage that will be published.
    let validation = tempfile::Builder::new()
        .prefix("pcbex-firmware-validation-")
        .tempdir()
        .context("creating private firmware validation directory")?;
    for (name, contents) in &generated {
        write_source(&output_dir.join(name), contents.as_bytes())?;
        write_source(&validation.path().join(name), contents.as_bytes())?;
    }
    let expected_artifacts = describe_artifacts(output_dir)?;
    if describe_artifacts(validation.path())? != expected_artifacts {
        bail!("firmware validation copies do not match generated sources");
    }

    let c_build = run_c_build(validation.path(), options);
    let cpp_build = run_cpp_build(validation.path(), options);
    let python_check = run_python_check(validation.path(), options);

    // Binaries and Python bytecode are validation by-products, never bundle
    // artifacts.  Cleanup is attempted after every build, even when a child
    // failed or timed out.
    remove_generated_outputs(validation.path())?;

    let artifacts = describe_artifacts(output_dir)?;
    if artifacts != expected_artifacts
        || describe_artifacts(validation.path())? != expected_artifacts
    {
        bail!("generated firmware sources changed during validation");
    }
    let manifest = FirmwareManifest {
        schema_version: FIRMWARE_SCHEMA_VERSION,
        engine: "pcbex".to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        schematic_sha256,
        artifacts,
        c_build,
        cpp_build,
        python_check,
    };
    // The manifest is intentionally the last write.  It therefore cannot
    // describe a partially rendered source set.
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    write_source(&output_dir.join("manifest.json"), &bytes)?;
    Ok(manifest)
}

fn validate_staging_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading firmware staging directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("firmware output directory must be an existing non-symlink directory");
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symlink firmware output {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn remove_generated_outputs(output_dir: &Path) -> Result<()> {
    for name in [
        "firmware_smoke_test",
        "firmware_cpp_smoke_test",
        ".pcbex-firmware-c-smoke",
        ".pcbex-firmware-c-smoke.exe",
        ".pcbex-firmware-cpp-smoke",
        ".pcbex-firmware-cpp-smoke.exe",
    ] {
        let path = output_dir.join(name);
        reject_symlink(&path)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("removing {}", path.display()));
            }
        }
    }
    let cache = output_dir.join("__pycache__");
    match fs::symlink_metadata(&cache) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symlink Python cache {}", cache.display())
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(&cache).with_context(|| format!("removing {}", cache.display()))?
        }
        Ok(_) => {
            fs::remove_file(&cache).with_context(|| format!("removing {}", cache.display()))?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("reading {}", cache.display())),
    }
    Ok(())
}

fn write_source(path: &Path, bytes: &[u8]) -> Result<()> {
    reject_symlink(path)?;
    // OpenOptions makes the intended regular-file write explicit.  A caller
    // cannot redirect a generated source through an existing symlink.
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    use std::io::Write;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    Ok(())
}

fn find_mcu<'a>(schematic: &'a SchematicDocument, reference: &str) -> Result<&'a SchematicSymbol> {
    let mut matches = schematic
        .symbols
        .iter()
        .filter(|symbol| symbol.reference == reference);
    let first = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("schematic does not contain MCU reference {reference}"))?;
    if matches.next().is_some() {
        bail!("MCU reference {reference} is not unique");
    }
    Ok(first)
}

fn validate_pin_map(pin_map: &BTreeMap<String, String>, symbol: &SchematicSymbol) -> Result<()> {
    let known_pins = symbol
        .pins
        .iter()
        .map(|pin| pin.number.as_str())
        .collect::<BTreeSet<_>>();
    let mut gpios = BTreeSet::new();
    for (pin, gpio) in pin_map {
        validate_text(pin, "pin-map key", MAX_PIN_NUMBER)?;
        validate_text(gpio, "pin-map GPIO", MAX_GPIO_NAME)?;
        if !known_pins.contains(pin.as_str()) {
            bail!("pin-map contains unknown MCU pin {pin}");
        }
        if !gpios.insert(gpio.clone()) {
            bail!("pin-map contains duplicate GPIO {gpio}");
        }
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be blank");
    }
    if value.trim() != value {
        bail!("{label} must not contain leading or trailing whitespace");
    }
    if value.len() > max_bytes {
        bail!("{label} exceeds {max_bytes} bytes");
    }
    if value.chars().any(char::is_control) {
        bail!("{label} contains control characters");
    }
    Ok(())
}

fn validate_tool_name(value: &str, label: &str) -> Result<()> {
    validate_text(value, label, MAX_COMMAND_TEXT)?;
    if !value.is_ascii()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
    {
        bail!("{label} must be a printable ASCII bare executable name resolved through PATH");
    }
    Ok(())
}

fn collect_assignments(
    schematic: &SchematicDocument,
    symbol: &SchematicSymbol,
    pin_map: &BTreeMap<String, String>,
) -> Result<Vec<PinAssignment>> {
    let nets = schematic
        .nets
        .iter()
        .map(|net| (net.id, net))
        .collect::<BTreeMap<_, _>>();
    let mut pins = Vec::new();
    for pin in &symbol.pins {
        if pin.net_id == 0 || pin.no_connect {
            continue;
        }
        let Some(net) = nets.get(&pin.net_id) else {
            continue;
        };
        validate_text(&pin.number, "MCU pin number", MAX_PIN_NUMBER)?;
        if net.name.trim().is_empty() {
            continue;
        }
        validate_text(&net.name, "connected net name", MAX_PIN_TEXT)?;
        let gpio = pin_map
            .get(&pin.number)
            .cloned()
            .unwrap_or_else(|| pin.number.clone());
        pins.push(PinAssignment {
            pin_number: pin.number.clone(),
            pin_name: pin.name.clone(),
            net_name: net.name.clone(),
            gpio,
            macro_name: String::new(),
        });
    }
    pins.sort_by(|left, right| {
        pin_sort_key(&left.pin_number)
            .cmp(&pin_sort_key(&right.pin_number))
            .then_with(|| left.net_name.cmp(&right.net_name))
            .then_with(|| left.pin_name.cmp(&right.pin_name))
    });
    let mut used = BTreeSet::new();
    for pin in &mut pins {
        let base = sanitize_macro(&pin.net_name);
        let mut macro_name = base.clone();
        let mut suffix = 2usize;
        while !used.insert(macro_name.clone()) {
            macro_name = format!("{base}_{suffix}");
            suffix = suffix.saturating_add(1);
        }
        pin.macro_name = macro_name;
    }
    let mut effective_gpios = BTreeSet::new();
    for pin in &pins {
        if !effective_gpios.insert(pin.gpio.clone()) {
            bail!("pin-map produces duplicate GPIO {}", pin.gpio);
        }
    }
    Ok(pins)
}

fn pin_sort_key(value: &str) -> (u8, u128, String) {
    value.parse::<u128>().map_or_else(
        |_| (1, 0, value.to_string()),
        |number| (0, number, value.to_string()),
    )
}

fn sanitize_macro(value: &str) -> String {
    let mut output = String::from("PCBEX_NET_");
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            output.push(character.to_ascii_uppercase());
        } else {
            output.push('_');
        }
    }
    if output.ends_with('_') {
        output.push('N');
    }
    output
}

fn canonical_schematic_sha256(schematic: &SchematicDocument) -> Result<String> {
    let bytes = serde_json::to_vec(schematic).context("serializing canonical schematic")?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

fn c_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for byte in value.bytes() {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'"' => escaped.push_str("\\\""),
            b'?' => escaped.push_str("\\?"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            0x20..=0x7e => escaped.push(char::from(byte)),
            _ => escaped.push_str(&format!("\\{byte:03o}")),
        }
    }
    escaped.push('"');
    escaped
}

fn render_pinout_header(mcu_reference: &str, pins: &[PinAssignment]) -> String {
    let mut output = format!(
        "#ifndef PCBEX_PINOUT_H\n#define PCBEX_PINOUT_H\n\n/* Generated by pcbex; do not edit. */\n#define PCBEX_MCU_REFERENCE {}\n\n",
        c_string(mcu_reference),
    );
    for pin in pins {
        output.push_str(&format!(
            "#define {}_NET {}\n#define {}_PIN {}\n#define {}_GPIO {}\n\n",
            pin.macro_name,
            c_string(&pin.net_name),
            pin.macro_name,
            c_string(&pin.pin_number),
            pin.macro_name,
            c_string(&pin.gpio),
        ));
    }
    output.push_str("#endif /* PCBEX_PINOUT_H */\n");
    output
}

fn render_firmware_header() -> String {
    "#ifndef PCBEX_FIRMWARE_H\n#define PCBEX_FIRMWARE_H\n\n#include <stddef.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\ntypedef struct {\n    const char *net_name;\n    const char *pin_number;\n    const char *gpio_name;\n} pcbex_pin_descriptor;\n\nextern const pcbex_pin_descriptor pcbex_pins[];\nextern const size_t pcbex_pins_count;\nsize_t pcbex_pin_count(void);\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name);\n\n#ifdef __cplusplus\n}\n#endif\n\n#endif /* PCBEX_FIRMWARE_H */\n"
        .to_string()
}

fn render_firmware_c(pins: &[PinAssignment]) -> String {
    let mut output = String::from(
        "/* Generated by pcbex; portable MCU integration descriptor. */\n#include <stddef.h>\n#include <string.h>\n#include \"pinout.h\"\n#include \"firmware.h\"\n\nconst pcbex_pin_descriptor pcbex_pins[] = {\n",
    );
    for pin in pins {
        output.push_str(&format!(
            "    {{{}, {}, {}}},\n",
            c_string(&pin.net_name),
            c_string(&pin.pin_number),
            c_string(&pin.gpio),
        ));
    }
    output.push_str(&format!(
        "}};\nconst size_t pcbex_pins_count = {}u;\n\nsize_t pcbex_pin_count(void) {{\n    return pcbex_pins_count;\n}}\n\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name) {{\n    if (net_name == NULL) return NULL;\n    for (size_t index = 0; index < pcbex_pins_count; ++index) {{\n        if (strcmp(pcbex_pins[index].net_name, net_name) == 0) return &pcbex_pins[index];\n    }}\n    return NULL;\n}}\n",
        pins.len()
    ));
    output
}

fn render_c_smoke_test(mcu_reference: &str, pins: &[PinAssignment]) -> String {
    let first = &pins[0];
    let mut output = format!(
        "#include <stddef.h>\n#include <string.h>\n#include \"firmware.h\"\n#include \"pinout.h\"\n\nint main(void) {{\n    if (strcmp(PCBEX_MCU_REFERENCE, {mcu}) != 0) return 1;\n    if (pcbex_pin_count() != {count}u || pcbex_pins_count != {count}u) return 1;\n    const pcbex_pin_descriptor *first = pcbex_pin_find({net});\n    if (first == NULL || first != &pcbex_pins[0]) return 2;\n",
        mcu = c_string(mcu_reference),
        count = pins.len(),
        net = c_string(&first.net_name),
    );
    for (index, pin) in pins.iter().enumerate() {
        output.push_str(&format!(
            "    if (strcmp(pcbex_pins[{index}].net_name, {net}) != 0 || strcmp(pcbex_pins[{index}].pin_number, {pin}) != 0 || strcmp(pcbex_pins[{index}].gpio_name, {gpio}) != 0) return 3;\n",
            net = c_string(&pin.net_name),
            pin = c_string(&pin.pin_number),
            gpio = c_string(&pin.gpio),
        ));
    }
    output.push_str("    return 0;\n}\n");
    output
}

fn render_firmware_cpp(pins: &[PinAssignment]) -> String {
    let mut output = String::from(
        "/* Generated by pcbex; portable C++ MCU integration descriptor. */\n#include <cstddef>\n#include <cstring>\n#include \"pinout.h\"\n#include \"firmware.h\"\n\nextern \"C\" {\nconst pcbex_pin_descriptor pcbex_pins[] = {\n",
    );
    for pin in pins {
        output.push_str(&format!(
            "    {{{}, {}, {}}},\n",
            c_string(&pin.net_name),
            c_string(&pin.pin_number),
            c_string(&pin.gpio),
        ));
    }
    output.push_str(&format!(
        "}};\nconst std::size_t pcbex_pins_count = {}u;\n\nstd::size_t pcbex_pin_count() {{\n    return pcbex_pins_count;\n}}\n\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name) {{\n    if (net_name == nullptr) return nullptr;\n    for (std::size_t index = 0; index < pcbex_pins_count; ++index) {{\n        if (std::strcmp(pcbex_pins[index].net_name, net_name) == 0) return &pcbex_pins[index];\n    }}\n    return nullptr;\n}}\n}}\n",
        pins.len()
    ));
    output
}

fn render_cpp_smoke_test(mcu_reference: &str, pins: &[PinAssignment]) -> String {
    let first = &pins[0];
    let mut output = format!(
        "#include <cstring>\n#include \"firmware.h\"\n#include \"pinout.h\"\n\nint main() {{\n    if (std::strcmp(PCBEX_MCU_REFERENCE, {mcu}) != 0) return 1;\n    if (pcbex_pin_count() != {count}u || pcbex_pins_count != {count}u) return 1;\n    const pcbex_pin_descriptor *first = pcbex_pin_find({net});\n    if (first == nullptr || first != &pcbex_pins[0]) return 2;\n",
        mcu = c_string(mcu_reference),
        count = pins.len(),
        net = c_string(&first.net_name),
    );
    for (index, pin) in pins.iter().enumerate() {
        output.push_str(&format!(
            "    if (std::strcmp(pcbex_pins[{index}].net_name, {net}) != 0 || std::strcmp(pcbex_pins[{index}].pin_number, {pin}) != 0 || std::strcmp(pcbex_pins[{index}].gpio_name, {gpio}) != 0) return 3;\n",
            net = c_string(&pin.net_name),
            pin = c_string(&pin.pin_number),
            gpio = c_string(&pin.gpio),
        ));
    }
    output.push_str("    return 0;\n}\n");
    output
}

fn render_host_python(mcu_reference: &str, pins: &[PinAssignment]) -> String {
    let entries = pins
        .iter()
        .map(|pin| {
            format!(
                "    {{'net': {}, 'pin': {}, 'gpio': {}}},",
                python_string(&pin.net_name),
                python_string(&pin.pin_number),
                python_string(&pin.gpio),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let first = &pins[0];
    format!(
        "#!/usr/bin/env python3\n\"\"\"Generated pcbex host-side pinout helper.\"\"\"\nimport json\nimport sys\n\nMCU_REFERENCE = {mcu}\nPINS = [\n{entries}\n]\n\ndef pin(net_name):\n    for item in PINS:\n        if item['net'] == net_name:\n            return dict(item)\n    raise KeyError(net_name)\n\ndef self_test():\n    assert MCU_REFERENCE == {mcu}\n    assert len(PINS) == {count}\n    first = pin({net})\n    assert first == PINS[0]\n    assert first['pin'] == {pin}\n    assert first['gpio'] == {gpio}\n    for item in PINS:\n        assert item['net'] and item['pin'] and item['gpio']\n\nif __name__ == '__main__':\n    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':\n        self_test()\n    else:\n        print(json.dumps({{'mcu_reference': MCU_REFERENCE, 'pins': PINS}}, sort_keys=True))\n",
        mcu = python_string(mcu_reference),
        entries = entries,
        count = pins.len(),
        net = python_string(&first.net_name),
        pin = python_string(&first.pin_number),
        gpio = python_string(&first.gpio),
    )
}

fn python_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn command_evidence(
    command: Vec<String>,
    attempted: bool,
    passed: bool,
    exit_code: Option<i32>,
) -> FirmwareCommandEvidence {
    FirmwareCommandEvidence {
        attempted,
        passed,
        command,
        exit_code,
    }
}

fn skipped_command(command: Vec<String>) -> FirmwareCommandEvidence {
    command_evidence(command, false, false, None)
}

fn run_c_build(output_dir: &Path, options: FirmwareBuildOptions<'_>) -> FirmwareBuildEvidence {
    let binary = output_dir.join(C_SMOKE_BINARY);
    let compile = vec![
        options.cc.to_string(),
        "-std=c11".to_string(),
        "-Wall".to_string(),
        "-Wextra".to_string(),
        "-Werror".to_string(),
        "-pedantic".to_string(),
        "-I".to_string(),
        ".".to_string(),
        "firmware.c".to_string(),
        "firmware_smoke_test.c".to_string(),
        "-o".to_string(),
        C_SMOKE_BINARY.to_string(),
    ];
    let smoke = vec![smoke_command(C_SMOKE_BINARY)];
    run_build_evidence(output_dir, compile, smoke, binary, options)
}

fn run_cpp_build(output_dir: &Path, options: FirmwareBuildOptions<'_>) -> FirmwareBuildEvidence {
    let binary = output_dir.join(CPP_SMOKE_BINARY);
    let compile = vec![
        options.cxx.to_string(),
        "-std=c++17".to_string(),
        "-Wall".to_string(),
        "-Wextra".to_string(),
        "-Werror".to_string(),
        "-pedantic".to_string(),
        "-I".to_string(),
        ".".to_string(),
        "firmware.cpp".to_string(),
        "firmware_cpp_smoke_test.cpp".to_string(),
        "-o".to_string(),
        CPP_SMOKE_BINARY.to_string(),
    ];
    let smoke = vec![smoke_command(CPP_SMOKE_BINARY)];
    run_build_evidence(output_dir, compile, smoke, binary, options)
}

fn run_build_evidence(
    output_dir: &Path,
    compile: Vec<String>,
    smoke: Vec<String>,
    binary: PathBuf,
    options: FirmwareBuildOptions<'_>,
) -> FirmwareBuildEvidence {
    if options.skip_build {
        return FirmwareBuildEvidence {
            attempted: false,
            passed: false,
            command: compile,
            exit_code: None,
            smoke: skipped_command(smoke),
        };
    }
    let mut compile_evidence = run_process(output_dir, &compile, options.timeout);
    if compile_evidence.passed && !is_regular_file(&binary) {
        compile_evidence.passed = false;
    }
    let smoke_evidence = if compile_evidence.passed {
        match fs::canonicalize(&binary) {
            // Keep the stable relative command in retained evidence, but use
            // the exact validated binary path for process creation. Windows
            // resolves a relative application name before applying the
            // child's requested current directory.
            Ok(program) => run_process_with_program(
                output_dir,
                &smoke,
                Some(program.as_path()),
                options.timeout,
            ),
            Err(_) => command_evidence(smoke, true, false, None),
        }
    } else {
        skipped_command(smoke)
    };
    FirmwareBuildEvidence {
        attempted: compile_evidence.attempted,
        passed: compile_evidence.passed && smoke_evidence.passed,
        command: compile_evidence.command,
        exit_code: compile_evidence.exit_code,
        smoke: smoke_evidence,
    }
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn run_python_check(output_dir: &Path, options: FirmwareBuildOptions<'_>) -> FirmwareBuildEvidence {
    let compile = vec![
        options.python.to_string(),
        "-m".to_string(),
        "py_compile".to_string(),
        "host.py".to_string(),
    ];
    let smoke = vec![
        options.python.to_string(),
        "host.py".to_string(),
        "--self-test".to_string(),
    ];
    if options.skip_build {
        return FirmwareBuildEvidence {
            attempted: false,
            passed: false,
            command: compile,
            exit_code: None,
            smoke: skipped_command(smoke),
        };
    }
    let compile_evidence = run_process(output_dir, &compile, options.timeout);
    let smoke_evidence = if compile_evidence.passed {
        run_process(output_dir, &smoke, options.timeout)
    } else {
        skipped_command(smoke)
    };
    FirmwareBuildEvidence {
        attempted: compile_evidence.attempted,
        passed: compile_evidence.passed && smoke_evidence.passed,
        command: compile_evidence.command,
        exit_code: compile_evidence.exit_code,
        smoke: smoke_evidence,
    }
}

fn run_process(
    output_dir: &Path,
    command: &[String],
    timeout: Duration,
) -> FirmwareCommandEvidence {
    run_process_with_program(output_dir, command, None, timeout)
}

fn run_process_with_program(
    output_dir: &Path,
    command: &[String],
    program: Option<&Path>,
    timeout: Duration,
) -> FirmwareCommandEvidence {
    let command = command.to_vec();
    if command.is_empty() {
        return command_evidence(command, true, false, None);
    }
    let mut process = match program {
        Some(program) => Command::new(program),
        None => Command::new(&command[0]),
    };
    process.args(&command[1..]);
    process.current_dir(output_dir);
    let limits = ProcessLimits {
        timeout,
        stdout_bytes: FIRMWARE_PROCESS_STDOUT_LIMIT_BYTES,
        stderr_bytes: FIRMWARE_PROCESS_STDERR_LIMIT_BYTES,
    };
    match run_bounded(&mut process, limits, None) {
        Ok(output) => {
            command_evidence(command, true, output.status.success(), output.status.code())
        }
        Err(_) => command_evidence(command, true, false, None),
    }
}

fn smoke_command(binary: &str) -> String {
    #[cfg(windows)]
    {
        format!(r".\{binary}")
    }
    #[cfg(not(windows))]
    {
        format!("./{binary}")
    }
}

fn describe_artifacts(output_dir: &Path) -> Result<Vec<FirmwareArtifact>> {
    let mut total = 0u64;
    let mut artifacts = Vec::with_capacity(FIRMWARE_ARTIFACTS.len());
    for name in FIRMWARE_ARTIFACTS {
        let path = output_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("reading firmware artifact {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("firmware artifact {name} is not a regular file");
        }
        if metadata.len() == 0 || metadata.len() > MAX_FIRMWARE_ARTIFACT_BYTES {
            bail!("firmware artifact {name} has an invalid byte count");
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| anyhow::anyhow!("firmware artifact byte count overflow"))?;
        if total > MAX_TOTAL_ARTIFACT_BYTES {
            bail!("firmware artifacts exceed total byte limit");
        }
        let mut file = File::open(&path)
            .with_context(|| format!("opening firmware artifact {}", path.display()))?;
        let opened = file
            .metadata()
            .with_context(|| format!("inspecting firmware artifact {}", path.display()))?;
        if !same_file(&metadata, &opened) || opened.len() != metadata.len() {
            bail!("firmware artifact {name} changed while it was being opened");
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_FIRMWARE_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading firmware artifact {}", path.display()))?;
        let after = file
            .metadata()
            .with_context(|| format!("rechecking firmware artifact {}", path.display()))?;
        if !same_file(&opened, &after)
            || after.len() != metadata.len()
            || bytes.len() as u64 != metadata.len()
        {
            bail!("firmware artifact {name} changed while it was being read");
        }
        let mut digest = Sha256::new();
        digest.update(&bytes);
        artifacts.push(FirmwareArtifact {
            path: name.to_string(),
            bytes: metadata.len(),
            sha256: hex::encode(digest.finalize()),
        });
    }
    Ok(artifacts)
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

/// Parse and validate a JSON object mapping schematic pin numbers to GPIO
/// names.  Duplicate object keys and duplicate GPIO values are rejected.
pub(crate) fn parse_pin_map(source: &str) -> Result<BTreeMap<String, String>> {
    struct PinMapVisitor;
    impl<'de> Visitor<'de> for PinMapVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object mapping pin numbers to GPIO names")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((pin, gpio)) = map.next_entry::<String, String>()? {
                if values.insert(pin.clone(), gpio).is_some() {
                    return Err(de::Error::custom(format!("duplicate pin-map key {pin}")));
                }
            }
            Ok(values)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let map = deserializer
        .deserialize_map(PinMapVisitor)
        .map_err(|error| anyhow::anyhow!("invalid pin map JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow::anyhow!("invalid pin map JSON: {error}"))?;
    validate_pin_map_shape(&map)?;
    Ok(map)
}

fn validate_pin_map_shape(pin_map: &BTreeMap<String, String>) -> Result<()> {
    let mut gpios = BTreeSet::new();
    for (pin, gpio) in pin_map {
        validate_text(pin, "pin-map key", MAX_PIN_NUMBER)?;
        validate_text(gpio, "pin-map GPIO", MAX_GPIO_NAME)?;
        if !gpios.insert(gpio) {
            bail!("pin-map contains duplicate GPIO {gpio}");
        }
    }
    Ok(())
}

/// JSON Schema Draft 2020-12 for the closed firmware manifest.
pub(crate) fn firmware_bundle_schema() -> Value {
    let artifact = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "bytes", "sha256"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_FIRMWARE_ARTIFACT_BYTES},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    });
    let command = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["attempted", "passed", "command", "exit_code"],
        "properties": {
            "attempted": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "command": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_COMMAND_ARGUMENTS,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_COMMAND_TEXT,
                    "pattern": COMMAND_TEXT_PATTERN
                }
            },
            "exit_code": {
                "type": ["integer", "null"],
                "minimum": i32::MIN,
                "maximum": i32::MAX
            }
        },
        "allOf": [
            {
                "if": {"properties": {"attempted": {"const": false}}, "required": ["attempted"]},
                "then": {"properties": {"passed": {"const": false}, "exit_code": {"type": "null"}}}
            },
            {
                "if": {"properties": {"passed": {"const": true}}, "required": ["passed"]},
                "then": {"properties": {"attempted": {"const": true}, "exit_code": {"const": 0}}}
            },
            {
                "if": {
                    "properties": {"attempted": {"const": true}, "passed": {"const": false}},
                    "required": ["attempted", "passed"]
                },
                "then": {"properties": {"exit_code": {"not": {"const": 0}}}}
            }
        ]
    });
    let build = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["attempted", "passed", "command", "exit_code", "smoke"],
        "properties": {
            "attempted": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "command": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_COMMAND_ARGUMENTS,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_COMMAND_TEXT,
                    "pattern": COMMAND_TEXT_PATTERN
                }
            },
            "exit_code": {
                "type": ["integer", "null"],
                "minimum": i32::MIN,
                "maximum": i32::MAX
            },
            "smoke": {"$ref": "#/$defs/command_evidence"}
        },
        "allOf": [
            {
                "if": {"properties": {"attempted": {"const": false}}, "required": ["attempted"]},
                "then": {
                    "properties": {
                        "passed": {"const": false},
                        "exit_code": {"type": "null"},
                        "smoke": {
                            "properties": {"attempted": {"const": false}},
                            "required": ["attempted"]
                        }
                    }
                }
            },
            {
                "if": {"properties": {"passed": {"const": true}}, "required": ["passed"]},
                "then": {
                    "properties": {
                        "attempted": {"const": true},
                        "exit_code": {"const": 0},
                        "smoke": {
                            "properties": {"attempted": {"const": true}, "passed": {"const": true}, "exit_code": {"const": 0}},
                            "required": ["attempted", "passed", "exit_code"]
                        }
                    }
                }
            },
            {
                "if": {
                    "properties": {
                        "smoke": {
                            "properties": {"attempted": {"const": false}},
                            "required": ["attempted"]
                        }
                    },
                    "required": ["smoke"]
                },
                "then": {"properties": {"passed": {"const": false}}}
            },
            {
                "if": {
                    "properties": {
                        "smoke": {
                            "properties": {"attempted": {"const": true}},
                            "required": ["attempted"]
                        }
                    },
                    "required": ["smoke"]
                },
                "then": {"properties": {"attempted": {"const": true}, "exit_code": {"const": 0}}}
            },
            {
                "if": {
                    "properties": {
                        "smoke": {
                            "properties": {"passed": {"const": true}},
                            "required": ["passed"]
                        }
                    },
                    "required": ["smoke"]
                },
                "then": {"properties": {"passed": {"const": true}}}
            },
            {
                "if": {
                    "properties": {
                        "attempted": {"const": true},
                        "exit_code": {"not": {"const": 0}}
                    },
                    "required": ["attempted", "exit_code"]
                },
                "then": {
                    "properties": {
                        "passed": {"const": false},
                        "smoke": {
                            "properties": {"attempted": {"const": false}},
                            "required": ["attempted"]
                        }
                    }
                }
            }
        ]
    });
    let mut prefixes = Vec::with_capacity(FIRMWARE_ARTIFACTS.len());
    for name in FIRMWARE_ARTIFACTS {
        prefixes.push(json!({
            "allOf": [
                {"$ref": "#/$defs/artifact"},
                {"properties": {"path": {"const": name}}}
            ]
        }));
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/firmware-bundle-v2.json",
        "title": "pcbex generated firmware bundle manifest",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine", "engine_version", "schematic_sha256",
            "artifacts", "c_build", "cpp_build", "python_check"
        ],
        "properties": {
            "schema_version": {"const": FIRMWARE_SCHEMA_VERSION},
            "engine": {"const": "pcbex"},
            "engine_version": {
                "type": "string",
                "minLength": 5,
                "maxLength": MAX_ENGINE_VERSION,
                "pattern": ENGINE_VERSION_PATTERN
            },
            "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "artifacts": {
                "type": "array",
                "minItems": FIRMWARE_ARTIFACTS.len(),
                "maxItems": FIRMWARE_ARTIFACTS.len(),
                "prefixItems": prefixes,
                "items": false
            },
            "c_build": {"$ref": "#/$defs/build_evidence"},
            "cpp_build": {"$ref": "#/$defs/build_evidence"},
            "python_check": {"$ref": "#/$defs/build_evidence"}
        },
        "$defs": {
            "artifact": artifact,
            "command_evidence": command,
            "build_evidence": build
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcbex_kicad::import_schematic;
    use std::fs;

    const SCHEMATIC: &str = r#"(kicad_sch
      (version 20231120) (generator eeschema) (uuid root)
      (lib_symbols (symbol "MCU:Chip"
        (symbol "Chip_1_1"
          (pin bidirectional line (at 0 0 0) (length 2.54) (name "IO") (number "1"))
          (pin power_in line (at 0 2.54 0) (length 2.54) (name "VDD") (number "2")))))
      (wire (pts (xy 10 10) (xy 20 10)) (uuid w1))
      (label "DATA" (at 10 10 0) (uuid l1))
      (global_label "VDD" (shape input) (at 10 12.54 0) (uuid l2))
      (symbol (lib_id "MCU:Chip") (at 20 10 0) (unit 1) (in_bom yes) (on_board yes) (uuid u1)
        (property "Reference" "U1") (property "Value" "MCU")
        (pin "1" (uuid p1)) (pin "2" (uuid p2)))
      (sheet_instances (path "/" (page "1"))))"#;

    fn options() -> FirmwareBuildOptions<'static> {
        FirmwareBuildOptions {
            cc: "cc",
            cxx: "c++",
            python: "python3",
            skip_build: false,
            timeout: Duration::from_secs(10),
            allow_incomplete: false,
        }
    }

    #[test]
    fn generates_hash_bound_sources_and_runs_all_smoke_checks() {
        let schematic = import_schematic(SCHEMATIC).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let manifest = generate_firmware_bundle(
            &schematic,
            temporary.path(),
            "U1",
            &BTreeMap::from([("1".to_string(), "PA0".to_string())]),
            options(),
        )
        .unwrap();
        assert_eq!(manifest.artifacts.len(), 7);
        assert_eq!(
            manifest
                .artifacts
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            FIRMWARE_ARTIFACTS
        );
        assert!(manifest.c_build.passed);
        assert!(manifest.cpp_build.passed);
        assert!(manifest.python_check.passed);
        assert!(temporary.path().join("manifest.json").is_file());
        assert!(!temporary.path().join(".pcbex-firmware-c-smoke").exists());
        assert!(!temporary.path().join(".pcbex-firmware-cpp-smoke").exists());
        assert!(!temporary.path().join("__pycache__").exists());
        let header = fs::read_to_string(temporary.path().join("firmware.h")).unwrap();
        assert!(header.contains("extern \"C\""));
        let cpp = fs::read_to_string(temporary.path().join("firmware.cpp")).unwrap();
        assert!(cpp.contains("extern \"C\""));
    }

    #[test]
    fn parse_pin_map_rejects_bad_shapes() {
        assert!(parse_pin_map(r#"{"1":"PA0","2":"PA0"}"#).is_err());
        assert!(parse_pin_map(r#"{"1":""}"#).is_err());
        assert!(parse_pin_map(r#"{"1":"P\nA0"}"#).is_err());
        assert!(parse_pin_map(r#"{"1":"PA0","1":"PA1"}"#).is_err());
    }

    #[test]
    fn tool_names_are_portable_and_c_strings_preserve_utf8_bytes() {
        assert!(validate_tool_name("cc", "compiler").is_ok());
        assert!(validate_tool_name("x86_64-linux-gnu-g++", "compiler").is_ok());
        assert!(validate_tool_name("/usr/bin/cc", "compiler").is_err());
        assert!(validate_tool_name(r"C:\toolchain\cl.exe", "compiler").is_err());
        assert!(validate_tool_name("../cc", "compiler").is_err());
        assert_eq!(c_string("温度"), r#""\346\270\251\345\272\246""#);
        assert_eq!(c_string("??/"), r#""\?\?/""#);
    }

    #[cfg(windows)]
    #[test]
    fn windows_explicit_smoke_program_preserves_relative_path_free_evidence() {
        let temporary = tempfile::tempdir().unwrap();
        let private_binary = temporary.path().join(".pcbex-relative-smoke.exe");
        fs::copy(std::env::current_exe().unwrap(), &private_binary).unwrap();
        let executable = fs::canonicalize(&private_binary).unwrap();
        let evidence = vec![
            r".\.pcbex-relative-smoke.exe".to_string(),
            "--list".to_string(),
        ];
        assert!(
            !std::env::current_dir()
                .unwrap()
                .join(".pcbex-relative-smoke.exe")
                .exists()
        );

        let result = run_process_with_program(
            temporary.path(),
            &evidence,
            Some(&executable),
            Duration::from_secs(10),
        );

        assert!(result.passed);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.command, evidence);
    }

    #[test]
    fn trigraph_like_net_names_compile_in_c_and_cpp() {
        let source = SCHEMATIC.replace("\"DATA\"", "\"??/\"");
        let schematic = import_schematic(&source).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let manifest = generate_firmware_bundle(
            &schematic,
            temporary.path(),
            "U1",
            &BTreeMap::new(),
            options(),
        )
        .unwrap();
        assert!(manifest.c_build.passed);
        assert!(manifest.cpp_build.passed);
        assert!(
            fs::read_to_string(temporary.path().join("pinout.h"))
                .unwrap()
                .contains(r#""\?\?/""#)
        );
    }

    #[test]
    fn rejects_incomplete_coverage_and_unknown_pin_map_keys() {
        let mut schematic = import_schematic(SCHEMATIC).unwrap();
        schematic.coverage.complete = false;
        let temporary = tempfile::tempdir().unwrap();
        assert!(
            generate_firmware_bundle(
                &schematic,
                temporary.path(),
                "U1",
                &BTreeMap::new(),
                options(),
            )
            .is_err()
        );
        let schematic = import_schematic(SCHEMATIC).unwrap();
        assert!(
            generate_firmware_bundle(
                &schematic,
                temporary.path(),
                "U1",
                &BTreeMap::from([("99".to_string(), "PA0".to_string())]),
                options(),
            )
            .is_err()
        );
    }

    #[test]
    fn skips_build_and_keeps_closed_evidence() {
        let schematic = import_schematic(SCHEMATIC).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let manifest = generate_firmware_bundle(
            &schematic,
            temporary.path(),
            "U1",
            &BTreeMap::new(),
            FirmwareBuildOptions {
                skip_build: true,
                ..options()
            },
        )
        .unwrap();
        assert!(!manifest.c_build.attempted && !manifest.c_build.passed);
        assert!(!manifest.c_build.smoke.attempted);
        let parsed: FirmwareManifest =
            serde_json::from_slice(&fs::read(temporary.path().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(parsed, manifest);
        assert!(
            serde_json::from_value::<FirmwareManifest>(json!({
                "schema_version": FIRMWARE_SCHEMA_VERSION,
                "engine": "pcbex",
                "engine_version": "x",
                "schematic_sha256": "a".repeat(64),
                "artifacts": [],
                "c_build": {},
                "cpp_build": {},
                "python_check": {},
                "extra": true
            }))
            .is_err()
        );
    }

    #[test]
    fn schema_is_draft_2020_closed_and_exact() {
        let schema = firmware_bundle_schema();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            FIRMWARE_SCHEMA_VERSION
        );
        assert_eq!(schema["properties"]["artifacts"]["minItems"], 7);
        assert_eq!(schema["properties"]["artifacts"]["maxItems"], 7);
        assert_eq!(schema["properties"]["artifacts"]["items"], false);
        assert_eq!(
            schema["$defs"]["build_evidence"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["$defs"]["command_evidence"]["properties"]["command"]["items"]["pattern"],
            COMMAND_TEXT_PATTERN
        );
    }

    #[cfg(unix)]
    fn shell_command(script: &str, arguments: &[String]) -> Vec<String> {
        let mut command = vec![
            "sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "pcbex-firmware-test".to_string(),
        ];
        command.extend(arguments.iter().cloned());
        command
    }

    #[cfg(unix)]
    #[test]
    fn process_output_limits_allow_boundary_and_reject_overflow() {
        let temporary = tempfile::tempdir().unwrap();
        let timeout = Duration::from_secs(2);
        let boundary = FIRMWARE_PROCESS_STDOUT_LIMIT_BYTES;
        let stdout_ok = shell_command(&format!("printf '%{boundary}s' ''"), &[]);
        let evidence = run_process(temporary.path(), &stdout_ok, timeout);
        assert!(evidence.attempted && evidence.passed);
        assert_eq!(evidence.exit_code, Some(0));

        let stdout_overflow = shell_command(&format!("printf '%{}s' ''", boundary + 1), &[]);
        let evidence = run_process(temporary.path(), &stdout_overflow, timeout);
        assert!(evidence.attempted && !evidence.passed);
        assert_eq!(evidence.exit_code, None);

        let boundary = FIRMWARE_PROCESS_STDERR_LIMIT_BYTES;
        let stderr_ok = shell_command(&format!("printf '%{boundary}s' '' >&2"), &[]);
        let evidence = run_process(temporary.path(), &stderr_ok, timeout);
        assert!(evidence.attempted && evidence.passed);
        assert_eq!(evidence.exit_code, Some(0));

        let stderr_overflow = shell_command(&format!("printf '%{}s' '' >&2", boundary + 1), &[]);
        let evidence = run_process(temporary.path(), &stderr_overflow, timeout);
        assert!(evidence.attempted && !evidence.passed);
        assert_eq!(evidence.exit_code, None);
    }

    #[cfg(unix)]
    #[test]
    fn normal_child_cannot_leave_a_background_descendant() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("background-marker");
        let command = shell_command(
            "(sleep 0.2; printf leaked > \"$1\") >/dev/null 2>&1 &",
            &[marker.to_string_lossy().into_owned()],
        );
        let evidence = run_process(temporary.path(), &command, Duration::from_secs(1));
        assert!(evidence.attempted && evidence.passed);
        std::thread::sleep(Duration::from_millis(350));
        assert!(!marker.exists(), "background descendant outlived cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn timed_out_child_cannot_leave_a_background_descendant() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("timeout-marker");
        let command = shell_command(
            "(sleep 0.3; printf leaked > \"$1\") & wait",
            &[marker.to_string_lossy().into_owned()],
        );
        let evidence = run_process(temporary.path(), &command, Duration::from_millis(40));
        assert!(evidence.attempted && !evidence.passed);
        assert_eq!(evidence.exit_code, None);
        std::thread::sleep(Duration::from_millis(500));
        assert!(!marker.exists(), "timed-out descendant outlived cleanup");
    }
}
