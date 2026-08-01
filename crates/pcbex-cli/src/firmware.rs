//! Deterministic pinout and firmware/host bundle generation.

use anyhow::{Context, Result, bail};
use pcbex_kicad::{SchematicDocument, SchematicSymbol};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PinAssignment {
    pub reference: String,
    pub pin_number: String,
    pub pin_name: String,
    pub net_name: String,
    pub gpio: Option<String>,
    pub macro_name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FirmwareBundleReport {
    pub schema_version: u32,
    pub mcu_reference: String,
    pub mcu_value: String,
    pub pins: Vec<PinAssignment>,
    pub files: Vec<String>,
    pub c_build: BuildReport,
    pub cpp_build: BuildReport,
    pub python_check: BuildReport,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildReport {
    pub attempted: bool,
    pub passed: bool,
    pub command: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct FirmwareBuildOptions<'a> {
    pub cc: &'a str,
    pub cxx: &'a str,
    pub python: &'a str,
    pub skip_build: bool,
}

/// Generate C, C++, and host-side sources from one schematic pinout.
pub fn generate_firmware_bundle_with_cxx(
    schematic: &SchematicDocument,
    output_dir: &Path,
    mcu_reference: &str,
    pin_map: &BTreeMap<String, String>,
    options: FirmwareBuildOptions<'_>,
) -> Result<FirmwareBundleReport> {
    let FirmwareBuildOptions {
        cc,
        cxx,
        python,
        skip_build,
    } = options;
    if mcu_reference.trim().is_empty() {
        bail!("MCU reference must not be blank");
    }
    if !skip_build && cc.trim().is_empty() {
        bail!("C compiler command must not be blank");
    }
    if !skip_build && cxx.trim().is_empty() {
        bail!("C++ compiler command must not be blank");
    }
    if !skip_build && python.trim().is_empty() {
        bail!("Python command must not be blank");
    }
    validate_pin_map(pin_map)?;
    let symbol = schematic
        .symbols
        .iter()
        .find(|symbol| symbol.reference == mcu_reference)
        .ok_or_else(|| format!("schematic does not contain MCU reference {mcu_reference}"))
        .map_err(anyhow::Error::msg)?;
    let pins = collect_assignments(schematic, symbol, pin_map)?;
    if pins.is_empty() {
        bail!("MCU {mcu_reference} has no connected pins to generate");
    }
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    let files = [
        "pinout.h",
        "firmware.h",
        "firmware.c",
        "firmware_smoke_test.c",
        "firmware.cpp",
        "firmware_cpp_smoke_test.cpp",
        "host.py",
    ];
    fs::write(output_dir.join(files[0]), render_pinout_header(&pins))?;
    fs::write(output_dir.join(files[1]), render_firmware_header())?;
    fs::write(output_dir.join(files[2]), render_firmware_c(&pins))?;
    fs::write(output_dir.join(files[3]), render_smoke_test(pins.len()))?;
    fs::write(output_dir.join(files[4]), render_firmware_cpp(&pins))?;
    fs::write(output_dir.join(files[5]), render_cpp_smoke_test(pins.len()))?;
    fs::write(output_dir.join(files[6]), render_host_python(&pins))?;

    let c_command = vec![
        cc.to_string(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-pedantic".into(),
        "-I".into(),
        output_dir.display().to_string(),
        output_dir.join("firmware.c").display().to_string(),
        output_dir
            .join("firmware_smoke_test.c")
            .display()
            .to_string(),
        "-o".into(),
        output_dir.join("firmware_smoke_test").display().to_string(),
    ];
    let c_build = if skip_build {
        BuildReport {
            attempted: false,
            passed: false,
            command: c_command,
        }
    } else {
        run_build(&c_command, output_dir.join("firmware_smoke_test"))?
    };
    let cpp_command = vec![
        cxx.to_string(),
        "-std=c++17".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-pedantic".into(),
        "-I".into(),
        output_dir.display().to_string(),
        output_dir.join("firmware.cpp").display().to_string(),
        output_dir
            .join("firmware_cpp_smoke_test.cpp")
            .display()
            .to_string(),
        "-o".into(),
        output_dir
            .join("firmware_cpp_smoke_test")
            .display()
            .to_string(),
    ];
    let cpp_build = if skip_build {
        BuildReport {
            attempted: false,
            passed: false,
            command: cpp_command,
        }
    } else {
        run_build(&cpp_command, output_dir.join("firmware_cpp_smoke_test"))?
    };
    let python_command = vec![
        python.to_string(),
        "-m".into(),
        "py_compile".into(),
        output_dir.join("host.py").display().to_string(),
    ];
    let python_check = if skip_build {
        BuildReport {
            attempted: false,
            passed: false,
            command: python_command,
        }
    } else {
        run_status(&python_command)?;
        let self_test = vec![
            python.to_string(),
            output_dir.join("host.py").display().to_string(),
            "--self-test".into(),
        ];
        run_status(&self_test)?;
        BuildReport {
            attempted: true,
            passed: true,
            command: python_command,
        }
    };
    let files = files
        .iter()
        .map(|file| (*file).to_string())
        .collect::<Vec<_>>();
    let report = FirmwareBundleReport {
        schema_version: 1,
        mcu_reference: mcu_reference.to_string(),
        mcu_value: symbol.value.clone(),
        pins,
        files,
        c_build,
        cpp_build,
        python_check,
    };
    fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn collect_assignments(
    schematic: &SchematicDocument,
    symbol: &SchematicSymbol,
    pin_map: &BTreeMap<String, String>,
) -> Result<Vec<PinAssignment>> {
    let mut assignments = Vec::new();
    let mut used_macros = BTreeSet::new();
    for pin in &symbol.pins {
        let Some(net) = schematic.nets.iter().find(|net| net.id == pin.net_id) else {
            continue;
        };
        if pin.net_id == 0 || net.name.trim().is_empty() {
            continue;
        }
        let base = sanitize_macro(&net.name);
        let mut macro_name = base.clone();
        let mut suffix = 2;
        while !used_macros.insert(macro_name.clone()) {
            macro_name = format!("{base}_{suffix}");
            suffix += 1;
        }
        assignments.push(PinAssignment {
            reference: symbol.reference.clone(),
            pin_number: pin.number.clone(),
            pin_name: pin.name.clone(),
            net_name: net.name.clone(),
            gpio: pin_map.get(&pin.number).cloned(),
            macro_name,
        });
    }
    assignments.sort_by(|left, right| {
        pin_sort_key(&left.pin_number)
            .cmp(&pin_sort_key(&right.pin_number))
            .then_with(|| left.net_name.cmp(&right.net_name))
    });
    Ok(assignments)
}

fn pin_sort_key(value: &str) -> (u8, u64, String) {
    value
        .parse::<u64>()
        .map_or((1, 0, value.to_string()), |number| {
            (0, number, value.to_string())
        })
}

fn validate_pin_map(pin_map: &BTreeMap<String, String>) -> Result<()> {
    for (pin, gpio) in pin_map {
        if pin.trim().is_empty() || gpio.trim().is_empty() {
            bail!("pin map keys and values must not be blank");
        }
        if pin.len() > 64 || gpio.len() > 128 {
            bail!("pin map key/value is too long");
        }
    }
    Ok(())
}

fn sanitize_macro(value: &str) -> String {
    let mut output = String::from("PCBEX_NET_");
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
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

fn c_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_ascii() && !character.is_ascii_control() => {
                escaped.push(character)
            }
            _ => escaped.push('_'),
        }
    }
    escaped.push('"');
    escaped
}

fn render_pinout_header(pins: &[PinAssignment]) -> String {
    let mut output = String::from(
        "#ifndef PCBEX_PINOUT_H\n#define PCBEX_PINOUT_H\n\n/* Generated by pcbex; do not edit. */\n\n",
    );
    for pin in pins {
        let physical = c_string(&pin.pin_number);
        let gpio = pin.gpio.as_deref().unwrap_or(&pin.pin_number);
        output.push_str(&format!(
            "#define {}_NET {}\n#define {}_PIN {}\n#define {}_GPIO {}\n\n",
            pin.macro_name,
            c_string(&pin.net_name),
            pin.macro_name,
            physical,
            pin.macro_name,
            c_string(gpio),
        ));
    }
    output.push_str("#endif /* PCBEX_PINOUT_H */\n");
    output
}

fn render_firmware_header() -> String {
    "#ifndef PCBEX_FIRMWARE_H\n#define PCBEX_FIRMWARE_H\n\n#include <stddef.h>\n\ntypedef struct {\n    const char *net_name;\n    const char *pin_number;\n    const char *gpio_name;\n} pcbex_pin_descriptor;\n\nextern const pcbex_pin_descriptor pcbex_pins[];\nextern const size_t pcbex_pins_count;\nsize_t pcbex_pin_count(void);\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name);\n\n#endif /* PCBEX_FIRMWARE_H */\n"
        .to_string()
}

fn render_firmware_c(pins: &[PinAssignment]) -> String {
    let mut output = String::from(
        "/* Generated by pcbex; portable MCU integration descriptor. */\n#include <stddef.h>\n#include <string.h>\n#include \"pinout.h\"\n#include \"firmware.h\"\n\nconst pcbex_pin_descriptor pcbex_pins[] = {\n",
    );
    for pin in pins {
        let gpio = pin.gpio.as_deref().unwrap_or(&pin.pin_number);
        output.push_str(&format!(
            "    {{{}, {}, {}}},\n",
            c_string(&pin.net_name),
            c_string(&pin.pin_number),
            c_string(gpio),
        ));
    }
    output.push_str(&format!(
        "}};\nconst size_t pcbex_pins_count = {}u;\n\nsize_t pcbex_pin_count(void) {{\n    return pcbex_pins_count;\n}}\n\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name) {{\n    if (net_name == NULL) return NULL;\n    for (size_t index = 0; index < pcbex_pins_count; ++index) {{\n        if (strcmp(pcbex_pins[index].net_name, net_name) == 0) return &pcbex_pins[index];\n    }}\n    return NULL;\n}}\n",
        pins.len()
    ));
    output
}

fn render_smoke_test(pin_count: usize) -> String {
    format!(
        "#include \"firmware.h\"\nint main(void) {{ return pcbex_pin_count() == {pin_count}u ? 0 : 1; }}\n"
    )
}

fn render_firmware_cpp(pins: &[PinAssignment]) -> String {
    let mut output = String::from(
        "/* Generated by pcbex; portable C++ MCU integration descriptor. */\n#include <cstddef>\n#include <cstring>\n#include \"pinout.h\"\n#include \"firmware.h\"\n\nextern const pcbex_pin_descriptor pcbex_pins[] = {\n",
    );
    for pin in pins {
        let gpio = pin.gpio.as_deref().unwrap_or(&pin.pin_number);
        output.push_str(&format!(
            "    {{{}, {}, {}}},\n",
            c_string(&pin.net_name),
            c_string(&pin.pin_number),
            c_string(gpio),
        ));
    }
    output.push_str(&format!(
        "}};\nextern const std::size_t pcbex_pins_count = {}u;\n\nstd::size_t pcbex_pin_count() {{\n    return pcbex_pins_count;\n}}\n\nconst pcbex_pin_descriptor *pcbex_pin_find(const char *net_name) {{\n    if (net_name == nullptr) return nullptr;\n    for (std::size_t index = 0; index < pcbex_pins_count; ++index) {{\n        if (std::strcmp(pcbex_pins[index].net_name, net_name) == 0) return &pcbex_pins[index];\n    }}\n    return nullptr;\n}}\n",
        pins.len()
    ));
    output
}

fn render_cpp_smoke_test(pin_count: usize) -> String {
    format!(
        "#include \"firmware.h\"\nint main() {{ return pcbex_pin_count() == {pin_count}u ? 0 : 1; }}\n"
    )
}

fn render_host_python(pins: &[PinAssignment]) -> String {
    let entries = pins
        .iter()
        .map(|pin| {
            format!(
                "    {{'net': {}, 'pin': {}, 'gpio': {}}},",
                python_string(&pin.net_name),
                python_string(&pin.pin_number),
                python_string(pin.gpio.as_deref().unwrap_or(&pin.pin_number)),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "#!/usr/bin/env python3\n\"\"\"Generated pcbex host-side pinout helper.\"\"\"\nimport json\nimport sys\n\nPINS = [\n{entries}\n]\n\ndef pin(net_name):\n    for item in PINS:\n        if item['net'] == net_name:\n            return dict(item)\n    raise KeyError(net_name)\n\ndef self_test():\n    assert len(PINS) == {count}\n    for item in PINS:\n        assert item['net'] and item['pin'] and item['gpio']\n\nif __name__ == '__main__':\n    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':\n        self_test()\n    else:\n        print(json.dumps(PINS, sort_keys=True))\n",
        count = pins.len()
    )
}

fn python_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn run_build(command: &[String], output: PathBuf) -> Result<BuildReport> {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .with_context(|| format!("running C compiler {}", command[0]))?;
    if !status.success() {
        bail!("generated firmware C build failed with status {status}");
    }
    if !output.is_file() {
        bail!(
            "generated firmware build did not produce {}",
            output.display()
        );
    }
    Ok(BuildReport {
        attempted: true,
        passed: true,
        command: command.to_vec(),
    })
}

fn run_status(command: &[String]) -> Result<()> {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .with_context(|| format!("running {}", command[0]))?;
    if !status.success() {
        bail!("generated firmware validation failed with status {status}");
    }
    Ok(())
}

pub fn parse_pin_map(source: &str) -> Result<BTreeMap<String, String>> {
    let map: BTreeMap<String, String> = serde_json::from_str(source)
        .map_err(|error| anyhow::anyhow!("invalid pin map JSON: {error}"))?;
    validate_pin_map(&map)?;
    Ok(map)
}

pub fn firmware_bundle_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/firmware-bundle-v1.json",
        "title": "pcbex generated firmware bundle manifest",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "mcu_reference", "mcu_value", "pins", "files", "c_build", "cpp_build", "python_check"],
        "properties": {
            "schema_version": {"const": 1},
            "mcu_reference": {"type": "string", "minLength": 1},
            "mcu_value": {"type": "string"},
            "pins": {"type": "array", "items": {"type": "object"}},
            "files": {"type": "array", "items": {"type": "string"}},
            "c_build": {"type": "object"},
            "cpp_build": {"type": "object"},
            "python_check": {"type": "object"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcbex_kicad::import_schematic;

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

    #[test]
    fn renders_bundle_sources_and_pin_map() {
        let schematic = import_schematic(SCHEMATIC).unwrap();
        let path = std::env::temp_dir().join(format!("pcbex-firmware-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        let report = generate_firmware_bundle_with_cxx(
            &schematic,
            &path,
            "U1",
            &BTreeMap::from([("1".into(), "PA0".into())]),
            FirmwareBuildOptions {
                cc: "cc",
                cxx: "c++",
                python: "python3",
                skip_build: false,
            },
        )
        .unwrap();
        assert_eq!(report.pins.len(), 2);
        assert!(
            fs::read_to_string(path.join("pinout.h"))
                .unwrap()
                .contains("PA0")
        );
        assert!(
            fs::read_to_string(path.join("host.py"))
                .unwrap()
                .contains("DATA")
        );
        assert!(report.cpp_build.passed);
        assert!(path.join("firmware.cpp").is_file());
        assert!(path.join("firmware_cpp_smoke_test").is_file());
        fs::remove_dir_all(path).unwrap();
    }
}
