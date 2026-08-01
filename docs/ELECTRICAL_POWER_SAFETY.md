# Deterministic power-safety ERC

`pcbex check-schematic` now understands optional power metadata carried in
KiCad symbol properties. The metadata is deliberately explicit so existing
schematics are not rejected by guesses about a library's undocumented
electrical ratings.

Supported properties are:

- `pcbex:rail_voltage`: nominal voltage for a power source or rail.
- `pcbex:max_voltage`: maximum voltage accepted by a power-input symbol.
- `pcbex:requires_decoupling`: `true`, `yes`, `1`, or `required` to require a
  capacitor on every power-input net of the symbol.
- `pcbex:decoupling`: optional truthy marker for a capacitor whose purpose is
  local bypass; ordinary `C*` / `Device:C` parts are accepted by default.

Rail names are also parsed when they contain common forms such as `5V`,
`3V3`, `1V8`, `VCC_5V`, or `AVDD_1V8`. The deterministic gate reports:

- `power_rail_voltage_conflict` when one net describes multiple nominal
  voltages;
- `power_input_voltage_exceeded` when a declared maximum is exceeded; and
- `missing_decoupling_capacitor` when an explicitly power-sensitive symbol has
  no capacitor on its power net.

All findings are policy-controlled, digest-bound, and included in the existing
JSON, JUnit, and SARIF reports. `--require-approved` therefore blocks a CI
pipeline on an error-severity power-safety finding without involving an AI
model in the electrical decision.
