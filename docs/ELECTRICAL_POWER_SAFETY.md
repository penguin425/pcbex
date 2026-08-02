# Deterministic power-safety ERC

`pcbex check-schematic` now understands optional power metadata carried in
KiCad symbol properties. The metadata is deliberately explicit so existing
schematics are not rejected by guesses about a library's undocumented
electrical ratings.

Supported properties are:

- `pcbex:rail_voltage`: non-negative nominal voltage applied only when the
  symbol has exactly one distinct power-output net.
- `pcbex:max_voltage`: non-negative maximum voltage applied uniformly to every
  power-input pin of the symbol.
- `pcbex:requires_decoupling`: `true`, `yes`, `1`, or `required` to require a
  capacitor on every power-input net of the symbol.
- `pcbex:decoupling`: optional truthy marker for a capacitor whose purpose is
  local bypass; ordinary `C*` / `Device:C` parts are accepted by default.

Boolean properties also accept `false`, `no`, `0`, `optional`, `not_required`,
or `not-required`. Malformed values and conflicting aliases fail closed. Rail
names are parsed when they contain common non-negative forms such as `5V`,
`+5V`, `3V3`, `3.3V`, `1V8`, `VCC_5V`, or `AVDD_1V8`. Negative rail names are
not inferred by the current maximum-voltage-only model and are never
reinterpreted as positive voltages. The deterministic gate reports:

- `invalid_power_metadata` when a voltage or boolean value is malformed or
  aliases on one symbol disagree;
- `power_rail_voltage_conflict` when one net describes multiple nominal
  voltages;
- `power_input_voltage_exceeded` when a declared maximum is exceeded; and
- `missing_decoupling_capacitor` when an explicitly power-sensitive symbol has
  no capacitor on its power net. One finding is emitted per affected symbol and
  net, even when the symbol has multiple power-input pins on that net.

All findings are policy-controlled, digest-bound, and included in the existing
JSON, JUnit, and SARIF reports. `--require-approved` therefore blocks a CI
pipeline on an error-severity power-safety finding without involving an AI
model in the electrical decision.

Electrical policy documents remain partial overrides: omitted built-in rules
receive their release defaults before checking, and the review's
`policy_sha256` binds that complete effective 16-rule policy. The example
organization policy lists all rules explicitly so its signed intent is clear.
