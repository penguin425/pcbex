# Immutable ERC safety floor

pcbex treats every built-in error-severity electrical rule as a mandatory
approval floor. Organization policy can add stricter requirements, but it
cannot remove or weaken these rules.

The floor contains 12 rules:

- importer and identity integrity: `coverage_incomplete`,
  `duplicate_reference_unit`, and `unannotated_reference`;
- connection and driver safety: `no_connect_connected`,
  `pin_type_no_connect_connected`, `multiple_output_drivers`,
  `multiple_power_outputs`, and `power_input_not_driven`;
- explicit power safety: `invalid_power_metadata`,
  `power_rail_voltage_conflict`, `power_input_voltage_exceeded`, and
  `missing_decoupling_capacitor`.

The four advisory defaults remain configurable: `missing_footprint`,
`unconnected_pin`, `input_not_driven`, and `multiple_net_names`. They may be
disabled, promoted, or demoted. If an organization promotes an advisory rule
to error, its findings remain eligible for the existing audited, expiring
waiver flow.

## Policy boundary

Policy documents remain partial overrides. An omitted rule inherits its
release default. An explicit floor setting is accepted only when
`enabled` is `true` and `severity` is `error`; disabling or demoting it rejects
the complete policy before checking the schematic. The same validation is
used by direct policy files, signed policy packs, pipeline verification, AI
review preparation, and every direct Rust caller of `check_schematic`.

The policy schema encodes the same constants, so schema-aware clients can
reject an unsafe edit before invoking pcbex. Valid effective policies remain
digest-bound in the electrical review.

## Waivers and baselines

An electrical waiver that targets a floor finding is invalid. pcbex returns an
error instead of producing an approval report. This preserves temporary
waivers for organization-promoted advisory errors without allowing an
exception to the built-in safety contract.

The waiver command validates the supplied review but does not receive the
schematic and policy needed to recompute it. Treat that review as trusted gate
evidence: produce it with `check-schematic` in the same controlled pipeline,
retain its digest, and do not accept an arbitrary caller-authored review as
proof of schematic provenance.

Baseline comparison remains useful for advisory findings and other
non-floor errors, but any current error-severity floor finding makes the
comparison fail even when the same finding existed in the accepted baseline.
`error_regressions` counts the distinct union of new errors, severity
escalations, and current floor errors, so one finding is never double-counted.

Comparison reports validate their closed structure and digests but do not
recompute a schematic review because they do not receive the schematic or
policy. Production approval must therefore retain the raw
`check-schematic --require-approved` gate or use a pipeline/AI command that
recomputes it; a comparison report is not independent proof of schematic
provenance.
