# Security policy

## Supported versions

Security fixes are provided for the latest published release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository rather
than opening a public issue. Include affected versions, reproduction steps,
impact, and any suggested mitigation.

Maintainers will acknowledge a report within seven days, keep the reporter
updated while the issue is assessed, and coordinate disclosure with the
reporter. Please do not disclose the issue publicly before a fix or mitigation
is available.

## Local execution boundaries

The Rust CLI limits generic files to 128 MiB, rejects symbolic-link path
components, and publishes generic generated files with per-file atomic
replacement. Doctor, KiCad, and MCP child processes have deadlines and bounded
output capture; ordinary descendants are terminated through Unix process
groups or, after assignment, Windows Job Objects. Exact limits and exclusions
are documented in
[`docs/CLI_IO_LIMITS.md`](docs/CLI_IO_LIMITS.md).

These controls are fail-closed resource boundaries, not an operating-system
sandbox. Run untrusted third-party tools in a separate account, container, or
virtual machine with the required filesystem and network policy.
