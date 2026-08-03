# KiCad S-expression resource limits

All PCB, schematic, manufacturing, placement, and custom-design-rule consumers
use the same typed, iterative S-expression parser. The parser never recurses on
input nesting and does not retain a separate all-token buffer before building
the AST.

| Resource | Maximum |
|---|---:|
| UTF-8 input | 128 MiB |
| Lexical tokens | 4,000,000 |
| One decoded quoted or unquoted atom | 4 MiB |
| List nesting depth | 128 |
| Direct elements in one list or top-level sequence | 1,000,000 |
| Placement span results | 1,000,000 |

Each limit is checked before the corresponding parser structure grows beyond
the boundary. Errors identify the exceeded resource and limit without copying
input content into diagnostics. Quoted empty strings, Unicode, escaped quotes
and backslashes, and quoted `(` or `)` atoms remain valid. A normal KiCad
document must contain exactly one root expression; `.kicad_dru` input uses a
separate no-copy sequence mode that preserves its existing empty or multiple
top-level rule behavior without adding a virtual list depth.

These limits bound parser amplification after a caller has supplied a `&str`.
Some generic CLI paths still read a complete file before entering the parser;
bounded metadata checks and file reads at that outer I/O boundary are a
separate hardening step. KiCad's own DRC and format validation remain the final
authority for supported documents.
