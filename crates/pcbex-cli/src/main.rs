use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use pcbex_core::checking::{check_board, check_manufacturability, check_report_to_sarif};
use pcbex_core::placement::{PlacementOptions, PlacementProblem, place};
use pcbex_core::{
    AnalysisDelta, Board, DfmProfile, RoutingQuality, Rules, analysis_delta_to_sarif,
    apply_dfm_profile, board_json_schema, dfm_profile, dfm_profiles, impedance_report,
    migrate_board_json, parse_board_json, render_svg, repair_routes, repairable_net_ids,
    route_board, routing_quality, solve_stackup_differential_width_nm, solve_stackup_width_nm,
};
use pcbex_kicad::{apply_custom_design_rules, apply_project_net_settings, import as import_kicad};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

mod mcp;

#[derive(Parser)]
#[command(version, about = "Deterministic PCB physical-design engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Json,
    Sarif,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum QualityFormat {
    Json,
    Sarif,
}

#[derive(Debug, Serialize)]
struct InputDescriptor {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct AnalysisConfiguration {
    rules: Rules,
    project_settings_loaded: bool,
    applied_custom_rules: usize,
    dfm_profile: Option<DfmProfile>,
}

#[derive(Debug, Serialize)]
struct AnalysisResult {
    clean: bool,
    violations: usize,
    routed_nets: usize,
    unrouted_nets: usize,
    total_length_nm: i64,
    total_vias: usize,
}

#[derive(Debug, Serialize)]
struct RunManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    command: String,
    input: InputDescriptor,
    project: Option<InputDescriptor>,
    rules_file: Option<InputDescriptor>,
    configuration: AnalysisConfiguration,
    result: AnalysisResult,
    artifacts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ComparisonInputs {
    quality: InputDescriptor,
    checks: InputDescriptor,
}

#[derive(Debug, Serialize)]
struct ComparisonManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    command: String,
    baseline: ComparisonInputs,
    current: ComparisonInputs,
    regression: bool,
    artifacts: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate shell completion definitions on standard output.
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Serve pcbex tools over newline-delimited MCP JSON-RPC on stdio.
    McpServer,
    /// Print the current board JSON Schema.
    Schema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List built-in, revisioned fabrication profiles as JSON.
    DfmProfiles {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Upgrade an older board JSON document to the current schema.
    Migrate {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Route {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        svg: Option<PathBuf>,
        #[arg(long)]
        allow_unrouted: bool,
    },
    /// Reroute only violating or explicitly selected nets; keep all others locked.
    Repair {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Net ID to repair. Repeat for multiple nets; omit to use checker violations.
        #[arg(long = "net-id")]
        net_ids: Vec<u32>,
        #[arg(long)]
        svg: Option<PathBuf>,
    },
    /// Report routing quality and optionally fail on thresholds or regressions.
    Quality {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = QualityFormat::Json)]
        format: QualityFormat,
        /// Previous JSON quality report; increases fail the command.
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        max_total_length_nm: Option<i64>,
        #[arg(long)]
        max_vias: Option<usize>,
        #[arg(long)]
        max_unrouted: Option<usize>,
    },
    /// Analyze a KiCad board and emit a reproducible CI artifact bundle.
    AnalyzeKicad {
        input: PathBuf,
        /// KiCad project settings. Defaults to the input's sibling `.kicad_pro` when present.
        #[arg(long)]
        project: Option<PathBuf>,
        /// KiCad custom design rules. Defaults to the input's sibling `.kicad_dru`.
        #[arg(long)]
        rules_file: Option<PathBuf>,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 0.25)]
        grid_mm: f64,
        #[arg(long, default_value_t = 0.25)]
        width_mm: f64,
        #[arg(long, default_value_t = 0.20)]
        clearance_mm: f64,
        #[arg(long, default_value_t = 0.60)]
        via_diameter_mm: f64,
        #[arg(long, default_value_t = 0.30)]
        via_drill_mm: f64,
        #[arg(long, default_value_t = 5)]
        bend_cost: u32,
        #[arg(long, default_value_t = 20)]
        via_cost: u32,
        /// Built-in fabrication profile ID or stable alias.
        #[arg(long)]
        fab: Option<String>,
        /// Write all reports before exiting unsuccessfully on violations.
        #[arg(long)]
        fail_on_violations: bool,
    },
    /// Compare two `analyze-kicad` bundles and emit CI-ready deltas.
    CompareAnalysis {
        baseline_dir: PathBuf,
        current_dir: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Write all comparison artifacts before exiting unsuccessfully.
        #[arg(long)]
        fail_on_regressions: bool,
    },
    /// Route a placed KiCad board across its declared copper layers.
    RouteKicad {
        input: PathBuf,
        /// KiCad project settings. Defaults to the input's sibling `.kicad_pro` when present.
        #[arg(long)]
        project: Option<PathBuf>,
        /// KiCad custom design rules. Defaults to the input's sibling `.kicad_dru`.
        #[arg(long)]
        rules_file: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0.25)]
        grid_mm: f64,
        #[arg(long, default_value_t = 0.25)]
        width_mm: f64,
        #[arg(long, default_value_t = 0.20)]
        clearance_mm: f64,
        #[arg(long, default_value_t = 0.60)]
        via_diameter_mm: f64,
        #[arg(long, default_value_t = 0.30)]
        via_drill_mm: f64,
        #[arg(long, default_value_t = 5)]
        bend_cost: u32,
        #[arg(long, default_value_t = 20)]
        via_cost: u32,
        /// Built-in fabrication profile ID or stable alias.
        #[arg(long)]
        fab: Option<String>,
        #[arg(long)]
        svg: Option<PathBuf>,
        /// Also write routed items as JSON for the KiCad IPC adapter.
        #[arg(long)]
        json_output: Option<PathBuf>,
        /// Run `kicad-cli pcb drc` after writing the board.
        #[arg(long)]
        drc: bool,
        #[arg(long)]
        allow_unrouted: bool,
    },
    Check {
        input: PathBuf,
    },
    /// Run configured manufacturing checks and optionally write a JSON report.
    Dfm {
        input: PathBuf,
        /// Override embedded manufacturing rules with a built-in profile.
        #[arg(long)]
        fab: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// Solve trace width from a stackup layer and target impedance.
    ImpedanceWidth {
        input: PathBuf,
        /// Copper layer name, for example F.Cu or In1.Cu.
        #[arg(long)]
        layer: String,
        #[arg(long)]
        target_ohms: f64,
        /// Pair gap in millimetres; when set, solve differential impedance.
        #[arg(long)]
        differential_gap_mm: Option<f64>,
        #[arg(long, default_value_t = 0.01)]
        minimum_width_mm: f64,
        #[arg(long, default_value_t = 5.0)]
        maximum_width_mm: f64,
    },
    /// Report per-segment single-ended and differential impedance as JSON.
    ImpedanceReport {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Previous impedance JSON report; regressions fail the command.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Exit unsuccessfully when geometry, target, or transition violations exist.
        #[arg(long)]
        fail_on_violations: bool,
    },
    Render {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Optimize component placement from a placement JSON document.
    Place {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Optimize footprint placement directly in a KiCad board.
    PlaceKicad {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0.5)]
        grid_mm: f64,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        json_output: Option<PathBuf>,
    },
    /// Run KiCad DRC and generate Gerber and Excellon manufacturing files.
    Fabricate {
        input: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
    },
}

fn read(path: &PathBuf) -> Result<Board> {
    parse_board_json(
        &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .map_err(anyhow::Error::msg)
    .with_context(|| format!("parsing {}", path.display()))
}

fn resolve_dfm_profile(name: Option<&str>) -> Result<Option<DfmProfile>> {
    name.map(|name| {
        dfm_profile(name).ok_or_else(|| {
            let available = dfm_profiles()
                .iter()
                .map(|profile| profile.id)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("unknown fabrication profile {name:?}; available profiles: {available}")
        })
    })
    .transpose()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(shell, &mut command, name, &mut io::stdout());
        }
        Command::McpServer => mcp::serve_stdio()?,
        Command::Schema { output } => {
            let schema = serde_json::to_string_pretty(&board_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::DfmProfiles { output } => {
            let profiles = serde_json::to_string_pretty(&dfm_profiles())?;
            if let Some(path) = output {
                fs::write(path, profiles)?;
            } else {
                println!("{profiles}");
            }
        }
        Command::Migrate { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let migrated = migrate_board_json(&source).map_err(anyhow::Error::msg)?;
            parse_board_json(&serde_json::to_string(&migrated)?).map_err(anyhow::Error::msg)?;
            fs::write(output, serde_json::to_string_pretty(&migrated)?)?;
        }
        Command::Route {
            input,
            output,
            svg,
            allow_unrouted,
        } => {
            let (board, report) = route_board(&read(&input)?).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&board)?)?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&board))?;
            }
            eprintln!(
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; shoves: {}; escaped nets: {}; return vias: {}; optimized segments: {}; rounded corners: {}; parallel candidates: {}; workers: {}; fallbacks: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.shove_events,
                report.escaped_nets,
                report.generated_return_vias,
                report.optimized_segments,
                report.rounded_corners,
                report.parallel_candidates,
                report.parallel_workers,
                report.parallel_fallbacks,
                report.expanded_states,
                report.reroute_passes
            );
            if !allow_unrouted && !report.unrouted.is_empty() {
                bail!("unrouted nets: {}", report.unrouted.join(", "))
            }
            ensure_clean(&board)?;
        }
        Command::Repair {
            input,
            output,
            net_ids,
            svg,
        } => {
            let board = read(&input)?;
            let selected = if net_ids.is_empty() {
                repairable_net_ids(&board)
            } else {
                net_ids.into_iter().collect()
            };
            let (repaired, report) =
                repair_routes(&board, &selected).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&repaired)?)?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&repaired))?;
            }
            eprintln!(
                "repaired: {}; locked: {}",
                report.rerouted.join(", "),
                report.preserved.join(", ")
            );
        }
        Command::Quality {
            input,
            output,
            format,
            baseline,
            max_total_length_nm,
            max_vias,
            max_unrouted,
        } => {
            let quality = routing_quality(&read(&input)?);
            let mut regressions = baseline
                .map(|path| -> Result<Vec<String>> {
                    let baseline: RoutingQuality = serde_json::from_str(
                        &fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    )
                    .with_context(|| format!("parsing {}", path.display()))?;
                    Ok(quality.regressions_against(&baseline))
                })
                .transpose()?
                .unwrap_or_default();
            if max_total_length_nm.is_some_and(|limit| quality.total_length_nm > limit) {
                regressions.push(format!(
                    "total length {} exceeds {} nm",
                    quality.total_length_nm,
                    max_total_length_nm.unwrap()
                ));
            }
            if max_vias.is_some_and(|limit| quality.total_vias > limit) {
                regressions.push(format!(
                    "via count {} exceeds {}",
                    quality.total_vias,
                    max_vias.unwrap()
                ));
            }
            if max_unrouted.is_some_and(|limit| quality.unrouted_nets > limit) {
                regressions.push(format!(
                    "unrouted-net count {} exceeds {}",
                    quality.unrouted_nets,
                    max_unrouted.unwrap()
                ));
            }
            let rendered = match format {
                QualityFormat::Json => serde_json::to_string_pretty(&quality)?,
                QualityFormat::Sarif => serde_json::to_string_pretty(&serde_json::json!({
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {"driver": {
                            "name": "pcbex quality",
                            "rules": [{"id": "routing_quality_regression"}]
                        }},
                        "results": regressions.iter().map(|message| serde_json::json!({
                            "ruleId": "routing_quality_regression",
                            "level": "error",
                            "message": {"text": message}
                        })).collect::<Vec<_>>()
                    }]
                }))?,
            };
            if let Some(path) = output {
                fs::write(path, rendered)?;
            } else {
                println!("{rendered}");
            }
            if !regressions.is_empty() {
                bail!("routing quality failed: {}", regressions.join("; "))
            }
        }
        Command::AnalyzeKicad {
            input,
            project,
            rules_file,
            output_dir,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
            fab,
            fail_on_violations,
        } => {
            let input_bytes =
                fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let source = std::str::from_utf8(&input_bytes)
                .with_context(|| format!("decoding {} as UTF-8", input.display()))?;
            let rules = Rules {
                grid_nm: to_nm(grid_mm, "grid")?,
                track_width_nm: to_nm(width_mm, "track width")?,
                clearance_nm: to_nm(clearance_mm, "clearance")?,
                via_diameter_nm: to_nm(via_diameter_mm, "via diameter")?,
                via_drill_nm: to_nm(via_drill_mm, "via drill")?,
                bend_cost,
                via_cost,
            };
            if rules.via_drill_nm >= rules.via_diameter_nm {
                bail!("via drill must be smaller than via diameter");
            }
            let mut imported = import_kicad(source, rules.clone()).map_err(anyhow::Error::msg)?;

            let project = project.or_else(|| {
                let candidate = input.with_extension("kicad_pro");
                candidate.exists().then_some(candidate)
            });
            let project_descriptor = project
                .as_ref()
                .map(|path| -> Result<InputDescriptor> {
                    let bytes =
                        fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                    let project_source = std::str::from_utf8(&bytes)
                        .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
                    apply_project_net_settings(&mut imported.board, project_source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("importing rules from {}", path.display()))?;
                    Ok(input_descriptor(path, &bytes))
                })
                .transpose()?;

            let rules_file = rules_file.or_else(|| {
                let candidate = input.with_extension("kicad_dru");
                candidate.exists().then_some(candidate)
            });
            let mut applied_custom_rules = 0;
            let rules_descriptor = rules_file
                .as_ref()
                .map(|path| -> Result<InputDescriptor> {
                    let bytes =
                        fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                    let rules_source = std::str::from_utf8(&bytes)
                        .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
                    applied_custom_rules =
                        apply_custom_design_rules(&mut imported.board, rules_source)
                            .map_err(anyhow::Error::msg)
                            .with_context(|| {
                                format!("importing custom rules from {}", path.display())
                            })?;
                    Ok(input_descriptor(path, &bytes))
                })
                .transpose()?;
            let dfm_profile = resolve_dfm_profile(fab.as_deref())?;
            if let Some(profile) = &dfm_profile {
                apply_dfm_profile(&mut imported.board, profile);
            }

            let report = check_board(&imported.board);
            let quality = routing_quality(&imported.board);
            let summary = render_analysis_summary(&quality, &report);
            let artifacts = vec![
                "board.json".to_string(),
                "board.svg".to_string(),
                "checks.json".to_string(),
                "quality.json".to_string(),
                "report.sarif".to_string(),
                "summary.md".to_string(),
                "run.json".to_string(),
            ];
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            fs::write(
                output_dir.join("board.json"),
                serde_json::to_string_pretty(&imported.board)?,
            )?;
            fs::write(output_dir.join("board.svg"), render_svg(&imported.board))?;
            fs::write(
                output_dir.join("checks.json"),
                serde_json::to_string_pretty(&report)?,
            )?;
            fs::write(
                output_dir.join("quality.json"),
                serde_json::to_string_pretty(&quality)?,
            )?;
            fs::write(
                output_dir.join("report.sarif"),
                serde_json::to_string_pretty(&check_report_to_sarif(&report))?,
            )?;
            fs::write(output_dir.join("summary.md"), summary)?;
            let manifest = RunManifest {
                schema_version: 1,
                engine: "pcbex".to_string(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                command: "analyze-kicad".to_string(),
                input: input_descriptor(&input, &input_bytes),
                project: project_descriptor,
                rules_file: rules_descriptor,
                configuration: AnalysisConfiguration {
                    rules: imported.board.rules.clone(),
                    project_settings_loaded: project.is_some(),
                    applied_custom_rules,
                    dfm_profile,
                },
                result: AnalysisResult {
                    clean: report.is_clean(),
                    violations: report.violations.len(),
                    routed_nets: quality.routed_nets,
                    unrouted_nets: quality.unrouted_nets,
                    total_length_nm: quality.total_length_nm,
                    total_vias: quality.total_vias,
                },
                artifacts,
            };
            fs::write(
                output_dir.join("run.json"),
                serde_json::to_string_pretty(&manifest)?,
            )?;
            eprintln!(
                "analysis written to {}: {} violation(s), {} routed, {} unrouted",
                output_dir.display(),
                report.violations.len(),
                quality.routed_nets,
                quality.unrouted_nets
            );
            if fail_on_violations && !report.is_clean() {
                bail!(
                    "KiCad analysis found {} violation(s)",
                    report.violations.len()
                );
            }
        }
        Command::CompareAnalysis {
            baseline_dir,
            current_dir,
            output_dir,
            fail_on_regressions,
        } => {
            let (baseline_quality, baseline_quality_input) =
                read_described_json::<RoutingQuality>(&baseline_dir.join("quality.json"))?;
            let (baseline_checks, baseline_checks_input) =
                read_described_json::<pcbex_core::checking::CheckReport>(
                    &baseline_dir.join("checks.json"),
                )?;
            let (current_quality, current_quality_input) =
                read_described_json::<RoutingQuality>(&current_dir.join("quality.json"))?;
            let (current_checks, current_checks_input) =
                read_described_json::<pcbex_core::checking::CheckReport>(
                    &current_dir.join("checks.json"),
                )?;
            let delta = AnalysisDelta::between(
                &baseline_quality,
                &baseline_checks,
                &current_quality,
                &current_checks,
            );
            let regression = delta.is_regression();
            let artifacts = vec![
                "delta.json".to_string(),
                "report.sarif".to_string(),
                "run.json".to_string(),
                "summary.md".to_string(),
            ];
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            fs::write(
                output_dir.join("delta.json"),
                serde_json::to_string_pretty(&delta)?,
            )?;
            fs::write(
                output_dir.join("report.sarif"),
                serde_json::to_string_pretty(&analysis_delta_to_sarif(&delta))?,
            )?;
            fs::write(
                output_dir.join("summary.md"),
                render_comparison_summary(&delta),
            )?;
            let manifest = ComparisonManifest {
                schema_version: 1,
                engine: "pcbex".to_string(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                command: "compare-analysis".to_string(),
                baseline: ComparisonInputs {
                    quality: baseline_quality_input,
                    checks: baseline_checks_input,
                },
                current: ComparisonInputs {
                    quality: current_quality_input,
                    checks: current_checks_input,
                },
                regression,
                artifacts,
            };
            fs::write(
                output_dir.join("run.json"),
                serde_json::to_string_pretty(&manifest)?,
            )?;
            eprintln!(
                "comparison written to {}: {} quality regression(s), {} new violation(s), {} resolved violation(s)",
                output_dir.display(),
                delta.quality_regressions.len(),
                delta.new_violations.len(),
                delta.resolved_violations.len()
            );
            if fail_on_regressions && regression {
                bail!("analysis comparison found regressions");
            }
        }
        Command::RouteKicad {
            input,
            project,
            rules_file,
            output,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
            fab,
            svg,
            json_output,
            drc,
            allow_unrouted,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let rules = Rules {
                grid_nm: to_nm(grid_mm, "grid")?,
                track_width_nm: to_nm(width_mm, "track width")?,
                clearance_nm: to_nm(clearance_mm, "clearance")?,
                via_diameter_nm: to_nm(via_diameter_mm, "via diameter")?,
                via_drill_nm: to_nm(via_drill_mm, "via drill")?,
                bend_cost,
                via_cost,
            };
            if rules.via_drill_nm >= rules.via_diameter_nm {
                bail!("via drill must be smaller than via diameter");
            }
            let mut imported = import_kicad(&source, rules).map_err(anyhow::Error::msg)?;
            let project = project.or_else(|| {
                let candidate = input.with_extension("kicad_pro");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = project {
                let project_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                apply_project_net_settings(&mut imported.board, &project_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing rules from {}", path.display()))?;
            }
            let rules_file = rules_file.or_else(|| {
                let candidate = input.with_extension("kicad_dru");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = rules_file {
                let rules_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let applied = apply_custom_design_rules(&mut imported.board, &rules_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing custom rules from {}", path.display()))?;
                eprintln!(
                    "applied {applied} routing constraints from {}",
                    path.display()
                );
            }
            if let Some(profile) = resolve_dfm_profile(fab.as_deref())? {
                apply_dfm_profile(&mut imported.board, &profile);
                eprintln!("applied fabrication profile {}", profile.id);
            }
            let (board, report) = route_board(&imported.board).map_err(anyhow::Error::msg)?;
            fs::write(
                &output,
                imported
                    .write_routes(&board.routes)
                    .map_err(anyhow::Error::msg)?,
            )
            .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&board))?;
            }
            if let Some(path) = json_output {
                fs::write(
                    path,
                    serde_json::to_string_pretty(&serde_json::json!({
                        "origin": imported.origin(),
                        "nets": board.nets.iter().map(|net| serde_json::json!({
                            "id": net.id,
                            "name": net.name,
                        })).collect::<Vec<_>>(),
                        "routes": board.routes,
                    }))?,
                )?;
            }
            eprintln!(
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; shoves: {}; escaped nets: {}; return vias: {}; optimized segments: {}; rounded corners: {}; parallel candidates: {}; workers: {}; fallbacks: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.shove_events,
                report.escaped_nets,
                report.generated_return_vias,
                report.optimized_segments,
                report.rounded_corners,
                report.parallel_candidates,
                report.parallel_workers,
                report.parallel_fallbacks,
                report.expanded_states,
                report.reroute_passes
            );
            if !allow_unrouted && !report.unrouted.is_empty() {
                bail!("unrouted nets: {}", report.unrouted.join(", "))
            }
            ensure_clean(&board)?;
            if drc {
                run_kicad_drc(&output)?;
            }
        }
        Command::Check { input } => {
            let b = read(&input)?;
            if b.width_nm <= 0 || b.height_nm <= 0 || b.rules.grid_nm <= 0 {
                bail!("invalid board dimensions or grid")
            }
            for n in &b.nets {
                if n.terminals.len() < 2 {
                    bail!("net {} has fewer than two terminals", n.name)
                }
            }
            ensure_clean(&b)?;
            println!(
                "ok: {} nets, {} obstacles, {} routes",
                b.nets.len(),
                b.obstacles.len(),
                b.routes.len()
            );
        }
        Command::Dfm {
            input,
            fab,
            output,
            format,
        } => {
            let mut board = read(&input)?;
            if let Some(profile) = resolve_dfm_profile(fab.as_deref())? {
                apply_dfm_profile(&mut board, &profile);
            }
            if board.manufacturing_rules.is_none() {
                bail!("board does not define manufacturing_rules; select --fab PROFILE")
            }
            let report = check_manufacturability(&board);
            let json = match format {
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
                ReportFormat::Sarif => {
                    serde_json::to_string_pretty(&check_report_to_sarif(&report))?
                }
            };
            if let Some(path) = output {
                fs::write(path, &json)?;
            } else {
                println!("{json}");
            }
            if !report.is_clean() {
                bail!("{} manufacturing violations", report.violations.len())
            }
        }
        Command::ImpedanceWidth {
            input,
            layer,
            target_ohms,
            differential_gap_mm,
            minimum_width_mm,
            maximum_width_mm,
        } => {
            if !target_ohms.is_finite() || target_ohms <= 0.0 {
                bail!("target impedance must be a positive finite value")
            }
            let board = read(&input)?;
            let stackup = board
                .stackup
                .iter()
                .find(|entry| entry.layer.name() == layer)
                .with_context(|| format!("no stackup entry for layer {layer}"))?;
            let minimum = to_nm(minimum_width_mm, "minimum width")?;
            let maximum = to_nm(maximum_width_mm, "maximum width")?;
            if maximum < minimum {
                bail!("maximum width must be at least minimum width")
            }
            let (width, estimated, mode) = if let Some(gap_mm) = differential_gap_mm {
                let gap = to_nm(gap_mm, "differential gap")?;
                let width = solve_stackup_differential_width_nm(
                    target_ohms,
                    gap,
                    stackup,
                    minimum,
                    maximum,
                )
                .context("target impedance is unreachable within the width range")?;
                let estimated =
                    pcbex_core::estimated_stackup_differential_impedance_ohms(width, gap, stackup)
                        .context("solved differential geometry is invalid")?;
                (width, estimated, "differential")
            } else {
                let width = solve_stackup_width_nm(target_ohms, stackup, minimum, maximum)
                    .context("target impedance is unreachable within the width range")?;
                let estimated = pcbex_core::estimated_stackup_impedance_ohms(width, stackup)
                    .context("solved single-ended geometry is invalid")?;
                (width, estimated, "single_ended")
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mode": mode,
                    "layer": layer,
                    "target_ohms": target_ohms,
                    "estimated_ohms": estimated,
                    "width_nm": width,
                    "width_mm": width as f64 / 1_000_000.0
                }))?
            );
        }
        Command::ImpedanceReport {
            input,
            output,
            baseline,
            fail_on_violations,
        } => {
            let result = impedance_report(&read(&input)?);
            let regressions = baseline
                .map(|path| -> Result<Vec<String>> {
                    let baseline: pcbex_core::ImpedanceReport = serde_json::from_str(
                        &fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    )
                    .with_context(|| format!("parsing {}", path.display()))?;
                    Ok(result.regressions_against(&baseline))
                })
                .transpose()?
                .unwrap_or_default();
            let report = serde_json::to_string_pretty(&result)?;
            if let Some(path) = output {
                fs::write(path, report)?;
            } else {
                println!("{report}");
            }
            if fail_on_violations && !result.is_clean() {
                bail!(
                    "impedance quality failed: {} invalid geometries, {} out-of-tolerance segments, {} excessive transitions",
                    result.invalid_geometry_count,
                    result.out_of_tolerance_segment_count,
                    result.excessive_transition_count
                )
            }
            if !regressions.is_empty() {
                bail!("impedance regressions: {}", regressions.join("; "))
            }
        }
        Command::Render { input, output } => fs::write(output, render_svg(&read(&input)?))?,
        Command::Place {
            input,
            output,
            iterations,
            seed,
        } => {
            let problem: PlacementProblem = serde_json::from_str(
                &fs::read_to_string(&input)
                    .with_context(|| format!("reading {}", input.display()))?,
            )
            .with_context(|| format!("parsing {}", input.display()))?;
            let mut options = PlacementOptions::default();
            if let Some(value) = iterations {
                options.iterations = value;
            }
            if let Some(value) = seed {
                options.seed = value;
            }
            let result = place(&problem, &options).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&result)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "placement score: {:.3} -> {:.3}; accepted moves: {}",
                result.initial_score.total, result.final_score.total, result.accepted_moves
            );
        }
        Command::PlaceKicad {
            input,
            output,
            grid_mm,
            iterations,
            seed,
            json_output,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let imported = import_kicad(
                &source,
                Rules {
                    grid_nm: 250_000,
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    bend_cost: 5,
                    via_cost: 20,
                },
            )
            .map_err(anyhow::Error::msg)?;
            let problem = imported
                .placement_problem(to_nm(grid_mm, "placement grid")?)
                .map_err(anyhow::Error::msg)?;
            let mut options = PlacementOptions::default();
            if let Some(value) = iterations {
                options.iterations = value;
            }
            if let Some(value) = seed {
                options.seed = value;
            }
            let result = place(&problem, &options).map_err(anyhow::Error::msg)?;
            let placed = imported
                .write_placements(&result.components)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, placed).with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = json_output {
                fs::write(&path, serde_json::to_string_pretty(&result)?)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "placement score: {:.3} -> {:.3}; accepted moves: {}",
                result.initial_score.total, result.final_score.total, result.accepted_moves
            );
        }
        Command::Fabricate { input, output_dir } => {
            run_kicad_drc(&input)?;
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            run_kicad_export(
                &[
                    "pcb",
                    "export",
                    "gerbers",
                    "--layers",
                    "F.Cu,B.Cu,F.Mask,B.Mask,F.Silkscreen,B.Silkscreen,Edge.Cuts",
                    "--output",
                ],
                &output_dir,
                &input,
            )?;
            run_kicad_export(&["pcb", "export", "drill", "--output"], &output_dir, &input)?;
            eprintln!("manufacturing files written to {}", output_dir.display());
        }
    }
    Ok(())
}

fn input_descriptor(path: &Path, bytes: &[u8]) -> InputDescriptor {
    InputDescriptor {
        path: path.display().to_string(),
        bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn read_described_json<T: DeserializeOwned>(path: &Path) -> Result<(T, InputDescriptor)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok((value, input_descriptor(path, &bytes)))
}

fn render_comparison_summary(delta: &AnalysisDelta) -> String {
    let length_percent = delta
        .changes
        .total_length_percent
        .map_or_else(|| "n/a".to_string(), |value| format!("{value:+.2}%"));
    let mut summary = format!(
        "# pcbex analysis comparison\n\n\
         **Status:** {}\n\n\
         | Metric | Baseline | Current | Change |\n\
         |---|---:|---:|---:|\n\
         | Total route length (nm) | {} | {} | {:+} ({}) |\n\
         | Vias | {} | {} | {:+} |\n\
         | Bends | {} | {} | {:+} |\n\
         | Routed nets | {} | {} | {:+} |\n\
         | Unrouted nets | {} | {} | {:+} |\n\
         | Violations | {} | {} | {:+} |\n",
        if delta.is_regression() {
            "regressions found"
        } else {
            "no regressions"
        },
        delta.baseline.total_length_nm,
        delta.current.total_length_nm,
        delta.changes.total_length_nm,
        length_percent,
        delta.baseline.total_vias,
        delta.current.total_vias,
        delta.changes.total_vias,
        delta.baseline.total_bends,
        delta.current.total_bends,
        delta.changes.total_bends,
        delta.baseline.routed_nets,
        delta.current.routed_nets,
        delta.changes.routed_nets,
        delta.baseline.unrouted_nets,
        delta.current.unrouted_nets,
        delta.changes.unrouted_nets,
        delta.baseline.violations,
        delta.current.violations,
        delta.changes.violations,
    );
    if !delta.quality_regressions.is_empty() {
        summary.push_str("\n## Quality regressions\n\n");
        for regression in &delta.quality_regressions {
            summary.push_str(&format!("- {}\n", regression.replace(['\r', '\n'], " ")));
        }
    }
    append_violation_delta(&mut summary, "New violations", &delta.new_violations);
    append_violation_delta(
        &mut summary,
        "Resolved violations",
        &delta.resolved_violations,
    );
    summary
}

fn append_violation_delta(
    summary: &mut String,
    heading: &str,
    violations: &[pcbex_core::analysis::ViolationFingerprint],
) {
    if violations.is_empty() {
        return;
    }
    summary.push_str(&format!("\n## {heading}\n\n"));
    for violation in violations {
        summary.push_str(&format!(
            "- `{}`: {} (nets: {})\n",
            violation.rule,
            violation.message.replace(['\r', '\n'], " "),
            violation
                .net_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_analysis_summary(
    quality: &RoutingQuality,
    report: &pcbex_core::checking::CheckReport,
) -> String {
    let mut summary = format!(
        "# pcbex KiCad analysis\n\n\
         **Status:** {}\n\n\
         | Metric | Value |\n\
         |---|---:|\n\
         | Internal DRC/DFM violations | {} |\n\
         | Routed nets | {} |\n\
         | Unrouted nets | {} |\n\
         | Total route length (nm) | {} |\n\
         | Vias | {} |\n\
         | Bends | {} |\n",
        if report.is_clean() {
            "clean"
        } else {
            "violations found"
        },
        report.violations.len(),
        quality.routed_nets,
        quality.unrouted_nets,
        quality.total_length_nm,
        quality.total_vias,
        quality.total_bends,
    );
    if !report.violations.is_empty() {
        summary.push_str("\n## Violations\n\n");
        for violation in &report.violations {
            summary.push_str(&format!(
                "- `{}`: {}\n",
                violation.rule,
                violation.message.replace(['\r', '\n'], " ")
            ));
        }
    }
    summary
}

fn to_nm(mm: f64, name: &str) -> Result<i64> {
    if !mm.is_finite() || mm <= 0.0 {
        bail!("{name} must be a positive finite value")
    }
    Ok((mm * 1_000_000.0).round() as i64)
}

fn run_kicad_drc(board: &PathBuf) -> Result<()> {
    let report = board.with_extension("drc.rpt");
    let temp = std::env::temp_dir();
    let status = ProcessCommand::new("kicad-cli")
        .args(["pcb", "drc", "--exit-code-violations", "--output"])
        .arg(&report)
        .arg(board)
        .env("XDG_CONFIG_HOME", temp.join("pcbex-kicad-config"))
        .env("XDG_CACHE_HOME", temp.join("pcbex-kicad-cache"))
        .env("XDG_DATA_HOME", temp.join("pcbex-kicad-data"))
        .status()
        .context("running kicad-cli; install KiCad or omit --drc")?;
    if !status.success() {
        bail!(
            "KiCad DRC failed (status {status}); report: {}",
            report.display()
        )
    }
    eprintln!("KiCad DRC passed; report: {}", report.display());
    Ok(())
}

fn run_kicad_export(arguments: &[&str], output: &PathBuf, board: &PathBuf) -> Result<()> {
    let temp = std::env::temp_dir();
    let status = ProcessCommand::new("kicad-cli")
        .args(arguments)
        .arg(output)
        .arg(board)
        .env("XDG_CONFIG_HOME", temp.join("pcbex-kicad-config"))
        .env("XDG_CACHE_HOME", temp.join("pcbex-kicad-cache"))
        .env("XDG_DATA_HOME", temp.join("pcbex-kicad-data"))
        .status()
        .context("running kicad-cli manufacturing export")?;
    if !status.success() {
        bail!("KiCad manufacturing export failed with status {status}")
    }
    Ok(())
}

fn ensure_clean(board: &Board) -> Result<()> {
    let report = check_board(board);
    if report.is_clean() {
        return Ok(());
    }
    let summary = report
        .violations
        .iter()
        .take(8)
        .map(|v| format!("[{}] {}", v.rule, v.message))
        .collect::<Vec<_>>()
        .join("; ");
    bail!(
        "internal rule check found {} violation(s): {}",
        report.violations.len(),
        summary
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_completions_for_every_supported_shell() {
        for shell in [
            Shell::Bash,
            Shell::Elvish,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Zsh,
        ] {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            let mut output = Vec::new();
            generate(shell, &mut command, name, &mut output);
            let output = String::from_utf8(output).expect("completion output must be UTF-8");
            assert!(output.contains("pcbex"));
            assert!(output.contains("completion"));
        }
    }

    #[test]
    fn parses_impedance_width_solver_arguments() {
        let cli = Cli::try_parse_from([
            "pcbex",
            "impedance-width",
            "board.json",
            "--layer",
            "In1.Cu",
            "--target-ohms",
            "90",
            "--differential-gap-mm",
            "0.15",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::ImpedanceWidth {
                layer,
                target_ohms: 90.0,
                differential_gap_mm: Some(0.15),
                ..
            } if layer == "In1.Cu"
        ));
    }

    #[test]
    fn parses_impedance_report_output() {
        let cli = Cli::try_parse_from([
            "pcbex",
            "impedance-report",
            "board.json",
            "--output",
            "report.json",
            "--baseline",
            "baseline.json",
            "--fail-on-violations",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::ImpedanceReport {
                input,
                output: Some(output),
                baseline: Some(baseline),
                fail_on_violations: true
            } if input.as_os_str() == "board.json"
                && output.as_os_str() == "report.json"
                && baseline.as_os_str() == "baseline.json"
        ));
    }

    #[test]
    fn parses_analyze_kicad_artifact_options() {
        let cli = Cli::try_parse_from([
            "pcbex",
            "analyze-kicad",
            "board.kicad_pcb",
            "--output-dir",
            "analysis",
            "--project",
            "board.kicad_pro",
            "--rules-file",
            "board.kicad_dru",
            "--fab",
            "jlcpcb-2layer",
            "--fail-on-violations",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::AnalyzeKicad {
                input,
                project: Some(project),
                rules_file: Some(rules_file),
                output_dir,
                fab: Some(fab),
                fail_on_violations: true,
                ..
            } if input.as_os_str() == "board.kicad_pcb"
                && project.as_os_str() == "board.kicad_pro"
                && rules_file.as_os_str() == "board.kicad_dru"
                && fab == "jlcpcb-2layer"
                && output_dir.as_os_str() == "analysis"
        ));
    }

    #[test]
    fn resolves_fabrication_profile_aliases_with_versioned_identity() {
        let profile = resolve_dfm_profile(Some("pcbway-2layer")).unwrap().unwrap();
        assert_eq!(profile.id, "pcbway-standard-2layer-1oz-v1");
        assert!(resolve_dfm_profile(Some("missing-profile")).is_err());
    }

    #[test]
    fn input_descriptors_use_sha256() {
        let descriptor = input_descriptor(&PathBuf::from("board.kicad_pcb"), b"abc");
        assert_eq!(descriptor.bytes, 3);
        assert_eq!(
            descriptor.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn analysis_summary_reports_metrics_and_violations() {
        let quality = RoutingQuality {
            total_length_nm: 42,
            total_vias: 2,
            total_bends: 3,
            routed_nets: 1,
            unrouted_nets: 4,
            nets: vec![],
            differential_pairs: vec![],
        };
        let report = pcbex_core::checking::CheckReport {
            violations: vec![pcbex_core::checking::Violation {
                rule: "clearance".to_string(),
                message: "too close".to_string(),
                net_ids: vec![1],
            }],
        };

        let summary = render_analysis_summary(&quality, &report);
        assert!(summary.contains("violations found"));
        assert!(summary.contains("| Unrouted nets | 4 |"));
        assert!(summary.contains("- `clearance`: too close"));
    }

    #[test]
    fn parses_compare_analysis_regression_gate() {
        let cli = Cli::try_parse_from([
            "pcbex",
            "compare-analysis",
            "baseline",
            "current",
            "--output-dir",
            "comparison",
            "--fail-on-regressions",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Command::CompareAnalysis {
                baseline_dir,
                current_dir,
                output_dir,
                fail_on_regressions: true,
            } if baseline_dir.as_os_str() == "baseline"
                && current_dir.as_os_str() == "current"
                && output_dir.as_os_str() == "comparison"
        ));
    }
}
