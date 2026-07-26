use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use pcbex_core::checking::{check_board, check_manufacturability, check_report_to_sarif};
use pcbex_core::placement::{PlacementOptions, PlacementProblem, place};
use pcbex_core::{
    Board, Rules, board_json_schema, migrate_board_json, parse_board_json, render_svg, route_board,
};
use pcbex_kicad::{apply_project_net_settings, import as import_kicad};
use std::{fs, io, path::PathBuf, process::Command as ProcessCommand};

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

#[derive(Subcommand)]
enum Command {
    /// Generate shell completion definitions on standard output.
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Print the current board JSON Schema.
    Schema {
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
    /// Route a placed KiCad board across its declared copper layers.
    RouteKicad {
        input: PathBuf,
        /// KiCad project settings. Defaults to the input's sibling `.kicad_pro` when present.
        #[arg(long)]
        project: Option<PathBuf>,
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
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
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
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(shell, &mut command, name, &mut io::stdout());
        }
        Command::Schema { output } => {
            let schema = serde_json::to_string_pretty(&board_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
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
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; escaped nets: {}; optimized segments: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.escaped_nets,
                report.optimized_segments,
                report.expanded_states,
                report.reroute_passes
            );
            if !allow_unrouted && !report.unrouted.is_empty() {
                bail!("unrouted nets: {}", report.unrouted.join(", "))
            }
            ensure_clean(&board)?;
        }
        Command::RouteKicad {
            input,
            project,
            output,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
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
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; escaped nets: {}; optimized segments: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.escaped_nets,
                report.optimized_segments,
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
            output,
            format,
        } => {
            let board = read(&input)?;
            if board.manufacturing_rules.is_none() {
                bail!("board does not define manufacturing_rules")
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
}
