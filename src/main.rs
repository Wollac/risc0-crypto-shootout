use anyhow::Context;
use colored::Colorize;
use regex::Regex;
use risc0_crypto_shootout::GUEST_ELF;
use risc0_zkvm::{ExecutorEnv, default_executor};
use std::{collections::HashMap, sync::LazyLock};
use tabular::{Row, Table};
use thousands::Separable;

/// Matches cycle markers: `R0VM[{cycle}] cycle-(start|end): {topic}`
///
/// Topics may carry an iteration suffix `*N` (e.g. `eip2537/msm/128*10`).
/// When present the host divides the total cycles by N and displays the per-op cost.
static CYCLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"R0VM\[(\d+)\] cycle-(start|end): (.+)").unwrap());

#[derive(serde::Serialize)]
struct BenchResult {
    name: String,
    unit: &'static str,
    value: u64,
}

fn main() -> anyhow::Result<()> {
    let json_path = parse_json_flag();

    let mut out = Vec::new();
    let env = ExecutorEnv::builder().stdout(&mut out).build()?;

    println!("Running benchmarks in the guest...");
    let _ = default_executor().execute(env, GUEST_ELF)?;
    let stdout = String::from_utf8(out).context("guest stdout was not valid UTF-8")?;

    let results = parse_results(&stdout)?;
    print_table(&results);

    if let Some(path) = json_path {
        write_json(&results, &path)?;
        println!("\nJSON results written to {path}");
    }

    Ok(())
}

/// Parse `--json <path>` from command-line arguments.
fn parse_json_flag() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2).find(|w| w[0] == "--json").map(|w| w[1].clone())
}

/// Splits a topic like `"eip2537/msm/128*10"` into `("eip2537/msm/128", 10)`.
/// Topics without `*N` return a divisor of 1.
fn parse_topic(topic: &str) -> (&str, u64) {
    match topic.rsplit_once('*') {
        Some((name, n)) => match n.parse::<u64>() {
            Ok(d) if d > 0 => (name, d),
            _ => (topic, 1),
        },
        None => (topic, 1),
    }
}

/// Parse guest stdout into structured benchmark results.
fn parse_results(out: &str) -> anyhow::Result<Vec<BenchResult>> {
    let mut starts: HashMap<&str, u64> = HashMap::new();
    let mut results = Vec::new();

    for (_, [cycle_count, cmd, topic]) in CYCLE_RE.captures_iter(out).map(|c| c.extract()) {
        let cycle_count: u64 = cycle_count.parse()?;
        match cmd {
            "start" => {
                starts.insert(topic, cycle_count);
            }
            "end" => {
                if let Some(start) = starts.remove(topic) {
                    let (name, divisor) = parse_topic(topic);
                    results.push(BenchResult {
                        name: name.to_string(),
                        unit: "cycles",
                        value: (cycle_count - start) / divisor,
                    });
                }
            }
            _ => unreachable!(),
        }
    }

    for topic in starts.keys() {
        eprintln!("warning: unmatched start for {topic}");
    }

    Ok(results)
}

/// Render results as a human-readable table with grouping.
fn print_table(results: &[BenchResult]) {
    let mut table = Table::new("{:<}  {:>} cycles");
    let mut last_group: Option<&str> = None;

    for r in results {
        let group = r.name.rsplit_once('/').map(|x| x.0).unwrap_or(&r.name);
        if last_group.is_some() && last_group != Some(group) {
            table.add_heading("");
        }
        last_group = Some(group);
        table.add_row(
            Row::new().with_cell(r.name.green()).with_cell(r.value.separate_with_commas()),
        );
    }

    println!("{table}");
}

/// Write results as JSON in the `customSmallerIsBetter` format for
/// github-action-benchmark.
fn write_json(results: &[BenchResult], path: &str) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    Ok(())
}
