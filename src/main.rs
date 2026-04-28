use anyhow::Context;
use colored::Colorize;
use regex::Regex;
use risc0_crypto_shootout::GUEST_ELF;
use risc0_zkvm::{ExecutorEnv, default_executor};
use std::{collections::HashMap, fmt::Write as _, sync::LazyLock};
use tabular::{Row, Table};
use thousands::Separable;

/// Matches cycle markers: `R0VM[{cycle}] cycle-(start|end): {topic}`
///
/// Topics may carry an iteration suffix `*N` (e.g. `eip2537/msm/128*10`).
/// When present the host divides the total cycles by N and displays the per-op cost.
static CYCLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"R0VM\[(\d+)\] cycle-(start|end): (.+)").unwrap());

/// The reference implementation; counterpart libraries are paired against this.
const REFERENCE: &str = "risc0-crypto";

/// Embedded at compile time so we can report the exact `risc0-crypto` git rev
/// that produced these numbers.
const GUEST_CARGO_TOML: &str = include_str!("../guest/Cargo.toml");

/// Extract `(repo_url, rev)` for the `risc0-crypto` dependency.
fn risc0_crypto_source() -> Option<(&'static str, &'static str)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"risc0-crypto\s*=\s*\{[^}]*git\s*=\s*"([^"]+)"[^}]*rev\s*=\s*"([^"]+)""#)
            .unwrap()
    });
    let caps = RE.captures(GUEST_CARGO_TOML)?;
    Some((caps.get(1)?.as_str(), caps.get(2)?.as_str()))
}

#[derive(serde::Serialize)]
struct BenchResult {
    name: String,
    unit: &'static str,
    value: u64,
}

fn main() -> anyhow::Result<()> {
    let json_path = parse_flag("--json");
    let markdown_path = parse_flag("--markdown");

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

    if let Some(path) = markdown_path {
        write_markdown(&results, &path)?;
        println!("Markdown results written to {path}");
    }

    Ok(())
}

/// Parse `--<name> <value>` from command-line arguments.
fn parse_flag(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
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

/// Write a head-to-head markdown comparison: risc0-crypto vs counterpart per benchmark.
///
/// Topics are split on the last `/` into a `benchmark` prefix and an `impl` suffix.
/// Rows where the same benchmark has both `risc0-crypto` and a counterpart are paired up;
/// unpaired rows are skipped (e.g. `overhead/log`).
fn write_markdown(results: &[BenchResult], path: &str) -> anyhow::Result<()> {
    // Map benchmark -> (impl -> cycles), preserving first-seen benchmark order.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for r in results {
        let Some((benchmark, impl_name)) = r.name.rsplit_once('/') else { continue };
        let entry = groups.entry(benchmark.to_string()).or_insert_with(|| {
            order.push(benchmark.to_string());
            HashMap::new()
        });
        entry.insert(impl_name.to_string(), r.value);
    }

    let mut md = String::new();
    writeln!(md, "| Benchmark | risc0-crypto | Counterpart | Library | Ratio |")?;
    writeln!(md, "|-----------|-------------:|------------:|---------|------:|")?;

    for benchmark in &order {
        let entries = &groups[benchmark];
        let Some(&ours) = entries.get(REFERENCE) else { continue };
        let Some((lib, &theirs)) = entries.iter().find(|(k, _)| k.as_str() != REFERENCE) else {
            continue;
        };
        let ratio = theirs as f64 / ours as f64;
        writeln!(
            md,
            "| `{benchmark}` | {} | {} | `{lib}` | {ratio:.2}× |",
            ours.separate_with_commas(),
            theirs.separate_with_commas(),
        )?;
    }

    if let Some((repo, rev)) = risc0_crypto_source() {
        let short = &rev[..rev.len().min(8)];
        let repo_trimmed = repo.trim_end_matches(".git");
        writeln!(md)?;
        writeln!(md, "_risc0-crypto rev [`{short}`]({repo_trimmed}/commit/{rev})_")?;
    }

    std::fs::write(path, md)?;
    Ok(())
}
