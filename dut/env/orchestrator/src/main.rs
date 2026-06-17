//! tc8-orchestrator — Rust successor to `dut/env/smoke-test.sh`.
//!
//! Drives the TC8 conformance harness against a per-topology DUT, extracts the
//! verdict, and (later stages) aggregates JUnit and ports the per-case
//! conditioning from bash. Built incrementally (strangler): each stage absorbs
//! more of smoke-test.sh, with the bash original kept as the parity baseline
//! until the S8 CI cutover.
//!
//! Stage 1: CLI + single-pc topology + single-worker positive-case dispatch.
//! Stage 2: round-robin distribution across N parallel workers (per-worker
//! netns/symlink isolation, explicit join, execution ledger, non-conclusion
//! gate, signal-time + stale teardown).
//! Stage 3: native netns fixture — the `netns` module ports setup-netns.sh /
//! cleanup.sh (ip/sysctl/ethtool/neigh), retiring the shell-out.

mod cleanup;
mod config;
mod dispatch;
mod netns;
mod topology;
mod worker;

/// Verdict taxonomy generated from src/sce_integration/verdict_taxonomy.def —
/// the orchestrator derives the wire-names from the same single source as the
/// C++/bash/Python consumers. Regenerate: python3 tools/gen_verdict_taxonomy.py
mod taxonomy {
    include!("verdict_taxonomy.gen.rs");
}

use anyhow::{bail, Result};
use clap::Parser;
use std::env;
use std::fs;

use config::Config;
use topology::{SinglePc, Topology};
use worker::WorkerResult;

/// Orchestrate TC8 conformance cases against a DUT (smoke-test.sh successor).
///
/// Flags mirror smoke-test.sh exactly so the two can run side by side for
/// parity verification during the migration.
#[derive(Parser, Debug)]
#[command(name = "tc8-orchestrator", version, about, long_about = None)]
struct Cli {
    /// Topology profile: single-pc (per-worker netns), external, ssh-remote.
    #[arg(long, default_value = "single-pc")]
    topology: String,

    /// Additional site config applied after the profile.
    #[arg(long)]
    topology_conf: Option<String>,

    /// Parallel worker count (must be >= 1).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    workers: u32,

    /// Invert harness-first startup order (negative tests only).
    #[arg(long)]
    dut_first: bool,

    /// Run the curated negative validation rows instead of positive cases.
    #[arg(long)]
    negative: bool,

    /// Preserve per-case pcap + harness/dut logs in this directory.
    #[arg(long)]
    log_dir: Option<String>,

    /// Emit a JUnit XML report to this path.
    #[arg(long)]
    junit_xml: Option<String>,

    /// DUT-control backend for seam-routed cases.
    #[arg(long, value_parser = ["opcode", "testability"])]
    dut_control: Option<String>,

    /// Case IDs to run (default: SOMEIPSRV_FORMAT_01).
    cases: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cases: Vec<String> = if cli.cases.is_empty() {
        vec!["SOMEIPSRV_FORMAT_01".to_string()]
    } else {
        cli.cases.clone()
    };

    // Stage 2 scope: single-pc, positive cases. The flags below are parsed (CLI
    // parity with smoke-test.sh) but their behaviour lands in later stages —
    // fail loudly rather than silently ignoring them.
    if cli.topology != "single-pc" {
        bail!("Stage 1 supports only --topology single-pc (got '{}')", cli.topology);
    }
    if cli.negative {
        bail!("Stage 1 does not implement --negative yet");
    }
    if cli.topology_conf.is_some() || cli.log_dir.is_some() || cli.junit_xml.is_some()
        || cli.dut_control.is_some()
    {
        bail!("Stage 1 does not implement --topology-conf/--log-dir/--junit-xml/--dut-control yet");
    }

    let cfg = Config::resolve()?;
    // Reap leftovers from prior runs that died before cleanup (bash startup GC).
    cleanup::stale_gc(&cfg);
    fs::create_dir_all(&cfg.work_root)?;
    fs::create_dir_all(&cfg.vsomeip_base)?;

    let topo = SinglePc::new(&cfg);
    topo.preflight()?;

    // Cap the worker count at the schedule size — empty buckets would bring up
    // netns pairs for no work. Bash always brings up `--workers` netns; the cap
    // is a deliberate divergence, so surface it (never a silent reinterpretation).
    let workers = cli.workers.min(cases.len() as u32);
    if workers < cli.workers {
        eprintln!(
            "orchestrator: --workers {} capped to {} ({} case(s) scheduled)",
            cli.workers,
            workers,
            cases.len()
        );
    }

    // Tear workers down on SIGINT/SIGTERM (Drop does not run on signal exit).
    cleanup::install_signal_handler(&cfg, workers)?;

    let buckets = worker::distribute(&cases, workers);
    let results = worker::run_all(&cfg, &topo, buckets, cli.dut_first);

    let _ = fs::remove_dir_all(&cfg.work_root);
    let _ = fs::remove_dir_all(&cfg.vsomeip_base);

    summarize(&cli.topology, cases.len(), workers, &results)
}

/// Aggregate worker tallies, print the summary, and apply the gates: the
/// execution ledger (processed == scheduled) and the non-conclusion ceiling,
/// both ported from smoke-test.sh (lines 2959-3024).
fn summarize(topology: &str, total: usize, workers: u32, results: &[WorkerResult]) -> Result<()> {
    let mut fails: Vec<&str> = Vec::new();
    let mut skips: Vec<&worker::Skip> = Vec::new();
    let mut nonconcl: Vec<&worker::Skip> = Vec::new();
    let mut processed = 0usize;
    let mut worker_errors: Vec<&str> = Vec::new();
    for r in results {
        fails.extend(r.fails.iter().map(String::as_str));
        skips.extend(r.skips.iter());
        nonconcl.extend(r.nonconclusions.iter());
        processed += r.processed;
        if let Some(e) = &r.worker_error {
            worker_errors.push(e);
        }
    }

    println!(
        "orchestrator summary [topology={topology}]: {total} case(s), {} failure(s), {} skipped, {} non-conclusion(s) across {workers} worker(s)",
        fails.len(),
        skips.len(),
        nonconcl.len(),
    );
    for s in &skips {
        println!("  SKIP  {} — {}", s.case, s.reason);
    }
    for s in &nonconcl {
        println!("  SKIP* {} — {}  (non-conclusion / regression-watch)", s.case, s.reason);
    }

    // Execution-ledger cross-check — every scheduled case must have concluded.
    // A shortfall means a worker died mid-bucket; fail loudly rather than
    // reporting a clean summary over partial work.
    if processed != total {
        for e in &worker_errors {
            eprintln!("orchestrator: {e}");
        }
        eprintln!(
            "orchestrator: FATAL — scheduled {total} case(s) but only {processed} were processed; a worker terminated early. Treat every result above as suspect."
        );
        std::process::exit(1);
    }

    // Non-conclusion ceiling — a storm of inconclusive/error results is a
    // systemic environment/flake problem, not a clean pass; red the gate when it
    // is systemic. Thresholds env-overridable, same defaults/semantics as bash
    // (TC8_MAX_NONCONCLUSION_PCT=5, TC8_MIN_NONCONCLUSION_FAIL=3). Positive-run
    // detector; the negative set (later stage) gates differently.
    if !nonconcl.is_empty() {
        let max_pct = env_usize("TC8_MAX_NONCONCLUSION_PCT", 5);
        let min_fail = env_usize("TC8_MIN_NONCONCLUSION_FAIL", 3);
        eprintln!(
            "orchestrator: {}/{total} case(s) reached a non-conclusion (inconclusive/error) — routed to skip so they did not red the gate, but they are NOT clean passes; a previously-passing case now skipping is a regression signal.",
            nonconcl.len()
        );
        if nonconcl.len() >= min_fail && nonconcl.len() * 100 > total * max_pct {
            eprintln!(
                "orchestrator: FATAL — non-conclusion rate {}/{total} exceeds the {max_pct}% ceiling (floor {min_fail}); systemic, not isolated noise. Investigate before trusting the green skips.",
                nonconcl.len()
            );
            std::process::exit(1);
        }
    }

    if !fails.is_empty() {
        for f in &fails {
            eprintln!("  FAIL {f}");
        }
        std::process::exit(1);
    }
    Ok(())
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
