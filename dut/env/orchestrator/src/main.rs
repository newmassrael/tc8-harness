//! tc8-orchestrator — Rust successor to `dut/env/smoke-test.sh`.
//!
//! Drives the TC8 conformance harness against a per-topology DUT, extracts the
//! verdict, and (later stages) parallelises workers, aggregates JUnit, and
//! ports the netns/conditioning logic from bash. Built incrementally
//! (strangler): early stages shell out to the proven bash helpers
//! (`setup-netns.sh`, `cleanup.sh`); later stages replace them with Rust.
//!
//! Stage 1: CLI + single-pc topology + single-worker positive-case dispatch.

mod config;
mod dispatch;
mod topology;

use anyhow::{bail, Result};
use clap::Parser;
use std::fs;

use config::Config;
use dispatch::Verdict;
use topology::{SinglePc, Topology};

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

    // Stage 1 scope: single-pc, single worker, positive cases. The flags below
    // are parsed (CLI parity with smoke-test.sh) but their behaviour lands in
    // later stages — fail loudly rather than silently ignoring them.
    if cli.topology != "single-pc" {
        bail!("Stage 1 supports only --topology single-pc (got '{}')", cli.topology);
    }
    if cli.workers != 1 {
        bail!("Stage 1 supports only --workers 1 (got {})", cli.workers);
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
    fs::create_dir_all(&cfg.work_root)?;
    fs::create_dir_all(&cfg.vsomeip_base)?;

    let topo = SinglePc::new(&cfg);
    topo.preflight()?;
    let ctx = topo.bring_up_worker(0)?;

    let mut fails = 0usize;
    let mut skips = 0usize;
    for case in &cases {
        match dispatch::run_case(&cfg, &topo, 0, &ctx, case, cli.dut_first)? {
            Verdict::Pass => println!("[w0] PASS {case}"),
            Verdict::Skip(reason) => {
                println!("[w0] SKIP {case} — {reason}");
                skips += 1;
            }
            Verdict::Fail(reason) => {
                println!("[w0] FAIL {case} — {reason}");
                fails += 1;
            }
        }
    }

    topo.tear_down_worker(0).ok();
    let _ = fs::remove_dir_all(&cfg.work_root);
    let _ = fs::remove_dir_all(&cfg.vsomeip_base);

    println!(
        "orchestrator summary [topology={}]: {} case(s), {} failure(s), {} skipped",
        cli.topology,
        cases.len(),
        fails,
        skips
    );
    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}
