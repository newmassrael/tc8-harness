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
//! Stage 4: per-case conditioning — the `conditioning` module data-tables the
//! case-keyed sysctl/neigh toggles run_case applies, driven via a Topology seam.
//! Stage 5a: external / ssh-remote topologies — TOML site config (`site`), the
//! two new `Topology` impls, the contract gates, and the netns/ssh verification
//! fixtures (`fixtures`) that stand up a DUT for self-hosted parity.
//! Stage 5b: the first-class `lwip-tap` topology (`fixtures::lwip_tap`) — a host
//! tap + a per-case-respawning lwIP embedded-stack DUT, mirroring the bash
//! `topology.d/lwip-tap.conf` profile so both drivers share one dispatch axis.

mod cleanup;
mod conditioning;
mod config;
mod dispatch;
mod fixtures;
mod netns;
mod site;
mod topology;
mod worker;

/// Wire/fixture constants generated from tools/wire.def — the
/// orchestrator shares one source with the C++ stimulus builders and the bash
/// smoke-test profiles, cross-checked against the C++ headers by the generator.
/// Regenerate: python3 tools/gen_wire_manifest.py
///
/// `allow(dead_code)`: this is a generated cross-LANGUAGE constants SSOT — the
/// Rust side consumes a subset; values that are bash-only today (the Topology-2
/// secondary IPs, used by setup-netns.sh/smoke-test.sh until USAGE_01 is ported
/// to the orchestrator) are still emitted here so the one source stays whole.
#[allow(dead_code)]
mod wire {
    include!("wire.gen.rs");
}

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
use std::path::Path;

use config::Config;
use site::SiteConf;
use topology::{External, SinglePc, SshRemote, Topology};
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

    /// Print the resolved static `--expect` identity (sorted key=value) and exit,
    /// without standing up any fixture. Used by parity-check.sh to diff value-level
    /// identity against bash smoke-test.sh's `--print-expect`.
    #[arg(long)]
    print_expect: bool,

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

    let topology = cli.topology.as_str();
    if !matches!(topology, "single-pc" | "external" | "ssh-remote" | "lwip-tap") {
        bail!("--topology '{topology}' is not recognised (single-pc | external | ssh-remote | lwip-tap)");
    }
    // Flags parsed for CLI parity with smoke-test.sh but not yet ported — fail
    // loudly, never silently ignore. (Stage-agnostic wording: a stage number in a
    // user-facing string goes stale every stage.)
    if cli.log_dir.is_some() || cli.junit_xml.is_some() || cli.dut_control.is_some() {
        bail!("--log-dir/--junit-xml/--dut-control not yet implemented");
    }

    let mut cfg = Config::resolve()?;

    // Site config (TOML --topology-conf). external/ssh-remote REQUIRE it — their
    // iface / wire IPs / remote paths live there, and sudo strips the environment.
    // single-pc and lwip-tap derive their wire identity from fixed defaults and may
    // omit the conf entirely (lwip-tap's optional [lwip] section only overrides the
    // standalone-UTM binary / probe / kill-name).
    let site = match &cli.topology_conf {
        Some(path) => SiteConf::load(Path::new(path), topology, &cfg.root)?,
        None => {
            if !matches!(topology, "single-pc" | "lwip-tap") {
                bail!("--topology {topology} requires --topology-conf (iface/dut_ip/tester_ip live there; sudo strips the environment)");
            }
            SiteConf::default()
        }
    };
    // The site's wire IPs (when present) override the defaults Config resolved, so
    // expect_args + the conditioning-skip log see the real tester/DUT addresses.
    if let Some(ip) = &site.tester_ip {
        cfg.tester_ip4 = ip.clone();
    }
    if let Some(ip) = &site.dut_ip {
        cfg.dut_ip4 = ip.clone();
    }

    // Build the topology as a trait object so one worker fan-out drives them all.
    // lwip-tap is its own first-class topology (LwipTap): the lwIP embedded-stack DUT
    // needs a fixture-owned per-case respawn (drain → SIGTERM-slot-abort → respawn)
    // a persistent External does not do; it self-provisions the tap + DUT in
    // bring_up_worker and reaps them in tear_down_worker.
    let topo: Box<dyn Topology + Sync> = match topology {
        "single-pc" => Box::new(SinglePc::new(&cfg)),
        "lwip-tap" => Box::new(fixtures::LwipTap::new(&cfg, &site)),
        "external" => Box::new(External::new(&cfg, &site)),
        "ssh-remote" => Box::new(SshRemote::new(&cfg, &site)),
        _ => unreachable!("topology validated above"),
    };

    // --print-expect: dump the resolved per-case-invariant --expect identity and exit
    // BEFORE any fixture/root work, so parity-check.sh can diff value-level identity
    // between the two drivers unprivileged (disposition tokens alone are blind to it).
    // Built after the topology so the dump includes the topology's UT ARP-cache expect
    // exactly as run_case does (lwip-tap), matching bash's static --expect surface.
    if cli.print_expect {
        dispatch::print_static_identity(&cfg, topo.ut_arp_cache_timeout().as_deref());
        return Ok(());
    }

    // Contract gates (smoke-test.sh) — BEFORE provisioning a fixture, so a
    // rejected invocation never executes side-effectful host setup.
    if cli.negative {
        if !topo.supports_negative() {
            bail!("--negative requires a topology with a spawned reference DUT (deliberate mis-expectations + start-order control); topology '{topology}' does not support it");
        }
        bail!("--negative not yet implemented");
    }
    if cli.dut_first && !topo.supports_dut_spawn() {
        bail!("--dut-first controls DUT-vs-harness start order, but topology '{topology}' does not spawn the DUT");
    }
    if let Some(max) = topo.max_workers() {
        if cli.workers > max {
            bail!("--workers {} exceeds topology '{topology}' limit of {max} (one shared physical/remote DUT cannot serve parallel workers)", cli.workers);
        }
    }

    // Side effects begin only after the gates pass (a rejected invocation leaves no
    // scratch and no fixture). Reap leftovers from prior runs that died before
    // cleanup (bash startup GC), then create this run's scratch roots.
    cleanup::stale_gc(&cfg);
    fs::create_dir_all(&cfg.work_root)?;
    fs::create_dir_all(&cfg.vsomeip_base)?;

    // Cap the worker count at the schedule size — empty buckets would bring up
    // resources for no work. A deliberate divergence from bash, so surface it
    // (never a silent reinterpretation). The MAX_WORKERS gate above already
    // rejected an over-cap request for external/ssh-remote.
    let workers = cli.workers.min(cases.len() as u32);
    if workers < cli.workers {
        eprintln!(
            "orchestrator: --workers {} capped to {} ({} case(s) scheduled)",
            cli.workers,
            workers,
            cases.len()
        );
    }

    // Install the signal handler BEFORE provisioning the fixture and running
    // preflight: both touch host state (fixture netns/sshd/DUT; the ssh-remote
    // preflight spawns a transient remote DUT and sleeps), and a SIGINT/SIGTERM in
    // that window bypasses every Drop — so without an early handler it would leak.
    // The handler is idempotent and no-ops on absent state (a not-yet-provisioned
    // or partially-provisioned fixture is safely reclaimed by teardown_by_kind), so
    // installing it early is sound. It composes the teardown the per-worker reap
    // cannot do: the ssh-remote remote DUT (owned ssh params — the handler cannot
    // borrow the topology) then the verification fixture.
    let ssh_reap: Option<(String, Option<String>)> = if topology == "ssh-remote" {
        Some((site.require("ssh_target").to_string(), site.ssh_opts.clone()))
    } else {
        None
    };
    let fixture_kind: Option<String> = site.fixture.as_ref().map(|f| f.kind.clone());
    // Resolve the lwip-tap kill name HERE (the closure cannot borrow the topology)
    // so the abort path reaps exactly the configured process, not a stale literal.
    let lwip_signal_kill: Option<String> = if topology == "lwip-tap" {
        Some(fixtures::lwip_tap::resolve_kill_name(&site))
    } else {
        None
    };
    cleanup::install_signal_handler(&cfg, workers, move || {
        if let Some((target, opts)) = &ssh_reap {
            topology::ssh_reap_remote_dut(target, opts.as_deref());
        }
        if let Some(kill) = &lwip_signal_kill {
            fixtures::lwip_signal_teardown(kill);
        }
        if let Some(kind) = &fixture_kind {
            fixtures::teardown_by_kind(kind);
        }
    })?;

    // Provision the verification fixture (if any) BEFORE preflight — preflight
    // probes the DUT the fixture stands up. The guard tears it down on Drop
    // (normal/panic); the handler installed above covers SIGINT/SIGTERM. The
    // lwip-tap topology needs no fixture: LwipTap self-provisions the tap + DUT in
    // bring_up_worker and reaps them in tear_down_worker (a `[fixture]` block is
    // only ever netns-dut/ssh-netns-dut, enforced by SiteConf::validate).
    let _fixture = match &site.fixture {
        Some(spec) => Some(fixtures::provision(spec, &cfg)?),
        None => None,
    };

    topo.preflight()?;

    let buckets = worker::distribute(&cases, workers);
    let results = worker::run_all(&cfg, topo.as_ref(), buckets, cli.dut_first);

    let _ = fs::remove_dir_all(&cfg.work_root);
    let _ = fs::remove_dir_all(&cfg.vsomeip_base);

    summarize(topology, cases.len(), workers, &results)
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
        // bail! (not process::exit) so main unwinds normally and the runtime sets
        // the non-zero exit — the scratch cleanup already ran before summarize, and
        // no destructor is bypassed.
        bail!(
            "FATAL — scheduled {total} case(s) but only {processed} were processed; a worker terminated early. Treat every result above as suspect."
        );
    }

    // Non-conclusion ceiling — a storm of inconclusive/error results is a
    // systemic environment/flake problem, not a clean pass; red the gate when it
    // is systemic. Thresholds env-overridable, same defaults/semantics as bash
    // (TC8_MAX_NONCONCLUSION_PCT=5, TC8_MIN_NONCONCLUSION_FAIL=3). Positive-run
    // detector; the negative set (later stage) gates differently.
    if !nonconcl.is_empty() {
        let max_pct = env_usize("TC8_MAX_NONCONCLUSION_PCT", 5)?;
        let min_fail = env_usize("TC8_MIN_NONCONCLUSION_FAIL", 3)?;
        eprintln!(
            "orchestrator: {}/{total} case(s) reached a non-conclusion (inconclusive/error) — routed to skip so they did not red the gate, but they are NOT clean passes; a previously-passing case now skipping is a regression signal.",
            nonconcl.len()
        );
        if nonconcl.len() >= min_fail && nonconcl.len() * 100 > total * max_pct {
            bail!(
                "FATAL — non-conclusion rate {}/{total} exceeds the {max_pct}% ceiling (floor {min_fail}); systemic, not isolated noise. Investigate before trusting the green skips.",
                nonconcl.len()
            );
        }
    }

    if !fails.is_empty() {
        for f in &fails {
            eprintln!("  FAIL {f}");
        }
        bail!("{} conformance failure(s) — see the FAIL line(s) above", fails.len());
    }
    Ok(())
}

/// An unset env var falls back to `default`; a SET-but-unparseable one is a hard
/// error (matches bash smoke-test.sh, and the crate's fail-loud config
/// philosophy — a typo'd tuning knob must not silently take the default).
fn env_usize(key: &str, default: usize) -> Result<usize> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(s) => s
            .parse()
            .map_err(|_| anyhow::anyhow!("env {key}='{s}' must be a non-negative integer")),
    }
}
