//! tc8-orchestrator — Rust successor to the retired bash smoke-test driver.
//!
//! Drives the TC8 conformance harness against a per-topology DUT, extracts the
//! verdict, and aggregates JUnit. Built incrementally (strangler): each stage
//! absorbed more of smoke-test.sh.
//!
//! THE STRANGLER IS FINISHED. The bash driver was deleted at the S8
//! cutover and this binary is the sole CI driver; there is no bash baseline left
//! to stay in parity with. The stage list below is kept as the record of how the
//! port was sequenced — it explains why the modules are shaped the way they are —
//! but nothing in it is pending. Comments elsewhere that spoke of the bash
//! original as a live SSOT were true once and are not now.
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
//! Stage 5b: the first-class `lwip-tap` topology (`topology::lwip_tap`) — a host
//! tap + a per-case-respawning lwIP embedded-stack DUT, mirroring the bash
//! `topology.d/lwip-tap.conf` profile so both drivers share one dispatch axis.

mod case_token;
mod cleanup;
mod conditioning;
mod config;
mod dispatch;
mod dut_variant;
mod fixtures;
mod junit;
mod netns;
mod proc;
mod site;
mod source_digest;
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

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;

use config::Config;
use site::{ResolvedSite, TopologyConf, TopologyKind};
use topology::{External, SinglePc, SshRemote, Topology};
use worker::WorkerResult;

/// Orchestrate TC8 conformance cases against a DUT (smoke-test.sh successor).
///
/// Flags mirror smoke-test.sh exactly so the two can run side by side for
/// parity verification during the migration.
#[derive(Parser, Debug)]
#[command(name = "tc8-orchestrator", version, about, long_about = None)]
struct Cli {
    /// Topology profile: single-pc (per-worker netns), external, ssh-remote,
    /// lwip-tap. clap parses the value into `TopologyKind`, so an unrecognised
    /// selector is rejected at parse time — the valid set lives in the enum alone.
    #[arg(long, default_value_t = TopologyKind::SinglePc)]
    topology: TopologyKind,

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

    /// Run the registered platform known-fails and assert each lands its registered
    /// verdict. Nothing is injected — the platform's own deviation produces it — so this
    /// is what stops `--exclude-platform-known-fail` from letting a stale registration
    /// rot unobserved.
    #[arg(long, conflicts_with = "negative")]
    known_fail: bool,

    /// Preserve per-case pcap + harness/dut logs in this directory.
    #[arg(long)]
    log_dir: Option<String>,

    /// Emit a JUnit XML report to this path.
    #[arg(long)]
    junit_xml: Option<String>,

    /// DUT-control backend for seam-routed cases.
    #[arg(long, value_parser = ["opcode", "testability"])]
    dut_control: Option<String>,

    /// The harness's inventory overrides file (default: the harness's own,
    /// docs/spec/inventory_overrides.json). Passed to every harness call that
    /// reads the inventory, so a consumer's DUT platform file reaches them all.
    #[arg(long)]
    inventory_overrides: Option<String>,

    /// An injected suite's inventory, the harness's `--inventory-extra`
    /// (repeatable). Passed with the overrides file to every harness call that
    /// reads the inventory, so a `suite:ID` overrides entry has a case to apply to.
    #[arg(long)]
    inventory_extra: Vec<String>,

    /// Print the resolved static `--expect` identity (sorted key=value) and exit,
    /// without standing up any fixture. Used by parity-check.sh to diff value-level
    /// identity against bash smoke-test.sh's `--print-expect`.
    #[arg(long)]
    print_expect: bool,

    /// Case IDs to run (default: SOMEIPSRV_FORMAT_01).
    cases: Vec<String>,
}

/// Overlay the site's caller-specified-IP aliases onto the run identity, leaving
/// the wire.def defaults in place for whichever the site did not name. Only the
/// host-NIC topologies reach this: single-pc and lwip-tap build the aliases
/// themselves, so their configured value IS the wire constant and there is
/// nothing to override.
fn apply_alias_overrides(cfg: &mut Config, wire: &site::WireSite) {
    if let Some(ip) = &wire.dut_alias_ip {
        cfg.dut_alias_ip4 = ip.clone();
    }
    if let Some(ip) = &wire.tester_alias_ip {
        cfg.tester_alias_ip4 = ip.clone();
    }
}

/// The source tree this binary was compiled from, and what `build.rs` recorded
/// about it (the `source_digest` module says why the binary checks it).
const SOURCE_DIR: &str = env!("CARGO_MANIFEST_DIR");
const BUILT_DIGEST: &str = env!("TC8_ORCH_SOURCE_DIGEST");
const BUILT_COMMIT: &str = env!("TC8_ORCH_BUILD_COMMIT");

/// Refuses to run a binary that is older than the sources it was built from.
///
/// The tree checked is the one the binary was compiled in, so the rebuild
/// command names the consumer's own path when the consumer built it. A binary
/// copied away from its tree has nothing to compare against; that is said, and
/// the check is skipped rather than guessed.
fn refuse_a_stale_binary() -> Result<()> {
    let dir = Path::new(SOURCE_DIR);
    if !dir.join("Cargo.toml").is_file() {
        eprintln!(
            "note: the orchestrator's source tree {SOURCE_DIR} is not here, so whether \
             this binary matches it is not checked"
        );
        return Ok(());
    }
    let now = source_digest::digest(dir)
        .with_context(|| format!("digesting the orchestrator's sources in {SOURCE_DIR}"))?;
    match stale_binary_refusal(&now, &source_head(dir)) {
        Some(refusal) => bail!("{refusal}"),
        None => Ok(()),
    }
}

/// The commit the source tree is at now. The orchestrator runs under sudo, and
/// git refuses a repository owned by another user unless told it is safe; this
/// only reads HEAD.
fn source_head(dir: &Path) -> String {
    std::process::Command::new("git")
        .args(["-c", "safe.directory=*", "-C"])
        .arg(dir)
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The refusal for a binary whose baked digest differs from `now`, naming both
/// commits (a pin bump shows up as exactly that difference) and the command
/// that rebuilds this binary in this tree with this profile.
fn stale_binary_refusal(now: &str, head: &str) -> Option<String> {
    if now == BUILT_DIGEST {
        return None;
    }
    let profile = if cfg!(debug_assertions) { "" } else { " --release" };
    Some(format!(
        "this tc8-orchestrator binary is older than its sources, so it does not do what \
         they say\n  sources:     {SOURCE_DIR}\n  built from:  {BUILT_COMMIT}\n  \
         sources now: {head}\n  rebuild:     cargo build{profile} --manifest-path \
         {SOURCE_DIR}/Cargo.toml"
    ))
}

fn main() -> Result<()> {
    refuse_a_stale_binary()?;
    let cli = Cli::parse();
    let mut cases: Vec<String> = if cli.cases.is_empty() {
        vec!["SOMEIPSRV_FORMAT_01".to_string()]
    } else {
        cli.cases.clone()
    };

    // clap parsed --topology into a TopologyKind (Copy), so the valid set is
    // enforced at parse time — no stringly-typed re-validation here.
    let topology = cli.topology;
    let mut cfg = Config::resolve()?;
    // Run-level CLI knobs consumed deep in dispatch — set on Config right after
    // resolve, parallel to extra_expect (which main also populates post-resolve).
    cfg.log_dir = cli.log_dir.as_deref().map(std::path::PathBuf::from);
    cfg.dut_control = cli.dut_control.clone();
    // Checked and absolutised here, before any harness call
    // (config::resolve_inventory_file).
    if let Some(p) = &cli.inventory_overrides {
        cfg.inventory_overrides = Some(config::resolve_inventory_file("--inventory-overrides", p)?);
    }
    cfg.inventory_extra = cli
        .inventory_extra
        .iter()
        .map(|p| config::resolve_inventory_file("--inventory-extra", p))
        .collect::<Result<_>>()?;
    if let Some(dir) = &cfg.log_dir {
        fs::create_dir_all(dir)
            .with_context(|| format!("creating --log-dir {}", dir.display()))?;
    }

    // Site config (TOML --topology-conf). external/ssh-remote REQUIRE it — their
    // iface / wire IPs / remote paths live there, and sudo strips the environment.
    // single-pc and lwip-tap derive their wire identity from fixed defaults and may
    // omit the conf entirely (lwip-tap's optional [lwip] section only overrides the
    // standalone-UTM binary / probe / kill-name).
    // The site's extra_expect is cross-cutting run identity (like the wire IPs
    // below), so it moves into cfg; `site` then names the typed per-topology conf.
    let ResolvedSite { conf: site, extra_expect, no_multicast_membership } =
        TopologyConf::load(cli.topology_conf.as_deref().map(Path::new), topology, &cfg.root)?;
    cfg.extra_expect = extra_expect;
    cfg.no_multicast_membership = no_multicast_membership;
    // The site's wire IPs override the defaults Config resolved, so expect_args + the
    // conditioning-skip log see the real tester/DUT addresses. lwip-tap is wire-fixed
    // — its variant carries no IP field, so it structurally cannot override (the flat
    // struct used to let a stray lwip-tap dut_ip clobber the default).
    match &site {
        TopologyConf::SinglePc { tester_ip, dut_ip, .. } => {
            if let Some(ip) = tester_ip {
                cfg.tester_ip4 = ip.clone();
            }
            if let Some(ip) = dut_ip {
                cfg.dut_ip4 = ip.clone();
            }
        }
        TopologyConf::External(e) => {
            cfg.tester_ip4 = e.wire.tester_ip.clone();
            cfg.dut_ip4 = e.wire.dut_ip.clone();
            apply_alias_overrides(&mut cfg, &e.wire);
        }
        TopologyConf::SshRemote(s) => {
            cfg.tester_ip4 = s.wire.tester_ip.clone();
            cfg.dut_ip4 = s.wire.dut_ip.clone();
            apply_alias_overrides(&mut cfg, &s.wire);
        }
        TopologyConf::LwipTap { .. } => {}
    }

    // Build the topology as a trait object so one worker fan-out drives them all.
    // lwip-tap is its own first-class topology (LwipTap): the lwIP embedded-stack DUT
    // needs a fixture-owned per-case respawn (drain → SIGTERM-slot-abort → respawn)
    // a persistent External does not do; it self-provisions the tap + DUT in
    // provision_run and reaps them in teardown_run.
    // The requires_secondary_iface set (harness axis). Stored on cfg so run_case can
    // pass --interface-secondary per-case; single-pc also provisions the second veth
    // pair only when a SCHEDULED case is in it (bash's sticky NEED_SECOND_VETH), so
    // the common single-pair run pays nothing. ONLY for actual case runs: it shells
    // the harness, and --print-expect must stay a pure identity dump with no harness
    // dependency (the flag it feeds is unused on that path — the topology's
    // ut_arp_cache_timeout is all --print-expect reads).
    let schedule_needs_secondary = if cli.print_expect {
        false
    } else {
        cfg.secondary_iface_cases = list_secondary_iface_cases(&cfg)?;
        cases
            .iter()
            .any(|c| cfg.secondary_iface_cases.contains(&c.to_uppercase()))
    };

    let topo: Box<dyn Topology + Sync> = match &site {
        TopologyConf::SinglePc { dut, .. } => {
            Box::new(SinglePc::new(&cfg, schedule_needs_secondary, dut))
        }
        TopologyConf::LwipTap { lwip, iface_secondary } => {
            Box::new(topology::LwipTap::new(&cfg, lwip, iface_secondary.as_deref()))
        }
        TopologyConf::External(e) => Box::new(External::new(&cfg, e)),
        TopologyConf::SshRemote(s) => Box::new(SshRemote::new(&cfg, s)),
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
    // A `--negative` run dispatches each case as its authored negative row instead
    // of positively. Built here (after the topology gate) so the schedule and the
    // worker cap below see the negative case set, not the positive default.
    let neg_schedule: Option<worker::AssertSchedule> = if cli.known_fail {
        // The known-fail set is the harness's --list-known-fails (the platform overrides'
        // measured landed verdicts) — the SAME one-home rule the negative set follows.
        let rows = dispatch::list_known_fails(&cfg)?;
        let filtered: Vec<(String, String)> = if cli.cases.is_empty() {
            rows
        } else {
            let want: HashSet<String> = cli.cases.iter().map(|c| c.to_uppercase()).collect();
            rows.into_iter()
                .filter(|(case, _)| want.contains(&case.to_uppercase()))
                .collect()
        };
        if filtered.is_empty() {
            bail!("--known-fail: no case carries a registered platform_known_fail_verdict (narrow the case list, or measure one first)");
        }
        cases = filtered.iter().map(|(case, _)| case.clone()).collect();
        cases.sort();
        Some(worker::AssertSchedule {
            mode: worker::AssertMode::KnownFail,
            expect: filtered.into_iter().collect(),
        })
    } else if cli.negative {
        if !topo.supports_negative() {
            bail!("--negative requires a topology with a spawned reference DUT (deliberate mis-expectations + start-order control); topology '{topology}' does not support it");
        }
        // The negative set is the harness's --list-neg-rows (the inventory
        // overrides' sixth axis) — the SAME source bash and the coverage audit read.
        let rows = dispatch::list_negative_rows(&cfg)?;
        // A positional case list narrows the run to those rows (rapid per-case
        // iteration); bare --negative runs the whole curated set. Case-insensitive,
        // matching the harness registry.
        let filtered: Vec<(String, String)> = if cli.cases.is_empty() {
            rows
        } else {
            let want: HashSet<String> = cli.cases.iter().map(|c| c.to_uppercase()).collect();
            rows.into_iter()
                // Match the CASE, not the row: a case's extra rows carry a `#N`
                // suffix, and naming `ARP_35` means every row it authors. Without
                // the split, asking for a case ran only its primary — the run
                // looked complete while proving half of what it had listed
                // (docs/tech-debt.md TD-53).
                .filter(|(case, _)| {
                    let base = case.split('#').next().unwrap_or(case);
                    want.contains(&base.to_uppercase())
                })
                .collect()
        };
        if filtered.is_empty() {
            bail!("--negative: none of the requested case(s) carry an authored negative row");
        }
        // Sorted case-id schedule (deterministic worker distribution + summary),
        // plus the case_id -> expected_fail map the workers assert against.
        cases = filtered.iter().map(|(case, _)| case.clone()).collect();
        cases.sort();
        Some(worker::AssertSchedule {
            mode: worker::AssertMode::NegativeRow,
            expect: filtered.into_iter().collect(),
        })
    } else {
        None
    };
    // Load the DUT vsomeip flavor table once from the harness (the SSOT:
    // --list-vsomeip-variants, the seventh inventory-overrides axis — the SAME
    // source bash reads). Positive runs look it up per case; a negative run keeps
    // the base cfg, so it is inert there but harmless. After --print-expect's early
    // return above, so the identity path never shells the harness.
    dut_variant::init(&cfg)?;
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
    // The wrap rides along with the ssh params: the handler's reap must carry the
    // same elevation the launch did, or a SIGINT leaks the very DUT it is trying
    // to clean up (see `remote_reap_dut`).
    let ssh_reap: Option<(String, Option<String>, Option<String>)> = match &site {
        TopologyConf::SshRemote(s) => {
            Some((s.ssh_target.clone(), s.ssh_opts.clone(), s.remote_wrap.clone()))
        }
        _ => None,
    };
    let fixture_kind: Option<String> = match &site {
        TopologyConf::External(e) => e.wire.fixture.as_ref().map(|f| f.kind.clone()),
        TopologyConf::SshRemote(s) => s.wire.fixture.as_ref().map(|f| f.kind.clone()),
        _ => None,
    };
    // Resolve the lwip-tap kill name HERE (the closure cannot borrow the topology)
    // so the abort path reaps exactly the configured process, not a stale literal.
    let lwip_signal_kill: Option<String> = match &site {
        TopologyConf::LwipTap { lwip, .. } => Some(topology::resolve_kill_name(lwip)),
        _ => None,
    };
    cleanup::install_signal_handler(&cfg, workers, move || {
        if let Some((target, opts, wrap)) = &ssh_reap {
            topology::ssh_reap_remote_dut(target, opts.as_deref(), wrap.as_deref());
        }
        if let Some(kill) = &lwip_signal_kill {
            topology::lwip_signal_teardown(kill);
        }
        if let Some(kind) = &fixture_kind {
            fixtures::teardown_by_kind(kind);
        }
    })?;

    // Provision the verification fixture (if any) before the topology lifecycle —
    // provision_run probes the DUT the fixture stands up. The guard tears it down on
    // Drop (normal/panic); the handler installed above covers SIGINT/SIGTERM. The
    // lwip-tap topology needs no fixture: LwipTap self-provisions the tap + DUT in
    // provision_run and reaps them in teardown_run (a `[fixture]` block is
    // only ever netns-dut/ssh-netns-dut, enforced when the site config resolves).
    let fixture_spec = match &site {
        TopologyConf::External(e) => e.wire.fixture.as_ref(),
        TopologyConf::SshRemote(s) => s.wire.fixture.as_ref(),
        _ => None,
    };
    let _fixture = match fixture_spec {
        Some(spec) => Some(fixtures::provision(spec, &cfg)?),
        None => None,
    };

    topo.preflight()?;

    // Run-level provisioning: stand up what the topology OWNS (lwip-tap's tap + DUT +
    // lock; external/ssh-remote verify the pre-existing DUT is live) ONCE, after
    // preflight and before the worker fork (bash topology_provision_run, smoke-test.sh
    // pre-fork). Distinct from the per-worker bring_up_worker the fan-out calls: this
    // is the seam whose absence let the lwip-tap fixture hide run-level work inside
    // bring_up_worker, correct only because max_workers caps it at one.
    topo.provision_run()?;

    let buckets = worker::distribute(&cases, workers);
    let results = worker::run_all(&cfg, topo.as_ref(), buckets, cli.dut_first, neg_schedule.as_ref());

    // Run-level teardown of what provision_run owns (bash topology_teardown_run, run
    // from the cleanup trap). Best-effort — a failure here must not mask the case
    // results; the fixture's Drop is the panic/SIGINT backstop.
    if let Err(e) = topo.teardown_run() {
        eprintln!("orchestrator: warning: run-level teardown failed: {e:#}");
    }

    // Write the JUnit report BEFORE summarize (which may bail on the gate) so the
    // CI consumer gets a report reflecting what ran, pass or fail — bash emits it
    // unconditionally too. Records are cloned out; summarize still reads &results.
    if let Some(path) = &cli.junit_xml {
        let records: Vec<junit::CaseRecord> =
            results.iter().flat_map(|r| r.records.iter().cloned()).collect();
        junit::write(Path::new(path), &records, &junit_timestamp())?;
    }

    let _ = fs::remove_dir_all(&cfg.work_root);
    let _ = fs::remove_dir_all(&cfg.vsomeip_base);

    summarize(topology, cases.len(), workers, &results)
}

/// The case ids (UPPER-cased) that need the Topology-2 second tester interface —
/// the harness's `requires_secondary_iface` axis via `--list-cases
/// --only-secondary-iface`. A case id is the first token of each indented listing
/// line (dut/env/list-cases-ids.awk); flush-left lines are banners/summary. This is
/// the SSOT for both "provision the second veth" (any scheduled member) and
/// "pass --interface-secondary for THIS case" (per-case membership), matching
/// bash's `case_needs_secondary_iface`.
fn list_secondary_iface_cases(cfg: &Config) -> Result<HashSet<String>> {
    let out = cfg
        .harness_test()
        .args(["--list-cases", "--only-secondary-iface"])
        .output()
        .with_context(|| format!("running {} --list-cases", cfg.harness.display()))?;
    if !out.status.success() {
        bail!(
            "{} test --list-cases --only-secondary-iface exited {}",
            cfg.harness.display(),
            out.status
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with(char::is_whitespace))
        .filter_map(|l| l.split_whitespace().next())
        .map(|id| id.to_uppercase())
        .collect())
}

/// The run timestamp for the JUnit `<testsuites timestamp=...>` — `date -u
/// +%Y-%m-%dT%H:%M:%S`, the exact command + format bash uses. Shelling out (the
/// orchestrator already invokes `ip`/`pgrep`/the harness) avoids a civil-time
/// dependency for one informational attribute; an empty string on failure is
/// harmless (the attribute is not load-bearing for dorny/test-reporter).
fn junit_timestamp() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Aggregate worker tallies, print the summary, and apply the gates: the
/// execution ledger (processed == scheduled) and the non-conclusion ceiling,
/// both ported from smoke-test.sh (lines 2959-3024).
fn summarize(topology: TopologyKind, total: usize, workers: u32, results: &[WorkerResult]) -> Result<()> {
    let mut fails: Vec<&str> = Vec::new();
    let mut skips: Vec<&worker::Skip> = Vec::new();
    let mut nonconcl: Vec<&worker::Skip> = Vec::new();
    let mut undispatched: Vec<&worker::Skip> = Vec::new();
    let mut processed = 0usize;
    let mut worker_errors: Vec<&str> = Vec::new();
    for r in results {
        fails.extend(r.fails.iter().map(String::as_str));
        skips.extend(r.skips.iter());
        nonconcl.extend(r.nonconclusions.iter());
        undispatched.extend(r.undispatched.iter());
        processed += r.processed;
        if let Some(e) = &r.worker_error {
            worker_errors.push(e);
        }
    }

    println!(
        "orchestrator summary [topology={topology}]: {total} case(s), {} failure(s), {} skipped, {} non-conclusion(s), {} not dispatched across {workers} worker(s)",
        fails.len(),
        skips.len(),
        nonconcl.len(),
        undispatched.len(),
    );
    for s in &skips {
        println!("  SKIP  {} — {}", s.case, s.reason);
    }
    for s in &nonconcl {
        println!("  SKIP* {} — {}  (non-conclusion / regression-watch)", s.case, s.reason);
    }
    for s in &undispatched {
        println!("  ERROR {} — {}  (not dispatched)", s.case, s.reason);
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

    // Dispatch ledger — the same promise per case: every scheduled case produced a
    // verdict. One that could not be dispatched has none, so no rate absorbs it; the
    // non-conclusion ceiling below is for verdicts, not for their absence (TD-59).
    if !undispatched.is_empty() {
        bail!(
            "{} case(s) could not be dispatched and have no verdict — see the ERROR line(s) above",
            undispatched.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use worker::{Skip, WorkerResult};

    fn skip(case: &str, reason: &str) -> Skip {
        Skip { case: case.into(), reason: reason.into() }
    }

    /// The consumer's run (TD-59): 5 of 261 not dispatched, 1.9%, under the 5%
    /// ceiling that used to absorb them. One is enough to red the run now.
    #[test]
    fn a_single_undispatched_case_reds_the_run_below_any_ceiling() {
        let r = WorkerResult {
            undispatched: vec![skip("SOMEIPSRV_RPC_13", "dispatch_fault: refused")],
            processed: 261,
            ..Default::default()
        };
        let err = summarize(TopologyKind::SinglePc, 261, 1, &[r]).unwrap_err().to_string();
        assert!(err.contains("could not be dispatched"), "{err}");
    }

    /// The ceiling still governs verdicts: two non-conclusions in 261 stay green,
    /// so moving dispatch faults out did not tighten what the harness reports.
    #[test]
    fn non_conclusions_below_the_ceiling_still_pass() {
        let r = WorkerResult {
            nonconclusions: vec![
                skip("ARP_01", "inconclusive:x"),
                skip("ARP_02", "error:capture_open"),
            ],
            processed: 261,
            ..Default::default()
        };
        summarize(TopologyKind::SinglePc, 261, 1, &[r]).expect("under the ceiling");
    }

    /// `cargo test` has just built this binary from this tree, so the digest
    /// `build.rs` baked and the one computed now must agree. If the two sides
    /// computed it differently, every binary would refuse itself.
    #[test]
    fn a_binary_built_from_this_tree_is_not_refused() {
        let now = source_digest::digest(Path::new(SOURCE_DIR)).expect("digesting this crate");
        assert_eq!(now, BUILT_DIGEST);
        assert_eq!(stale_binary_refusal(&now, "any"), None);
    }

    /// A consumer bumped its pin without rebuilding: the refusal names both
    /// commits and the command that rebuilds this binary where it was built.
    #[test]
    fn a_stale_binary_is_refused_with_both_commits_and_its_rebuild_command() {
        let refusal = stale_binary_refusal("0000000000000000", "abc123def456").expect("refused");
        assert!(refusal.contains(&format!("built from:  {BUILT_COMMIT}")), "{refusal}");
        assert!(refusal.contains("sources now: abc123def456"), "{refusal}");
        assert!(
            refusal.contains(&format!("--manifest-path {SOURCE_DIR}/Cargo.toml")),
            "{refusal}"
        );
    }
}
