//! Per-case dispatch: apply per-case conditioning (via the topology seam), build
//! `--expect`, spawn harness + DUT in start order, poll to a verdict, classify it,
//! then restore conditioning. Mirrors smoke-test.sh run_case for the positive path.

use anyhow::Result;
use std::path::Path;
use std::process::Child;
use std::thread::sleep;
use std::time::Duration;

use crate::config::Config;
use crate::topology::{Topology, WorkerCtx};
use crate::wire;

/// Disposition of one case, mapped from the harness verdict line via the
/// generated taxonomy (`crate::taxonomy`).
pub enum Verdict {
    /// `pass` — gate-green.
    Pass,
    /// `fail:reason` — observed conformance violation, reds the gate.
    Fail(String),
    /// Deterministic skip: capability gap / topology limit. Expected, non-gating.
    Skip(String),
    /// `inconclusive:`/`error:` — a case that would normally conclude did not, or
    /// a test-system fault. Routed to a non-gating skip but counted against the
    /// non-conclusion ceiling (see main::summarize).
    NonConclusion(String),
}

// --- Timing (named; the bash magic numbers with their rationale) ------------
const POLL_INTERVAL_MS: u64 = 200;
/// dut_first: let the DUT's first OfferService settle before the harness opens
/// its pcap (negative tests only).
const DUT_FIRST_SETTLE_MS: u64 = 1500;
/// harness-first barrier: poll interval and ceiling for the harness's
/// `--ready-file` capture-live signal (see `wait_for_capture_ready`). The
/// ceiling is a backstop only — the signal normally lands in tens of ms; it
/// sits far above capture setup even under CPU starvation, which is exactly the
/// load that made the retired fixed 500 ms settle miss the DUT's first offer.
const CAPTURE_READY_POLL_MS: u64 = 20;
const CAPTURE_READY_MAX_POLLS: u32 = 250;
/// Bound on waiting for a case DUT's wrapper / ssh-client `Child` to exit after
/// `stop_dut` (≈3 s at 200 ms/tick). On the happy path the wrapper exits in the
/// first tick or two; the bound exists only so a MISSED remote kill (an ssh failure
/// or comm mismatch on the ssh-remote path) cannot block the worker for the whole
/// harness backstop. On timeout the local child is killed and the run proceeds.
/// `pub(crate)` so the ssh-remote preflight transient-DUT reap reuses the same
/// bound (the structurally identical hang site).
pub(crate) const REAP_WAIT_TICKS: u32 = 15;

/// Poll a child to exit within `ticks` × `POLL_INTERVAL_MS`, non-blocking between
/// polls. Returns whether it exited in budget. A `try_wait` error (already reaped /
/// unwaitable) counts as exited — there is nothing left to wait on.
pub(crate) fn wait_bounded(child: &mut Child, ticks: u32) -> bool {
    for _ in 0..ticks {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => sleep(Duration::from_millis(POLL_INTERVAL_MS)),
            Err(_) => return true,
        }
    }
    matches!(child.try_wait(), Ok(Some(_)) | Err(_))
}

/// Block until a harness capture child signals it is live (its `--ready-file`
/// appears), then let the caller start the DUT. Returns early — proceeding
/// anyway — if the child exits first (capture open failed; its log will classify
/// it) or the poll ceiling elapses, so a missing signal never hangs the worker.
///
/// Shared with the ssh-remote SD-egress preflight, whose `sd-probe` child arms
/// the same kind of capture around the same kind of DUT spawn: both need the
/// ring armed before the DUT's first frame, and one barrier is the only way the
/// two can stay right together.
pub(crate) fn wait_for_capture_ready(ready: &Path, harness: &mut Child) {
    for _ in 0..CAPTURE_READY_MAX_POLLS {
        if ready.exists() {
            return;
        }
        if matches!(harness.try_wait(), Ok(Some(_)) | Err(_)) {
            return;
        }
        sleep(Duration::from_millis(CAPTURE_READY_POLL_MS));
    }
    eprintln!(
        "orchestrator: warning: harness capture-ready signal did not arrive; \
         proceeding to start the DUT"
    );
}

// --- Verdict line parsing ---------------------------------------------------
/// Harness verdict line prefix — SSOT is the printf at src/cli/test_command.cpp
/// (`printf("verdict  : %s\n", ...)`). Not a taxonomy class, so it is pinned
/// here (with a unit test) rather than generated from the .def.
const VERDICT_LINE_PREFIX: &str = "verdict  : ";
/// `skip` is a smoke-runner concept (capability/topology) layered on the
/// non-conclusion disposition, not a `.def` verdict class.
const SKIP_TOKEN: &str = "skip";

// The harness-emitted wire constants (tester MACs, ICMP echo id/seq, alias IPs,
// SD version + default eventgroup) are single-homed in `crate::wire`.

/// Owns the spawned harness + DUT children for one case so they are reaped on
/// EVERY exit path — normal return, an error `return`, or a panic. The reaping
/// (kill the `ip netns exec` wrappers we forked + pkill the reparented real
/// binaries via their worker-unique symlinks + wait to avoid zombies) is the
/// single source `reap()`, called explicitly on the happy path (before reading
/// the log) and by Drop on the error/panic paths. Without this, a spawn/IO error
/// mid-setup would drop a Child unreaped and leave a reparented harness holding a
/// pcap across the rest of the worker's bucket — the FORMAT_02 session-id
/// corruption the worker-unique-symlink design exists to prevent.
struct CaseProcs<'a> {
    topo: &'a dyn Topology,
    w: u32,
    harness: Option<Child>,
    dut: Option<Child>,
    reaped: bool,
}

impl<'a> CaseProcs<'a> {
    fn new(topo: &'a dyn Topology, w: u32) -> Self {
        CaseProcs { topo, w, harness: None, dut: None, reaped: false }
    }

    fn reap(&mut self) {
        if self.reaped {
            return;
        }
        self.reaped = true;
        if let Some(mut h) = self.harness.take() {
            let _ = h.kill();
            let _ = h.wait(); // reap the ip-netns-exec wrapper PID we forked
        }
        let _ = self.topo.stop_harness(self.w); // pkill the reparented real harness
        let _ = self.topo.stop_dut(self.w);
        if let Some(mut d) = self.dut.take() {
            // stop_dut killed the DUT (by worker-symlink path for single-pc, by a
            // separate ssh pkill for ssh-remote), after which this wrapper / ssh
            // client exits. Bound the wait: a MISSED remote kill must not hang the
            // worker for the whole backstop. On timeout, kill the local child
            // (signals the wrapper / drops the ssh channel) and warn — the next
            // bring-up's stale-reap is the backstop for a surviving remote DUT.
            if !wait_bounded(&mut d, REAP_WAIT_TICKS) {
                eprintln!(
                    "orchestrator: warning: worker {} case DUT did not exit after stop_dut; the kill may have missed (a stale DUT could affect the next case)",
                    self.w
                );
                let _ = d.kill();
                let _ = d.wait();
            }
        }
    }
}

impl Drop for CaseProcs<'_> {
    fn drop(&mut self) {
        self.reap();
    }
}

pub fn run_case(
    cfg: &Config,
    topo: &dyn Topology,
    w: u32,
    ctx: &WorkerCtx,
    case_id: &str,
    dut_first: bool,
) -> Result<Verdict> {
    run_case_impl(cfg, topo, w, ctx, case_id, dut_first, false)
}

/// Run a case as its authored NEGATIVE row: the harness flips one `--expect`
/// value to a deliberately wrong one (`--negative-row`, applied last so it wins)
/// and the case MUST land on `expected_fail`, proving the guard is not
/// trivially-true. The flip + expected verdict are the inventory overrides' sixth
/// axis, listed via `list_negative_rows`; the harness owns the flip, so this only
/// passes the flag and asserts the outcome.
///
/// The harness verdict is mapped into the negative test's frame, matching bash
/// `run_negative_case` (smoke-test.sh) precedence EXACTLY — parity with that SSOT
/// is the strangler's cutover precondition:
///   skip / inconclusive / error  -> Skip  (the guard was never exercised; the
///                                          DUT never offered / never replied —
///                                          non-gating, bash's skip ledger)
///   fail == expected_fail         -> Pass  (the guard reacted; green)
///   fail != expected_fail         -> Fail  (landed on the wrong reason)
///   pass                          -> Fail  (the DUT accepted the bad input —
///                                          exactly what the row guards against)
pub fn run_negative_row(
    cfg: &Config,
    topo: &dyn Topology,
    w: u32,
    ctx: &WorkerCtx,
    case_id: &str,
    expected_fail: &str,
) -> Result<Verdict> {
    // Negative rows run DUT-first — the deliberate mis-expectation plus start-order
    // control bash's negative path uses (a topology that supports negatives spawns
    // the reference DUT, so dut_first is always valid here).
    let raw = run_case_impl(cfg, topo, w, ctx, case_id, true, true)?;
    Ok(map_negative_verdict(raw, expected_fail))
}

/// Map a harness verdict into the negative test's frame — the bash
/// `run_negative_case` precedence, pure over the inputs so it is unit-tested
/// without a harness run (the parity-critical decision, so it must be pinned).
fn map_negative_verdict(raw: Verdict, expected_fail: &str) -> Verdict {
    match raw {
        // A sound non-conclusion — the DUT never offered / never replied, so the
        // fault was never reachable and the guard was never exercised. Bash routes
        // this to its skip ledger; non-gating, never a negative-test failure.
        Verdict::Skip(reason) | Verdict::NonConclusion(reason) => {
            Verdict::Skip(format!("guard not exercised: {reason}"))
        }
        // The guard reacted with exactly the authored reason — the negative passed.
        Verdict::Fail(reason) if reason == expected_fail => Verdict::Pass,
        // A fail, but the wrong reason — the guard fired on something else.
        Verdict::Fail(reason) => Verdict::Fail(format!(
            "expected '{expected_fail}', harness returned '{reason}'"
        )),
        // The DUT accepted the deliberately-wrong input — exactly what the row
        // guards against. A hard fail, matching bash (a `pass` reds the gate).
        Verdict::Pass => Verdict::Fail(format!(
            "DUT accepted the non-conformant input; expected '{expected_fail}'"
        )),
    }
}

/// The negative set: every case carrying an authored negative row, read from the
/// harness's `--list-neg-rows` (which prints the inventory overrides' sixth axis in
/// the historical `CASE|wrong_token|fail:reason` grammar). Returns `(case_id,
/// expected_fail)`; the `wrong_token` is informational (the harness applies it), so
/// it is dropped here. This is the SAME source the bash driver and
/// `negative_coverage_audit.py` read — one home, no drift. A non-zero exit or an
/// empty list is a hard error: an empty negative run would pass by vacuity.
pub fn list_negative_rows(cfg: &Config) -> Result<Vec<(String, String)>> {
    use anyhow::{bail, Context};
    let out = std::process::Command::new(&cfg.harness)
        .args(["test", "--list-neg-rows"])
        .output()
        .with_context(|| format!("running {} test --list-neg-rows", cfg.harness.display()))?;
    if !out.status.success() {
        bail!(
            "{} test --list-neg-rows exited {}: {}",
            cfg.harness.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8(out.stdout).context("--list-neg-rows output not UTF-8")?;
    parse_neg_rows_output(&text)
}

/// Parse the `CASE|wrong_token|class:reason` lines into `(case_id, expected_fail)`.
/// Pure over the text so it is unit-tested without invoking the harness. A
/// malformed row or an empty set is a hard error (an empty negative run would pass
/// by vacuity).
fn parse_neg_rows_output(text: &str) -> Result<Vec<(String, String)>> {
    use anyhow::bail;
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The expected verdict is the 3rd field (a `class:reason`, e.g.
        // `fail:entry_service_id_mismatch`), which contains no `|`, so splitn(3)
        // keeps it intact even though a reason could in principle hold a colon.
        let mut it = line.splitn(3, '|');
        match (it.next(), it.next(), it.next()) {
            (Some(case), Some(_wrong), Some(expected))
                if !case.is_empty() && !expected.is_empty() =>
            {
                rows.push((case.to_string(), expected.to_string()));
            }
            _ => bail!("--list-neg-rows produced a malformed row: {line:?}"),
        }
    }
    if rows.is_empty() {
        bail!("--list-neg-rows returned no rows; an empty negative run would pass by vacuity");
    }
    Ok(rows)
}

fn run_case_impl(
    cfg: &Config,
    topo: &dyn Topology,
    w: u32,
    ctx: &WorkerCtx,
    case_id: &str,
    dut_first: bool,
    negative_row: bool,
) -> Result<Verdict> {
    // --log-dir redirects the per-case logs to a KEPT directory (bash smoke-test.sh
    // keep_logs=1); otherwise they are scratch under work_root, removed at run end.
    // The verdict is read from hlog either way, so classification is unaffected.
    let (hlog, dlog) = match &cfg.log_dir {
        Some(dir) => (
            dir.join(format!("{case_id}.harness.log")),
            dir.join(format!("{case_id}.dut.log")),
        ),
        None => (
            cfg.work_root.join(format!("{w}/{case_id}.harness.log")),
            cfg.work_root.join(format!("{w}/{case_id}.dut.log")),
        ),
    };
    let iface = topo.tester_iface(w);

    // TC8 Topology 2 cases need a second tester interface — data-driven from the
    // harness's requires_secondary_iface axis (cfg.secondary_iface_cases), NOT a
    // hardcoded id, so USAGE_01 AND its _NEG mutant (and any future member) are all
    // covered. A topology that provides none cannot execute such a case — explicit
    // SKIP, never a misleading timeout FAIL (bash run_case, smoke-test.sh). Decided
    // before conditioning: a skipped case applies none, and the next case's flush
    // covers the DUT-cache reset regardless.
    let mut extra_args: Vec<String> = Vec::new();
    if cfg.secondary_iface_cases.contains(&case_id.to_uppercase()) {
        match topo.tester_iface_secondary(w) {
            None => {
                return Ok(Verdict::Skip(
                    "requires a secondary tester interface (TC8 Topology 2); topology provides none"
                        .to_string(),
                ))
            }
            Some(sec) => {
                extra_args.push("--interface-secondary".to_string());
                extra_args.push(sec);
            }
        }
    }

    // Per-case DUT/tester kernel conditioning (smoke-test.sh run_case prefix neigh
    // flush + the case-keyed sysctl/neigh toggles). Declared BEFORE CaseProcs so on
    // any early-return `?` the procs guard drops first (reap), then this restores —
    // matching bash's kill → restore order. The guard reverts on the explicit
    // restore() below and as a Drop backstop on the error/panic paths.
    let mut cond = topo.condition_case(w, case_id, ctx)?;

    let mut args = vec![
        "test".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "-i".to_string(),
        iface,
        "-t".to_string(),
        cfg.backstop_sec.to_string(),
    ];
    args.extend(expect_args(cfg, &ctx.dut_mac));
    args.extend(extra_args);
    // Topology-level UT ARP-cache conditioning (lwIP DUT — bash smoke-test.sh):
    // a global expect so the harness UT-ages the DUT's ARP table for ARP_48/49 (the
    // stack has no host sysctls to compress). Inert for cases that do not read it.
    // A negative run gets it too (the same expect surface bash's negative baseline
    // splices in); the row's flip is applied by the harness AFTER all of these, so
    // it still wins.
    if let Some(t) = topo.ut_arp_cache_timeout() {
        args.push("--expect".to_string());
        args.push(format!("arp_stimulus.ut_cache_conditioning_s={t}"));
    }
    // This invocation IS the case's negative row: the harness appends the authored
    // flip after every --expect above and asserts the guard reacts. Suppresses the
    // positive expect_overrides (which describe the positive run) so they cannot
    // overwrite the flip.
    if negative_row {
        args.push("--negative-row".to_string());
    }
    // --dut-control backend passthrough (bash smoke-test.sh): seam-migrated cases
    // route their stimulus through the selected UT backend; opcode-builder cases
    // ignore it. Validated by the harness's CLI (opcode|testability), not here.
    if let Some(backend) = &cfg.dut_control {
        args.push("--dut-control".to_string());
        args.push(backend.clone());
    }
    // Site-declared opt-out of the capture's IGMP memberships (--topology-conf
    // `no_multicast_membership`). Passed through, never inferred from the topology:
    // whether the wire prunes unjoined multicast is a property of the switch in
    // front of the tester, which no topology name can tell us. Absent = hold them,
    // so a site that says nothing gets the behaviour that keeps an absence-based
    // verdict honest.
    if cfg.no_multicast_membership {
        args.push("--no-multicast-membership".to_string());
    }
    // --log-dir also saves every captured frame to a per-case pcap for post-mortem
    // (bash smoke-test.sh appends --pcap-dump under $LOG_DIR).
    if let Some(dir) = &cfg.log_dir {
        args.push("--pcap-dump".to_string());
        args.push(dir.join(format!("{case_id}.pcap")).to_string_lossy().into_owned());
    }

    // Spawn order: harness first so its pcap is open before the DUT's first
    // OfferService (FORMAT_02 session_id==0x0001); --dut-first inverts it. On any
    // spawn error the `?` returns and CaseProcs::drop reaps whatever started.
    // Per-case DUT vsomeip flavor (CASE_VSOMEIP_VARIANT), POSITIVE runs only — a
    // negative run keeps the base cfg (bash run_negative_case). The flavor (an
    // alternate config sibling + TC8_DUT_* env) comes from the harness's
    // --list-vsomeip-variants (the SSOT), loaded once in main.
    let variant = if negative_row {
        None
    } else {
        crate::dut_variant::resolve(case_id)
    };
    let vcfg = match variant.and_then(|v| v.cfg_basename.as_deref()) {
        Some(name) => cfg
            .vsomeip_cfg
            .parent()
            .map(|p| p.join(name))
            .unwrap_or_else(|| cfg.vsomeip_cfg.clone()),
        None => cfg.vsomeip_cfg.clone(),
    };
    let flavor_env: Vec<String> = variant.map(|v| v.env.clone()).unwrap_or_default();

    let mut procs = CaseProcs::new(topo, w);
    if dut_first {
        procs.dut = topo.start_dut(w, &dlog, &vcfg, &flavor_env)?;
        sleep(Duration::from_millis(DUT_FIRST_SETTLE_MS));
        procs.harness = Some(topo.run_harness(w, &hlog, &args)?);
    } else {
        // Harness-first with a real barrier: the harness creates its
        // `--ready-file` once the capture is armed, and we start the DUT only
        // after that file appears. This replaces a fixed startup sleep — under
        // CPU starvation capture setup can outlast any guess, letting the DUT's
        // first OfferService (session_id 0x0001, SOMEIPSRV_FORMAT_02) precede
        // the live capture. Anchoring to the observed ready state, not wall
        // time, is robust to load (and faster on the common path).
        let ready = hlog.with_extension("ready");
        let _ = std::fs::remove_file(&ready);
        let mut hargs = args.clone();
        hargs.push("--ready-file".to_string());
        hargs.push(ready.to_string_lossy().into_owned());
        let mut harness = topo.run_harness(w, &hlog, &hargs)?;
        wait_for_capture_ready(&ready, &mut harness);
        let _ = std::fs::remove_file(&ready);
        procs.harness = Some(harness);
        procs.dut = topo.start_dut(w, &dlog, &vcfg, &flavor_env)?;
    }

    // Poll ceiling in ticks — ports bash's wait_budget (smoke-test.sh):
    // (backstop+3)*5, capped at 1100 ticks (220s @ 200ms/tick). The cap is bash's
    // and sits just below the harness -t backstop (240s) BY BASH'S DESIGN: real
    // cases conclude on their SCXML final state well under 215s, so neither bound
    // normally fires. Matching the cap keeps verdict PARITY with bash. Raising
    // both bash's cap AND this above the backstop and reclassifying a
    // budget-exceeded case as a non-conclusion (ISO 9646) is a tracked JOINT
    // bash+Rust change — not done unilaterally here, which would diverge the two
    // strangler halves on that one case. A try_wait error returns and the guard
    // reaps both children.
    let budget_ticks = ((u64::from(cfg.backstop_sec) + 3) * 5).min(1100);
    {
        let harness = procs.harness.as_mut().expect("harness spawned above");
        for _ in 0..budget_ticks {
            if harness.try_wait()?.is_some() {
                break;
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
    }

    // Reap on the happy path BEFORE reading the log (the harness must be stopped
    // and its log flushed); Drop then no-ops via the `reaped` flag.
    procs.reap();
    // Restore conditioning after the procs are down — mirrors bash run_case
    // (kill_worker_procs → restore toggles → classify, smoke-test.sh).
    // Drop is the backstop for the error/panic paths.
    cond.restore();
    Ok(classify(&hlog))
}

/// Read the harness log and classify its verdict line.
fn classify(hlog: &Path) -> Verdict {
    let text = match std::fs::read_to_string(hlog) {
        Ok(t) => t,
        // An UNREADABLE log (permissions, full disk) is a test-system I/O fault,
        // not a DUT verdict → error non-conclusion (distinct from the readable-
        // but-no-verdict case below, per the verdict taxonomy's error class).
        Err(e) => return Verdict::NonConclusion(format!("error:harness_log_unreadable: {e}")),
    };
    // The harness emits EXACTLY ONE `verdict  :` line per run — it prints the
    // donedata verdict when the SCXML reaches its single final state — so taking
    // the first occurrence equals taking the only one. bash (smoke-test.sh-
    // 1611) instead greps for a skip/inconclusive/error class anywhere, then for
    // pass; with one verdict line per run the two are equivalent. If the harness
    // ever emitted multiple verdict lines, this first-line policy would diverge
    // from bash's class-precedence scan — the single-line invariant is the pin.
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(VERDICT_LINE_PREFIX) {
            return classify_verdict(rest.trim());
        }
    }
    // Readable log, no verdict line = the harness ran but never concluded (killed
    // at the poll ceiling, or crashed mid-run). bash scores this FAIL ("did not
    // return pass verdict", smoke-test.sh) — match it for parity. Reclassifying this
    // (and the poll-ceiling kill in run_case) as an ISO-9646 non-conclusion is the
    // SAME tracked JOINT bash+Rust change as the budget-exceeded reclassification —
    // one honesty gap, moved together, never unilaterally here.
    Verdict::Fail("did not return pass verdict".to_string())
}

/// Map a verdict value (`pass`, `fail:reason`, `inconclusive:reason`, …) to a
/// disposition using the generated taxonomy. Pure over the string so it is unit-
/// tested without a harness run. Intentionally matches the class TOKEN (the part
/// before the first ':') rather than bash's `class:` substring grep — this is the
/// more robust form (it also fixes a latent bash bug: `grep "verdict  : pass"`
/// would accept `passive`), and the harness always emits the colon form.
fn classify_verdict(value: &str) -> Verdict {
    let token = value.split(':').next().unwrap_or(value);
    if token == crate::taxonomy::SUCCESS {
        Verdict::Pass
    } else if token == crate::taxonomy::FAIL {
        Verdict::Fail(value.to_string())
    } else if crate::taxonomy::NONCONCLUSION.contains(&token) {
        Verdict::NonConclusion(value.to_string())
    } else if token == SKIP_TOKEN {
        Verdict::Skip(value.to_string())
    } else {
        // Unknown token = taxonomy drift: fail loud rather than silently pass.
        Verdict::Fail(format!("unknown_verdict_class: {value}"))
    }
}

fn ex(e: &mut Vec<String>, key: &str, value: &str) {
    e.push("--expect".to_string());
    e.push(format!("{key}={value}"));
}

/// The base `--expect` set bash passes for EVERY case (smoke-test.sh):
/// `TC8_DUT_EXPECT` (SOME/IP identity, derived from vsomeip.json via
/// `config::DutIdentity`) + the per-worker DUT-MAC block + ALL category static
/// groups (ARP / ICMPv4 / IPv4), unconditionally.
///
/// These are emitted flat for every case, NOT gated by case prefix. The harness
/// reads only the keys its case references; extra keys are inert. The previous
/// prefix-gated shape DROPPED `dut.mac`/`dhcpv4.dut_iface_mac` entirely and hid
/// `arp.dut_iface_mac` behind the ARP branch — a silent parity gap vs bash, which
/// gives every case the full set. Mirroring bash's flat array removes the whole
/// cross-category-read hazard. The per-case / negative-row OVERRIDE layers (the
/// last-wins precedence merge) land in a later stage; this is its `base` input.
///
/// The key->source list is SINGLE-SOURCED with bash's tc8_expect_<bucket> functions
/// from tools/expect_surface.def (docs/tech-debt.md TD-12) via the generated
/// `append_someip_identity` / `append_l2l3_identity` below, so the two drivers cannot
/// drift; parity-check.sh still diffs the resolved values as defence in depth.
fn expect_args(cfg: &Config, dut_mac: &str) -> Vec<String> {
    let mut e = Vec::new();
    append_someip_identity(&mut e, cfg);

    // Operator-supplied extra --expect tokens from the --topology-conf (bash's
    // TC8_TOPOLOGY_EXTRA_EXPECT holds the SAME bare key=value grammar). Folded
    // BETWEEN the someip identity and the L2/L3 statics — the same position bash
    // folds it into TC8_DUT_EXPECT — so a token shadows a repeated someip key
    // (last-wins) while the ARP/ICMPv4/IPv4 statics appended below still win over a
    // colliding token. The keys are validated by the harness --expect parser
    // (tc8_expect_keys.def) at run-time consumption; this carries them opaquely.
    // Empty for every in-tree topology, so the parity dump is byte-unchanged unless
    // a conf declares extra_expect.
    for tok in &cfg.extra_expect {
        e.push("--expect".to_string());
        e.push(tok.clone());
    }

    append_l2l3_identity(&mut e, cfg, dut_mac);
    e
}

// The base identity surface — the key->source list generated from
// tools/expect_surface.def, single-sourced with bash's tc8_expect_<bucket>
// (see the expect_args doc / docs/tech-debt.md TD-12). Defines
// append_someip_identity, append_l2l3_identity, and RUNTIME_MAC_KEYS.
include!("expect_surface.gen.rs");

/// Print the resolved per-case-invariant `--expect` surface — the deterministic
/// wire identity the bash and Rust drivers must agree on — as sorted `key=value`
/// lines, one per line, for the `--print-expect` parity dump (`parity-check.sh`
/// diffs the two drivers' output). Reuses `expect_args` so the dumped surface
/// always tracks the real one, and appends the topology's UT ARP-cache expect the
/// same way `run_case` does (so lwip-tap matches bash). The runtime DUT-MAC block
/// is filtered out (see `RUNTIME_MAC_KEYS`).
pub fn print_static_identity(cfg: &Config, ut_arp_cache_timeout: Option<&str>) {
    let mut kvs: Vec<String> = expect_args(cfg, "<runtime>")
        .into_iter()
        .filter(|a| a != "--expect")
        .filter(|kv| !RUNTIME_MAC_KEYS.contains(&kv.split('=').next().unwrap_or("")))
        .collect();
    if let Some(t) = ut_arp_cache_timeout {
        kvs.push(format!("arp_stimulus.ut_cache_conditioning_s={t}"));
    }
    kvs.sort();
    for kv in kvs {
        println!("{kv}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_taxonomy_tokens() {
        assert!(matches!(classify_verdict("pass"), Verdict::Pass));
        assert!(matches!(classify_verdict("fail:entry_ttl_mismatch"), Verdict::Fail(_)));
        assert!(matches!(
            classify_verdict("inconclusive:precondition_unmet"),
            Verdict::NonConclusion(_)
        ));
        assert!(matches!(
            classify_verdict("error:test_system_fault"),
            Verdict::NonConclusion(_)
        ));
        assert!(matches!(
            classify_verdict("skip:requires_capability_0x16_unavailable_on_linux"),
            Verdict::Skip(_)
        ));
    }

    #[test]
    fn classify_unknown_token_fails_loud() {
        // Taxonomy drift must surface as a gate-red Fail, never a silent pass.
        assert!(matches!(classify_verdict("passive"), Verdict::Fail(_)));
        assert!(matches!(classify_verdict("bogus"), Verdict::Fail(_)));
    }

    use crate::config::fake_cfg;

    #[test]
    fn expect_args_emits_dut_mac_block_for_every_case() {
        // Regression guard for the prefix-gating false-pass: bash emits
        // arp.dut_iface_mac + dut.mac + dhcpv4.dut_iface_mac for EVERY case
        // (smoke-test.sh). All three must always be present.
        let args = expect_args(&fake_cfg(), "02:00:00:00:00:DD");
        for key in [
            "arp.dut_iface_mac=02:00:00:00:00:DD",
            "dut.mac=02:00:00:00:00:DD",
            "dhcpv4.dut_iface_mac=02:00:00:00:00:DD",
        ] {
            assert!(args.iter().any(|a| a == key), "missing --expect {key}");
        }
    }

    #[test]
    fn expect_args_emits_tester_ipv4_mirroring_bash() {
        // tester_ipv4 is now single-sourced with bash via tools/expect_surface.def
        // (TD-12), so the two drivers cannot drift on it by construction; this stays
        // as a regression guard that the generated someip surface still carries the
        // row (its historical bash-only omission is what motivated the manifest). The
        // expected value is derived from the fixture, not hardcoded, so a fixture IP
        // change cannot desync it.
        let cfg = fake_cfg();
        let want = format!("tester_ipv4={}", cfg.tester_ip4);
        let args = expect_args(&cfg, "02:00:00:00:00:DD");
        assert!(
            args.contains(&want),
            "expect_args missing {want} (bash emits it): {args:?}"
        );
    }

    #[test]
    fn expect_args_folds_in_topology_extra_expect() {
        // A --topology-conf's extra_expect tokens appear as --expect pairs in the
        // per-case surface (the typed mirror of bash's TC8_TOPOLOGY_EXTRA_EXPECT), so
        // both drivers' --print-expect dumps stay in parity.
        let mut cfg = fake_cfg();
        cfg.extra_expect = vec![
            "can_start_offset_ms=1000".into(),
            "tester_udp_port=51712".into(),
        ];
        let args = expect_args(&cfg, "02:00:00:00:00:DD");
        for tok in ["can_start_offset_ms=1000", "tester_udp_port=51712"] {
            let idx = args
                .iter()
                .position(|a| a == tok)
                .unwrap_or_else(|| panic!("missing extra token {tok} in {args:?}"));
            assert_eq!(args[idx - 1], "--expect", "token {tok} not preceded by --expect");
        }
        // Empty extra_expect adds nothing — the default surface is byte-unchanged.
        assert!(!expect_args(&fake_cfg(), "02:00:00:00:00:DD")
            .iter()
            .any(|a| a.starts_with("can_") || a.starts_with("tester_udp_port=")));
    }

    // --- negative-row dispatch (Stage B) ------------------------------------

    #[test]
    fn map_negative_verdict_matches_bash_precedence() {
        let want = "fail:entry_service_id_mismatch";
        // fail on the authored reason -> the guard reacted -> negative PASS.
        assert!(matches!(
            map_negative_verdict(Verdict::Fail(want.to_string()), want),
            Verdict::Pass
        ));
        // fail on a DIFFERENT reason -> the guard fired on something else -> FAIL.
        assert!(matches!(
            map_negative_verdict(Verdict::Fail("fail:other".to_string()), want),
            Verdict::Fail(_)
        ));
        // pass -> the DUT accepted the bad input -> hard FAIL (bash reds the gate).
        assert!(matches!(
            map_negative_verdict(Verdict::Pass, want),
            Verdict::Fail(_)
        ));
        // non-conclusion / skip -> guard never exercised -> non-gating SKIP.
        assert!(matches!(
            map_negative_verdict(
                Verdict::NonConclusion("inconclusive:no_method_response".to_string()),
                want
            ),
            Verdict::Skip(_)
        ));
        assert!(matches!(
            map_negative_verdict(Verdict::Skip("requires_secondary_iface".to_string()), want),
            Verdict::Skip(_)
        ));
    }

    #[test]
    fn parse_neg_rows_keeps_case_and_expected_drops_wrong_token() {
        let rows = parse_neg_rows_output(
            "SOMEIPSRV_FORMAT_14|service_id=0x0000|fail:entry_service_id_mismatch\n\
             ARP_03|arp.tester_ip=10.99.99.99|fail:dut_arp_request_after_cache_populated\n",
        )
        .expect("well-formed rows parse");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "SOMEIPSRV_FORMAT_14");
        assert_eq!(rows[0].1, "fail:entry_service_id_mismatch");
        assert_eq!(rows[1].0, "ARP_03");
    }

    #[test]
    fn parse_neg_rows_rejects_malformed_and_empty() {
        // Only two fields — a half row.
        assert!(parse_neg_rows_output("SOMEIPSRV_FORMAT_14|service_id=0x0000\n").is_err());
        // No rows at all — an empty negative run would pass by vacuity.
        assert!(parse_neg_rows_output("\n  \n").is_err());
    }
}
