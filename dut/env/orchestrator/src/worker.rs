//! Parallel worker fan-out — the bash `distribute` + `worker_main` +
//! explicit-PID-join model from smoke-test.sh (lines 2032-2072, 2923-2966)
//! reimplemented with scoped threads.
//!
//! Each worker owns an isolated netns pair (`tc8-tester-W` / `tc8-dut-W`) and a
//! worker-unique binary symlink, so workers never contend; cases are handed out
//! round-robin (every case provisions a fresh tc8-dut, so order is immaterial).
//! Bash joins explicitly on the recorded PIDs rather than a bare `wait` — the
//! Rust analogue is joining each `JoinHandle` we spawned, never a process-wide
//! reap. The execution ledger (processed vs scheduled) is preserved: a worker
//! that dies mid-bucket must surface as a hard error, never as a silent pass.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::dispatch::{self, Verdict};
use crate::junit::{CaseRecord, Status};
use crate::topology::{Topology, WorkerCtx};

/// Which authored expectation an asserted run drives, and therefore what has to be
/// injected to reach it. Both modes assert one `class:reason` verdict per case and share
/// `dispatch::map_negative_verdict`; they differ ONLY in whether anything is injected,
/// which is exactly the difference between the two axes they read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AssertMode {
    /// The inventory overrides' SIXTH axis. The harness flips one `--expect` value
    /// (`--negative-row`) and the case must land the authored fail — the self-check that
    /// its guard is not trivially true.
    NegativeRow,
    /// The platform known-fail axis. NOTHING is injected: the platform's own deviation is
    /// what produces the verdict, and the case must still land the registered one. It
    /// exists because `--exclude-platform-known-fail` means both lanes otherwise SKIP
    /// these cases, so a registration that has gone stale — the platform fixed, or its
    /// defect changed shape — is never observed.
    KnownFail,
}

/// An asserted schedule: `case_id -> expected class:reason`, plus the mode saying how each
/// case is driven. `None` = an ordinary positive run. Threaded by reference into the
/// scoped worker threads (it is `Sync` and outlives the scope), so `distribute` stays over
/// plain case-id strings.
pub struct AssertSchedule {
    pub mode: AssertMode,
    pub expect: HashMap<String, String>,
}

pub type NegSchedule<'a> = Option<&'a AssertSchedule>;

/// A non-failing case outcome carrying its reason — `case` + `reason` kept
/// structured (the bash `case|reason` string encoding existed only for its file
/// IPC, which scoped threads do not need).
pub struct Skip {
    pub case: String,
    pub reason: String,
}

/// One worker's tally, aggregated by the caller after join.
#[derive(Default)]
pub struct WorkerResult {
    /// Case IDs that returned a gating FAIL verdict.
    pub fails: Vec<String>,
    /// Deterministic skips (capability / topology) — expected, non-gating.
    pub skips: Vec<Skip>,
    /// Non-conclusions (the harness's inconclusive/error verdicts) — routed to a
    /// non-gating skip but counted against the non-conclusion ceiling.
    pub nonconclusions: Vec<Skip>,
    /// Cases the orchestrator could not dispatch, so the harness never returned a
    /// verdict: a refused DUT flavor, failed conditioning, a spawn or wait fault.
    /// Not a non-conclusion, which is a verdict about a run that happened. Any one
    /// of these reds the run, whatever the rate (docs/tech-debt.md TD-59).
    pub undispatched: Vec<Skip>,
    /// Cases this worker actually concluded — cross-checked against the schedule.
    pub processed: usize,
    /// One record per concluded case (name, status, duration, message) for the
    /// `--junit-xml` report. Built unconditionally — cheap, and it keeps the
    /// dispatch loop's bookkeeping in one place; main emits XML only when asked.
    pub records: Vec<CaseRecord>,
    /// Set when the worker never ran its bucket (bring-up failed, or panicked).
    pub worker_error: Option<String>,
}

/// Is this case id a fault-injection NEGATIVE — `<base>_NEG` or `<base>_NEG<n>`?
///
/// The suffix is the whole discriminator, deliberately: the harness registers a
/// negative as an ordinary case, so there is no flag on the wire that says "this one
/// is a negative", and the naming is already the convention every register in the tree
/// keys on (`tools/negative_coverage_audit.py` splits the same way). Case-insensitive
/// because the orchestrator takes case ids as the user typed them.
fn is_negative_case(case: &str) -> bool {
    let upper = case.to_uppercase();
    let Some(idx) = upper.rfind("_NEG") else { return false };
    upper[idx + "_NEG".len()..].chars().all(|c| c.is_ascii_digit())
}

/// Round-robin the cases into `workers` buckets — bash `distribute` (`i % WORKERS`).
/// Precondition: `workers >= 1` (the caller clamps to the schedule size and clap
/// enforces `range(1..)`); asserted here so the modulo can never divide by zero.
pub fn distribute(cases: &[String], workers: u32) -> Vec<Vec<String>> {
    assert!(workers >= 1, "distribute requires workers >= 1");
    let mut buckets: Vec<Vec<String>> = (0..workers).map(|_| Vec::new()).collect();
    for (i, case) in cases.iter().enumerate() {
        buckets[i % workers as usize].push(case.clone());
    }
    buckets
}

/// Reaps a worker's netns/symlinks on scope exit — including a panic unwind or
/// an early bring-up failure (every topology's `tear_down_worker` is idempotent,
/// so a half-built or never-built worker is safe to tear down). Mirrors bash's
/// `trap cleanup EXIT` for the normal/panic paths; signal-time teardown is handled
/// in `cleanup`. Holds the topology as a `dyn` trait object so one worker fan-out
/// drives single-pc / external / ssh-remote without monomorphising per type.
struct WorkerGuard<'a> {
    topo: &'a (dyn Topology + Sync),
    w: u32,
}

impl Drop for WorkerGuard<'_> {
    fn drop(&mut self) {
        // tear_down_worker emits its own warnings for surviving processes; the
        // netns delete is best-effort idempotent (mirrors cleanup.sh `|| true`).
        let _ = self.topo.tear_down_worker(self.w);
    }
}

/// Per-case netns rebuild policy: total attempts and the growing backoff between
/// them. The first attempt runs with no delay (the common case succeeds there, so
/// a clean run pays nothing); each retry waits `REBUILD_BACKOFF_MS * attempt` for
/// in-flight kernel teardown to drain. Four attempts + 100/200/300 ms backoffs
/// bound a retrying case's extra latency to ~0.6 s and only when it actually races.
const REBUILD_ATTEMPTS: u32 = 4;
const REBUILD_BACKOFF_MS: u64 = 100;

/// Rebuild one worker's netns fixture (single-pc), retrying a transient failure.
///
/// Tearing down a case leaves the kernel asynchronously freeing the just-killed
/// DUT's sockets, multicast memberships, and netns references AFTER the process is
/// reaped; recreating the netns before that finishes can race (a half-freed veth, a
/// stale `/run/netns` mount, a route the recreate cannot re-add) and surface as a
/// transient `ip` error mid-`netns::setup`. bash masked this with its per-`ip`
/// fork/exec latency; the native path runs the setup ops back to back and can
/// outrun the cleanup. Each attempt tears down first (idempotent — `netns::setup`
/// itself teardown-firsts, and this also reaps any lingering DUT/harness) and, from
/// the second attempt on, waits a short growing backoff so the cleanup drains. A
/// rebuild that fails every attempt is a real fixture fault and returns the last
/// error (the caller routes it to the FATAL execution-ledger path).
fn rebuild_worker_netns(topo: &(dyn Topology + Sync), w: u32) -> anyhow::Result<WorkerCtx> {
    let mut last_err = None;
    for attempt in 0..REBUILD_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(REBUILD_BACKOFF_MS * attempt as u64));
        }
        if let Err(e) = topo.tear_down_worker(w) {
            eprintln!("orchestrator: warning: worker {w} rebuild teardown (attempt {}): {e:#}", attempt + 1);
        }
        match topo.bring_up_worker(w) {
            Ok(ctx) => return Ok(ctx),
            Err(e) => {
                eprintln!(
                    "orchestrator: warning: worker {w} netns rebuild attempt {}/{REBUILD_ATTEMPTS} failed: {e:#}",
                    attempt + 1
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("REBUILD_ATTEMPTS >= 1 guarantees at least one attempt ran"))
}

/// Bring up one worker, drain its bucket sequentially, tear down. The teardown
/// guard is armed *before* bring-up so a partial `netns::setup` still gets reaped.
fn run_worker(
    cfg: &Config,
    topo: &(dyn Topology + Sync),
    w: u32,
    bucket: Vec<String>,
    dut_first: bool,
    neg: NegSchedule,
) -> WorkerResult {
    let mut r = WorkerResult::default();
    let _guard = WorkerGuard { topo, w };

    let ctx = match topo.bring_up_worker(w) {
        Ok(c) => c,
        Err(e) => {
            // No cases processed → the ledger will flag the shortfall as FATAL.
            r.worker_error = Some(format!("worker {w} bring-up failed: {e:#}"));
            return r;
        }
    };

    // Static per-topology contract bit: does this worker own a netns it must rebuild
    // before every case? Queried once (single-pc → true; remote/persistent → false).
    let rebuild = topo.rebuild_netns_per_case();

    for case in &bucket {
        // Per-case network isolation — bash run_case's TOPOLOGY_DUT_CONDITIONING
        // rebuild (smoke-test.sh). On a netns-owning topology, tear the worker's
        // netns down and bring it back up before every case so each starts on a
        // PRISTINE kernel network stack. Without this, any kernel-network mutation a
        // case leaves behind — a flushed `224.0.0.0/4` multicast route after a
        // link-flap teardown case (a link down/up on either leg drops that leg's
        // explicit route), a stale multicast membership, a sysctl, a neigh entry, an
        // iptables rule — leaks into every later case on this worker
        // (deterministically: one link-flap SD case can turn every subsequent
        // multicast-SD case a false `inconclusive`). The rebuild re-reads the fresh
        // veth MACs, so `case_ctx` (the `--expect` dut_mac and the tester-side neigh
        // pins) tracks the new namespace, never a stale one. `rebuild_worker_netns`
        // retries a transient bring-up (see there) so only a persistent fixture
        // fault reaches the FATAL path.
        let rebuilt;
        let case_ctx = if rebuild {
            match rebuild_worker_netns(topo, w) {
                Ok(c) => {
                    rebuilt = c;
                    &rebuilt
                }
                Err(e) => {
                    // The netns is down and could not be rebuilt after retries, so
                    // every remaining case on this worker is doomed. Abort the bucket
                    // with a worker error (bash's `set -e` worker-subshell death) —
                    // the ledger fails the run rather than silently skipping the tail.
                    r.worker_error = Some(format!(
                        "worker {w} per-case netns rebuild before {case} failed: {e:#}"
                    ));
                    break;
                }
            }
        } else {
            &ctx
        };

        // A negative run dispatches each case as its authored negative row; the
        // schedule carries every scheduled case's expected fail (built alongside
        // the bucket in main), so a miss is a construction bug, not a data gap.
        let negative = matches!(neg, Some(s) if s.mode == AssertMode::NegativeRow);
        let started = Instant::now();
        let outcome = match neg {
            Some(sched) => {
                let expected = sched
                    .expect
                    .get(case)
                    .expect("asserted schedule carries every scheduled case");
                match sched.mode {
                    AssertMode::NegativeRow => {
                        dispatch::run_negative_row(cfg, topo, w, case_ctx, case, expected)
                    }
                    AssertMode::KnownFail => {
                        dispatch::run_known_fail(cfg, topo, w, case_ctx, case, expected)
                    }
                }
            }
            None => dispatch::run_case(cfg, topo, w, case_ctx, case, dut_first),
        };
        let duration_s = started.elapsed().as_secs_f64();
        // bash names a negative testcase `<case>_neg` in the junit stream. A known-fail
        // assertion keeps the plain case name: it runs the case exactly as the positive
        // lane would, so a report reader should see the same testcase identity.
        let rec_name = if negative { format!("{case}_neg") } else { case.clone() };
        // Derive the report status + message per outcome (a non-conclusion renders
        // as a skip carrying its reason, matching bash; a dispatch fault as an error).
        let (status, message) = match outcome {
            Ok(Verdict::Pass) => {
                println!("[w{w}] PASS {case}");
                (Status::Pass, String::new())
            }
            Ok(Verdict::Fail(reason)) => {
                println!("[w{w}] FAIL {case} — {reason}");
                r.fails.push(case.clone());
                (Status::Fail, reason)
            }
            Ok(Verdict::Skip(reason)) => {
                println!("[w{w}] SKIP {case} — {reason}");
                r.skips.push(Skip { case: case.clone(), reason: reason.clone() });
                (Status::Skip, reason)
            }
            // A NEGATIVE that did not conclude is a hard failure, unlike every other
            // case, because of what a negative is FOR. Its whole job is to reach a
            // guard and prove a fault fires there; a run that never reached it
            // demonstrates nothing, and the exhaustiveness ledger goes on counting
            // that guard as proven checkable on the strength of a case that has
            // silently stopped checking it (docs/tech-debt.md TD-47).
            //
            // ⚠ This is NOT the capability skip. Those arrive as Verdict::Skip with
            // `skip:requires_capability_…` — measured 2026-09-25, the six lwIP-only
            // negatives on the Linux lane all land there — so an lwIP-only negative
            // sitting out a run it cannot drive is untouched by this.
            //
            // ⚠ Safe to gate because the population was measured first: all 163
            // negatives the lwIP sweep runs PASS, with zero non-conclusions, so this
            // turns nothing green into red today. It exists to catch the first one
            // that regresses.
            Ok(Verdict::NonConclusion(reason)) if is_negative_case(case) => {
                let reason = format!(
                    "negative did not exercise its guard, so it proves nothing: {reason}"
                );
                println!("[w{w}] FAIL {case} — {reason}");
                r.fails.push(case.clone());
                (Status::Fail, reason)
            }
            Ok(Verdict::NonConclusion(reason)) => {
                println!("[w{w}] SKIP* {case} — {reason}  (non-conclusion)");
                r.nonconclusions.push(Skip { case: case.clone(), reason: reason.clone() });
                (Status::Skip, reason)
            }
            Err(e) => {
                // A dispatch failure is not a DUT violation, so not Fail. It is not a
                // non-conclusion either: that is a verdict about a run, and this case
                // never ran. Hence no `error:` class token — the harness assigns
                // those, and none was assigned here. It stays out of the flake ceiling
                // because a rate cannot tell a transient fault from a deterministic
                // refusal such as TD-17's, and hiding either loses the case.
                let reason = format!("dispatch_fault: {e:#}");
                println!("[w{w}] ERROR {case} — {reason}  (not dispatched)");
                r.undispatched.push(Skip { case: case.clone(), reason: reason.clone() });
                (Status::Error, reason)
            }
        };
        r.records.push(CaseRecord { name: rec_name, status, duration_s, message, negative });
        r.processed += 1;
    }
    r
}

/// Fan workers out across scoped threads and join each explicitly. A panicking
/// worker yields a `worker_error` result (its processed count drops to zero, so
/// the caller's ledger fails the run) rather than aborting the whole process.
pub fn run_all(
    cfg: &Config,
    topo: &(dyn Topology + Sync),
    buckets: Vec<Vec<String>>,
    dut_first: bool,
    neg: NegSchedule,
) -> Vec<WorkerResult> {
    std::thread::scope(|s| {
        let handles: Vec<(u32, _)> = buckets
            .into_iter()
            .enumerate()
            .map(|(w, bucket)| {
                let w = w as u32;
                (w, s.spawn(move || run_worker(cfg, topo, w, bucket, dut_first, neg)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(w, h)| {
                h.join().unwrap_or_else(|_| WorkerResult {
                    worker_error: Some(format!("worker {w} thread panicked")),
                    ..Default::default()
                })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("C{i}")).collect()
    }

    #[test]
    fn negative_case_detection_matches_the_registers_naming() {
        // The shapes the tree actually uses.
        assert!(is_negative_case("ARP_34_NEG"));
        assert!(is_negative_case("ARP_34_NEG2"));
        assert!(is_negative_case("IPv4_REASSEMBLY_10_NEG4"));
        assert!(is_negative_case("arp_34_neg"));  // ids arrive as the user typed them
        // Positives, including ones whose NAME contains the letters.
        assert!(!is_negative_case("ARP_34"));
        assert!(!is_negative_case("TCP_UNACCEPTABLE_08"));
        // `_NEG` must END the id: a suffix after it is a different case, and
        // mis-classifying one would make an ordinary non-conclusion a hard failure.
        assert!(!is_negative_case("ARP_34_NEG_EXTRA"));
        assert!(!is_negative_case("ARP_NEGOTIATION_01"));
    }

    #[test]
    fn distribute_round_robin_assigns_each_case_once() {
        let c = cases(5);
        let buckets = distribute(&c, 2);
        assert_eq!(buckets.len(), 2);
        // i % 2: bucket0 = C0,C2,C4 ; bucket1 = C1,C3
        assert_eq!(buckets[0], vec!["C0", "C2", "C4"]);
        assert_eq!(buckets[1], vec!["C1", "C3"]);
        let total: usize = buckets.iter().map(Vec::len).sum();
        assert_eq!(total, c.len());
    }

    #[test]
    fn distribute_single_worker_gets_all() {
        let c = cases(3);
        let buckets = distribute(&c, 1);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0], c);
    }

    #[test]
    fn distribute_more_workers_than_cases_leaves_empty_buckets() {
        let buckets = distribute(&cases(2), 4);
        assert_eq!(buckets.len(), 4);
        assert_eq!(buckets[0], vec!["C0"]);
        assert_eq!(buckets[1], vec!["C1"]);
        assert!(buckets[2].is_empty());
        assert!(buckets[3].is_empty());
    }

    #[test]
    fn distribute_balances_within_one() {
        let buckets = distribute(&cases(10), 3);
        let lens: Vec<usize> = buckets.iter().map(Vec::len).collect();
        let (min, max) = (*lens.iter().min().unwrap(), *lens.iter().max().unwrap());
        assert!(max - min <= 1, "round-robin must balance within 1, got {lens:?}");
    }

    #[test]
    #[should_panic(expected = "workers >= 1")]
    fn distribute_zero_workers_panics() {
        distribute(&cases(1), 0);
    }
}
