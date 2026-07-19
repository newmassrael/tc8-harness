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

/// The negative schedule: `case_id -> expected_fail` for a `--negative` run. When
/// present, every scheduled case is dispatched as its authored negative row
/// (`dispatch::run_negative_row`) instead of positively. `None` = a positive run.
/// Threaded by reference into the scoped worker threads (it is `Sync` and outlives
/// the scope), so `distribute` stays over plain case-id strings.
pub type NegSchedule<'a> = Option<&'a HashMap<String, String>>;

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
    /// Non-conclusions (inconclusive/error, incl. dispatch faults) — routed to a
    /// non-gating skip but counted against the non-conclusion ceiling.
    pub nonconclusions: Vec<Skip>,
    /// Cases this worker actually concluded — cross-checked against the schedule.
    pub processed: usize,
    /// One record per concluded case (name, status, duration, message) for the
    /// `--junit-xml` report. Built unconditionally — cheap, and it keeps the
    /// dispatch loop's bookkeeping in one place; main emits XML only when asked.
    pub records: Vec<CaseRecord>,
    /// Set when the worker never ran its bucket (bring-up failed, or panicked).
    pub worker_error: Option<String>,
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
        let negative = neg.is_some();
        let started = Instant::now();
        let outcome = match neg {
            Some(map) => {
                let expected = map
                    .get(case)
                    .expect("negative schedule carries every scheduled case");
                dispatch::run_negative_row(cfg, topo, w, case_ctx, case, expected)
            }
            None => dispatch::run_case(cfg, topo, w, case_ctx, case, dut_first),
        };
        let duration_s = started.elapsed().as_secs_f64();
        // bash names a negative testcase `<case>_neg` in the junit stream.
        let rec_name = if negative { format!("{case}_neg") } else { case.clone() };
        // Derive the report status + message per outcome (a non-conclusion and a
        // dispatch fault both render as a skip carrying their reason, matching bash).
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
            Ok(Verdict::NonConclusion(reason)) => {
                println!("[w{w}] SKIP* {case} — {reason}  (non-conclusion)");
                r.nonconclusions.push(Skip { case: case.clone(), reason: reason.clone() });
                (Status::Skip, reason)
            }
            Err(e) => {
                // A dispatch failure (spawn/IO) is a test-system fault, not a DUT
                // violation — route to the error non-conclusion class, not Fail.
                let reason = format!("error:dispatch_fault: {e:#}");
                println!("[w{w}] SKIP* {case} — {reason}  (non-conclusion)");
                r.nonconclusions.push(Skip { case: case.clone(), reason: reason.clone() });
                (Status::Skip, reason)
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
