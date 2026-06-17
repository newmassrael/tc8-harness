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

use crate::config::Config;
use crate::dispatch::{self, Verdict};
use crate::topology::Topology;

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
/// an early bring-up failure (`netns::teardown` is idempotent, so a half-built or
/// never-built worker is safe to tear down). Mirrors bash's `trap cleanup EXIT`
/// for the normal/panic paths; signal-time teardown is handled in `cleanup`.
struct WorkerGuard<'a, T: Topology> {
    topo: &'a T,
    w: u32,
}

impl<T: Topology> Drop for WorkerGuard<'_, T> {
    fn drop(&mut self) {
        // tear_down_worker emits its own warnings for surviving processes; the
        // netns delete is best-effort idempotent (mirrors cleanup.sh `|| true`).
        let _ = self.topo.tear_down_worker(self.w);
    }
}

/// Bring up one worker, drain its bucket sequentially, tear down. The teardown
/// guard is armed *before* bring-up so a partial `netns::setup` still gets reaped.
fn run_worker<T: Topology + Sync>(
    cfg: &Config,
    topo: &T,
    w: u32,
    bucket: Vec<String>,
    dut_first: bool,
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

    for case in &bucket {
        match dispatch::run_case(cfg, topo, w, &ctx, case, dut_first) {
            Ok(Verdict::Pass) => println!("[w{w}] PASS {case}"),
            Ok(Verdict::Fail(reason)) => {
                println!("[w{w}] FAIL {case} — {reason}");
                r.fails.push(case.clone());
            }
            Ok(Verdict::Skip(reason)) => {
                println!("[w{w}] SKIP {case} — {reason}");
                r.skips.push(Skip { case: case.clone(), reason });
            }
            Ok(Verdict::NonConclusion(reason)) => {
                println!("[w{w}] SKIP* {case} — {reason}  (non-conclusion)");
                r.nonconclusions.push(Skip { case: case.clone(), reason });
            }
            Err(e) => {
                // A dispatch failure (spawn/IO) is a test-system fault, not a DUT
                // violation — route to the error non-conclusion class, not Fail.
                let reason = format!("error:dispatch_fault: {e:#}");
                println!("[w{w}] SKIP* {case} — {reason}  (non-conclusion)");
                r.nonconclusions.push(Skip { case: case.clone(), reason });
            }
        }
        r.processed += 1;
    }
    r
}

/// Fan workers out across scoped threads and join each explicitly. A panicking
/// worker yields a `worker_error` result (its processed count drops to zero, so
/// the caller's ledger fails the run) rather than aborting the whole process.
pub fn run_all<T: Topology + Sync>(
    cfg: &Config,
    topo: &T,
    buckets: Vec<Vec<String>>,
    dut_first: bool,
) -> Vec<WorkerResult> {
    std::thread::scope(|s| {
        let handles: Vec<(u32, _)> = buckets
            .into_iter()
            .enumerate()
            .map(|(w, bucket)| {
                let w = w as u32;
                (w, s.spawn(move || run_worker(cfg, topo, w, bucket, dut_first)))
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
