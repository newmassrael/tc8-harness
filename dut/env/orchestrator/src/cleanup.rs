//! Crash/interrupt resilience — the bash `trap cleanup EXIT` + startup stale-GC
//! (smoke-test.sh) ported to Rust.
//!
//! Two parts:
//!   * a SIGINT/SIGTERM handler that tears down every worker before exit, so an
//!     interrupted run does not leak netns / reparented processes — Drop does
//!     NOT run on signal termination, so the per-worker RAII guard is not enough;
//!   * a startup sweep that reaps the processes + PID-scoped scratch dirs of
//!     prior orchestrator runs whose owner PID is dead. The netns themselves are
//!     reclaimed by `netns::setup`'s idempotent re-create at bring-up (teardown-
//!     first), the same contract bash relies on (the sweep only clears what would
//!     block the next run: leftover vsomeip UDS sockets and orphaned processes).

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Config;
use crate::topology;

/// Install the termination handler. On the first SIGINT/SIGTERM it tears down all
/// `workers` workers (idempotent), runs the caller's `extra` teardown, removes the
/// scratch roots, and exits 130.
///
/// `extra` carries the topology/fixture teardown the per-worker reap below cannot:
/// the ssh-remote remote DUT and the verification fixture (netns/sshd/veth). It is
/// an owned closure (`'static`) because the signal handler outlives every borrow —
/// `main` composes it from owned ssh params + the fixture kind.
pub fn install_signal_handler<F>(cfg: &Config, workers: u32, extra: F) -> anyhow::Result<()>
where
    F: Fn() + Send + 'static,
{
    let work_root = cfg.work_root.clone();
    let vsomeip_base = cfg.vsomeip_base.clone();
    ctrlc::set_handler(move || {
        eprintln!("orchestrator: signal received — tearing down {workers} worker(s)");
        // This runs on the ctrlc thread, possibly concurrently with live worker
        // threads (mid-spawn, mid-pcap, writing into these dirs) and their own RAII
        // reaps. Every step below is idempotent + best-effort, so a racing double
        // kill or a remove_dir_all over a file a worker is still creating yields at
        // most a transient error, never corruption — the same best-effort signal
        // race bash's `trap cleanup EXIT` accepts. process::exit(130) then ends all
        // threads.
        // Per-worker LOCAL reap first: kills the local harness/DUT under each worker
        // symlink and removes the netns (single-pc). Idempotent and safe for every
        // topology — external/ssh-remote have no netns, but the harness symlink reap
        // still applies and `netns::teardown` no-ops on an absent netns.
        for w in 0..workers {
            topology::teardown_worker(&vsomeip_base, w);
        }
        // Topology/fixture reap next, so the ssh-remote DUT dies before its sshd and
        // netns are removed (the fixture teardown).
        extra();
        let _ = fs::remove_dir_all(&work_root);
        let _ = fs::remove_dir_all(&vsomeip_base);
        // 128 + SIGINT(2): conventional shell exit status for an interrupt.
        std::process::exit(130);
    })
    .map_err(|e| anyhow::anyhow!("installing signal handler: {e}"))
}

/// Reap leftovers from prior orchestrator runs that died before cleanup.
/// Best-effort: every step no-ops on a clean host.
pub fn stale_gc(cfg: &Config) {
    reap_dead_scratch("tc8-orch-vsomeip.", &cfg.vsomeip_base, true);
    reap_orphan_processes();
    reap_dead_scratch("tc8-orch-workers.", &cfg.work_root, false);
}

/// True if `pid` is a live process. Linux-native liveness via /proc presence —
/// no libc dependency for a single `kill -0` equivalent.
fn pid_alive(pid: &str) -> bool {
    Path::new(&format!("/proc/{pid}")).is_dir()
}

fn is_dead_owner(owner: &str) -> bool {
    !owner.is_empty() && owner.bytes().all(|b| b.is_ascii_digit()) && !pid_alive(owner)
}

/// For each `/tmp/<prefix>PID` dir other than `mine` whose owner PID is dead:
/// optionally SIGKILL any process whose argv contains the dir path, then rm it.
fn reap_dead_scratch(prefix: &str, mine: &Path, kill_procs: bool) {
    let entries = match fs::read_dir("/tmp") {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.as_path() == mine || !path.is_dir() {
            continue;
        }
        let owner = match path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_prefix(prefix)) {
            Some(o) => o,
            None => continue,
        };
        if !is_dead_owner(owner) {
            continue;
        }
        if kill_procs {
            let _ = Command::new("pkill")
                .args(["-KILL", "-f"])
                .arg(format!("{}/", path.display()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&path);
    }
}

/// A process can outlive its scratch dir (bash note, smoke-test.sh): reap
/// anything executed from a dead run's `/tmp/tc8-orch-vsomeip.PID/` path.
fn reap_orphan_processes() {
    let out = match Command::new("pgrep")
        .args(["-af", r"^/tmp/tc8-orch-vsomeip\.[0-9]+/"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return,
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.splitn(2, ' ');
        let opid = it.next().unwrap_or("");
        let oargs = it.next().unwrap_or("");
        let owner = oargs
            .strip_prefix("/tmp/tc8-orch-vsomeip.")
            .and_then(|s| s.split('/').next())
            .unwrap_or("");
        if opid.is_empty() || !is_dead_owner(owner) {
            continue;
        }
        eprintln!("orchestrator: reaping orphan pid {opid} of dead run {owner}");
        let _ = Command::new("kill").args(["-KILL", opid]).status();
    }
}
