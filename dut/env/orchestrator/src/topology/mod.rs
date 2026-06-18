//! Topology abstraction — the bash `source`+function-override profile contract
//! (single-pc.conf / external.conf / ssh-remote.conf) reimplemented as a Rust
//! trait. single-pc spawns per-worker netns pairs.
//!
//! Stage 3 ported the netns fixture natively: bring-up/teardown call the `netns`
//! module instead of shelling out to `setup-netns.sh` / `cleanup.sh` (the bash
//! originals remain the SSOT baseline for smoke-test.sh until the S8 CI cutover).
//!
//! Reap-selector decision matrix (the SINGLE place this is documented; the four
//! kill sites below all point here). The rule is: scope the match as narrowly as
//! the target's identity allows.
//!
//! | selector            | site                          | why this one |
//! |---------------------|-------------------------------|--------------|
//! | `-f <symlink path>` | `kill_by_marker` (this mod),  | argv[0] is a per-worker / per-fixture UNIQUE path, so the match hits exactly this run's procs; the orchestrator's own cmdline never contains a symlink path → never self-matched. |
//! |                     | `fixtures::pkill_path`        | |
//! | `-x <comm>`         | `host::SshRemote` remote reap | runs on the REMOTE DUT host: `-f` would also match the ssh session's own remote shell line, and that host runs exactly one `tc8-dut`, so an exact-comm match is both sufficient and necessary. |
//! | `-f <kill_name>`    | `lwip_tap` (DUT app name)     | a process NAME, not a unique path — safe ONLY because the lwIP-tap fixture holds a host-wide flock (single-instance), so at most one such DUT exists host-wide and a name match cannot stomp a concurrent fixture. Relaxing that flock invariant would force this back to a path scope. |
//! | exact PID (pidfile) | `fixtures::kill_pidfile`      | sshd: even a `-x sshd` would hit the host's own system sshd, so kill only the recorded PID. |
//!
//! PGID-based kill was deliberately rejected (bash smoke-test.sh, the SSOT
//! baseline): under `set -m`, `ip netns exec` forks internally and the real binary
//! is reparented to init, so its PGID is unreliable across iproute2 versions —
//! matching by the worker-unique argv[0] is the robust, TERMINAL design.

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use crate::conditioning::{CondDir, CondStep};
use crate::netns;

// Every topology lives in a submodule (host = External + SshRemote + the shared
// HostTester transport; lwip_tap; single_pc); this file keeps only the cross-topology
// layer they share — the Topology trait, the worker-scoped netns/symlink naming +
// teardown, and `kill_by_marker`. LwipTap moved here from `fixtures/` (it is a
// first-class host-NIC topology, not a verification fixture); SinglePc moved out of
// this file into `single_pc` so all four topologies are siblings.
mod host;
mod lwip_tap;
mod single_pc;

pub use host::{ssh_reap_remote_dut, External, SshRemote};
pub(crate) use host::HostTester;
pub use lwip_tap::LwipTap;
pub(crate) use lwip_tap::{resolve_kill_name, signal_teardown as lwip_signal_teardown};
pub use single_pc::SinglePc;

/// Per-worker identity captured at bring-up (kernel-assigned veth MACs).
pub struct WorkerCtx {
    pub dut_mac: String,
    /// Kernel-assigned tester veth MAC. Read by the IPv4 AUTOCONF per-case
    /// conditioning to pin <tester_ip> PERMANENT on the DUT side.
    pub tester_mac: String,
}

/// RAII handle that reverts one case's per-case conditioning. It holds the
/// SEMANTIC restore steps and a handle to the topology, and `restore()` replays
/// each step in the `Restore` direction through `Topology::exec_cond_step` — so
/// the guard is transport-neutral: it owns WHAT to undo and that it runs once, the
/// topology owns HOW (single-pc renders to `ip`; S5 transports render to ssh /
/// host-exec). Drop calls `restore()` so a panic or an early-return error between
/// apply and the explicit restore still unwinds the kernel state. Idempotent via
/// `restored`. Restore is best-effort and logged: the worker's netns teardown is
/// the ultimate backstop (sysctls vanish with the netns), but a silently-failed
/// restore would leak a toggle into the next case in the bucket — so a failure is
/// surfaced, never swallowed.
pub struct Conditioning<'a> {
    topo: &'a dyn Topology,
    w: u32,
    restore_steps: Vec<CondStep>,
    restored: bool,
}

impl Conditioning<'_> {
    /// Revert the toggles. Safe to call more than once (Drop also calls it).
    pub fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        // Replayed in apply (forward) order. Safe because per-case steps are
        // mutually independent (one family per case; the sysctls within a family
        // touch distinct keys) — matching bash, which also restores forward. An
        // order-dependent toggle would need reverse replay; none exists today.
        for step in &self.restore_steps {
            if let Err(e) = self.topo.exec_cond_step(self.w, step, CondDir::Restore) {
                eprintln!("orchestrator: warning: conditioning restore failed: {e}");
            }
        }
    }
}

impl Drop for Conditioning<'_> {
    fn drop(&mut self) {
        self.restore();
    }
}

impl<'a> Conditioning<'a> {
    /// A guard starting with no restore steps — `host_condition_case` builds on this,
    /// pushing a restore for each tester-side step it applies (often none, e.g. a
    /// flush-only case, in which case `restore`/Drop are genuine no-ops).
    pub(crate) fn empty(topo: &'a dyn Topology, w: u32) -> Self {
        Conditioning { topo, w, restore_steps: Vec::new(), restored: false }
    }
}

// --- Worker-scoped names (SSOT for netns / veth / symlink naming) -----------
// Every consumer (bring-up, per-case kill, full teardown, the signal handler)
// derives names here so they can never drift apart.

fn netns_tester(w: u32) -> String {
    format!("tc8-tester-{w}")
}
fn netns_dut(w: u32) -> String {
    format!("tc8-dut-{w}")
}
/// Worker-unique argv[0] for the DUT (the marker `pkill -f` scopes the kill to).
fn dut_link(vsomeip_base: &Path, w: u32) -> PathBuf {
    vsomeip_base.join(format!("{w}/tc8-dut"))
}
/// Worker-unique argv[0] for the harness.
pub(crate) fn harness_link(vsomeip_base: &Path, w: u32) -> PathBuf {
    vsomeip_base.join(format!("{w}/tc8-harness"))
}

/// The per-topology contract smoke-test.sh expresses as sourced bash functions.
///
/// The three capability methods are the Rust form of the bash TOPOLOGY_* contract
/// vars consumed by the `main` gates (smoke-test.sh). They are required —
/// no default — so every topology states its contract explicitly, the same
/// guarantee bash got from its startup contract check. The fourth bash var,
/// TOPOLOGY_DUT_CONDITIONING, is not a separate method: each topology encodes that
/// policy directly in `condition_case` (single-pc applies the toggles; external /
/// ssh-remote log the omission and return an empty guard).
pub trait Topology {
    /// Worker cap (bash `TOPOLOGY_MAX_WORKERS`): `None` = no cap (single-pc netns
    /// pairs are cheap), `Some(1)` = one shared physical/remote DUT serves one
    /// worker. Enforced as a hard reject in `main`, not a silent clamp.
    fn max_workers(&self) -> Option<u32>;
    /// Whether the orchestrator starts a fresh DUT per case (bash
    /// `TOPOLOGY_SUPPORTS_DUT_SPAWN`). `false` ⇒ a persistent external DUT, and
    /// `--dut-first` (start-order control) is rejected as inapplicable.
    fn supports_dut_spawn(&self) -> bool;
    /// Whether the curated negative rows can run here (bash
    /// `TOPOLOGY_SUPPORTS_NEGATIVE`) — they need a spawned reference DUT plus
    /// deliberate mis-expectations and start-order tricks. Gated in `main`;
    /// consumed in full by the S6 negative stage.
    fn supports_negative(&self) -> bool;
    /// For a DUT that ages its ARP cache through the Upper Tester channel (UT 0x17)
    /// instead of host sysctls — the lwIP stack — the cache-conditioning window in
    /// virtual seconds (bash `TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S`). `Some(n)` makes
    /// dispatch emit a global `--expect arp_stimulus.ut_cache_conditioning_s=n` (the
    /// harness then UT-ages the table for ARP_48/49) and suppresses those cases'
    /// host-sysctl conditioning-skip line (they are UT-conditioned, not skipped).
    /// `None` (Linux DUTs) → host sysctls. Default `None`; only LwipTap overrides.
    fn ut_arp_cache_timeout(&self) -> Option<String> {
        None
    }
    /// Pre-provision precondition checks ONLY (required config, local binary/tool/
    /// interface existence) — never DUT liveness (bash `topology_preflight`). Runs
    /// before `provision_run`, so it must not assume anything `provision_run` (or a
    /// `[fixture]` overlay) stands up exists yet.
    fn preflight(&self) -> Result<()>;
    /// Stand up what this topology OWNS for the whole run — netns / tap / DUT / lock
    /// / socket-baseline — ONCE, post-`preflight` and pre-worker-fork, AND verify the
    /// DUT is live (bash `topology_provision_run`). A topology that owns nothing
    /// (single-pc provisions per-worker netns pairs; a pre-existing external DUT
    /// stands up nothing) still uses this as the DUT-liveness gate. This is the run-
    /// level seam: per-worker work belongs in `bring_up_worker`, which `max_workers`
    /// may call more than once — run-level provisioning here is called exactly once.
    /// Default: no-op (single-pc).
    fn provision_run(&self) -> Result<()> {
        Ok(())
    }
    /// Reap what `provision_run` stood up, ONCE in the main flow (bash
    /// `topology_teardown_run`); no-op for a pre-existing DUT. Best-effort: it runs
    /// on the teardown path, so the caller logs a failure rather than aborting.
    /// Default: no-op. (Per-worker teardown is `tear_down_worker`; a fixture's Drop
    /// remains the panic/SIGINT backstop.)
    fn teardown_run(&self) -> Result<()> {
        Ok(())
    }
    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx>;
    fn tear_down_worker(&self, w: u32) -> Result<()>;
    fn tester_iface(&self, w: u32) -> String;
    /// The secondary tester interface for TC8 Topology 2 (DHCPv4_CLIENT_USAGE_01),
    /// or `None` when this topology/run provides none — in which case dispatch
    /// SKIPs the case instead of running it to a misleading timeout (bash
    /// `topology_tester_iface_secondary` + run_case skip, smoke-test.sh).
    /// A required bash contract hook (smoke-test.sh).
    fn tester_iface_secondary(&self, w: u32) -> Option<String>;
    /// Apply one case's per-case kernel conditioning (the per-case neigh flush + the
    /// case-keyed sysctl/neigh toggles smoke-test.sh's run_case applies before the
    /// harness runs), returning a guard that reverts every applied toggle on
    /// `restore()` / Drop. The case→toggle POLICY is shared (`conditioning::plan`);
    /// only `exec_cond_step` (rendering to this topology's transport) varies per
    /// topology. This is also where the bash TOPOLOGY_DUT_CONDITIONING contract bit
    /// lives: single-pc applies every step (it owns both stacks); a topology that
    /// does not manage the DUT (external / ssh-remote) applies the TESTER-side steps
    /// — the tester is always a host we own (smoke-test.sh) — and skips +
    /// logs only the DUT-side steps.
    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>>;
    /// Render+run ONE semantic conditioning step in `dir` on this topology's
    /// transport: single-pc → `ip netns exec` / `ip -n` in the worker's namespaces;
    /// external / ssh-remote → a plain host command for the tester-side step (the
    /// tester is this host). The `Conditioning` guard calls this to replay restores,
    /// so it stays object-safe.
    fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()>;
    /// Spawn the harness backgrounded in the tester context; caller waits on it.
    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child>;
    /// Spawn a fresh DUT backgrounded. Called once per case UNCONDITIONALLY (the
    /// dispatcher does not gate on `supports_dut_spawn`); a topology with a
    /// persistent / externally-owned DUT (external, ssh-remote, lwip-tap) returns
    /// `Ok(None)` to signal "no per-case spawn". The caller owns any returned Child
    /// and must `wait()` it after stop_dut to reap the `ip netns exec` wrapper PID.
    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>>;
    /// SIGKILL+confirm the DUT process tree (keeps the netns alive for the next
    /// case on this worker).
    fn stop_dut(&self, w: u32) -> Result<()>;
    /// SIGKILL+confirm the harness process tree. Needed because `harness.kill()`
    /// only signals the `ip netns exec` wrapper, not the reparented harness.
    fn stop_harness(&self, w: u32) -> Result<()>;
}

/// Tear down one worker's processes + netns. Idempotent and best-effort (safe on
/// a partially-brought-up worker and to call twice) — the kills no-op when their
/// targets are absent and `netns::teardown` is idempotent. Shared by the
/// per-worker teardown path and the signal handler so both reap identically.
pub fn teardown_worker(vsomeip_base: &Path, w: u32) {
    kill_by_marker(&dut_link(vsomeip_base, w));
    kill_by_marker(&harness_link(vsomeip_base, w));
    netns::teardown(&netns_tester(w), &netns_dut(w));
}

/// SIGKILL every process whose argv contains `marker` (a worker-unique symlink
/// path), then poll up to 5×0.1s for them to disappear before returning. The
/// next case on a worker must not start while a prior DUT is still emitting SD
/// offers (the FORMAT_02 session_id==0x0001 race). Mirrors bash
/// kill_worker_procs's kill-and-confirm loop (smoke-test.sh).
pub(crate) fn kill_by_marker(marker: &Path) {
    let m = marker.as_os_str();
    if Command::new("pkill")
        .args(["-KILL", "-f"])
        .arg(m)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!(
            "orchestrator: warning: could not spawn pkill to reap {}",
            marker.display()
        );
        return;
    }
    for _ in 0..5 {
        // pgrep exits non-zero when nothing matches → the processes are gone.
        let gone = !crate::proc::run_ok(Command::new("pgrep").args(["-f"]).arg(m));
        if gone {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    eprintln!(
        "orchestrator: warning: process(es) under {} survived SIGKILL+confirm",
        marker.display()
    );
}

/// The vsomeip runtime artifacts a fresh DUT spawn must not inherit: the routing
/// UDS sockets (`vsomeip-*`) and the routing lock (`vsomeip.lck`). Single-homed so
/// the local fs wipe (`single_pc::wipe_vsomeip_runtime`) and the remote shell wipe
/// (`host::SshRemote::start_dut`) name one token set and can never drift.
pub(crate) const VSOMEIP_RT_SOCK_PREFIX: &str = "vsomeip-";
pub(crate) const VSOMEIP_RT_LOCK: &str = "vsomeip.lck";

pub(crate) fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = fs::remove_file(link);
    symlink(target, link)
        .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
}

pub(crate) fn which(prog: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(prog);
            if p.is_file() {
                Some(p)
            } else {
                None
            }
        })
    })
}
