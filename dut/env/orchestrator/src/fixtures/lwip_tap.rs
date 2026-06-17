//! lwIP tap fixture — the Rust port of `topology.d/examples/lwip-tap-fixture.conf`.
//!
//! The lwIP DUT (dut/lwip_dut/, a real embedded TCP/IP stack) attaches to a host
//! TAP via its unix-port tapif driver and answers ARP/ICMP/IP/UDP/TCP itself,
//! serving the Upper Tester on UDP 30600. Unlike the netns/ssh verification
//! fixtures — which only PROVISION a DUT for the External/SshRemote topologies —
//! the lwIP fixture also owns a per-case DUT LIFECYCLE: it respawns the DUT after
//! every case (the stack hands out UT socket ids 1,2,… that a persistent DUT would
//! drift, and tester-side connection halves must be drained before the kill to
//! avoid FIN-WAIT-2 orphans). bash expressed this by overriding `topology_stop_dut`
//! on `--topology external`; here it is a dedicated `Topology` (`LwipTap`) selected
//! by `[fixture] kind = "lwip-tap"`, reusing External's tester-side seam
//! (host-exec harness + host conditioning) via the `topology::host_*` helpers.
//!
//! Lock: bash held a flock on /var/lock and ran a fuser/leaked-holder SELF-HEAL,
//! because it leaked the lock fd to backgrounded children that outlived the run. A
//! Rust `File` is `O_CLOEXEC` by default, so the orchestrator's spawned DUT never
//! inherits this fd — the orchestrator never CREATES a leaked holder, so the
//! self-heal is omitted. The one residual the self-heal also covered, and we do
//! not: a leaked holder from a CRASHED bash run sharing this host (the strangler
//! runs both). There the orchestrator aborts loudly with a `fuser -k` hint rather
//! than auto-reaping — a rare, documented manual step, not silent corruption. The
//! base job (refuse a second concurrent fixture user) is a plain
//! `flock(LOCK_EX|LOCK_NB)`; the lock releases when the held `File` drops.

use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

use crate::conditioning::{CondDir, CondStep};
use crate::config::Config;
use crate::netns;
use crate::site::SiteConf;
use crate::topology::{self, Conditioning, Topology, WorkerCtx};
use crate::wire;

// Fixed host names / addresses — mirror lwip-tap-fixture.conf. Not PID-scoped (the
// fixture is host-global and runs sequentially with the bash original; provisioning
// teardown-firsts to reclaim a leftover).
const TAP: &str = "tc8lwip0";
const FIX_DIR: &str = "/tmp/tc8-lwipfix";
const LAST_DUT_LOG: &str = "/tmp/tc8-lwipfix-last-dut.log";
const LOCK_FILE: &str = "/var/lock/tc8-lwip-fixture.lock";
const DUT_IP: &str = "172.16.0.2";
const DUT_MASK: &str = "255.255.255.0";
const TESTER_IP: &str = "172.16.0.1";
// The AIface-0 alias the readiness probe sources from (cold-cache steering +
// UDP_USER_INTERFACE_08) and the Host-2 address (UDP_FIELDS_04, /32 host-local
// answerability) are single-homed in `crate::wire` (wire::TESTER_ALIAS_IP /
// wire::HOST2_IP) — referenced directly below, never re-declared here.
const DEFAULT_APP_REL: &str = "build-lwip-dut/tc8-lwip-dut";
const DEFAULT_KILL_NAME: &str = "tc8-lwip-dut";
/// UT 0x17 ARP-cache conditioning window (virtual seconds). MUST track
/// dut/lwip_dut/lwipopts.h ARP_MAXAGE (lwIP default 300): the ARP_48/49 trait
/// stimulus ages the table by exactly this to cross the stack's `age >= ARP_MAXAGE`
/// free condition (bash TOPOLOGY_UT_ARP_CACHE_TIMEOUT_S, lwip-tap-fixture.conf:49).
const UT_ARP_CACHE_TIMEOUT_S: &str = "300";

// Timings (mirror the bash seq/sleep budgets).
const READY_ATTEMPTS: u32 = 25;
const READY_TICK: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT_MS: &str = "200";
const DRAIN_ATTEMPTS: u32 = 20;
const DRAIN_TICK: Duration = Duration::from_millis(100);
const KILL_ATTEMPTS: u32 = 10;
const KILL_TICK: Duration = Duration::from_millis(50);

/// Readiness-probe backend (bash LWIP_READY_PROBE).
#[derive(Clone, Copy)]
enum ReadyProbe {
    /// In-house opcode UT OpPing (the conformance DUT).
    Opcode,
    /// AUTOSAR Testability GET_VERSION (the standalone UTM has no opcode UT).
    Testability,
}

/// Mutable fixture state, behind a `Mutex` so the `&self` Topology methods can
/// mutate it (MAX_WORKERS=1, so it is uncontended). Built in `bring_up_worker`.
struct LwipState {
    /// flock held for the run; releases when this `File` drops. `O_CLOEXEC`, so the
    /// spawned DUT never inherits it.
    _lock: fs::File,
    /// The current DUT child — held so it is reaped (waited) after the kill rather
    /// than left a zombie (bash setsid+disowns to reparent to init; Rust waits).
    dut: Option<Child>,
    /// Pre-existing (frozen) tester sockets toward the DUT IP, snapshotted once at
    /// bring-up; the per-case drain subtracts these so it only waits on this run's.
    baseline_socks: BTreeSet<String>,
}

/// lwIP-on-a-tap topology: External's tester side + a fixture-owned, per-case-
/// respawning lwIP DUT.
pub struct LwipTap<'a> {
    cfg: &'a Config,
    site: &'a SiteConf,
    app: PathBuf,
    ready_probe: ReadyProbe,
    kill_name: String,
    state: Mutex<Option<LwipState>>,
}

impl<'a> LwipTap<'a> {
    pub fn new(cfg: &'a Config, site: &'a SiteConf) -> Self {
        let fx = site.fixture.as_ref();
        let app = fx
            .and_then(|f| f.lwip_app.clone())
            .map(PathBuf::from)
            .unwrap_or_else(|| cfg.root.join(DEFAULT_APP_REL));
        let ready_probe = match fx.and_then(|f| f.lwip_ready_probe.as_deref()) {
            Some("testability") => ReadyProbe::Testability,
            _ => ReadyProbe::Opcode,
        };
        let kill_name = fx
            .and_then(|f| f.lwip_kill_name.clone())
            .unwrap_or_else(|| DEFAULT_KILL_NAME.to_string());
        LwipTap { cfg, site, app, ready_probe, kill_name, state: Mutex::new(None) }
    }

    // --- DUT lifecycle primitives -------------------------------------------

    /// Provision the host tap + addresses (idempotent: pre-clean a leftover first).
    fn provision_tap(&self) -> Result<()> {
        // Reclaim a stale fixture from a crashed prior run (best-effort).
        super::pkill_path(&self.app.to_string_lossy());
        netns::ip_quiet(&["link", "del", TAP]);
        let _ = fs::remove_dir_all(FIX_DIR);
        fs::create_dir_all(FIX_DIR).with_context(|| format!("mkdir {FIX_DIR}"))?;

        netns::ip(&["tuntap", "add", "dev", TAP, "mode", "tap"])?;
        netns::ip(&["addr", "add", &format!("{TESTER_IP}/24"), "dev", TAP])?;
        netns::ip(&["addr", "add", &format!("{}/24", wire::TESTER_ALIAS_IP), "dev", TAP])?;
        // /32: host-local answerability for the DUT's Host-2 ARP query, no 2nd subnet.
        netns::ip(&["addr", "add", &format!("{}/32", wire::HOST2_IP), "dev", TAP])?;
        netns::ip(&["link", "set", TAP, "up"])?;
        Ok(())
    }

    /// Spawn one lwIP DUT attached to the tap; stdout+stderr APPENDED to dut.log
    /// (a run accumulates the per-case respawns). The lock fd is not passed (Rust
    /// `File` is `O_CLOEXEC`), so the DUT cannot hold the fixture lock.
    fn spawn_dut(&self) -> Result<Child> {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{FIX_DIR}/dut.log"))
            .with_context(|| format!("opening {FIX_DIR}/dut.log"))?;
        let err = log.try_clone()?;
        Command::new(&self.app)
            .env("PRECONFIGURED_TAPIF", TAP)
            .env("TC8_LWIP_DUT_IP", DUT_IP)
            .env("TC8_LWIP_DUT_MASK", DUT_MASK)
            .env("TC8_LWIP_DUT_GW", TESTER_IP)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .with_context(|| format!("spawning lwIP DUT {}", self.app.display()))
    }

    /// Poll the DUT to readiness (an OpPing / GET_VERSION round trip proves the tap
    /// link, the lwIP netif, and the UT/testability server bind end to end — the
    /// "stack up" stderr line precedes the server thread's bind, so a fixed sleep
    /// is insufficient). Worst case ~READY_ATTEMPTS×(probe timeout + tick).
    fn wait_dut_ready(&self) -> Result<()> {
        for _ in 0..READY_ATTEMPTS {
            if self.probe_ready() {
                return Ok(());
            }
            sleep(READY_TICK);
        }
        bail!(
            "lwIP DUT did not answer the {} readiness probe after spawn (DUT log preserved at {LAST_DUT_LOG} on teardown)",
            self.probe_name()
        )
    }

    fn probe_name(&self) -> &'static str {
        match self.ready_probe {
            ReadyProbe::Opcode => "opcode",
            ReadyProbe::Testability => "testability",
        }
    }

    fn probe_ready(&self) -> bool {
        let h = &self.cfg.harness;
        match self.ready_probe {
            // GET_VERSION lifecycle only (--no-data); no --source-ip (a UTM fixture
            // runs no cold-cache case, so a warm primary-IP ARP entry is harmless).
            ReadyProbe::Testability => run_ok(
                Command::new(h)
                    .args(["testability-probe", "--dut-ip", DUT_IP, "--timeout", PROBE_TIMEOUT_MS, "--no-data"]),
            ),
            // --source-ip pins the probe to the tester ALIAS, not the primary IP:
            // the DUT ARP-resolves the probe's source and this fixture cannot flush
            // the lwIP ARP table per case, so a primary-IP probe would warm the
            // <172.16.0.1> entry the cold-cache ARP cases assert is absent.
            ReadyProbe::Opcode => run_ok(Command::new(h).args([
                "ut-ping", "--dut-ip", DUT_IP, "--timeout", PROBE_TIMEOUT_MS, "--source-ip", wire::TESTER_ALIAS_IP,
            ])),
        }
    }

    /// Drain tester-side sockets still mid-close toward the DUT BEFORE killing it,
    /// so their FINs complete against the live stack (reaching CLOSED / reopenable
    /// TIME-WAIT) instead of orphaning as FIN-WAIT-1/LAST-ACK that would answer the
    /// next run's same-quad SYN with a stale challenge-ACK. Subtracts the bring-up
    /// baseline (this dev host carries permanently-frozen orphans from tap-deleted
    /// runs that never drain). Polled; loud warning (not fatal) on timeout.
    fn drain_tester_sockets(&self, baseline: &BTreeSet<String>) {
        let mut residual = 0;
        for _ in 0..DRAIN_ATTEMPTS {
            residual = socket_snapshot().difference(baseline).count();
            if residual == 0 {
                return;
            }
            sleep(DRAIN_TICK);
        }
        eprintln!(
            "lwip-tap: WARNING — {residual} tester socket(s) toward {DUT_IP} still mid-close after drain; the respawn may orphan them (stale challenge-ACK risk on port-quad reuse)"
        );
    }

    /// Kill the DUT: SIGTERM first (the stack aborts every open UT slot — RSTs on
    /// the wire — so tester-side leaked halves reach CLOSED rather than FIN-WAIT-2;
    /// a userspace stack emits nothing on SIGKILL), SIGKILL backstop with a loud
    /// warning if TERM did not take. Then reap the held child (avoid a zombie).
    fn kill_dut(&self, held: &mut Option<Child>) {
        pkill(&["-TERM", "-f", &self.kill_name]);
        let mut gone = false;
        for _ in 0..KILL_ATTEMPTS {
            if !pgrep_alive(&self.kill_name) {
                gone = true;
                break;
            }
            sleep(KILL_TICK);
        }
        if !gone {
            eprintln!(
                "lwip-tap: WARNING — DUT ignored SIGTERM for {} ms, SIGKILL fallback (UT slot abort incomplete; FIN-WAIT-2 orphan risk on reused quads)",
                KILL_ATTEMPTS as u64 * KILL_TICK.as_millis() as u64
            );
            pkill(&["-KILL", "-f", &self.kill_name]);
        }
        if let Some(mut c) = held.take() {
            // Bounded like dispatch::CaseProcs::reap: the pkill above reaps the DUT
            // (its argv carries kill_name), so wait() returns promptly; the bound
            // guards the pathological missed-match (a decoupled kill_name) from
            // hanging the run under the held state lock.
            if !crate::dispatch::wait_bounded(&mut c, crate::dispatch::REAP_WAIT_TICKS) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// Full fixture teardown — kill the DUT, remove the tap, preserve the DUT log,
    /// drop the lock. Idempotent + best-effort (safe before bring-up / twice).
    ///
    /// The flock releases here (when `*guard = None` drops `LwipState`), i.e. at
    /// worker teardown — slightly earlier than bash, which holds it to process exit.
    /// That is a safe narrowing: the lock guards tap/scratch provisioning, and by
    /// this point the tap is deleted and the dir removed, so a concurrent fixture
    /// user acquiring the lock and provisioning a fresh tap cannot collide with this
    /// run (which is done with the tap).
    fn teardown(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(st) = guard.as_mut() {
            self.kill_dut(&mut st.dut);
        } else {
            // No tracked state (already torn down, or bring-up failed before storing
            // it). Best-effort reap by the SAME selector the live kill uses
            // (kill_name), not the app path — so a custom lwip_kill_name is honored.
            pkill(&["-KILL", "-f", &self.kill_name]);
        }
        netns::ip_quiet(&["link", "del", TAP]);
        // Preserve the DUT log for postmortems; the run dir goes away.
        let _ = fs::rename(format!("{FIX_DIR}/dut.log"), LAST_DUT_LOG);
        let _ = fs::remove_dir_all(FIX_DIR);
        *guard = None; // drop LwipState → release the flock
    }
}

impl Drop for LwipTap<'_> {
    fn drop(&mut self) {
        // Backstop for the normal/panic paths if tear_down_worker did not run; the
        // signal path uses fixtures::teardown_by_kind. Idempotent.
        self.teardown();
    }
}

impl Topology for LwipTap<'_> {
    fn max_workers(&self) -> Option<u32> {
        Some(1)
    }
    fn supports_dut_spawn(&self) -> bool {
        // The fixture owns the DUT (spawned at bring-up, respawned in stop_dut), so
        // dispatch must not also start one — start_dut returns None.
        false
    }
    fn supports_negative(&self) -> bool {
        false
    }

    fn ut_arp_cache_timeout(&self) -> Option<String> {
        Some(UT_ARP_CACHE_TIMEOUT_S.to_string())
    }

    fn preflight(&self) -> Result<()> {
        if !self.cfg.harness.is_file() {
            bail!("preflight: tc8-harness binary missing: {}", self.cfg.harness.display());
        }
        if !self.app.is_file() {
            bail!(
                "preflight: lwIP DUT binary missing: {} (build dut/lwip_dut into build-lwip-dut/)",
                self.app.display()
            );
        }
        // Tools the fixture invokes at runtime; a missing one would degrade silently
        // (a missing pgrep makes kill_dut think the DUT is gone after one tick; a
        // missing ss makes the drain a no-op) — fail loud instead.
        for tool in ["ip", "ss", "pkill", "pgrep"] {
            if topology::which(tool).is_none() {
                bail!("preflight: '{tool}' not found on PATH (the lwIP fixture needs it for tap setup / socket drain / DUT reap)");
            }
        }
        println!("orchestrator[lwip-tap]: preflight: lwIP DUT {} present — OK", self.app.display());
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        topology::host_bring_up_common(self.cfg, w)?;
        let lock = acquire_lock()?;
        self.provision_tap()?;
        // Snapshot pre-existing frozen sockets BEFORE spawning, so the per-case
        // drain only ever waits on sockets this run created.
        let baseline_socks = socket_snapshot();
        let dut = self.spawn_dut()?;
        *self.state.lock().unwrap() = Some(LwipState { _lock: lock, dut: Some(dut), baseline_socks });
        self.wait_dut_ready()?;
        // The readiness probe warmed the host neigh entry for the DUT IP — resolve
        // the lwIP MAC from it (the DUT MAC is not operator-pinned for this fixture).
        let dut_mac = topology::resolve_dut_mac(self.site, TAP, DUT_IP)?;
        let tester_mac = topology::iface_mac(TAP)?;
        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    fn tear_down_worker(&self, _w: u32) -> Result<()> {
        self.teardown();
        Ok(())
    }

    fn tester_iface(&self, _w: u32) -> String {
        TAP.to_string()
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        // The in-tree lwIP fixture conf sets no secondary iface, but honor one if an
        // OEM conf configures it (Topology-2 on a tap is not in the in-tree set).
        topology::site_secondary_iface(self.site)
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        // Same per-side policy as External: tester-side toggles apply (the tester is
        // this host's tap), DUT-side toggles are skipped + logged (the lwIP stack is
        // not a Linux kernel we can sysctl; ARP_48/49 cache aging rides the UT 0x17
        // channel instead — a per-case stimulus concern, not host conditioning).
        topology::host_condition_case(self, &self.cfg.tester_ip4, &ctx.tester_mac, w, case_id, "lwip-tap")
    }

    fn exec_cond_step(&self, _w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        topology::host_exec_cond_step(TAP, step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        topology::host_run_harness(&topology::harness_link(&self.cfg.vsomeip_base, w), hlog, args)
    }

    fn start_dut(&self, _w: u32, dlog: &Path, _cfg_path: &Path) -> Result<Option<Child>> {
        // The fixture already has the DUT up (bring-up, or the prior case's respawn).
        let _ = fs::write(dlog, format!("[lwip-tap] persistent lwIP DUT on {TAP} at {DUT_IP}\n"));
        Ok(None)
    }

    fn stop_dut(&self, _w: u32) -> Result<()> {
        // Per-case respawn (bash topology_stop_dut): drain tester sockets → kill the
        // DUT (SIGTERM slot-abort then KILL) → respawn → readiness. A respawn/ready
        // failure is a loud warning, not an error (the established fixture policy:
        // the NEXT case fails visibly rather than aborting the worker from teardown).
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let st = match guard.as_mut() {
            Some(st) => st,
            None => return Ok(()), // bring-up never ran; nothing to respawn
        };
        self.drain_tester_sockets(&st.baseline_socks);
        self.kill_dut(&mut st.dut);
        match self.spawn_dut() {
            Ok(child) => st.dut = Some(child),
            Err(e) => {
                eprintln!("lwip-tap: WARNING — DUT respawn failed: {e:#} (the next case will fail readiness)");
                return Ok(());
            }
        }
        drop(guard); // wait_dut_ready does not touch state
        if let Err(e) = self.wait_dut_ready() {
            eprintln!("lwip-tap: WARNING — {e:#}");
        }
        Ok(())
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        topology::kill_by_marker(&topology::harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
}

/// Idempotent teardown for the signal handler (which cannot hold the `LwipTap`):
/// SIGKILL the DUT by either lwIP process name (the fixture runs exactly one; the
/// absent name no-ops — both are fixture-owned), remove the tap, preserve the log,
/// drop the run dir. SIGKILL (not the per-case SIGTERM slot-abort) is acceptable on
/// an interrupted run — the whole run is aborting. The flock releases on process
/// exit (the held fd closes). Fixed names, so no state is needed.
pub(crate) fn signal_teardown() {
    pkill(&["-KILL", "-f", DEFAULT_KILL_NAME]);
    pkill(&["-KILL", "-f", "tc8-lwip-utm"]);
    netns::ip_quiet(&["link", "del", TAP]);
    let _ = fs::rename(format!("{FIX_DIR}/dut.log"), LAST_DUT_LOG);
    let _ = fs::remove_dir_all(FIX_DIR);
}

// --- free helpers -----------------------------------------------------------

/// Acquire the host-global fixture lock (LOCK_EX|LOCK_NB). Held by the returned
/// `File`; releases when it drops. See the module docs for why bash's
/// fuser/leaked-holder self-heal is omitted (and the one residual it covered).
fn acquire_lock() -> Result<fs::File> {
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false) // a lock file is just an inode to flock; its content is irrelevant
        .open(LOCK_FILE)
        .with_context(|| format!("opening lwIP fixture lock {LOCK_FILE}"))?;
    // SAFETY: a live, owned fd from `f`; flock has no memory effects.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        bail!(
            "lwIP fixture lock {LOCK_FILE} is held — a live fixture user (CI lwip-sweep / local run), or a leaked holder from a crashed run; refusing to corrupt its tap/scratch. If no fixture is running, clear it: fuser -k {LOCK_FILE}. ({})",
            std::io::Error::last_os_error()
        );
    }
    Ok(f)
}

/// `ss -H -tn state connected dst <DUT_IP>` → set of `"<local> <peer>"` quads,
/// excluding TIME-WAIT / FIN-WAIT-2 (the tester's FIN is already out+ACKed there).
/// A `BTreeSet` gives the sorted-unique set bash got from `sort` + `comm`.
fn socket_snapshot() -> BTreeSet<String> {
    let out = match Command::new("ss")
        .args(["-H", "-tn", "state", "connected", "dst", DUT_IP])
        .output()
    {
        Ok(o) => o,
        Err(_) => return BTreeSet::new(),
    };
    let mut set = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains("TIME-WAIT") || line.contains("FIN-WAIT-2") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 {
            // awk '{print $(NF-1), $NF}' — the local + peer endpoints.
            set.insert(format!("{} {}", cols[cols.len() - 2], cols[cols.len() - 1]));
        }
    }
    set
}

/// `pkill ARGS` (best-effort, output discarded).
fn pkill(args: &[&str]) {
    let _ = Command::new("pkill")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// `pgrep -f PATTERN` — true if any process matches (pgrep excludes its own pid).
fn pgrep_alive(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run a command with stdio discarded; true on exit 0.
fn run_ok(cmd: &mut Command) -> bool {
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
