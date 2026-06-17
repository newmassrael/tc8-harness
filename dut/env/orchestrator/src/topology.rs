//! Topology abstraction — the bash `source`+function-override profile contract
//! (single-pc.conf / external.conf / ssh-remote.conf) reimplemented as a Rust
//! trait. single-pc spawns per-worker netns pairs.
//!
//! Stage 3 ported the netns fixture natively: bring-up/teardown call the `netns`
//! module instead of shelling out to `setup-netns.sh` / `cleanup.sh` (the bash
//! originals remain the SSOT baseline for smoke-test.sh until the S8 CI cutover).
//!
//! Process teardown uses `pkill -f` on the worker-unique symlink path, matching
//! the bash design. This is the TERMINAL design, not a placeholder: bash
//! (smoke-test.sh:624-638) deliberately rejected PGID-based kill because under
//! `set -m` `ip netns exec` forks internally and the real binary is reparented
//! to init, so its PGID is unreliable across iproute2 versions — matching by the
//! worker-unique argv[0] is the robust approach. The orchestrator's own cmdline
//! never contains a symlink path, so it is never self-matched.

use anyhow::{bail, Context, Result};
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use crate::conditioning::{self, CondDir, CondStep, Side};
use crate::config::Config;
use crate::netns::{self, NetnsParams};
use crate::site::SiteConf;
use crate::wire;

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
fn veth_tester(w: u32) -> String {
    format!("veth-tester-{w}")
}
fn veth_dut(w: u32) -> String {
    format!("veth-dut-{w}")
}
/// Worker-unique argv[0] for the DUT (the marker `pkill -f` scopes the kill to).
pub fn dut_link(vsomeip_base: &Path, w: u32) -> PathBuf {
    vsomeip_base.join(format!("{w}/tc8-dut"))
}
/// Worker-unique argv[0] for the harness.
pub fn harness_link(vsomeip_base: &Path, w: u32) -> PathBuf {
    vsomeip_base.join(format!("{w}/tc8-harness"))
}

// --- single-pc conditioning rendering ---------------------------------------
// Bind the semantic `conditioning::plan` steps to the netns transport for one
// worker. This is single-pc's renderer; S5 topologies (external/ssh-remote)
// render the same steps to host-exec / ssh / a logged skip. Kept pure (no I/O)
// so the rendering is unit-tested directly, separate from the case→toggle policy.

/// The (namespace, L3 interface) a logical `Side` resolves to on worker `w`.
fn side_ns_iface(w: u32, side: Side) -> (String, String) {
    match side {
        Side::Dut => (netns_dut(w), veth_dut(w)),
        Side::Tester => (netns_tester(w), veth_tester(w)),
    }
}

/// `ip netns exec NS sysctl -qw KEY=VALUE` argv.
fn sysctl_argv(ns: String, kv: String) -> Vec<String> {
    vec!["netns".into(), "exec".into(), ns, "sysctl".into(), "-qw".into(), kv]
}

/// Render one semantic step to an `ip` argv for `dir`, or `None` when the
/// direction is a no-op (a flush or a no-undo pin has no restore action).
fn render_cond_step(w: u32, step: &CondStep, dir: CondDir) -> Option<Vec<String>> {
    match step {
        CondStep::SysctlIface { side, table, leaf, on, off } => {
            let (ns, iface) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.{}.{iface}.{leaf}={val}", table.as_str())))
        }
        CondStep::SysctlConfAll { side, leaf, on, off } => {
            let (ns, _) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.conf.all.{leaf}={val}")))
        }
        CondStep::SysctlGlobal { side, key, on, off } => {
            let (ns, _) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.{key}={val}")))
        }
        CondStep::NeighPin { side, ip, mac, undo } => {
            let (ns, iface) = side_ns_iface(w, *side);
            match dir {
                CondDir::Apply => Some(vec![
                    "-n".into(), ns, "neigh".into(), "replace".into(), ip.clone(),
                    "lladdr".into(), mac.clone(), "dev".into(), iface, "nud".into(), "permanent".into(),
                ]),
                CondDir::Restore if *undo => Some(vec![
                    "-n".into(), ns, "neigh".into(), "del".into(), ip.clone(), "dev".into(), iface,
                ]),
                CondDir::Restore => None,
            }
        }
        CondStep::NeighFlush { side } => match dir {
            CondDir::Apply => {
                let (ns, iface) = side_ns_iface(w, *side);
                Some(vec!["-n".into(), ns, "neigh".into(), "flush".into(), "dev".into(), iface])
            }
            CondDir::Restore => None,
        },
    }
}

/// The per-topology contract smoke-test.sh expresses as sourced bash functions.
///
/// The three capability methods are the Rust form of the bash TOPOLOGY_* contract
/// vars consumed by the `main` gates (smoke-test.sh:412-422). They are required —
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
    fn preflight(&self) -> Result<()>;
    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx>;
    fn tear_down_worker(&self, w: u32) -> Result<()>;
    fn tester_iface(&self, w: u32) -> String;
    /// The secondary tester interface for TC8 Topology 2 (DHCPv4_CLIENT_USAGE_01),
    /// or `None` when this topology/run provides none — in which case dispatch
    /// SKIPs the case instead of running it to a misleading timeout (bash
    /// `topology_tester_iface_secondary` + run_case skip, smoke-test.sh:1436-1446).
    /// A required bash contract hook (smoke-test.sh:390-393).
    fn tester_iface_secondary(&self, w: u32) -> Option<String>;
    /// Apply one case's per-case kernel conditioning (the per-case neigh flush + the
    /// case-keyed sysctl/neigh toggles smoke-test.sh's run_case applies before the
    /// harness runs), returning a guard that reverts every applied toggle on
    /// `restore()` / Drop. The case→toggle POLICY is shared (`conditioning::plan`);
    /// only `exec_cond_step` (rendering to this topology's transport) varies per
    /// topology. This is also where the bash TOPOLOGY_DUT_CONDITIONING contract bit
    /// lives: single-pc applies every step (it owns both stacks); a topology that
    /// does not manage the DUT (external / ssh-remote) applies the TESTER-side steps
    /// — the tester is always a host we own (smoke-test.sh:966-974) — and skips +
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

/// single-pc: tester + reference tc8-dut in per-worker netns pairs on this host.
pub struct SinglePc<'a> {
    cfg: &'a Config,
}

impl<'a> SinglePc<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        SinglePc { cfg }
    }
}

impl Topology for SinglePc<'_> {
    // single-pc.conf contract: cheap netns pairs (no cap), fresh DUT per case,
    // negative self-validation, and per-case kernel conditioning all available.
    fn max_workers(&self) -> Option<u32> {
        None
    }
    fn supports_dut_spawn(&self) -> bool {
        true
    }
    fn supports_negative(&self) -> bool {
        true
    }

    fn preflight(&self) -> Result<()> {
        let cfg = self.cfg;
        if !cfg.dut_bin.is_file() {
            bail!("preflight: tc8-dut binary missing: {}", cfg.dut_bin.display());
        }
        if !cfg.vsomeip_cfg.is_file() {
            bail!("preflight: vsomeip.json missing: {}", cfg.vsomeip_cfg.display());
        }
        // Tools the netns module (S3 port) invokes directly. `ip`/`sysctl`/`ping`
        // are mandatory — bash setup-netns.sh runs them without `|| true` under
        // `set -e`. `ethtool` is best-effort there (offload-disable is advisory),
        // so it is intentionally not a hard preflight requirement.
        for tool in ["ip", "sysctl", "ping"] {
            if which(tool).is_none() {
                bail!("preflight: '{tool}' not found on PATH");
            }
        }
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        let cfg = self.cfg;
        fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
        fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;

        // Build the netns fixture natively (S3 port of setup-netns.sh).
        // single-pc destroys + recreates the netns pair each bring-up, which
        // wipes any leftover iptables `tc8-stimulus` rule — so unlike bash's
        // common_bring_up_worker (smoke-test.sh:681) no explicit chain flush is
        // needed here. A persistent topology (external/ssh-remote) that reuses a
        // netns WILL need that flush ported alongside it.
        //
        // second_veth / vlan are None: the single-pc orchestrator drives the
        // single-pair, no-VLAN path. netns::setup implements both optional
        // branches (full setup-netns.sh port); S5 / USAGE_01 wire the Config
        // fields + a parity case that drive them.
        netns::setup(&NetnsParams {
            tester_ns: netns_tester(w),
            dut_ns: netns_dut(w),
            veth_t: veth_tester(w),
            veth_d: veth_dut(w),
            tester_ip: format!("{}/24", cfg.tester_ip4),
            dut_ip: format!("{}/24", cfg.dut_ip4),
            second_veth: None,
            vlan: None,
        })
        .with_context(|| format!("bringing up netns for worker {w}"))?;

        // Worker-unique argv[0] so a teardown pkill is scoped to this worker.
        symlink_force(&cfg.dut_bin, &dut_link(&cfg.vsomeip_base, w))?;
        symlink_force(&cfg.harness, &harness_link(&cfg.vsomeip_base, w))?;

        let dut_mac = veth_mac(&netns_dut(w), &veth_dut(w))?;
        let tester_mac = veth_mac(&netns_tester(w), &veth_tester(w))?;

        // Neigh pins mirror single-pc.conf: pin <DUT_IP, dut_mac> on the tester
        // side (keeps the ARP cold-cache premise) and <HOST2_IP, tester_mac>
        // on the DUT side (Host-2 emulation for UDP_FIELDS_04/05).
        ip_neigh_replace(&netns_tester(w), &cfg.dut_ip4, &dut_mac, &veth_tester(w))?;
        ip_neigh_replace(&netns_dut(w), wire::HOST2_IP, &tester_mac, &veth_dut(w))?;

        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        teardown_worker(&self.cfg.vsomeip_base, w);
        Ok(())
    }

    fn tester_iface(&self, w: u32) -> String {
        // Bare veth (not a VLAN subif) so libpcap sees any 802.1Q tag intact.
        veth_tester(w)
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        // The single-pc netns bring-up does not yet provision the Topology-2 second
        // veth pair (netns::setup is called with second_veth: None), so no secondary
        // iface is available and USAGE_01 SKIPs here. Wiring the second pair (and
        // running USAGE_01) is deferred; this is a noted gap, not a silent
        // wrong-pass — bash single-pc runs USAGE_01 via NEED_SECOND_VETH.
        None
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        let steps = conditioning::plan(case_id, &self.cfg.tester_ip4, &ctx.tester_mac);
        // Build the guard incrementally and record a step's restore only AFTER its
        // apply succeeds, so a mid-sequence failure (the `?`) drops `cond` and
        // reverts exactly the steps already applied. bash gets this for free from
        // `set -e` + the EXIT-trap netns destroy.
        let mut cond = Conditioning { topo: self, w, restore_steps: Vec::new(), restored: false };
        for step in steps {
            self.exec_cond_step(w, &step, CondDir::Apply)
                .with_context(|| format!("conditioning {case_id} (worker {w})"))?;
            if step.has_restore() {
                cond.restore_steps.push(step);
            }
        }
        Ok(cond)
    }

    fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        // single-pc renders every step to `ip netns exec` / `ip -n` in the
        // worker's namespaces. `None` = a no-op direction (a flush or a no-undo
        // pin has no restore).
        match render_cond_step(w, step, dir) {
            Some(argv) => {
                let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                netns::ip(&refs)
            }
            None => Ok(()),
        }
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        let log = fs::File::create(hlog).context("creating harness log")?;
        let err = log.try_clone()?;
        Command::new("ip")
            .args(["netns", "exec", &netns_tester(w)])
            .arg(harness_link(&self.cfg.vsomeip_base, w))
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning harness via ip netns exec")
    }

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>> {
        let cfg = self.cfg;
        let log = fs::File::create(dlog).context("creating dut log")?;
        let err = log.try_clone()?;
        let base = cfg.vsomeip_base.join(w.to_string());
        // Per-case wipe of stale vsomeip UDS sockets + lock (smoke-test.sh:884) so
        // a leftover from the prior case in this worker's bucket cannot make the
        // fresh DUT's vsomeip routing init bind stale. Scoped to vsomeip-*/.lck —
        // never the worker symlinks kill_by_marker matches.
        wipe_vsomeip_runtime(&base);
        let child = Command::new("ip")
            .args(["netns", "exec", &netns_dut(w), "env"])
            .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
            .arg(format!("VSOMEIP_CONFIGURATION={}", cfg_path.display()))
            .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
            .arg(format!("VSOMEIP_BASE_PATH={}/", base.display()))
            .arg(dut_link(&cfg.vsomeip_base, w))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning tc8-dut via ip netns exec")?;
        Ok(Some(child))
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        kill_by_marker(&dut_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
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
/// kill_worker_procs's kill-and-confirm loop (smoke-test.sh:639-648).
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
        let gone = Command::new("pgrep")
            .args(["-f"])
            .arg(m)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| !s.success())
            .unwrap_or(true);
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

/// Remove a worker's stale vsomeip UDS sockets + lock before a fresh DUT spawn
/// (smoke-test.sh:884). Scoped to `vsomeip-*` / `vsomeip.lck` — NEVER the
/// per-worker `tc8-dut`/`tc8-harness` symlinks `kill_by_marker` pattern-matches.
/// Best-effort: a missing dir or entry is a no-op.
fn wipe_vsomeip_runtime(base: &Path) {
    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        if let Some(name) = ent.file_name().to_str() {
            if name.starts_with("vsomeip-") || name == "vsomeip.lck" {
                let _ = fs::remove_file(ent.path());
            }
        }
    }
}

fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = fs::remove_file(link);
    symlink(target, link)
        .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
}

/// `ip -n NS link show DEV | awk '/link\/ether/ {print $2}'` in Rust.
fn veth_mac(ns: &str, dev: &str) -> Result<String> {
    let out = Command::new("ip")
        .args(["-n", ns, "link", "show", dev])
        .output()
        .with_context(|| format!("ip -n {ns} link show {dev}"))?;
    if !out.status.success() {
        bail!("ip -n {ns} link show {dev} failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("link/ether ") {
            if let Some(mac) = rest.split_whitespace().next() {
                return Ok(mac.to_string());
            }
        }
    }
    bail!("no link/ether for {dev} in {ns}")
}

fn ip_neigh_replace(ns: &str, ip: &str, mac: &str, dev: &str) -> Result<()> {
    let st = Command::new("ip")
        .args(["-n", ns, "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", dev])
        .status()
        .with_context(|| format!("ip -n {ns} neigh replace {ip}"))?;
    if !st.success() {
        bail!("ip -n {ns} neigh replace {ip} failed");
    }
    Ok(())
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

// ===========================================================================
// external / ssh-remote topologies (S5)
// ===========================================================================
// Both drive the tester side locally on a host NIC (no netns), so they share the
// harness symlink scaffolding, the host-exec harness spawn, and the DUT/tester MAC
// resolution below. They differ only in the DUT lifecycle (persistent vs
// ssh-spawned-per-case) and their contract capabilities. Neither manages the DUT
// network stack, so both reuse the S4 conditioning seam: `condition_case` logs the
// per-case omission and returns an empty guard, leaving `conditioning::plan`
// untouched.

/// Per-worker scratch dirs + the worker-unique harness symlink (the argv[0] marker
/// `kill_by_marker` scopes to). external/ssh-remote run the harness locally, so —
/// unlike single-pc — there is no DUT symlink (no local DUT spawn).
pub(crate) fn host_bring_up_common(cfg: &Config, w: u32) -> Result<()> {
    fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
    fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;
    symlink_force(&cfg.harness, &harness_link(&cfg.vsomeip_base, w))
}

/// Spawn the harness directly on this host (the tester context is the root ns),
/// stdout+stderr to `hlog`. No `ip netns exec` wrapper — so the returned Child IS
/// the harness, not a reparented grandchild, and `kill()`+`wait()` reaps it
/// directly; `stop_harness`'s pkill is then a harmless belt-and-suspenders.
pub(crate) fn host_run_harness(harness: &Path, hlog: &Path, args: &[String]) -> Result<Child> {
    let log = fs::File::create(hlog).context("creating harness log")?;
    let err = log.try_clone()?;
    Command::new(harness)
        .args(args)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .with_context(|| format!("spawning harness {}", harness.display()))
}

/// True if `iface` is a network interface on this host.
fn iface_exists(iface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{iface}")).is_dir()
}

/// The configured secondary tester iface (TC8 Topology 2), with an empty string
/// normalized to absent. Shared by External + SshRemote.
pub(crate) fn site_secondary_iface(site: &SiteConf) -> Option<String> {
    site.iface_secondary.clone().filter(|s| !s.is_empty())
}

/// `condition_case` for a topology that does not manage the DUT stack (external /
/// ssh-remote). It APPLIES the TESTER-side steps — the tester is this host, and
/// bash applies tester-side conditioning (ARP_39/40 `arp_ignore`) on every topology
/// (smoke-test.sh:966-974) — recording their restores in the guard, and SKIPS the
/// DUT-side steps (logged via `log_dut_skips`). The applied tester-side steps are
/// rendered to host commands by the topology's `exec_cond_step`
/// (`host_exec_cond_step`), so the guard reverts them through the same path on Drop.
pub(crate) fn host_condition_case<'a>(
    topo: &'a dyn Topology,
    tester_ip4: &str,
    tester_mac: &str,
    w: u32,
    case_id: &str,
    topology_name: &str,
) -> Result<Conditioning<'a>> {
    let steps = conditioning::plan(case_id, tester_ip4, tester_mac);
    let mut cond = Conditioning::empty(topo, w);
    for step in steps {
        if step.side() == Side::Tester {
            topo.exec_cond_step(w, &step, CondDir::Apply)
                .with_context(|| format!("tester-side conditioning {case_id} (worker {w})"))?;
            if step.has_restore() {
                cond.restore_steps.push(step);
            }
        }
    }
    conditioning::log_dut_skips(
        w,
        case_id,
        topology_name,
        tester_ip4,
        tester_mac,
        topo.ut_arp_cache_timeout().is_some(),
    );
    Ok(cond)
}

/// Render a TESTER-side conditioning step to a plain host command — external /
/// ssh-remote's `exec_cond_step`. The tester is this host's NIC, so there is no
/// `ip netns exec`. Only tester-side steps reach here (`host_condition_case` skips
/// DUT-side steps rather than executing them); a DUT-side or unrecognised step is a
/// logic bug, surfaced loudly rather than silently mis-targeted at the host.
pub(crate) fn host_exec_cond_step(iface: &str, step: &CondStep, dir: CondDir) -> Result<()> {
    match step {
        CondStep::SysctlIface { side: Side::Tester, table, leaf, on, off } => {
            let val = match dir {
                CondDir::Apply => on,
                CondDir::Restore => off,
            };
            host_sysctl(&format!("net.ipv4.{}.{iface}.{leaf}={val}", table.as_str()))
        }
        _ => bail!(
            "external/ssh-remote: unrenderable conditioning step {step:?} on the host transport (DUT-side steps are skipped; a new tester-side family needs a host renderer here)"
        ),
    }
}

/// `sysctl -qw KEY=VALUE` on this host (no netns). Mandatory — bash applies the
/// tester-side toggle without `|| true`.
fn host_sysctl(kv: &str) -> Result<()> {
    let st = Command::new("sysctl")
        .args(["-qw", kv])
        .status()
        .with_context(|| format!("sysctl -qw {kv}"))?;
    if !st.success() {
        bail!("host sysctl `{kv}` failed");
    }
    Ok(())
}

/// The tester NIC/veth MAC, read from sysfs — the host-side analogue of
/// single-pc's `ip -n NS link show`. Fed to the per-worker DUT-MAC / identity
/// expectations (external.conf / ssh-remote.conf `cat .../address`).
pub(crate) fn iface_mac(iface: &str) -> Result<String> {
    let path = format!("/sys/class/net/{iface}/address");
    let mac = fs::read_to_string(&path)
        .with_context(|| format!("reading tester iface MAC from {path}"))?
        .trim()
        .to_string();
    if mac.is_empty() {
        bail!("tester iface '{iface}' reported an empty MAC ({path})");
    }
    Ok(mac)
}

/// Resolve the DUT MAC: operator-pinned (`dut_mac`, when a topology-conf supplies
/// one) or read from the host neigh table the preflight ICMP probe populated (the
/// host's ARP request for the DUT IP, answered, lands `<dut_ip, dut_mac>` in the
/// cache). Takes the pin directly rather than the whole `SiteConf`, so a topology
/// with no MAC override (lwip-tap) passes `None`. Mirrors external.conf bring-up.
pub(crate) fn resolve_dut_mac(dut_mac: Option<&str>, iface: &str, dut_ip: &str) -> Result<String> {
    if let Some(mac) = dut_mac.filter(|m| !m.is_empty()) {
        println!("orchestrator: DUT MAC pinned by operator: {mac}");
        return Ok(mac.to_string());
    }
    let out = Command::new("ip")
        .args(["-4", "neigh", "show", dut_ip, "dev", iface])
        .output()
        .with_context(|| format!("ip -4 neigh show {dut_ip} dev {iface}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = toks.iter().position(|&t| t == "lladdr") {
            if let Some(mac) = toks.get(i + 1) {
                println!("orchestrator: DUT MAC resolved from neigh table: {mac}");
                return Ok((*mac).to_string());
            }
        }
    }
    bail!("failed to resolve the DUT MAC for {dut_ip} on '{iface}' — set dut_mac in the topology-conf")
}

/// `ping -c1 -W2 -I <src> <dut_ip>` from the host root ns; `src` is a source IP
/// (cold-cache probe steering) or the iface name. Returns whether the DUT answered.
fn ping_dut(src: &str, dut_ip: &str) -> bool {
    Command::new("ping")
        .args(["-c", "1", "-W", "2", "-I", src, dut_ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `tc8-harness ut-ping --dut-ip <dut_ip> [--source-ip <src>]` — a side-effect-free
/// Upper Tester OpPing round trip. Returns whether the UT answered.
fn ut_ping(harness: &Path, dut_ip: &str, source_ip: Option<&str>) -> bool {
    let mut c = Command::new(harness);
    c.args(["ut-ping", "--dut-ip", dut_ip]);
    if let Some(src) = source_ip {
        c.args(["--source-ip", src]);
    }
    c.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// external: a persistent, already-running DUT (real ECU / second PC) on a host
/// NIC. The orchestrator drives the tester side only — never starting, stopping,
/// or conditioning the DUT (external.conf). One physical DUT serves one worker.
pub struct External<'a> {
    cfg: &'a Config,
    site: &'a SiteConf,
}

impl<'a> External<'a> {
    pub fn new(cfg: &'a Config, site: &'a SiteConf) -> Self {
        External { cfg, site }
    }
    fn iface(&self) -> &str {
        self.site.require("iface")
    }
}

impl Topology for External<'_> {
    fn max_workers(&self) -> Option<u32> {
        Some(1)
    }
    fn supports_dut_spawn(&self) -> bool {
        false
    }
    fn supports_negative(&self) -> bool {
        false
    }

    fn preflight(&self) -> Result<()> {
        let iface = self.iface();
        let dut_ip = self.site.require("dut_ip");
        let tester_ip = self.site.require("tester_ip");
        if !self.cfg.harness.is_file() {
            bail!("preflight: tc8-harness binary missing: {}", self.cfg.harness.display());
        }
        if !iface_exists(iface) {
            bail!("preflight: interface '{iface}' does not exist on this host");
        }
        let operstate = fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unreadable".into());
        match operstate.as_str() {
            "up" | "unknown" => {
                println!("orchestrator[external]: preflight: '{iface}' operstate={operstate} — OK")
            }
            other => bail!("preflight: interface '{iface}' operstate={other} (link down or not configured)"),
        }
        if let Some(sec) = self.site.iface_secondary.as_deref().filter(|s| !s.is_empty()) {
            if !iface_exists(sec) {
                bail!("preflight: secondary interface '{sec}' does not exist");
            }
        }
        // Tester identity sanity (WARNING, not fatal — split-identity can be
        // deliberate): does the iface actually carry the tester IP that raw stimulus
        // sources from? A no means kernel-socket (UT) traffic uses a different IP.
        let carries = Command::new("ip")
            .args(["-4", "addr", "show", "dev", iface])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("inet {tester_ip}/")))
            .unwrap_or(false);
        if !carries {
            eprintln!("orchestrator[external]: preflight WARNING — '{iface}' does not carry tester IP {tester_ip}; kernel-socket traffic (Upper Tester) will source a different address than raw-injected stimulus");
        }
        // DUT ICMP reachability — also warms the neigh entry bring-up reads. The
        // probe source steers which DUT ARP entry gets warmed (cold-cache cases).
        let probe_src = self.site.preflight_src_ip.as_deref().filter(|s| !s.is_empty());
        if ping_dut(probe_src.unwrap_or(iface), dut_ip) {
            println!("orchestrator[external]: preflight: DUT {dut_ip} answers ICMP Echo — OK");
        } else {
            bail!("preflight: DUT {dut_ip} did not answer ICMP Echo on '{iface}' (DUT down, cable, or IP mismatch)");
        }
        // Upper Tester probe — WARNING unless require_ut promotes it to fatal.
        if ut_ping(&self.cfg.harness, dut_ip, probe_src) {
            println!("orchestrator[external]: preflight: Upper Tester probe — OK");
        } else if self.site.require_ut {
            bail!("preflight: Upper Tester did not answer (UDP 30600) and require_ut=true");
        } else {
            eprintln!("orchestrator[external]: preflight WARNING — Upper Tester did not answer (UDP 30600); UT-dependent cases will fail visibly. Set require_ut=true to make this fatal.");
        }
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        host_bring_up_common(self.cfg, w)?;
        let dut_mac = resolve_dut_mac(self.site.dut_mac.as_deref(), self.iface(), self.site.require("dut_ip"))?;
        let tester_mac = iface_mac(self.iface())?;
        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        // The DUT + NIC belong to the operator; only reap a possibly-surviving local
        // harness under this worker's symlink (run_case already reaped it). The
        // scratch dirs are removed by main.
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }

    fn tester_iface(&self, _w: u32) -> String {
        self.iface().to_string()
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        site_secondary_iface(self.site)
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        host_condition_case(self, &self.cfg.tester_ip4, &ctx.tester_mac, w, case_id, "external")
    }

    fn exec_cond_step(&self, _w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        host_exec_cond_step(self.iface(), step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        host_run_harness(&harness_link(&self.cfg.vsomeip_base, w), hlog, args)
    }

    fn start_dut(&self, _w: u32, dlog: &Path, _cfg_path: &Path) -> Result<Option<Child>> {
        // Persistent DUT — nothing to spawn. Record the provenance in the dut log
        // (bash run_case, smoke-test.sh:1478) so a postmortem shows which DUT a case
        // ran against. `None` tells the dispatcher there is no Child to reap.
        //
        // `_cfg_path` is ignored because S5a always passes the default vsomeip cfg.
        // When per-case vsomeip FLAVORS land, bash (smoke-test.sh:1475-1477) emits an
        // INFO when a case requests a non-default flavor against a non-spawning
        // topology ("the external DUT must provide the equivalent service"); that
        // warning must be ported here then — a prerequisite for the flavor stage.
        let _ = fs::write(
            dlog,
            format!("[external] using persistent DUT at {}\n", self.site.require("dut_ip")),
        );
        Ok(None)
    }

    fn stop_dut(&self, _w: u32) -> Result<()> {
        Ok(()) // persistent — deliberately nothing to stop
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
}

/// ssh-remote: the tester runs here; a fresh reference tc8-dut is spawned per case
/// on a second host over SSH (ssh-remote.conf). Same fresh-DUT-per-case semantics
/// as single-pc, but the remote kernel is not ours to condition. One remote host
/// serves one worker.
pub struct SshRemote<'a> {
    cfg: &'a Config,
    site: &'a SiteConf,
}

impl<'a> SshRemote<'a> {
    pub fn new(cfg: &'a Config, site: &'a SiteConf) -> Self {
        SshRemote { cfg, site }
    }
    fn iface(&self) -> &str {
        self.site.require("iface")
    }

    /// `ssh -n -o BatchMode=yes [-o ConnectTimeout=5] <opts...> <target>`, ready for
    /// a remote-command argument. `-n` keeps ssh off the orchestrator's stdin.
    /// `connect_timeout` bounds only the TCP/auth handshake: the short-lived
    /// probe/reap commands set it (fail fast on an unreachable host), but the
    /// long-lived per-case DUT spawn does NOT — bash makes the same split
    /// (ssh-remote.conf:47 `_ssh_dut` vs :182 `topology_start_dut`), because the
    /// spawn ssh stays connected for the whole case and a slow handshake under load
    /// must not abort it. Word-split opts mirror bash's intentional SC2086.
    fn ssh_command(&self, connect_timeout: bool) -> Command {
        let mut c = Command::new("ssh");
        c.args(["-n", "-o", "BatchMode=yes"]);
        if connect_timeout {
            c.args(["-o", "ConnectTimeout=5"]);
        }
        if let Some(opts) = self.site.ssh_opts.as_deref() {
            c.args(opts.split_whitespace());
        }
        c.arg(self.site.require("ssh_target"));
        c
    }

    /// Run a short remote command (probe/reap), returning whether it exited zero;
    /// output discarded. Uses the connect-timeout builder so an unreachable host
    /// fails fast.
    fn ssh_ok(&self, remote_cmd: &str) -> bool {
        self.ssh_command(true)
            .arg(remote_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl Topology for SshRemote<'_> {
    fn max_workers(&self) -> Option<u32> {
        Some(1)
    }
    fn supports_dut_spawn(&self) -> bool {
        true
    }
    fn supports_negative(&self) -> bool {
        false
    }

    fn preflight(&self) -> Result<()> {
        let iface = self.iface();
        let dut_ip = self.site.require("dut_ip");
        if !self.cfg.harness.is_file() {
            bail!("preflight: tc8-harness binary missing: {}", self.cfg.harness.display());
        }
        if !iface_exists(iface) {
            bail!("preflight: interface '{iface}' does not exist on this host");
        }
        println!("orchestrator[ssh-remote]: preflight: '{iface}' exists — OK");
        if !self.ssh_ok("true") {
            bail!(
                "preflight: cannot SSH to '{}' non-interactively (key auth + BatchMode required)",
                self.site.require("ssh_target")
            );
        }
        let rbin = self.site.require("remote_dut_bin");
        if !self.ssh_ok(&format!("test -x '{rbin}'")) {
            bail!("preflight: remote tc8-dut missing or not executable: {rbin}");
        }
        let rv = self.site.require("remote_vsomeip_cfg");
        let rc = self.site.require("remote_capi_cfg");
        if !self.ssh_ok(&format!("test -f '{rv}' && test -f '{rc}'")) {
            bail!("preflight: remote vsomeip/commonapi config missing: {rv} / {rc}");
        }
        println!("orchestrator[ssh-remote]: preflight: SSH + remote tc8-dut/configs present — OK");
        if !ping_dut(iface, dut_ip) {
            bail!("preflight: DUT host {dut_ip} did not answer ICMP Echo on '{iface}'");
        }
        println!("orchestrator[ssh-remote]: preflight: DUT host {dut_ip} answers ICMP Echo — OK");

        // UT probe: spawn one transient remote DUT, OpPing it, reap it — proving the
        // full spawn-over-SSH + UT path before any case runs. The reference tc8-dut
        // always implements UT, so no answer here is fatal (remote log dumped).
        let probe_log = self.cfg.work_root.join("ut-probe.dut.log");
        let child = self.start_dut(0, &probe_log, &self.cfg.vsomeip_cfg)?;
        sleep(Duration::from_millis(1500));
        let ut_ok = ut_ping(&self.cfg.harness, dut_ip, None);
        let _ = self.stop_dut(0);
        if let Some(mut c) = child {
            // Bounded, like dispatch::CaseProcs::reap: stop_dut's remote pkill may
            // miss (ssh failure / comm mismatch), and an unbounded wait here would
            // hang preflight before any case runs. On timeout kill the local ssh
            // client so the run proceeds (the bring-up stale-reap is the backstop).
            if !crate::dispatch::wait_bounded(&mut c, crate::dispatch::REAP_WAIT_TICKS) {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        if ut_ok {
            println!("orchestrator[ssh-remote]: preflight: remote tc8-dut spawn + Upper Tester probe — OK");
        } else {
            if let Ok(log) = fs::read_to_string(&probe_log) {
                for line in log.lines() {
                    eprintln!("    [remote tc8-dut] {line}");
                }
            }
            let _ = fs::remove_file(&probe_log);
            bail!("preflight: spawned a remote tc8-dut but its Upper Tester did not answer (UDP 30600); remote log dumped above");
        }
        let _ = fs::remove_file(&probe_log);
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        // Reap a stale remote tc8-dut from a previous run — it would steal the SD/UT
        // ports from the per-case spawn. pkill -x (exact comm), never -f (which would
        // match the ssh session's own remote shell command line).
        if self.ssh_ok(&remote_reap_dut()) {
            println!("orchestrator[ssh-remote]: reaped a stale remote tc8-dut from a previous run");
        }
        host_bring_up_common(self.cfg, w)?;
        let dut_mac = resolve_dut_mac(self.site.dut_mac.as_deref(), self.iface(), self.site.require("dut_ip"))?;
        let tester_mac = iface_mac(self.iface())?;
        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        self.ssh_ok(&remote_reap_dut()); // last-resort remote reap
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }

    fn tester_iface(&self, _w: u32) -> String {
        self.iface().to_string()
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        site_secondary_iface(self.site)
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        host_condition_case(self, &self.cfg.tester_ip4, &ctx.tester_mac, w, case_id, "ssh-remote")
    }

    fn exec_cond_step(&self, _w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        host_exec_cond_step(self.iface(), step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        host_run_harness(&harness_link(&self.cfg.vsomeip_base, w), hlog, args)
    }

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>> {
        // Map the local cfg's basename onto a sibling of the remote vsomeip cfg
        // (per-case flavor support; S5a always passes the default, so the basename
        // equals remote_vsomeip_cfg's). mkdir + wipe the per-worker remote vsomeip
        // scratch — vsomeip cannot create its base path and fails with a misleading
        // routing-manager error when it is missing.
        let rv = self.site.require("remote_vsomeip_cfg");
        let remote_dir = Path::new(rv)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let base = cfg_path.file_name().and_then(|n| n.to_str()).unwrap_or("vsomeip.json");
        let remote_cfg = if remote_dir.is_empty() {
            base.to_string()
        } else {
            format!("{remote_dir}/{base}")
        };
        let rbin = self.site.require("remote_dut_bin");
        let rcapi = self.site.require("remote_capi_cfg");
        let wrap = self.site.remote_wrap.as_deref().unwrap_or("");
        let scratch = format!("{REMOTE_VSOMEIP_PREFIX}-{w}");
        let remote_cmd = format!(
            "mkdir -p {scratch} && rm -f {scratch}/vsomeip-* {scratch}/vsomeip.lck && \
             {wrap} env COMMONAPI_CONFIG='{rcapi}' VSOMEIP_CONFIGURATION='{remote_cfg}' \
             VSOMEIP_APPLICATION_NAME=tc8-dut VSOMEIP_BASE_PATH={scratch}/ '{rbin}'"
        );
        let log = fs::File::create(dlog).context("creating remote dut log")?;
        let err = log.try_clone()?;
        // No ConnectTimeout: this ssh stays connected for the whole case.
        let child = self
            .ssh_command(false)
            .arg(remote_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning remote tc8-dut via ssh")?;
        Ok(Some(child))
    }

    fn stop_dut(&self, _w: u32) -> Result<()> {
        // Kill the remote process (the local ssh client dies with the connection
        // teardown). pkill exits 1 when nothing matched — the normal "DUT already
        // exited" case, not an error.
        self.ssh_ok(&remote_reap_dut_and_scratch());
        Ok(())
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
}

// --- ssh-remote reap SSOT ---------------------------------------------------
/// Remote tc8-dut process comm. `pkill -x` matches this exact name; `-f` would also
/// match the ssh session's own remote shell command line, so always use `-x`.
const REMOTE_DUT_COMM: &str = "tc8-dut";
/// Per-worker remote vsomeip scratch base on the DUT host (the `-{w}` suffix is the
/// worker; `-*` wipes them all on teardown).
const REMOTE_VSOMEIP_PREFIX: &str = "/tmp/tc8-remote-vsomeip";

/// `pkill -KILL -x <comm>` — reap the remote DUT only (stale-reap at bring-up,
/// last-resort at tear-down). pkill exits 1 on no match — the normal "already gone".
fn remote_reap_dut() -> String {
    format!("pkill -KILL -x {REMOTE_DUT_COMM}")
}
/// `pkill -KILL -x <comm>; rm -rf <prefix>-*` — reap the DUT and wipe every
/// per-worker remote scratch dir (per-case stop_dut + the signal-handler reap).
fn remote_reap_dut_and_scratch() -> String {
    format!("{}; rm -rf {REMOTE_VSOMEIP_PREFIX}-*", remote_reap_dut())
}

/// Best-effort remote tc8-dut reap for the signal handler, which cannot hold a
/// borrowed `SshRemote`. Builds ssh from owned params but shares the reap command
/// with `SshRemote::stop_dut` (via `remote_reap_dut_and_scratch`), so the two can
/// never drift.
pub fn ssh_reap_remote_dut(target: &str, opts: Option<&str>) {
    let mut c = Command::new("ssh");
    c.args(["-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
    if let Some(o) = opts {
        c.args(o.split_whitespace());
    }
    let _ = c
        .arg(target)
        .arg(remote_reap_dut_and_scratch())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditioning::SysctlTable;

    fn vs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn renders_iface_sysctl_both_directions_dut_ns() {
        let step = CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Conf, leaf: "arp_accept", on: "0", off: "1" };
        assert_eq!(
            render_cond_step(0, &step, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.conf.veth-dut-0.arp_accept=0"])
        );
        assert_eq!(
            render_cond_step(0, &step, CondDir::Restore).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.conf.veth-dut-0.arp_accept=1"])
        );
    }

    #[test]
    fn renders_tester_side_step_in_tester_ns() {
        let step = CondStep::SysctlIface { side: Side::Tester, table: SysctlTable::Conf, leaf: "arp_ignore", on: "8", off: "0" };
        assert_eq!(
            render_cond_step(1, &step, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-tester-1", "sysctl", "-qw", "net.ipv4.conf.veth-tester-1.arp_ignore=8"])
        );
    }

    #[test]
    fn renders_neigh_table_and_global_sysctl() {
        let neigh = CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Neigh, leaf: "gc_stale_time", on: "1", off: "60" };
        assert_eq!(
            render_cond_step(0, &neigh, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.neigh.veth-dut-0.gc_stale_time=1"])
        );
        let global = CondStep::SysctlGlobal { side: Side::Dut, key: "ipfrag_time", on: "3", off: "30" };
        assert_eq!(
            render_cond_step(0, &global, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.ipfrag_time=3"])
        );
    }

    #[test]
    fn renders_neigh_pin_replace_and_del_and_no_undo() {
        let pin = CondStep::NeighPin { side: Side::Dut, ip: "172.16.0.1".into(), mac: "aa:bb:cc".into(), undo: true };
        assert_eq!(
            render_cond_step(0, &pin, CondDir::Apply).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "replace", "172.16.0.1", "lladdr", "aa:bb:cc", "dev", "veth-dut-0", "nud", "permanent"])
        );
        assert_eq!(
            render_cond_step(0, &pin, CondDir::Restore).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "del", "172.16.0.1", "dev", "veth-dut-0"])
        );
        let no_undo = CondStep::NeighPin { side: Side::Dut, ip: "172.16.0.10".into(), mac: "aa:bb:cc".into(), undo: false };
        assert!(render_cond_step(0, &no_undo, CondDir::Restore).is_none());
    }

    #[test]
    fn renders_flush_apply_only() {
        let flush = CondStep::NeighFlush { side: Side::Dut };
        assert_eq!(
            render_cond_step(0, &flush, CondDir::Apply).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "flush", "dev", "veth-dut-0"])
        );
        assert!(render_cond_step(0, &flush, CondDir::Restore).is_none());
    }
}
