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

/// Host-2 emulation address: bring-up pins <HOST2_IP, tester_mac> on the DUT
/// side so UDP_FIELDS_04/05 (which expect a second host) resolve without a real
/// third node. Test-fixture IP, single use; not part of the DUT identity.
const HOST2_IP: &str = "172.16.0.3";

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
pub trait Topology {
    fn preflight(&self) -> Result<()>;
    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx>;
    fn tear_down_worker(&self, w: u32) -> Result<()>;
    fn tester_iface(&self, w: u32) -> String;
    /// Apply one case's per-case DUT/tester kernel conditioning (the per-case
    /// neigh flush + the case-keyed sysctl/neigh toggles smoke-test.sh's run_case
    /// applies before the harness runs), returning a guard that reverts every
    /// toggle on `restore()` / Drop. The case→toggle POLICY is shared
    /// (`conditioning::plan`); only `exec_cond_step` (rendering to this topology's
    /// transport) varies per topology.
    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>>;
    /// Render+run ONE semantic conditioning step in `dir` on this topology's
    /// transport (single-pc: `ip netns exec` / `ip -n`; a topology that does not
    /// manage the DUT stack renders the DUT-side steps as a logged skip — a later
    /// stage). The `Conditioning` guard calls this to replay restores, so it stays
    /// object-safe.
    fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()>;
    /// Spawn the harness backgrounded in the tester context; caller waits on it.
    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child>;
    /// Spawn a fresh DUT backgrounded; None for persistent (external) topologies.
    /// The caller owns the returned Child and must `wait()` it after stop_dut to
    /// reap the `ip netns exec` wrapper PID.
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
        ip_neigh_replace(&netns_dut(w), HOST2_IP, &tester_mac, &veth_dut(w))?;

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
fn kill_by_marker(marker: &Path) {
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

fn which(prog: &str) -> Option<PathBuf> {
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
