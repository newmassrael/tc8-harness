//! Host-NIC tester transport — the tester side shared by every topology that runs
//! the harness directly on a host interface (no per-worker netns): External,
//! SshRemote, and LwipTap. The harness spawns on the host, conditioning applies
//! tester-side steps to that iface, and the DUT/tester MACs resolve from the host.
//! [`HostTester`] captures that shared transport so each topology composes it and
//! adds only its own DUT lifecycle (persistent / ssh-spawned-per-case / lwIP-
//! respawned). External and SshRemote live here; LwipTap lives in the sibling
//! `topology/lwip_tap.rs` (a first-class host-NIC topology, not a `fixtures/`
//! verification fixture — that move retired the old fixture-to-topology upward dep).

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::conditioning::{self, CondDir, CondStep, Side};
use crate::config::Config;
use crate::site::{ExternalSite, SshSite, TopologyKind};

use super::dut::{
    remote_reap_dut_and_scratch, DutLifecycle, DutPlacement, PersistentDut, SshExecDut,
};
use super::{harness_link, kill_by_marker, symlink_force, Conditioning, Topology, WorkerCtx};

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
fn host_bring_up_common(cfg: &Config, w: u32) -> Result<()> {
    fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
    fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;
    symlink_force(&cfg.harness, &harness_link(&cfg.vsomeip_base, w))
}

/// Spawn the harness directly on this host (the tester context is the root ns),
/// stdout+stderr to `hlog`. No `ip netns exec` wrapper — so the returned Child IS
/// the harness, not a reparented grandchild, and `kill()`+`wait()` reaps it
/// directly; `stop_harness`'s pkill is then a harmless belt-and-suspenders.
fn host_run_harness(harness: &Path, hlog: &Path, args: &[String]) -> Result<Child> {
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

/// `condition_case` for a topology that does not manage the DUT stack (external /
/// ssh-remote). It APPLIES the TESTER-side steps — the tester is this host, and
/// bash applies tester-side conditioning (ARP_39/40 `arp_ignore`) on every topology
/// (smoke-test.sh) — recording their restores in the guard, and SKIPS the
/// DUT-side steps (logged via `log_dut_skips`). The applied tester-side steps are
/// rendered to host commands by the topology's `exec_cond_step`
/// (`host_exec_cond_step`), so the guard reverts them through the same path on Drop.
fn host_condition_case<'a>(
    topo: &'a dyn Topology,
    tester_ip4: &str,
    tester_mac: &str,
    w: u32,
    case_id: &str,
    kind: TopologyKind,
) -> Result<Conditioning<'a>> {
    let steps = conditioning::plan(case_id, tester_ip4, tester_mac);
    let mut cond = Conditioning::empty(topo, w);
    for step in steps {
        if step.side() == Side::Tester {
            topo.exec_cond_step(w, &step, CondDir::Apply)
                .with_context(|| format!("tester-side conditioning {case_id} (worker {w})"))?;
            if step.has_restore() {
                cond.record_restore(step);
            }
        }
    }
    conditioning::log_dut_skips(
        w,
        case_id,
        kind,
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
fn host_exec_cond_step(iface: &str, step: &CondStep, dir: CondDir) -> Result<()> {
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
fn iface_mac(iface: &str) -> Result<String> {
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
/// cache). Takes the pin directly rather than the whole site config, so a topology
/// with no MAC override (lwip-tap) passes `None`. Mirrors external.conf bring-up.
fn resolve_dut_mac(dut_mac: Option<&str>, iface: &str, dut_ip: &str) -> Result<String> {
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

// The DUT liveness probes (`ping_dut` / `ut_ping`) moved to `dut::probe`: what they
// check is a property of the DUT, not of the wire the tester sits on, so they belong
// to the lifecycle axis and are shared by `persistent` and `ssh-exec`.

/// The tester-side host transport every host-NIC topology shares. Holds the
/// resolved tester identity (iface + tester IP) and DUT-MAC inputs so the
/// delegating methods need no per-call plumbing; each topology composes one and
/// keeps only its DUT lifecycle. `tester_ip` is captured at construction — for
/// external/ssh-remote it is `site.wire.tester_ip`; for lwip-tap it is the wire-
/// fixed const (never the env-overridable cfg value), so the tap address and the
/// conditioning target read one source.
pub(crate) struct HostTester<'a> {
    cfg: &'a Config,
    iface: String,
    tester_ip: String,
    dut_ip: String,
    dut_mac_pin: Option<String>,
    /// Which host-NIC topology owns this transport — the single home of the name,
    /// rendered for the conditioning-skip log via `TopologyKind::as_str` (no bare
    /// "external"/"ssh-remote"/"lwip-tap" literal re-typed here).
    kind: TopologyKind,
}

impl<'a> HostTester<'a> {
    pub(crate) fn new(
        cfg: &'a Config,
        iface: impl Into<String>,
        tester_ip: impl Into<String>,
        dut_ip: impl Into<String>,
        dut_mac_pin: Option<String>,
        kind: TopologyKind,
    ) -> Self {
        HostTester {
            cfg,
            iface: iface.into(),
            tester_ip: tester_ip.into(),
            dut_ip: dut_ip.into(),
            dut_mac_pin,
            kind,
        }
    }

    pub(crate) fn iface(&self) -> &str {
        &self.iface
    }

    /// Per-worker scratch + harness symlink, then this worker's identity (DUT MAC
    /// from the operator pin or the warmed neigh entry, tester MAC from sysfs).
    pub(crate) fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        host_bring_up_common(self.cfg, w)?;
        let dut_mac = resolve_dut_mac(self.dut_mac_pin.as_deref(), &self.iface, &self.dut_ip)?;
        let tester_mac = iface_mac(&self.iface)?;
        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    pub(crate) fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        host_run_harness(&harness_link(&self.cfg.vsomeip_base, w), hlog, args)
    }

    /// Reap this worker's local harness by its symlink marker (tear_down + stop).
    pub(crate) fn kill_harness(&self, w: u32) {
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
    }

    pub(crate) fn condition_case<'t>(
        &self,
        topo: &'t dyn Topology,
        w: u32,
        case_id: &str,
        tester_mac: &str,
    ) -> Result<Conditioning<'t>> {
        host_condition_case(topo, &self.tester_ip, tester_mac, w, case_id, self.kind)
    }

    pub(crate) fn exec_cond_step(&self, step: &CondStep, dir: CondDir) -> Result<()> {
        host_exec_cond_step(&self.iface, step, dir)
    }
}

/// external: a persistent, already-running DUT (real ECU / second PC) on a host
/// NIC. The orchestrator drives the tester side only — never starting, stopping,
/// or conditioning the DUT (external.conf).
///
/// A pairing, like every topology here: the [`HostTester`] transport plus the
/// [`PersistentDut`] lifecycle. It re-asserts no contract bit of its own.
pub struct External<'a> {
    cfg: &'a Config,
    site: &'a ExternalSite,
    host: HostTester<'a>,
    dut: PersistentDut<'a>,
}

impl<'a> External<'a> {
    pub fn new(cfg: &'a Config, site: &'a ExternalSite) -> Self {
        // Tester/DUT identity read from the typed `site` (the resolve-layer output),
        // not the env-overridable `Config` flat fields — so construction does not
        // depend on `main` having copied site.wire.tester_ip into cfg first.
        let host = HostTester::new(
            cfg,
            site.wire.iface.clone(),
            site.wire.tester_ip.clone(),
            site.wire.dut_ip.clone(),
            site.wire.dut_mac.clone(),
            TopologyKind::External,
        );
        let dut = PersistentDut::new(
            cfg,
            site.wire.dut_ip.clone(),
            site.wire.iface.clone(),
            site.preflight_src_ip.clone(),
            site.require_ut,
        );
        External { cfg, site, host, dut }
    }
    fn iface(&self) -> &str {
        self.host.iface()
    }
}

impl Topology for External<'_> {
    fn max_workers(&self) -> Option<u32> {
        self.dut.max_workers()
    }
    fn supports_dut_spawn(&self) -> bool {
        self.dut.spawns_per_case()
    }
    fn supports_negative(&self) -> bool {
        self.dut.supports_negative()
    }
    fn dut_ready_marker(&self) -> Option<&'static str> {
        self.dut.ready_marker()
    }

    fn preflight(&self) -> Result<()> {
        // Preconditions only. Required config vars (iface/dut_ip/tester_ip) are
        // present by construction in the External site (the site resolve step
        // enumerates+bails on any missing one at load) — so there is nothing to
        // re-check here. Iface existence /
        // operstate / reachability are NOT here either: a `[fixture]` overlay stands
        // up the tester veth + DUT in provision_run, so those iface-dependent checks
        // belong post-stand-up in provision_run (mirrors external.conf: preflight=
        // vars [enforced at load], provision=verify). The binary can vanish after
        // load, so that one stays a live precondition.
        if !self.cfg.harness.is_file() {
            bail!("preflight: tc8-harness binary missing: {}", self.cfg.harness.display());
        }
        Ok(())
    }

    fn provision_run(&self) -> Result<()> {
        // Transport half first — the wire has to exist before "is the DUT on it?"
        // means anything. The DUT-liveness half (ICMP + Upper Tester) belongs to the
        // lifecycle and runs after, preserving bash's check order
        // (external.conf `_external_verify_dut_live`).
        let iface = self.iface();
        let tester_ip = self.site.wire.tester_ip.as_str();
        if !iface_exists(iface) {
            bail!("provision: interface '{iface}' does not exist on this host");
        }
        let operstate = fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unreadable".into());
        match operstate.as_str() {
            "up" | "unknown" => {
                println!("orchestrator[external]: provision: '{iface}' operstate={operstate} — OK")
            }
            other => bail!("provision: interface '{iface}' operstate={other} (link down or not configured)"),
        }
        if let Some(sec) = self.site.wire.iface_secondary.as_deref() {
            if !iface_exists(sec) {
                bail!("provision: secondary interface '{sec}' does not exist");
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
            eprintln!("orchestrator[external]: provision WARNING — '{iface}' does not carry tester IP {tester_ip}; kernel-socket traffic (Upper Tester) will source a different address than raw-injected stimulus");
        }
        // DUT half: ICMP reachability (which also warms the neigh entry bring-up
        // reads) and the Upper Tester probe.
        self.dut.provision_run(&DutPlacement::Foreign)
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        self.host.bring_up_worker(w)
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        // The DUT + NIC belong to the operator; only reap a possibly-surviving local
        // harness under this worker's symlink (run_case already reaped it). The
        // scratch dirs are removed by main.
        self.host.kill_harness(w);
        Ok(())
    }

    fn tester_iface(&self, _w: u32) -> String {
        self.iface().to_string()
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        self.site.wire.iface_secondary.clone()
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        self.host.condition_case(self, w, case_id, &ctx.tester_mac)
    }

    fn exec_cond_step(&self, _w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        self.host.exec_cond_step(step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        self.host.run_harness(w, hlog, args)
    }

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path, extra_env: &[String])
        -> Result<Option<Child>> {
        self.dut.start_dut(w, &DutPlacement::Foreign, dlog, cfg_path, extra_env)
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        self.dut.stop_dut(w, &DutPlacement::Foreign)
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        self.host.kill_harness(w);
        Ok(())
    }
}

/// ssh-remote: the tester runs here; a fresh reference tc8-dut is spawned per case
/// on a second host over SSH (ssh-remote.conf). Same fresh-DUT-per-case semantics
/// as single-pc, but the remote kernel is not ours to condition. One remote host
/// serves one worker.
/// A pairing, like every topology here: the [`HostTester`] transport plus the
/// [`SshExecDut`] lifecycle. It re-asserts no contract bit of its own.
pub struct SshRemote<'a> {
    cfg: &'a Config,
    site: &'a SshSite,
    host: HostTester<'a>,
    dut: SshExecDut<'a>,
}

impl<'a> SshRemote<'a> {
    pub fn new(cfg: &'a Config, site: &'a SshSite) -> Self {
        // Identity from the typed `site`, not the env-overridable `Config` (see
        // External::new) — symmetric sourcing, no main-ordering dependency.
        let host = HostTester::new(
            cfg,
            site.wire.iface.clone(),
            site.wire.tester_ip.clone(),
            site.wire.dut_ip.clone(),
            site.wire.dut_mac.clone(),
            TopologyKind::SshRemote,
        );
        SshRemote { cfg, site, host, dut: SshExecDut::new(cfg, site) }
    }
    fn iface(&self) -> &str {
        self.host.iface()
    }
}

impl Topology for SshRemote<'_> {
    fn max_workers(&self) -> Option<u32> {
        self.dut.max_workers()
    }
    fn supports_dut_spawn(&self) -> bool {
        self.dut.spawns_per_case()
    }
    fn supports_negative(&self) -> bool {
        self.dut.supports_negative()
    }
    fn dut_ready_marker(&self) -> Option<&'static str> {
        self.dut.ready_marker()
    }

    fn preflight(&self) -> Result<()> {
        // Preconditions only. The required config vars (iface/dut_ip/tester_ip/
        // ssh_target/remote_dut_bin/remote_vsomeip_cfg/remote_capi_cfg) are present
        // by construction in the SshRemote site (the site resolve step enumerates+
        // bails on any missing one at load) — nothing to re-check here. The SSH /
        // remote-binary / reachability /
        // spawn-probe checks are DUT liveness and live in provision_run (ssh-remote
        // .conf: preflight=vars [enforced at load], provision=verify) — the example
        // netns fixture also stands up the tester veth in provision_run. The binary
        // can vanish after load, so that one stays a live precondition.
        if !self.cfg.harness.is_file() {
            bail!("preflight: tc8-harness binary missing: {}", self.cfg.harness.display());
        }
        Ok(())
    }

    fn provision_run(&self) -> Result<()> {
        // Transport half (the tester leg exists), then the DUT half — SSH reachability,
        // remote binaries, ICMP, and a transient spawn+UT probe — which belongs to the
        // lifecycle (ssh-remote.conf `_sshremote_verify_dut_live`).
        let iface = self.iface();
        if !iface_exists(iface) {
            bail!("provision: interface '{iface}' does not exist on this host");
        }
        println!("orchestrator[ssh-remote]: provision: '{iface}' exists — OK");
        self.dut.provision_run(&DutPlacement::Foreign)
    }

    fn teardown_run(&self) -> Result<()> {
        self.dut.teardown_run()
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        // The lifecycle reaps a stale remote DUT from a previous run first — it would
        // otherwise steal the SD/UT ports from the per-case spawn.
        self.dut.bring_up_worker(w)?;
        self.host.bring_up_worker(w)
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        // Per-worker: reap this worker's local harness. The run-level remote DUT reap
        // is teardown_run (it owns the remote-side resource, once per run).
        self.host.kill_harness(w);
        Ok(())
    }

    fn tester_iface(&self, _w: u32) -> String {
        self.iface().to_string()
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        self.site.wire.iface_secondary.clone()
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        self.host.condition_case(self, w, case_id, &ctx.tester_mac)
    }

    fn exec_cond_step(&self, _w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        self.host.exec_cond_step(step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        self.host.run_harness(w, hlog, args)
    }

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path, extra_env: &[String])
        -> Result<Option<Child>> {
        self.dut.start_dut(w, &DutPlacement::Foreign, dlog, cfg_path, extra_env)
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        self.dut.stop_dut(w, &DutPlacement::Foreign)
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        self.host.kill_harness(w);
        Ok(())
    }
}

/// Best-effort remote tc8-dut reap for the signal handler, which cannot hold a
/// borrowed `SshRemote`. Builds ssh from owned params but shares the reap command
/// with `SshRemote::stop_dut` (via `remote_reap_dut_and_scratch`), so the two can
/// never drift.
///
/// `wrap` is the site's `remote_wrap`, carried here for the same reason the
/// per-case reap carries it: an elevated launch needs an elevated kill. This path
/// is the one that runs when the operator gives up on a run, which is exactly when
/// a leaked root DUT would be least likely to be noticed.
pub fn ssh_reap_remote_dut(target: &str, opts: Option<&str>, wrap: Option<&str>) {
    let mut c = Command::new("ssh");
    c.args(["-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]);
    if let Some(o) = opts {
        c.args(o.split_whitespace());
    }
    crate::proc::run_quiet(
        c.arg(target).arg(remote_reap_dut_and_scratch(wrap)).stdin(Stdio::null()),
    );
}
