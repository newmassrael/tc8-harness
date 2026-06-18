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
use std::thread::sleep;
use std::time::Duration;

use crate::conditioning::{self, CondDir, CondStep, Side};
use crate::config::Config;
use crate::site::{ExternalSite, SshSite};

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

/// `condition_case` for a topology that does not manage the DUT stack (external /
/// ssh-remote). It APPLIES the TESTER-side steps — the tester is this host, and
/// bash applies tester-side conditioning (ARP_39/40 `arp_ignore`) on every topology
/// (smoke-test.sh) — recording their restores in the guard, and SKIPS the
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
/// cache). Takes the pin directly rather than the whole site config, so a topology
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

/// The tester-side host transport every host-NIC topology shares. Holds the
/// resolved tester identity (iface + tester IP) and DUT-MAC inputs so the
/// delegating methods need no per-call plumbing; each topology composes one and
/// keeps only its DUT lifecycle. `tester_ip` is captured at construction — for
/// external/ssh-remote it is `cfg.tester_ip4`; for lwip-tap it is the wire-fixed
/// const (never the env-overridable cfg value), so the tap address and the
/// conditioning target read one source.
pub(crate) struct HostTester<'a> {
    cfg: &'a Config,
    iface: String,
    tester_ip: String,
    dut_ip: String,
    dut_mac_pin: Option<String>,
    topology_name: &'static str,
}

impl<'a> HostTester<'a> {
    pub(crate) fn new(
        cfg: &'a Config,
        iface: impl Into<String>,
        tester_ip: impl Into<String>,
        dut_ip: impl Into<String>,
        dut_mac_pin: Option<String>,
        topology_name: &'static str,
    ) -> Self {
        HostTester {
            cfg,
            iface: iface.into(),
            tester_ip: tester_ip.into(),
            dut_ip: dut_ip.into(),
            dut_mac_pin,
            topology_name,
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
        host_condition_case(topo, &self.tester_ip, tester_mac, w, case_id, self.topology_name)
    }

    pub(crate) fn exec_cond_step(&self, step: &CondStep, dir: CondDir) -> Result<()> {
        host_exec_cond_step(&self.iface, step, dir)
    }
}

/// external: a persistent, already-running DUT (real ECU / second PC) on a host
/// NIC. The orchestrator drives the tester side only — never starting, stopping,
/// or conditioning the DUT (external.conf). One physical DUT serves one worker.
pub struct External<'a> {
    cfg: &'a Config,
    site: &'a ExternalSite,
    host: HostTester<'a>,
}

impl<'a> External<'a> {
    pub fn new(cfg: &'a Config, site: &'a ExternalSite) -> Self {
        // cfg.tester_ip4 is the site's tester IP (main set it before constructing the
        // topology); capturing it here matches the former `&self.cfg.tester_ip4`.
        let host = HostTester::new(
            cfg,
            site.wire.iface.clone(),
            cfg.tester_ip4.clone(),
            site.wire.dut_ip.clone(),
            site.wire.dut_mac.clone(),
            "external",
        );
        External { cfg, site, host }
    }
    fn iface(&self) -> &str {
        self.host.iface()
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
        // The external DUT is operator-owned and already running — nothing to stand
        // up; verify it is live (and warm the neigh entry bring_up_worker reads)
        // before any case runs (external.conf `_external_verify_dut_live`).
        let iface = self.iface();
        let dut_ip = self.site.wire.dut_ip.as_str();
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
        // DUT ICMP reachability — also warms the neigh entry bring-up reads. The
        // probe source steers which DUT ARP entry gets warmed (cold-cache cases).
        let probe_src = self.site.preflight_src_ip.as_deref();
        if ping_dut(probe_src.unwrap_or(iface), dut_ip) {
            println!("orchestrator[external]: provision: DUT {dut_ip} answers ICMP Echo — OK");
        } else {
            bail!("provision: DUT {dut_ip} did not answer ICMP Echo on '{iface}' (DUT down, cable, or IP mismatch)");
        }
        // Upper Tester probe — WARNING unless require_ut promotes it to fatal.
        if ut_ping(&self.cfg.harness, dut_ip, probe_src) {
            println!("orchestrator[external]: provision: Upper Tester probe — OK");
        } else if self.site.require_ut {
            bail!("provision: Upper Tester did not answer (UDP 30600) and require_ut=true");
        } else {
            eprintln!("orchestrator[external]: provision WARNING — Upper Tester did not answer (UDP 30600); UT-dependent cases will fail visibly. Set require_ut=true to make this fatal.");
        }
        Ok(())
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

    fn start_dut(&self, _w: u32, dlog: &Path, _cfg_path: &Path) -> Result<Option<Child>> {
        // Persistent DUT — nothing to spawn. Record the provenance in the dut log
        // (bash run_case, smoke-test.sh) so a postmortem shows which DUT a case
        // ran against. `None` tells the dispatcher there is no Child to reap.
        //
        // `_cfg_path` is ignored because S5a always passes the default vsomeip cfg.
        // When per-case vsomeip FLAVORS land, bash (smoke-test.sh) emits an
        // INFO when a case requests a non-default flavor against a non-spawning
        // topology ("the external DUT must provide the equivalent service"); that
        // warning must be ported here then — a prerequisite for the flavor stage.
        let _ = fs::write(
            dlog,
            format!("[external] using persistent DUT at {}\n", self.site.wire.dut_ip),
        );
        Ok(None)
    }

    fn stop_dut(&self, _w: u32) -> Result<()> {
        Ok(()) // persistent — deliberately nothing to stop
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
pub struct SshRemote<'a> {
    cfg: &'a Config,
    site: &'a SshSite,
    host: HostTester<'a>,
}

impl<'a> SshRemote<'a> {
    pub fn new(cfg: &'a Config, site: &'a SshSite) -> Self {
        let host = HostTester::new(
            cfg,
            site.wire.iface.clone(),
            cfg.tester_ip4.clone(),
            site.wire.dut_ip.clone(),
            site.wire.dut_mac.clone(),
            "ssh-remote",
        );
        SshRemote { cfg, site, host }
    }
    fn iface(&self) -> &str {
        self.host.iface()
    }

    /// `ssh -n -o BatchMode=yes [-o ConnectTimeout=5] <opts...> <target>`, ready for
    /// a remote-command argument. `-n` keeps ssh off the orchestrator's stdin.
    /// `connect_timeout` bounds only the TCP/auth handshake: the short-lived
    /// probe/reap commands set it (fail fast on an unreachable host), but the
    /// long-lived per-case DUT spawn does NOT — bash makes the same split
    /// (ssh-remote.conf `_ssh_dut` vs :182 `topology_start_dut`), because the
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
        c.arg(&self.site.ssh_target);
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
        // The remote DUT host is operator-owned — nothing to stand up; verify it is
        // live (SSH + remote bins + ICMP + spawn-probe) before any case runs
        // (ssh-remote.conf `_sshremote_verify_dut_live`).
        let iface = self.iface();
        let dut_ip = self.site.wire.dut_ip.as_str();
        if !iface_exists(iface) {
            bail!("provision: interface '{iface}' does not exist on this host");
        }
        println!("orchestrator[ssh-remote]: provision: '{iface}' exists — OK");
        if !self.ssh_ok("true") {
            bail!(
                "provision: cannot SSH to '{}' non-interactively (key auth + BatchMode required)",
                self.site.ssh_target
            );
        }
        let rbin = self.site.remote_dut_bin.as_str();
        if !self.ssh_ok(&format!("test -x '{rbin}'")) {
            bail!("provision: remote tc8-dut missing or not executable: {rbin}");
        }
        let rv = self.site.remote_vsomeip_cfg.as_str();
        let rc = self.site.remote_capi_cfg.as_str();
        if !self.ssh_ok(&format!("test -f '{rv}' && test -f '{rc}'")) {
            bail!("provision: remote vsomeip/commonapi config missing: {rv} / {rc}");
        }
        println!("orchestrator[ssh-remote]: provision: SSH + remote tc8-dut/configs present — OK");
        if !ping_dut(iface, dut_ip) {
            bail!("provision: DUT host {dut_ip} did not answer ICMP Echo on '{iface}'");
        }
        println!("orchestrator[ssh-remote]: provision: DUT host {dut_ip} answers ICMP Echo — OK");

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
            println!("orchestrator[ssh-remote]: provision: remote tc8-dut spawn + Upper Tester probe — OK");
        } else {
            if let Ok(log) = fs::read_to_string(&probe_log) {
                for line in log.lines() {
                    eprintln!("    [remote tc8-dut] {line}");
                }
            }
            let _ = fs::remove_file(&probe_log);
            bail!("provision: spawned a remote tc8-dut but its Upper Tester did not answer (UDP 30600); remote log dumped above");
        }
        let _ = fs::remove_file(&probe_log);
        Ok(())
    }

    fn teardown_run(&self) -> Result<()> {
        // Last-resort remote reap of any tc8-dut left running (per-case stop_dut
        // already ran). pkill -x (exact comm) — a -f pattern would match the ssh
        // session's own remote command line (ssh-remote.conf topology_teardown_run).
        self.ssh_ok(&remote_reap_dut());
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        // Reap a stale remote tc8-dut from a previous run — it would steal the SD/UT
        // ports from the per-case spawn. pkill -x (exact comm), never -f (which would
        // match the ssh session's own remote shell command line).
        if self.ssh_ok(&remote_reap_dut()) {
            println!("orchestrator[ssh-remote]: reaped a stale remote tc8-dut from a previous run");
        }
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

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>> {
        // Map the local cfg's basename onto a sibling of the remote vsomeip cfg
        // (per-case flavor support; S5a always passes the default, so the basename
        // equals remote_vsomeip_cfg's). mkdir + wipe the per-worker remote vsomeip
        // scratch — vsomeip cannot create its base path and fails with a misleading
        // routing-manager error when it is missing.
        let rv = self.site.remote_vsomeip_cfg.as_str();
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
        let rbin = self.site.remote_dut_bin.as_str();
        let rcapi = self.site.remote_capi_cfg.as_str();
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
        self.host.kill_harness(w);
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
