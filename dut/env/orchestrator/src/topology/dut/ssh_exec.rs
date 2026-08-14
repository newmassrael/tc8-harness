//! `ssh-exec` DUT lifecycle — a fresh reference tc8-dut spawned per case on a second
//! host over SSH. Same fresh-DUT-per-case semantics as `local-exec`, but the remote
//! kernel is not ours, so nothing here conditions it.
//!
//! Note what this lifecycle already was before the axis existed: a DUT launched by an
//! operator-configured command against operator-configured paths. It is the same shape
//! as `command`, differing only in transport (ssh) and in reaping by exact comm rather
//! than by a site-supplied stop argv — which is why the `[dut]` seam for single-pc is
//! a generalisation of something the codebase had already built once, not a new idea.
//!
//! The reap keeps the fixed `-x tc8-dut` selector because it CAN: the binary is still
//! ours, so the selector is derivable in a way `command`'s is not. What is not
//! derivable is the AUTHORITY to signal it, which is why `remote_wrap` — the site's
//! prefix on the launch — is applied to the reap as well (see `remote_reap_dut`). The
//! preflight then proves the pair actually works instead of trusting that it does.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use super::probe::SdEgress;
use super::{DutLifecycle, DutPlacement};
use crate::config::Config;
use crate::site::SshSite;
use crate::topology::{VSOMEIP_RT_LOCK, VSOMEIP_RT_SOCK_PREFIX};

/// Remote tc8-dut process comm. `pkill -x` matches this exact name; `-f` would also
/// match the ssh session's own remote shell command line, so always use `-x`.
const REMOTE_DUT_COMM: &str = "tc8-dut";
/// Per-worker remote vsomeip scratch base on the DUT host (the `-{w}` suffix is the
/// worker; `-*` wipes them all on teardown).
const REMOTE_VSOMEIP_PREFIX: &str = "/tmp/tc8-remote-vsomeip";

/// How long `provision_run`'s SD-egress probe listens.
///
/// It has to outlast the whole transient-DUT window the UT probe already waits
/// out — the ssh spawn, the 1500 ms settle, the UT round trip — because the probe
/// is armed BEFORE the DUT starts and collected after it is reaped. The
/// observation itself needs no budget of its own: a DUT whose routing comes up
/// puts its first Offer on the wire in a few hundred ms, and the probe exits on
/// that first frame. So the whole of this value is spent only when there is
/// nothing to hear — the path that ends the run anyway.
const SD_PROBE_TIMEOUT_MS: u32 = 5000;

/// Confirming a suspected survivor: how many times to re-ask the DUT host, and how
/// long between asks. Reached only once the ssh child has already failed to exit,
/// so a healthy run pays nothing. The retries exist because SIGKILL delivery and
/// the sshd-side session cleanup are not instantaneous, and a preflight that
/// aborted a run on a process caught mid-exit would be its own false accusation.
const REAP_CONFIRM_ATTEMPTS: u32 = 5;
const REAP_CONFIRM_GAP_MS: u64 = 200;

/// Remote predicate for "a tc8-dut is still RUNNING on the DUT host" — exit 0 when
/// at least one process with that exact comm is in a state other than zombie.
///
/// `ps -C` matches the command name exactly, the way the reap's `pkill -x` does,
/// and ships in the same procps package the reap already requires — so this asks
/// nothing of a DUT host that was not already required.
///
/// Zombies are excluded deliberately. A defunct process holds no port and runs no
/// code, so it is not a survivor in any sense that matters, and the just-reaped
/// probe DUT is routinely one for a moment. Measured: the first draft used
/// `pgrep -x`, which matches zombies, and reported a corpse as a survivor.
fn remote_live_dut_predicate() -> String {
    format!("ps -C {REMOTE_DUT_COMM} -o stat= | grep -qv '^Z'")
}

/// `[<wrap>] pkill -KILL -x <comm>` — reap the remote DUT only (stale-reap at
/// bring-up, last-resort at tear-down). pkill exits 1 on no match — the normal
/// "already gone". `-x` (exact comm), not `-f`: reap-selector matrix in `topology`
/// mod docs.
///
/// `wrap` is the site's `remote_wrap`, the SAME prefix the launch carries, and it
/// is here because a lifecycle must reap what it started with the authority it
/// started it with. `remote_wrap` hands the launch to the operator, and the
/// obvious thing to put in it is `sudo -n`: `suspendEthernetInterface` is an Upper
/// Tester opcode, so a conforming DUT has to be able to drop its own link, which
/// makes CAP_NET_ADMIN part of the DUT role rather than a packaging preference.
/// Measured: elevating the launch alone fixes the DUT completely and leaves it
/// unreapable — the ssh user's `pkill` cannot signal a root process, and the
/// survivor holds the SD/UT ports for every later case.
///
/// This is `command`'s rule (a site-supplied launch needs a site-supplied stop)
/// applied at the narrower width this lifecycle actually needs. There the whole
/// argv belongs to the operator, so the SELECTOR cannot be derived and a `stop`
/// argv is mandatory. Here the binary is still our reference tc8-dut and `-x
/// tc8-dut` still selects exactly it; what the wrap changes is the AUTHORITY, so
/// carrying the wrap is the whole fix. Delegating the selector as well would let a
/// site supply a stop that does not match its own start.
pub(crate) fn remote_reap_dut(wrap: Option<&str>) -> String {
    let prefix = match wrap {
        Some(w) if !w.trim().is_empty() => format!("{} ", w.trim()),
        _ => String::new(),
    };
    format!("{prefix}pkill -KILL -x {REMOTE_DUT_COMM}")
}

/// `[<wrap>] pkill -KILL -x <comm>; rm -rf <prefix>-*` — reap the DUT and wipe every
/// per-worker remote scratch dir (per-case stop_dut + the signal-handler reap).
///
/// The wipe deliberately stays UNWRAPPED even when the kill is elevated. The
/// scratch dirs are created by the unwrapped `mkdir -p` in `start_dut`, so the ssh
/// user owns them, and unlinking inside a directory you own does not depend on who
/// owns the files. Elevating it would buy nothing and would turn a recursive
/// delete of a glob into a privileged one.
pub(crate) fn remote_reap_dut_and_scratch(wrap: Option<&str>) -> String {
    format!("{}; rm -rf {REMOTE_VSOMEIP_PREFIX}-*", remote_reap_dut(wrap))
}

/// A reference tc8-dut spawned per case on a second host over SSH.
pub(crate) struct SshExecDut<'a> {
    cfg: &'a Config,
    site: &'a SshSite,
}

impl<'a> SshExecDut<'a> {
    pub(crate) fn new(cfg: &'a Config, site: &'a SshSite) -> Self {
        SshExecDut { cfg, site }
    }

    /// `ssh -n -o BatchMode=yes [-o ConnectTimeout=5] <opts...> <target>`, ready for a
    /// remote-command argument. `-n` keeps ssh off the orchestrator's stdin.
    /// `connect_timeout` bounds only the TCP/auth handshake: the short-lived probe/reap
    /// commands set it (fail fast on an unreachable host), but the long-lived per-case
    /// DUT spawn does NOT — that ssh stays connected for the whole case and a slow
    /// handshake under load must not abort it. Word-split opts mirror bash's
    /// intentional SC2086.
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
    /// output discarded. Uses the connect-timeout builder so an unreachable host fails
    /// fast.
    fn ssh_ok(&self, remote_cmd: &str) -> bool {
        crate::proc::run_ok(self.ssh_command(true).arg(remote_cmd).stdin(Stdio::null()))
    }

    /// Turn the SD-egress window's outcome into a preflight decision.
    ///
    /// The DUT is our reference tc8-dut and it offers a service the moment its
    /// external routing is ready, so on this lifecycle a silent SD leg is never a
    /// legitimate DUT state — it is a host that cannot put SD on the wire, and
    /// every SOME/IP verdict downstream would report the resulting silence as a
    /// DUT defect. Measured: a DUT host whose test NIC had no multicast route
    /// passed SSH, binaries, ICMP and the UT probe, and then made every case read
    /// `inconclusive:no_first_offer_observed_after_reactivation`.
    ///
    /// A probe that could not CONCLUDE is warned about rather than fatal. It has
    /// established neither "the environment is not ready" nor "the DUT is at
    /// fault", and failing a run on the absence of evidence about our own probe
    /// would let a probe malfunction cost a lab session — while the misattribution
    /// this check exists to prevent cannot happen once the operator has been told
    /// the check did not conclude.
    fn report_sd_egress(&self, sd: SdEgress, dut_ip: &str, probe_log: &Path) -> Result<()> {
        match sd {
            SdEgress::Observed => {
                println!(
                    "orchestrator[ssh-remote]: provision: SOME/IP-SD from {dut_ip} observed on '{}' — OK",
                    self.site.wire.iface
                );
                Ok(())
            }
            SdEgress::Unknown => {
                eprintln!(
                    "orchestrator[ssh-remote]: provision WARNING — the SD-egress probe could not conclude (see its message above); the run proceeds, but a SOME/IP case reporting the DUT silent has not been cleared of a tester-side cause"
                );
                Ok(())
            }
            SdEgress::NotObserved => {
                // The remote log is the cheapest confirmation of the usual cause:
                // vsomeip prints the interface coming up and, separately, the ROUTE
                // coming up. The interface line without its route partner is the
                // signature of a DUT whose SD is gated shut.
                if let Ok(log) = fs::read_to_string(probe_log) {
                    for line in log.lines() {
                        eprintln!("    [remote tc8-dut] {line}");
                    }
                }
                let _ = fs::remove_file(probe_log);
                bail!(
                    "provision: the remote tc8-dut spawned and its Upper Tester answered, but no \
                     SOME/IP-SD frame from {dut_ip} reached the tester on '{}'. The DUT host is \
                     most likely missing a multicast route on its test NIC — vsomeip only starts \
                     external routing once the kernel reports a route whose output interface is \
                     the one holding the configured unicast address:\n    \
                     ip route replace 224.244.224.0/24 dev <DUT host test NIC>\n\
                     In the remote log above, a 'Network interface \"<nic>\" state changed: up' \
                     line with no matching 'Route \"<nic>\" state changed: up' confirms that \
                     reading; a send error logged against the SD group instead points at the DUT \
                     host's egress path (a filter, a down link) rather than at the route. Without \
                     SD on the wire no offer-observation verdict in the suite carries \
                     information, so the run stops here rather than reporting a mute host as a \
                     mute DUT.",
                    self.site.wire.iface
                )
            }
        }
    }

    /// Confirm the transient probe DUT is actually GONE now that `stop_dut` has run.
    ///
    /// `remote_wrap` hands the launch to the operator, and the obvious thing to put
    /// in it is `sudo -n`. The reap follows the wrap for exactly that reason, but a
    /// site can still arrive at a launch it cannot reap — a sudoers rule that
    /// permits the DUT binary and not `pkill`, a wrap that is not a usable command
    /// prefix, a DUT elevated by something other than the wrap. That failure is
    /// invisible in the case that causes it and lethal to the NEXT one: the
    /// survivor holds the SD and Upper Tester ports, so every later case grades a
    /// DUT it did not start.
    ///
    /// Checked by measurement rather than by inspecting the config at resolve time.
    /// A config-shaped guard would have to guess which wraps change the process
    /// owner; this asks the host, which is the only thing that actually knows.
    ///
    /// TWO INDEPENDENT SIGNALS, AND WHY NEITHER IS ENOUGH ALONE
    /// -------------------------------------------------------
    /// `ssh_child_exited` is the precise one: our own ssh client stays connected
    /// exactly as long as the remote command runs, so its failure to exit after the
    /// reap IS this DUT refusing to die. It cannot see a stranger's process — but it
    /// also cannot tell a live DUT from an ssh client that merely hung.
    ///
    /// The host query is the corroborating one: it proves a tc8-dut is genuinely
    /// running. On its own it is host-wide, and a second orchestrator on the same
    /// machine (an OEM run against a vendored copy, which the netns fixtures make
    /// possible) has tc8-duts of its own. Measured, and the reason this is a
    /// conjunction: asking the host alone reported a survivor that belonged to a
    /// concurrent run, moments after our own had been reaped correctly.
    ///
    /// Requiring both makes the bail mean "OUR DUT did not exit, and a DUT is
    /// indeed still running" — the two false positives are independent, so their
    /// conjunction is close to unreachable by accident.
    fn check_reap_left_nothing_behind(&self, ssh_child_exited: bool) -> Result<()> {
        if ssh_child_exited {
            return Ok(());
        }
        let live_dut = remote_live_dut_predicate();
        for attempt in 0..REAP_CONFIRM_ATTEMPTS {
            if !self.ssh_ok(&live_dut) {
                // Signal one fired, signal two did not: the DUT is gone and the ssh
                // client was slow to notice (or hung for its own reasons). Not
                // fatal — nothing is holding the ports — but not silent either,
                // because a reap that needs the local kill to finish is one step
                // from the failure this check exists for.
                eprintln!(
                    "orchestrator[ssh-remote]: provision WARNING — the probe DUT's ssh session \
                     did not end within the reap wait, though no tc8-dut is running on '{}' now. \
                     The reap needed the local ssh client to be killed to complete.",
                    self.site.ssh_target
                );
                return Ok(());
            }
            if attempt + 1 < REAP_CONFIRM_ATTEMPTS {
                sleep(Duration::from_millis(REAP_CONFIRM_GAP_MS));
            }
        }
        bail!(
            "provision: the probe tc8-dut survived the reap on '{}' — the launch and the reap do \
             not have the same privileges. The reap is '{}', issued as the ssh user, and it \
             cannot signal a DUT that was started as another one. Either give the reaping side \
             the same elevation (a `remote_wrap` prefix is applied to both), or drop the \
             elevation from the launch. Left in place, the survivor holds the SD and Upper Tester \
             ports and every case after the first would grade a DUT this run did not start.",
            self.site.ssh_target,
            remote_reap_dut(self.site.remote_wrap.as_deref())
        )
    }
}

impl DutLifecycle for SshExecDut<'_> {
    fn name(&self) -> &'static str {
        "ssh-exec"
    }

    fn max_workers(&self) -> Option<u32> {
        // One remote host serves one worker.
        Some(1)
    }

    fn spawns_per_case(&self) -> bool {
        true
    }

    fn supports_negative(&self) -> bool {
        // It IS our reference tc8-dut, but the negative rows also need the start-order
        // control and per-case kernel conditioning that only a locally-owned namespace
        // gives; the remote kernel is not ours. Preserved from the pre-axis contract.
        false
    }

    fn bring_up_worker(&self, _w: u32) -> Result<()> {
        // Reap a stale remote tc8-dut from a previous run — it would steal the SD/UT
        // ports from the per-case spawn. pkill -x (exact comm), never -f (which would
        // match the ssh session's own remote shell command line).
        if self.ssh_ok(&remote_reap_dut(self.site.remote_wrap.as_deref())) {
            println!("orchestrator[ssh-remote]: reaped a stale remote tc8-dut from a previous run");
        }
        Ok(())
    }

    fn provision_run(&self, placement: &DutPlacement) -> Result<()> {
        // The remote DUT host is operator-owned — nothing to stand up; verify it is
        // live (SSH + remote bins + ICMP + spawn-probe) before any case runs.
        let dut_ip = self.site.wire.dut_ip.as_str();
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
        if !super::probe::ping_dut(&self.site.wire.iface, dut_ip) {
            bail!(
                "provision: DUT host {dut_ip} did not answer ICMP Echo on '{}'",
                self.site.wire.iface
            );
        }
        println!("orchestrator[ssh-remote]: provision: DUT host {dut_ip} answers ICMP Echo — OK");

        // UT probe: spawn one transient remote DUT, OpPing it, reap it — proving the
        // full spawn-over-SSH + UT path before any case runs. The reference tc8-dut
        // always implements UT, so no answer here is fatal (remote log dumped).
        //
        // The same window carries two more checks, because it is the only moment a
        // DUT exists before the run and each of them is otherwise paid for by a
        // whole suite of misattributed verdicts:
        //   - the tester listens for the DUT's SD (see SD_PROBE_TIMEOUT_MS), which
        //     the unicast UT probe is structurally unable to exercise;
        //   - the reap that ends the window is checked for survivors, which is what
        //     makes a launch/reap privilege asymmetry fail here instead of on the
        //     SECOND case.
        let probe_log = self.cfg.work_root.join("ut-probe.dut.log");
        let sd_ready = self.cfg.work_root.join("sd-probe.ready");
        let mut sd_probe = super::probe::spawn_sd_probe(
            &self.cfg.harness,
            &self.site.wire.iface,
            dut_ip,
            SD_PROBE_TIMEOUT_MS,
            &sd_ready,
        )?;
        // Same barrier the per-case dispatch uses: the ring must be armed and the SD
        // group held before the DUT is released, or its first Offer is gone before
        // anything can hear it.
        crate::dispatch::wait_for_capture_ready(&sd_ready, &mut sd_probe);
        let _ = fs::remove_file(&sd_ready);
        let child = self.start_dut(0, placement, &probe_log, &self.cfg.vsomeip_cfg, &[])?;
        sleep(Duration::from_millis(1500));
        let ut_ok = super::probe::ut_ping(&self.cfg.harness, dut_ip, None);
        let _ = self.stop_dut(0, placement);
        // Whether the DUT's own ssh session ended when the reap ran. The ssh client
        // lives exactly as long as the remote command does, so this is the precise,
        // OUR-process-only half of the survivor check below — a fact the bounded
        // wait was already computing and discarding.
        let mut ssh_child_exited = true;
        if let Some(mut c) = child {
            // Bounded, like dispatch::CaseProcs::reap: stop_dut's remote pkill may miss
            // (ssh failure / comm mismatch), and an unbounded wait here would hang
            // preflight before any case runs. On timeout kill the local ssh client so
            // the run proceeds (the bring-up stale-reap is the backstop).
            if !crate::dispatch::wait_bounded(&mut c, crate::dispatch::REAP_WAIT_TICKS) {
                ssh_child_exited = false;
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        let sd = super::probe::sd_egress_outcome(&mut sd_probe, SD_PROBE_TIMEOUT_MS);
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

        // The survivor check goes first of the two: a preflight bail skips
        // `teardown_run` (it runs after the cases, not on this path), so a DUT that
        // outlived the reap is host state this run created and cannot clean up, and
        // the operator has to be told about it before any diagnosis of the wire.
        self.check_reap_left_nothing_behind(ssh_child_exited)?;
        self.report_sd_egress(sd, dut_ip, &probe_log)?;
        let _ = fs::remove_file(&probe_log);
        Ok(())
    }

    fn teardown_run(&self) -> Result<()> {
        // Last-resort remote reap of any tc8-dut left running (per-case stop_dut
        // already ran). pkill -x (exact comm) — a -f pattern would match the ssh
        // session's own remote command line.
        self.ssh_ok(&remote_reap_dut(self.site.remote_wrap.as_deref()));
        Ok(())
    }

    fn start_dut(
        &self,
        w: u32,
        _placement: &DutPlacement,
        dlog: &Path,
        cfg_path: &Path,
        extra_env: &[String],
    ) -> Result<Option<Child>> {
        // Map the local cfg's basename onto a sibling of the remote vsomeip cfg
        // (per-case flavor support). mkdir + wipe the per-worker remote vsomeip
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
        // Per-case DUT flavor env (CASE_VSOMEIP_VARIANT); empty for the common case.
        // TC8_DUT_*=1 tokens are shell-safe, so a plain space-join needs no quoting.
        let flavor_env = if extra_env.is_empty() {
            String::new()
        } else {
            format!("{} ", extra_env.join(" "))
        };
        let remote_cmd = format!(
            "mkdir -p {scratch} && rm -f {scratch}/{VSOMEIP_RT_SOCK_PREFIX}* {scratch}/{VSOMEIP_RT_LOCK} && \
             {wrap} env COMMONAPI_CONFIG='{rcapi}' VSOMEIP_CONFIGURATION='{remote_cfg}' \
             VSOMEIP_APPLICATION_NAME=tc8-dut VSOMEIP_BASE_PATH={scratch}/ {flavor_env}'{rbin}'"
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

    fn stop_dut(&self, _w: u32, _placement: &DutPlacement) -> Result<()> {
        // Kill the remote process (the local ssh client dies with the connection
        // teardown). pkill exits 1 when nothing matched — the normal "DUT already
        // exited" case, not an error.
        self.ssh_ok(&remote_reap_dut_and_scratch(self.site.remote_wrap.as_deref()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unwrapped_site_reaps_exactly_as_before() {
        // The wrap is optional, and a site that does not set one must produce the
        // byte-identical command it always did — the elevation seam has to be
        // invisible to every site that does not use it.
        assert_eq!(remote_reap_dut(None), "pkill -KILL -x tc8-dut");
        assert_eq!(
            remote_reap_dut_and_scratch(None),
            "pkill -KILL -x tc8-dut; rm -rf /tmp/tc8-remote-vsomeip-*"
        );
        // An empty / whitespace wrap is the same as none: it reaches here from a
        // config field, and `wrap ` with nothing in it must not become a leading
        // space that changes how the remote shell parses the command.
        assert_eq!(remote_reap_dut(Some("")), remote_reap_dut(None));
        assert_eq!(remote_reap_dut(Some("   ")), remote_reap_dut(None));
    }

    #[test]
    fn the_survivor_predicate_excludes_zombies() {
        // The corroborating half of the reap check asks whether a DUT is RUNNING,
        // not whether a process table entry exists. A just-reaped DUT is briefly a
        // zombie, and the first draft (`pgrep -x`) reported one as a survivor.
        let p = remote_live_dut_predicate();
        assert!(p.contains("tc8-dut"), "{p}");
        assert!(p.contains("-qv '^Z'"), "the zombie state must be filtered out: {p}");
    }

    #[test]
    fn a_wrapped_launch_gets_a_wrapped_reap() {
        // The measured failure this exists to prevent: `remote_wrap = "sudo -n …"`
        // fixes the DUT's privileges and leaves it unreapable, because the reap ran
        // as the ssh user. The prefix must reach the pkill.
        let wrap = Some("sudo -n env LD_LIBRARY_PATH=/opt/someip/lib");
        assert_eq!(
            remote_reap_dut(wrap),
            "sudo -n env LD_LIBRARY_PATH=/opt/someip/lib pkill -KILL -x tc8-dut"
        );
        // The scratch wipe stays UNWRAPPED behind it — the dirs are the ssh user's
        // own, so elevating a recursive delete of a glob would add risk, not reach.
        assert_eq!(
            remote_reap_dut_and_scratch(wrap),
            "sudo -n env LD_LIBRARY_PATH=/opt/someip/lib pkill -KILL -x tc8-dut; \
             rm -rf /tmp/tc8-remote-vsomeip-*"
        );
    }
}
