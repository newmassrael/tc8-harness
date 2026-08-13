//! `ssh-exec` DUT lifecycle — a fresh reference tc8-dut spawned per case on a second
//! host over SSH. Same fresh-DUT-per-case semantics as `local-exec`, but the remote
//! kernel is not ours, so nothing here conditions it.
//!
//! Note what this lifecycle already was before the axis existed: a DUT launched by an
//! operator-configured command against operator-configured paths. It is the same shape
//! as `command`, differing only in transport (ssh) and in reaping by exact comm rather
//! than by a site-supplied stop argv — which is why the `[dut]` seam for single-pc is
//! a generalisation of something the codebase had already built once, not a new idea.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

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

/// `pkill -KILL -x <comm>` — reap the remote DUT only (stale-reap at bring-up,
/// last-resort at tear-down). pkill exits 1 on no match — the normal "already gone".
/// `-x` (exact comm), not `-f`: reap-selector matrix in `topology` mod docs.
pub(crate) fn remote_reap_dut() -> String {
    format!("pkill -KILL -x {REMOTE_DUT_COMM}")
}

/// `pkill -KILL -x <comm>; rm -rf <prefix>-*` — reap the DUT and wipe every per-worker
/// remote scratch dir (per-case stop_dut + the signal-handler reap).
pub(crate) fn remote_reap_dut_and_scratch() -> String {
    format!("{}; rm -rf {REMOTE_VSOMEIP_PREFIX}-*", remote_reap_dut())
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
        if self.ssh_ok(&remote_reap_dut()) {
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
        let probe_log = self.cfg.work_root.join("ut-probe.dut.log");
        let child = self.start_dut(0, placement, &probe_log, &self.cfg.vsomeip_cfg, &[])?;
        sleep(Duration::from_millis(1500));
        let ut_ok = super::probe::ut_ping(&self.cfg.harness, dut_ip, None);
        let _ = self.stop_dut(0, placement);
        if let Some(mut c) = child {
            // Bounded, like dispatch::CaseProcs::reap: stop_dut's remote pkill may miss
            // (ssh failure / comm mismatch), and an unbounded wait here would hang
            // preflight before any case runs. On timeout kill the local ssh client so
            // the run proceeds (the bring-up stale-reap is the backstop).
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
        // session's own remote command line.
        self.ssh_ok(&remote_reap_dut());
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
        self.ssh_ok(&remote_reap_dut_and_scratch());
        Ok(())
    }
}
