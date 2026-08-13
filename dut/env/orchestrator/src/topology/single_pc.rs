//! single-pc topology — tester + reference tc8-dut in per-worker netns pairs on
//! this host. The cheap default: no worker cap, a fresh DUT per case, negative
//! self-validation, and per-case kernel conditioning.
//!
//! Like every topology here, this is a PAIRING of two independent axes:
//!
//!   * the tester transport — [`super::NetnsPair`], which builds the per-worker
//!     wire fixture and runs the harness in its tester half;
//!   * the DUT lifecycle — the `start_dut`/`stop_dut` half below, which exec's the
//!     reference tc8-dut into the namespace the transport prepared.
//!
//! Sibling of `host` (external / ssh-remote, composing `HostTester`) and `lwip_tap`.
//! The shared worker-scoped names (`netns_*`/`dut_link`/`harness_link`) +
//! `teardown_worker` live in the parent `topology` module.
//!
//! The DUT half's ONLY dependency on the transport is `NetnsPair::dut_netns` — the
//! placement a DUT must occupy to sit on this worker's wire. That narrow interface
//! is what keeps the two axes genuinely independent rather than nominally split.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::conditioning::{CondDir, CondStep};
use crate::config::Config;

use super::{
    dut_link, kill_by_marker, symlink_force, teardown_worker, Conditioning, NetnsPair, Topology,
    WorkerCtx, VSOMEIP_RT_LOCK, VSOMEIP_RT_SOCK_PREFIX,
};

/// single-pc: tester + reference tc8-dut in per-worker netns pairs on this host.
pub struct SinglePc<'a> {
    cfg: &'a Config,
    /// The per-worker netns wire fixture (both namespaces + the veth pair(s)) and the
    /// tester-side transport on it. `secondary_iface` selects the Topology-2 second
    /// pair; main sets it iff the schedule contains a `requires_secondary_iface` case.
    wire: NetnsPair<'a>,
}

impl<'a> SinglePc<'a> {
    pub fn new(cfg: &'a Config, secondary_iface: bool) -> Self {
        SinglePc { cfg, wire: NetnsPair::new(cfg, secondary_iface) }
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
    fn rebuild_netns_per_case(&self) -> bool {
        // single-pc owns the per-worker netns pair and reuses it across the bucket,
        // so it MUST rebuild between cases (bash TOPOLOGY_DUT_CONDITIONING=1).
        // `netns::setup` is idempotent (teardown-first) and re-captures the veth
        // MACs, so each case starts on a pristine stack with a fresh WorkerCtx.
        true
    }

    fn preflight(&self) -> Result<()> {
        // DUT-lifecycle preconditions first (the local binary + its vsomeip config),
        // then the transport's own tool requirements — the order bash checked them in.
        let cfg = self.cfg;
        if !cfg.dut_bin.is_file() {
            bail!("preflight: tc8-dut binary missing: {}", cfg.dut_bin.display());
        }
        if !cfg.vsomeip_cfg.is_file() {
            bail!("preflight: vsomeip.json missing: {}", cfg.vsomeip_cfg.display());
        }
        self.wire.preflight()
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        // Transport: the netns pair, the harness marker, and this worker's identity.
        let ctx = self.wire.bring_up_worker(w)?;
        // DUT lifecycle: the worker-unique argv[0] the per-case reap scopes to. Only
        // read at spawn time, so its position relative to the fixture build is inert.
        symlink_force(&self.cfg.dut_bin, &dut_link(&self.cfg.vsomeip_base, w))?;
        Ok(ctx)
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        teardown_worker(&self.cfg.vsomeip_base, w);
        Ok(())
    }

    fn tester_iface(&self, w: u32) -> String {
        self.wire.tester_iface(w)
    }

    fn tester_iface_secondary(&self, w: u32) -> Option<String> {
        self.wire.tester_iface_secondary(w)
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        // Every step applies: the transport owns BOTH kernel stacks.
        self.wire.condition_case(self, w, case_id, &ctx.tester_mac)
    }

    fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        self.wire.exec_cond_step(w, step, dir)
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        self.wire.run_harness(w, hlog, args)
    }

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path, extra_env: &[String])
        -> Result<Option<Child>> {
        let cfg = self.cfg;
        let log = fs::File::create(dlog).context("creating dut log")?;
        let err = log.try_clone()?;
        let base = cfg.vsomeip_base.join(w.to_string());
        // Per-case wipe of stale vsomeip UDS sockets + lock (smoke-test.sh) so
        // a leftover from the prior case in this worker's bucket cannot make the
        // fresh DUT's vsomeip routing init bind stale. Scoped to vsomeip-*/.lck —
        // never the worker symlinks kill_by_marker matches.
        wipe_vsomeip_runtime(&base);
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.wire.dut_netns(w), "env"])
            .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
            .arg(format!("VSOMEIP_CONFIGURATION={}", cfg_path.display()))
            .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
            .arg(format!("VSOMEIP_BASE_PATH={}/", base.display()));
        // Per-case DUT flavor env (CASE_VSOMEIP_VARIANT): TC8_DUT_* the DUT app reads
        // to offer a 2nd instance/service or run as a client. Empty for the common
        // case; goes in the `env KEY=VAL ...` list before the binary.
        for kv in extra_env {
            cmd.arg(kv);
        }
        let child = cmd
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
        self.wire.kill_harness(w);
        Ok(())
    }
}

/// Remove a worker's stale vsomeip UDS sockets + lock before a fresh DUT spawn
/// (smoke-test.sh). Scoped to `vsomeip-*` / `vsomeip.lck` — NEVER the
/// per-worker `tc8-dut`/`tc8-harness` symlinks `kill_by_marker` pattern-matches.
/// Best-effort: a missing dir or entry is a no-op.
fn wipe_vsomeip_runtime(base: &Path) {
    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        if let Some(name) = ent.file_name().to_str() {
            if name.starts_with(VSOMEIP_RT_SOCK_PREFIX) || name == VSOMEIP_RT_LOCK {
                let _ = fs::remove_file(ent.path());
            }
        }
    }
}
