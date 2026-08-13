//! single-pc topology — tester + a DUT in per-worker netns pairs on this host.
//!
//! This is a PAIRING of the two axes, and holds nothing of its own beyond them:
//!
//!   * tester transport — [`NetnsPair`], which builds the per-worker wire fixture
//!     and runs the harness in its tester half;
//!   * DUT lifecycle — by default [`LocalExec`], the reference tc8-dut exec'd into
//!     the namespace the transport prepared.
//!
//! Every contract bit is delegated to the axis that owns the fact. `max_workers` /
//! `supports_negative` / `supports_dut_spawn` describe the DUT, so they come from the
//! lifecycle; `rebuild_netns_per_case` and the interface names describe the wire, so
//! they come from the transport. Nothing is re-asserted here, which is what stops the
//! two from drifting once a second lifecycle exists.
//!
//! Sibling of `host` (external / ssh-remote, composing `HostTester`) and `lwip_tap`;
//! those still open-code their DUT half and migrate onto the lifecycle axis later.

use anyhow::Result;
use std::path::Path;
use std::process::Child;

use crate::conditioning::{CondDir, CondStep};
use crate::config::Config;

use super::dut::{DutLifecycle, DutPlacement, LocalExec};
use super::{teardown_worker, Conditioning, NetnsPair, Topology, WorkerCtx};

/// single-pc: tester + DUT in per-worker netns pairs on this host.
pub struct SinglePc<'a> {
    cfg: &'a Config,
    /// The per-worker netns wire fixture (both namespaces + the veth pair(s)) and the
    /// tester-side transport on it. `secondary_iface` selects the Topology-2 second
    /// pair; main sets it iff the schedule contains a `requires_secondary_iface` case.
    wire: NetnsPair<'a>,
    /// How a DUT gets onto that wire.
    dut: Box<dyn DutLifecycle + Sync + 'a>,
}

impl<'a> SinglePc<'a> {
    pub fn new(cfg: &'a Config, secondary_iface: bool) -> Self {
        SinglePc {
            cfg,
            wire: NetnsPair::new(cfg, secondary_iface),
            dut: Box::new(LocalExec::new(cfg)),
        }
    }

    /// Where a DUT must sit to be on this worker's wire.
    fn placement(&self, w: u32) -> DutPlacement {
        DutPlacement::Netns(self.wire.dut_netns(w))
    }
}

impl Topology for SinglePc<'_> {
    fn max_workers(&self) -> Option<u32> {
        self.dut.max_workers()
    }
    fn supports_dut_spawn(&self) -> bool {
        self.dut.spawns_per_case()
    }
    fn supports_negative(&self) -> bool {
        self.dut.supports_negative()
    }
    fn ut_arp_cache_timeout(&self) -> Option<String> {
        self.dut.ut_arp_cache_timeout()
    }
    fn rebuild_netns_per_case(&self) -> bool {
        // The transport owns and REUSES a per-worker netns pair across the bucket, so
        // it MUST rebuild between cases (bash TOPOLOGY_DUT_CONDITIONING=1).
        // `netns::setup` is idempotent (teardown-first) and re-captures the veth
        // MACs, so each case starts on a pristine stack with a fresh WorkerCtx.
        true
    }

    fn preflight(&self) -> Result<()> {
        // DUT-side preconditions first (the binary and its config), then the
        // transport's tool requirements — the order bash checked them in.
        self.dut.preflight()?;
        self.wire.preflight()
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        let ctx = self.wire.bring_up_worker(w)?;
        self.dut.bring_up_worker(w)?;
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
        // Every step applies: the transport owns both kernel stacks, and the DUT is
        // placed inside one of them.
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
        self.dut.start_dut(w, &self.placement(w), dlog, cfg_path, extra_env)
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        self.dut.stop_dut(w)
    }

    fn stop_harness(&self, w: u32) -> Result<()> {
        self.wire.kill_harness(w);
        Ok(())
    }
}
