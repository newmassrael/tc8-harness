//! `persistent` DUT lifecycle — a DUT that is already running and stays running: a
//! real ECU, a second PC, anything the operator owns. The orchestrator never starts,
//! stops, or conditions it; the entire lifecycle is "confirm it is there, then leave
//! it alone".
//!
//! That is not an empty lifecycle. Confirming the thing we are about to certify is
//! actually reachable, and that its Upper Tester answers, is the difference between a
//! run of honest failures and a run of failures that only mean the cable was out —
//! so the liveness probes live here rather than in the topology.

use anyhow::{bail, Result};
use std::fs;
use std::path::Path;
use std::process::Child;

use super::{DutLifecycle, DutPlacement};
use crate::config::Config;

/// An operator-owned DUT the orchestrator only ever probes.
pub(crate) struct PersistentDut<'a> {
    cfg: &'a Config,
    dut_ip: String,
    /// Cold-cache probe-source steering: the source IP the preflight ICMP/UT probes
    /// use, so the warmed DUT ARP entry lands on an address no cold-cache ARP case
    /// references.
    probe_src: Option<String>,
    /// `ping -I` fallback when no `probe_src` steers the probe — the tester interface
    /// name. Supplied by the composing topology because WHICH leg to probe from is
    /// transport knowledge; what to conclude from the answer is this lifecycle's.
    probe_iface: String,
    /// Promote a failed Upper Tester probe from WARNING to a hard failure.
    require_ut: bool,
}

impl<'a> PersistentDut<'a> {
    pub(crate) fn new(
        cfg: &'a Config,
        dut_ip: impl Into<String>,
        probe_iface: impl Into<String>,
        probe_src: Option<String>,
        require_ut: bool,
    ) -> Self {
        PersistentDut {
            cfg,
            dut_ip: dut_ip.into(),
            probe_src,
            probe_iface: probe_iface.into(),
            require_ut,
        }
    }
}

impl DutLifecycle for PersistentDut<'_> {
    fn name(&self) -> &'static str {
        "persistent"
    }

    fn max_workers(&self) -> Option<u32> {
        // One physical DUT cannot serve parallel workers.
        Some(1)
    }

    fn spawns_per_case(&self) -> bool {
        false
    }

    fn supports_negative(&self) -> bool {
        // Not our reference implementation, and not even restartable — the negative
        // rows need a fresh DUT plus start-order control.
        false
    }

    fn ready_marker(&self) -> Option<&'static str> {
        // There is no per-case spawn to wait on: this DUT was already running before
        // the run began and stays up across every case, so the race the barrier exists
        // for cannot occur here. Its liveness question is asked once, in
        // `provision_run` below, where an ACTIVE probe is affordable precisely because
        // no case's capture is open yet.
        None
    }

    fn provision_run(&self, _placement: &DutPlacement) -> Result<()> {
        // The DUT is operator-owned and already running — nothing to stand up; verify
        // it is live (and warm the neigh entry bring-up reads) before any case runs.
        let probe_src = self.probe_src.as_deref();
        // The probe source steers which DUT ARP entry gets warmed (cold-cache cases);
        // absent one, source from the tester interface as bash's external.conf does.
        let iface_or_src = probe_src.unwrap_or(&self.probe_iface);
        if super::probe::ping_dut(iface_or_src, &self.dut_ip) {
            println!("orchestrator[external]: provision: DUT {} answers ICMP Echo — OK", self.dut_ip);
        } else {
            bail!(
                "provision: DUT {} did not answer ICMP Echo (DUT down, cable, or IP mismatch)",
                self.dut_ip
            );
        }
        if super::probe::ut_ping(&self.cfg.harness, &self.dut_ip, probe_src) {
            println!("orchestrator[external]: provision: Upper Tester probe — OK");
        } else if self.require_ut {
            bail!("provision: Upper Tester did not answer (UDP 30600) and require_ut=true");
        } else {
            eprintln!("orchestrator[external]: provision WARNING — Upper Tester did not answer (UDP 30600); UT-dependent cases will fail visibly. Set require_ut=true to make this fatal.");
        }
        Ok(())
    }

    fn start_dut(
        &self,
        _w: u32,
        _placement: &DutPlacement,
        dlog: &Path,
        _cfg_path: &Path,
        extra_env: &[String],
    ) -> Result<Option<Child>> {
        // Nothing to spawn. Record the provenance in the dut log so a postmortem
        // shows which DUT a case ran against. `None` tells the dispatcher there is
        // no Child. Surface a write failure: a silently-missing dut.log defeats the
        // postmortem.
        if let Err(e) =
            fs::write(dlog, format!("[external] using persistent DUT at {}\n", self.dut_ip))
        {
            eprintln!(
                "orchestrator[external]: WARNING — could not write DUT provenance to {}: {e}",
                dlog.display()
            );
        }
        // A case can ask for a non-default DUT vsomeip FLAVOR (an alternate config
        // and/or TC8_DUT_* env). A persistent DUT is whatever the operator already
        // started, so the request cannot be honoured — and unlike a spawn failure it
        // fails SILENTLY: the case runs against the base service and grades the DUT
        // for not offering the second one. Say so, naming the tokens, so the result
        // is read as "this DUT was not configured for this case" rather than a
        // conformance defect. `cfg_path` is deliberately not inspected: the flavor's
        // observable half is this env, and the dispatcher passes the base config
        // whenever no variant applies.
        if !extra_env.is_empty() {
            eprintln!(
                "orchestrator[external]: INFO — this case wants DUT flavor [{}], which a persistent DUT cannot be given; it must already provide the equivalent service or the case will report a difference that is configuration, not conformance",
                extra_env.join(" ")
            );
        }
        Ok(None)
    }

    fn stop_dut(&self, _w: u32, _placement: &DutPlacement) -> Result<()> {
        Ok(()) // persistent — deliberately nothing to stop
    }
}
