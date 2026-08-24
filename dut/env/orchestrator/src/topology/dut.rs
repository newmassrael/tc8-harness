//! DUT lifecycle — the second of the two axes a topology is built from (the first
//! is the tester transport: `HostTester` / `NetnsPair`).
//!
//! A tester transport builds a wire and says where a DUT must sit to be on it
//! ([`DutPlacement`]); a DUT lifecycle gets a DUT to that spot, keeps it there for a
//! case, and takes it away again. The two are genuinely independent — "tester in a
//! netns pair" does not imply "DUT is a local executable", which is exactly the
//! assumption that made single-pc the one topology whose DUT could not be a
//! separately deployed unit.
//!
//! Splitting them this way also puts the reap-selector decision (the matrix in the
//! parent module's docs) on a type instead of in prose: each lifecycle reaps what it
//! started, by the selector its own start path makes correct.
//!
//! Only the netns-pair topology is expressed through this axis so far. External /
//! ssh-remote / lwip-tap still open-code their DUT half against the `Topology` trait
//! directly; they migrate here one at a time, each with its own verification, rather
//! than in one blind sweep.

use anyhow::{bail, Result};
use std::path::Path;
use std::process::Child;

mod command;
mod local_exec;
mod persistent;
mod probe;
mod ssh_exec;

pub(crate) use command::CommandDut;
pub(crate) use local_exec::LocalExec;
pub(crate) use persistent::PersistentDut;
pub(crate) use ssh_exec::{remote_reap_dut_and_scratch, SshExecDut};

/// Where a DUT has to run in order to sit on the wire the tester transport built.
///
/// This is the ENTIRE interface between the two axes. A transport does not care how
/// a DUT arrives; a lifecycle does not care how the wire was made.
pub(crate) enum DutPlacement {
    /// A network namespace the transport owns end to end. A DUT placed here shares
    /// a kernel stack we control, which is what makes DUT-side per-case conditioning
    /// (sysctls, neigh pins) meaningful rather than a no-op aimed at the wrong host.
    Netns(String),
    /// The DUT lives somewhere we do not own — another host, a real ECU, an embedded
    /// stack behind a tap. We can reach it on the wire and nothing more.
    #[allow(dead_code)] // consumed as External/SshRemote/LwipTap migrate onto this axis
    Foreign,
}

impl DutPlacement {
    /// The namespace, when there is one. For a lifecycle that can work either way.
    pub(crate) fn netns(&self) -> Option<&str> {
        match self {
            DutPlacement::Netns(ns) => Some(ns),
            DutPlacement::Foreign => None,
        }
    }

    /// The namespace to exec into, or an error naming the mismatch. A lifecycle that
    /// can only work against a namespace (it exec's the DUT itself) calls this rather
    /// than silently degrading: pairing it with a transport that owns no namespace is
    /// a construction bug, and it should say so instead of starting a DUT on the
    /// wrong stack.
    pub(crate) fn require_netns(&self, lifecycle: &str) -> Result<&str> {
        match self {
            DutPlacement::Netns(ns) => Ok(ns),
            DutPlacement::Foreign => bail!(
                "the '{lifecycle}' DUT lifecycle needs a namespace to place the DUT in, but this topology's tester transport owns none"
            ),
        }
    }
}

/// How a DUT is brought onto the wire, held there for a case, and taken off again.
///
/// The contract bits (`max_workers` / `spawns_per_case` / `supports_negative` /
/// `ut_arp_cache_timeout`) live here rather than on the topology because every one of
/// them is a fact about the DUT, not about where the harness runs: how many DUTs can
/// exist at once, whether a fresh one appears per case, whether it is OUR reference
/// implementation (and so can be held to deliberately wrong expectations), and
/// whether it ages its ARP cache through the Upper Tester instead of host sysctls.
pub(crate) trait DutLifecycle {
    /// A short name for this lifecycle, used in the errors that name a bad pairing.
    fn name(&self) -> &'static str;

    /// Preconditions this lifecycle needs before anything is provisioned — a local
    /// binary, a config file. Never DUT liveness, which belongs to provisioning.
    fn preflight(&self) -> Result<()> {
        Ok(())
    }

    /// Per-worker setup this lifecycle owns (e.g. the worker-unique argv[0] marker a
    /// later reap scopes to). The transport has already built the wire.
    fn bring_up_worker(&self, _w: u32) -> Result<()> {
        Ok(())
    }

    /// Stand up and/or VERIFY the DUT once for the whole run, after the transport has
    /// provisioned the wire. A lifecycle that stands nothing up (a persistent DUT)
    /// still uses this as its liveness gate — "is the thing we are about to certify
    /// actually there" is a DUT question, so it belongs on this axis even when the
    /// answer costs nothing to obtain.
    fn provision_run(&self, _placement: &DutPlacement) -> Result<()> {
        Ok(())
    }

    /// Reap whatever `provision_run` stood up, once, on the teardown path.
    /// Best-effort: the caller logs a failure rather than aborting.
    fn teardown_run(&self) -> Result<()> {
        Ok(())
    }

    /// Worker cap: `None` = no cap (a per-worker DUT is cheap), `Some(1)` = one DUT
    /// serves one worker (a single remote host, a real ECU, a host-wide fixture).
    fn max_workers(&self) -> Option<u32>;

    /// Whether a fresh DUT appears for every case. `false` = persistent or
    /// fixture-owned, and `--dut-first` (start-order control) is inapplicable.
    fn spawns_per_case(&self) -> bool;

    /// Whether the curated negative rows can run against this DUT. They need OUR
    /// reference implementation: a negative row asserts a deliberately wrong
    /// expectation, so against a DUT we did not build it would report a difference in
    /// the DUT as a failure of the harness's self-validation.
    fn supports_negative(&self) -> bool;

    /// The line this lifecycle's DUT prints on stdout — and so into the per-case DUT
    /// log — once every endpoint a tester stimulus can arrive on is bound, or `None`
    /// for a DUT that announces nothing observable.
    ///
    /// `Some` is what lets the dispatcher hold the harness's stimulus until the DUT
    /// is actually listening ([`crate::dispatch::wait_for_dut_ready`]). `None` is not
    /// a degraded mode to be ashamed of: it is the honest answer for a DUT we did not
    /// build, and the dispatcher then behaves exactly as it did before the barrier
    /// existed rather than blocking for a signal that will never come.
    ///
    /// Required, with no default, for the same reason `supports_negative` is: it is a
    /// contract bit, and a lifecycle that silently inherited "announces nothing" would
    /// silently lose the barrier. Every lifecycle states it.
    fn ready_marker(&self) -> Option<&'static str>;

    /// For a DUT that ages its ARP cache through the Upper Tester (the lwIP stack)
    /// rather than host sysctls: the conditioning window in virtual seconds.
    fn ut_arp_cache_timeout(&self) -> Option<String> {
        None
    }

    /// Start a DUT for one case at `placement`, logging to `dlog`. `Ok(None)` = this
    /// lifecycle has no per-case spawn (persistent / fixture-owned). The caller owns
    /// any returned `Child` and waits it after `stop_dut`.
    fn start_dut(
        &self,
        w: u32,
        placement: &DutPlacement,
        dlog: &Path,
        cfg_path: &Path,
        extra_env: &[String],
    ) -> Result<Option<Child>>;

    /// Reap whatever `start_dut` started, by the selector this lifecycle's own start
    /// path makes correct. Takes the same `placement` as `start_dut` so a lifecycle
    /// whose stop path needs to address the DUT's location reads it from the axis
    /// boundary rather than reaching into the transport's naming.
    fn stop_dut(&self, w: u32, placement: &DutPlacement) -> Result<()>;
}
