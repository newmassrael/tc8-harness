//! DUT liveness probes shared by the lifecycles that have to answer "is it there?".
//!
//! These sit on the DUT axis rather than the transport one because what they check is
//! a property of the DUT — it answers ICMP, its Upper Tester replies, its Service
//! Discovery reaches us — not of the wire the tester is on. `persistent` uses the
//! first two as its whole provisioning step; `ssh-exec` uses all three to prove a
//! spawned remote DUT came up.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Host-preflight Upper Tester probe timeout. A one-shot reachability check run AFTER
/// ICMP already answered, so the DUT is reachable and the UT should reply promptly.
/// The value matches `ut-ping`'s CLI default (1000 ms), passed explicitly so the
/// preflight's timeout policy is readable at the call site rather than inherited.
/// (Distinct from lwip-tap's tighter 200 ms readiness POLL, which retries many times —
/// this is a single probe.)
const UT_PROBE_TIMEOUT_MS: &str = "1000";

/// `ping -c1 -W2 -I <src> <dut_ip>`; `src` is a source IP (cold-cache probe steering)
/// or an interface name. Returns whether the DUT answered.
pub(crate) fn ping_dut(src: &str, dut_ip: &str) -> bool {
    crate::proc::run_ok(Command::new("ping").args(["-c", "1", "-W", "2", "-I", src, dut_ip]))
}

/// `tc8-harness ut-ping --dut-ip <dut_ip> --timeout <ms> [--source-ip <src>]` — a
/// side-effect-free Upper Tester OpPing round trip. Returns whether the UT answered.
pub(crate) fn ut_ping(harness: &Path, dut_ip: &str, source_ip: Option<&str>) -> bool {
    let mut c = Command::new(harness);
    c.args(["ut-ping", "--dut-ip", dut_ip, "--timeout", UT_PROBE_TIMEOUT_MS]);
    if let Some(src) = source_ip {
        c.args(["--source-ip", src]);
    }
    crate::proc::run_ok(&mut c)
}

/// What an SD-egress listen window concluded. Three-valued because a preflight
/// exists to separate "the environment is not ready" from "the DUT is at fault",
/// and a silent window means neither until we know the tester could have heard
/// the group at all.
pub(crate) enum SdEgress {
    /// The tester saw the DUT's SD on the multicast group.
    Observed,
    /// The window elapsed with the group held and nothing heard. This IS about
    /// the DUT (or its host): its SD does not reach the tester's wire.
    NotObserved,
    /// The probe could not establish what it needed to conclude anything — it
    /// could not open the capture, or could not hold the group. Says nothing
    /// about the DUT, and must not be reported as if it did.
    Unknown,
}

/// `tc8-harness sd-probe` exit codes. Pinned here rather than derived: the SSOT
/// is `SdProbeCommand::kObserved` / `kNotObserved` / `kCouldNotRun` (see
/// `src/cli/commands/include/cli/sd_probe_command.h`, which names this reader),
/// and three integers do not earn a codegen step. Any other status — a crash, a
/// signal, a spawn that never ran — folds into `Unknown`, which is the safe
/// direction: an unexplained probe must never accuse the DUT.
const SD_PROBE_OBSERVED: i32 = 0;
const SD_PROBE_NOT_OBSERVED: i32 = 1;

/// Spawn `tc8-harness sd-probe` to listen for the DUT's SOME/IP-SD on `iface`
/// for `timeout_ms`, signalling `ready` once its capture is armed and the SD
/// multicast group is held.
///
/// Spawned rather than run to completion because the thing it observes is
/// produced by something the caller starts NEXT: the probe has to be listening
/// before the DUT is released, or the first Offer — the one that proves the
/// most, arriving ~200 ms after the DUT's routing comes up — is already gone.
/// The caller therefore waits on `ready`, starts its DUT, and collects the
/// verdict with `sd_egress_outcome`.
///
/// stdout/stderr are inherited on purpose: the probe's own lines say what it
/// heard and on which group, and that is exactly the evidence an operator
/// reading a failed preflight needs. Capturing them into a file the orchestrator
/// then re-prints would only add a copy.
pub(crate) fn spawn_sd_probe(
    harness: &Path,
    iface: &str,
    dut_ip: &str,
    timeout_ms: u32,
    ready: &Path,
) -> Result<Child> {
    let _ = std::fs::remove_file(ready);
    Command::new(harness)
        .args(["sd-probe", "--interface", iface, "--dut-ip", dut_ip, "--timeout"])
        .arg(timeout_ms.to_string())
        .arg("--ready-file")
        .arg(ready)
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning {} sd-probe", harness.display()))
}

/// Poll interval and grace for `sd_egress_outcome`'s bounded wait. The bound is
/// the probe's OWN listen window plus this grace, so it can only be reached by a
/// probe that failed to honour the deadline it was given — which is the one case
/// where waiting for it would hang a preflight that has run no case yet.
const SD_PROBE_POLL_MS: u64 = 100;
const SD_PROBE_GRACE_MS: u32 = 2000;

/// Wait for a `spawn_sd_probe` child (launched with `listen_ms`) and map its exit
/// status. Bounded like every other child wait on this path; a probe that has to
/// be killed reports `Unknown`, never an accusation.
pub(crate) fn sd_egress_outcome(child: &mut Child, listen_ms: u32) -> SdEgress {
    let ticks = u64::from(listen_ms + SD_PROBE_GRACE_MS) / SD_PROBE_POLL_MS + 1;
    for _ in 0..ticks {
        match child.try_wait() {
            Ok(Some(st)) => {
                return match st.code() {
                    Some(SD_PROBE_OBSERVED) => SdEgress::Observed,
                    Some(SD_PROBE_NOT_OBSERVED) => SdEgress::NotObserved,
                    _ => SdEgress::Unknown,
                }
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(SD_PROBE_POLL_MS)),
            Err(_) => return SdEgress::Unknown, // already reaped / unwaitable
        }
    }
    eprintln!(
        "orchestrator: warning: the SD-egress probe outlived its own {listen_ms} ms window; killing it"
    );
    let _ = child.kill();
    let _ = child.wait();
    SdEgress::Unknown
}
