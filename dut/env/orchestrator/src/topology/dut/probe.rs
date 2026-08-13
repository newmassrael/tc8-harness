//! DUT liveness probes shared by the lifecycles that have to answer "is it there?".
//!
//! These sit on the DUT axis rather than the transport one because what they check is
//! a property of the DUT — it answers ICMP, its Upper Tester replies — not of the wire
//! the tester is on. `persistent` uses both as its whole provisioning step;
//! `ssh-exec` uses them to prove a spawned remote DUT came up.

use std::path::Path;
use std::process::Command;

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
