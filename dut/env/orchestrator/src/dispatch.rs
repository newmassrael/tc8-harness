//! Per-case dispatch: build `--expect`, spawn harness + DUT in start order,
//! poll to a verdict, classify it. Mirrors smoke-test.sh run_case
//! (lines 1457-1630) for the single-worker positive path.

use anyhow::Result;
use std::path::Path;
use std::process::Child;
use std::thread::sleep;
use std::time::Duration;

use crate::config::Config;
use crate::topology::{Topology, WorkerCtx};

/// Disposition of one case, mapped from the harness verdict line via the
/// generated taxonomy (`crate::taxonomy`).
pub enum Verdict {
    /// `pass` — gate-green.
    Pass,
    /// `fail:reason` — observed conformance violation, reds the gate.
    Fail(String),
    /// Deterministic skip: capability gap / topology limit. Expected, non-gating.
    Skip(String),
    /// `inconclusive:`/`error:` — a case that would normally conclude did not, or
    /// a test-system fault. Routed to a non-gating skip but counted against the
    /// non-conclusion ceiling (see main::summarize).
    NonConclusion(String),
}

// --- Timing (named; the bash magic numbers with their rationale) ------------
const POLL_INTERVAL_MS: u64 = 200;
/// dut_first: let the DUT's first OfferService settle before the harness opens
/// its pcap (negative tests only).
const DUT_FIRST_SETTLE_MS: u64 = 1500;
/// harness-first: let the harness pcap open before the DUT's first OfferService
/// (FORMAT_02 expects session_id==0x0001 captured).
const HARNESS_FIRST_SETTLE_MS: u64 = 500;

// --- Verdict line parsing ---------------------------------------------------
/// Harness verdict line prefix — SSOT is the printf at src/cli/test_command.cpp
/// (`printf("verdict  : %s\n", ...)`). Not a taxonomy class, so it is pinned
/// here (with a unit test) rather than generated from the .def.
const VERDICT_LINE_PREFIX: &str = "verdict  : ";
/// `skip` is a smoke-runner concept (capability/topology) layered on the
/// non-conclusion disposition, not a `.def` verdict class.
const SKIP_TOKEN: &str = "skip";

// --- Wire constants whose SSOT is the C++ stimulus builders -----------------
// vsomeip.json-sourced values are derived in config::DutIdentity; these are the
// harness-emitted constants, which live in C++ `inline constexpr` and cannot yet
// be read from Rust. Pinned here with provenance pending a generated cross-
// language manifest (tracked for the expect-override stage). Drift here silently
// turns a positive test into a false pass, so they MUST match the headers.
const ARP_TESTER_MAC: &str = "02:00:00:00:00:A1"; // src/stimulus/arp_builder.h kTesterInjectedMac
const ARP_TESTER_MAC2: &str = "02:00:00:00:00:A2"; // kTesterInjectedMac2
const ARP_TESTER_MAC3: &str = "02:00:00:00:00:A3"; // kTesterInjectedMac3
const ICMP_ECHO_ID: &str = "0x1234"; // src/stimulus/icmpv4_builder.h kIcmpEchoId
const ICMP_ECHO_SEQ: &str = "0x5678"; // kIcmpEchoSeq
// SOME/IP-SD version — SSOT: dut/ets/ets.fidl `version { major 1 minor 0 }`.
const SD_MAJOR_VERSION: &str = "1";
const SD_MINOR_VERSION: &str = "0";
// 0x0001 is the UNCONFIGURED Subscribe target — NOT a deployed eventgroup (the
// fdepl declares 0x0002/0x0005/0x0006/0x0008). tc8-dut Nacks a Subscribe to it
// echoing the same ID, which several SOMEIPSRV/ETS cases assert. SSOT:
// smoke-test.sh init_expectation_defaults `eventgroup_id=0x0001`. Do NOT
// "correct" this to a deployed eventgroup — that breaks the Nack-echo baseline.
const SD_DEFAULT_EVENTGROUP: &str = "0x0001";
// IPv4 alias fixture IPs (SSOT: smoke-test.sh init_expectation_defaults).
const IPV4_DUT_ALIAS_IP: &str = "172.16.0.5";
const IPV4_TESTER_ALIAS_IP: &str = "172.16.0.4";

/// Owns the spawned harness + DUT children for one case so they are reaped on
/// EVERY exit path — normal return, an error `return`, or a panic. The reaping
/// (kill the `ip netns exec` wrappers we forked + pkill the reparented real
/// binaries via their worker-unique symlinks + wait to avoid zombies) is the
/// single source `reap()`, called explicitly on the happy path (before reading
/// the log) and by Drop on the error/panic paths. Without this, a spawn/IO error
/// mid-setup would drop a Child unreaped and leave a reparented harness holding a
/// pcap across the rest of the worker's bucket — the FORMAT_02 session-id
/// corruption the worker-unique-symlink design exists to prevent.
struct CaseProcs<'a> {
    topo: &'a dyn Topology,
    w: u32,
    harness: Option<Child>,
    dut: Option<Child>,
    reaped: bool,
}

impl<'a> CaseProcs<'a> {
    fn new(topo: &'a dyn Topology, w: u32) -> Self {
        CaseProcs { topo, w, harness: None, dut: None, reaped: false }
    }

    fn reap(&mut self) {
        if self.reaped {
            return;
        }
        self.reaped = true;
        if let Some(mut h) = self.harness.take() {
            let _ = h.kill();
            let _ = h.wait(); // reap the ip-netns-exec wrapper PID we forked
        }
        let _ = self.topo.stop_harness(self.w); // pkill the reparented real harness
        let _ = self.topo.stop_dut(self.w);
        if let Some(mut d) = self.dut.take() {
            let _ = d.wait(); // reap the DUT ip wrapper (Child::drop does not wait)
        }
    }
}

impl Drop for CaseProcs<'_> {
    fn drop(&mut self) {
        self.reap();
    }
}

pub fn run_case(
    cfg: &Config,
    topo: &dyn Topology,
    w: u32,
    ctx: &WorkerCtx,
    case_id: &str,
    dut_first: bool,
) -> Result<Verdict> {
    let hlog = cfg.work_root.join(format!("{w}/{case_id}.harness.log"));
    let dlog = cfg.work_root.join(format!("{w}/{case_id}.dut.log"));
    let iface = topo.tester_iface(w);

    let mut args = vec![
        "test".to_string(),
        "--case".to_string(),
        case_id.to_string(),
        "-i".to_string(),
        iface,
        "-t".to_string(),
        cfg.backstop_sec.to_string(),
    ];
    args.extend(expect_args(cfg, case_id, &ctx.dut_mac));

    // Spawn order: harness first so its pcap is open before the DUT's first
    // OfferService (FORMAT_02 session_id==0x0001); --dut-first inverts it. On any
    // spawn error the `?` returns and CaseProcs::drop reaps whatever started.
    let mut procs = CaseProcs::new(topo, w);
    if dut_first {
        procs.dut = topo.start_dut(w, &dlog, &cfg.vsomeip_cfg)?;
        sleep(Duration::from_millis(DUT_FIRST_SETTLE_MS));
        procs.harness = Some(topo.run_harness(w, &hlog, &args)?);
    } else {
        procs.harness = Some(topo.run_harness(w, &hlog, &args)?);
        sleep(Duration::from_millis(HARNESS_FIRST_SETTLE_MS));
        procs.dut = topo.start_dut(w, &dlog, &cfg.vsomeip_cfg)?;
    }

    // Poll ceiling in ticks — ports bash's wait_budget (smoke-test.sh:1497):
    // (backstop+3)*5, capped at 1100 ticks (220s @ 200ms/tick). The cap is bash's
    // and sits just below the harness -t backstop (240s) BY BASH'S DESIGN: real
    // cases conclude on their SCXML final state well under 215s, so neither bound
    // normally fires. Matching the cap keeps verdict PARITY with bash. Raising
    // both bash's cap AND this above the backstop and reclassifying a
    // budget-exceeded case as a non-conclusion (ISO 9646) is a tracked JOINT
    // bash+Rust change — not done unilaterally here, which would diverge the two
    // strangler halves on that one case. A try_wait error returns and the guard
    // reaps both children.
    let budget_ticks = ((u64::from(cfg.backstop_sec) + 3) * 5).min(1100);
    {
        let harness = procs.harness.as_mut().expect("harness spawned above");
        for _ in 0..budget_ticks {
            if harness.try_wait()?.is_some() {
                break;
            }
            sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
    }

    // Reap on the happy path BEFORE reading the log (the harness must be stopped
    // and its log flushed); Drop then no-ops via the `reaped` flag.
    procs.reap();
    Ok(classify(&hlog))
}

/// Read the harness log and classify its verdict line.
fn classify(hlog: &Path) -> Verdict {
    let text = match std::fs::read_to_string(hlog) {
        Ok(t) => t,
        // An UNREADABLE log (permissions, full disk) is a test-system I/O fault,
        // not a DUT verdict → error non-conclusion (distinct from the readable-
        // but-no-verdict case below, per the verdict taxonomy's error class).
        Err(e) => return Verdict::NonConclusion(format!("error:harness_log_unreadable: {e}")),
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(VERDICT_LINE_PREFIX) {
            return classify_verdict(rest.trim());
        }
    }
    // Readable log, no verdict line = the harness ran but never concluded (killed
    // at the poll ceiling, or crashed mid-run). bash scores this FAIL ("did not
    // return pass verdict", smoke-test.sh:1612) — match it for parity.
    Verdict::Fail("did not return pass verdict".to_string())
}

/// Map a verdict value (`pass`, `fail:reason`, `inconclusive:reason`, …) to a
/// disposition using the generated taxonomy. Pure over the string so it is unit-
/// tested without a harness run. Intentionally matches the class TOKEN (the part
/// before the first ':') rather than bash's `class:` substring grep — this is the
/// more robust form (it also fixes a latent bash bug: `grep "verdict  : pass"`
/// would accept `passive`), and the harness always emits the colon form.
fn classify_verdict(value: &str) -> Verdict {
    let token = value.split(':').next().unwrap_or(value);
    if token == crate::taxonomy::SUCCESS {
        Verdict::Pass
    } else if token == crate::taxonomy::FAIL {
        Verdict::Fail(value.to_string())
    } else if crate::taxonomy::NONCONCLUSION.contains(&token) {
        Verdict::NonConclusion(value.to_string())
    } else if token == SKIP_TOKEN {
        Verdict::Skip(value.to_string())
    } else {
        // Unknown token = taxonomy drift: fail loud rather than silently pass.
        Verdict::Fail(format!("unknown_verdict_class: {value}"))
    }
}

fn ex(e: &mut Vec<String>, key: &str, value: &str) {
    e.push("--expect".to_string());
    e.push(format!("{key}={value}"));
}

/// base TC8_DUT_EXPECT + the case's category static group
/// (smoke-test.sh init_expectation_defaults). The SOME/IP identity is derived
/// from vsomeip.json (config::DutIdentity); category statics cover ARP / ICMPv4
/// / IPv4. The full per-case / negative-row override layers land in a later
/// stage — when they do, this flat builder becomes one (base) input to a
/// precedence-ordered merge (base → category → per-case → negative), mirroring
/// bash's last-wins shadowing; it is intentionally not that shape yet (the
/// override maps do not exist in Rust).
fn expect_args(cfg: &Config, case_id: &str, dut_mac: &str) -> Vec<String> {
    let id = &cfg.identity;
    let mut e = Vec::new();
    // base — SOME/IP identity from vsomeip.json + SD deployment defaults
    ex(&mut e, "service_id", &id.service_id);
    ex(&mut e, "instance_id", &id.instance_id);
    ex(&mut e, "major_version", SD_MAJOR_VERSION);
    ex(&mut e, "ttl", &id.ttl);
    ex(&mut e, "minor_version", SD_MINOR_VERSION);
    ex(&mut e, "eventgroup_id", SD_DEFAULT_EVENTGROUP);
    ex(&mut e, "dut_iface_ip", &cfg.dut_ip4);
    ex(&mut e, "udp_port", &id.udp_port);
    ex(&mut e, "tcp_port", &id.tcp_port);
    ex(&mut e, "sd_multicast_ip", &id.sd_multicast_ip);
    ex(&mut e, "mcast_ipv4", &id.mcast_ipv4);
    ex(&mut e, "mcast_port", &id.mcast_port);

    let cat = case_id.to_uppercase();
    if cat.starts_with("ARP_") {
        ex(&mut e, "arp.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "arp.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "arp.dut_iface_mac", dut_mac);
        ex(&mut e, "dut.ip", &cfg.dut_ip4);
        ex(&mut e, "arp.tester_mac", ARP_TESTER_MAC);
        ex(&mut e, "arp.tester_mac2", ARP_TESTER_MAC2);
        ex(&mut e, "arp.tester_mac3", ARP_TESTER_MAC3);
    } else if cat.starts_with("ICMPV4_") {
        ex(&mut e, "icmpv4.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "icmpv4.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "icmpv4.echo_id", ICMP_ECHO_ID);
        ex(&mut e, "icmpv4.echo_seq", ICMP_ECHO_SEQ);
    } else if cat.starts_with("IPV4_") {
        ex(&mut e, "ipv4.tester_ip", &cfg.tester_ip4);
        ex(&mut e, "ipv4.dut_iface_ip", &cfg.dut_ip4);
        ex(&mut e, "ipv4.dut_alias_ip", IPV4_DUT_ALIAS_IP);
        ex(&mut e, "ipv4.tester_alias_ip", IPV4_TESTER_ALIAS_IP);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_taxonomy_tokens() {
        assert!(matches!(classify_verdict("pass"), Verdict::Pass));
        assert!(matches!(classify_verdict("fail:entry_ttl_mismatch"), Verdict::Fail(_)));
        assert!(matches!(
            classify_verdict("inconclusive:precondition_unmet"),
            Verdict::NonConclusion(_)
        ));
        assert!(matches!(
            classify_verdict("error:test_system_fault"),
            Verdict::NonConclusion(_)
        ));
        assert!(matches!(
            classify_verdict("skip:requires_capability_0x16_unavailable_on_linux"),
            Verdict::Skip(_)
        ));
    }

    #[test]
    fn classify_unknown_token_fails_loud() {
        // Taxonomy drift must surface as a gate-red Fail, never a silent pass.
        assert!(matches!(classify_verdict("passive"), Verdict::Fail(_)));
        assert!(matches!(classify_verdict("bogus"), Verdict::Fail(_)));
    }
}
