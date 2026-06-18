//! Per-case DUT/tester kernel-state conditioning — the case→toggle POLICY, as
//! transport-agnostic data. Ports the case-keyed `sysctl`/`neigh` toggles
//! smoke-test.sh applies in `run_case` (lines 842-1211) and reverts after the
//! verdict (lines 1505-1575), plus the unconditional per-case DUT neigh flush
//! (line 908).
//!
//! Transport-agnostic by design: `plan()` emits SEMANTIC `CondStep`s — a logical
//! `Side` (Dut/Tester) plus the knob and its on/off values — with NO `ip`/`netns`
//! tokens and no worker-scoped names. The topology renders each step to its own
//! transport (single-pc: `ip netns exec`; external/ssh-remote, a later stage:
//! host-exec / ssh / a logged skip). This keeps the case→toggle mapping — the
//! crate's highest-value SSOT — untouched when new topologies are added: only the
//! renderer changes, never this table. See `Topology::exec_cond_step`.
//!
//! Scope: the POSITIVE `run_case` path only. The `run_negative_case` copy
//! (smoke-test.sh) lands with the negative-row stage (S6).
//!
//! Case ids are matched UPPERCASED — the same canonicalisation
//! `dispatch::expect_args` does, so a lower-case or test-dir-name invocation
//! conditions correctly instead of silently taking the no-op path. Parity holds
//! for canonical-case invocations (what parity-check.sh and normal use pass).

use crate::netns;
use crate::site::TopologyKind;
use crate::wire;

/// Which side's network stack a step touches. The topology resolves this to a
/// concrete namespace + L3 interface for its transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Dut,
    Tester,
}

/// The `net.ipv4.<table>` family a per-interface sysctl lives under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SysctlTable {
    Conf,
    Neigh,
}

impl SysctlTable {
    pub fn as_str(self) -> &'static str {
        match self {
            SysctlTable::Conf => "conf",
            SysctlTable::Neigh => "neigh",
        }
    }
}

/// Direction a step is executed in: `Apply` before the case, `Restore` after.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CondDir {
    Apply,
    Restore,
}

/// One semantic kernel-state mutation a case needs. `on` is the apply value,
/// `off` the restore value. Rendering to a command is the topology's job.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CondStep {
    /// `net.ipv4.{table}.<Side's L3 iface>.{leaf}` — a per-interface sysctl.
    SysctlIface {
        side: Side,
        table: SysctlTable,
        leaf: &'static str,
        on: &'static str,
        off: &'static str,
    },
    /// `net.ipv4.conf.all.{leaf}`, executed in the Side's namespace.
    SysctlConfAll {
        side: Side,
        leaf: &'static str,
        on: &'static str,
        off: &'static str,
    },
    /// `net.ipv4.{key}` — a non-interface (global) sysctl, executed in the Side's ns.
    SysctlGlobal {
        side: Side,
        key: &'static str,
        on: &'static str,
        off: &'static str,
    },
    /// Pin `<ip> → <mac>` NUD_PERMANENT on the Side's L3 interface. `undo` =
    /// whether the restore deletes it (false = leave it; the next case's flush
    /// reclaims non-permanent entries and the leaked permanent one is harmless).
    NeighPin {
        side: Side,
        ip: String,
        mac: String,
        undo: bool,
    },
    /// Flush the Side's L3-interface neigh cache. Apply-only (no restore); the
    /// unconditional per-case prefix.
    NeighFlush { side: Side },
}

impl CondStep {
    /// Whether this step has a restore action (and so must be tracked by the guard).
    pub fn has_restore(&self) -> bool {
        match self {
            CondStep::NeighFlush { .. } => false,
            CondStep::NeighPin { undo, .. } => *undo,
            CondStep::SysctlIface { .. } | CondStep::SysctlConfAll { .. } | CondStep::SysctlGlobal { .. } => true,
        }
    }

    /// Which side's stack this step touches. The distinction is load-bearing for a
    /// topology that does not manage the DUT (external/ssh-remote): bash applies
    /// TESTER-side conditioning on every topology (the tester is always a host we
    /// own, smoke-test.sh) and skips only the DUT-side toggles.
    pub fn side(&self) -> Side {
        match self {
            CondStep::SysctlIface { side, .. }
            | CondStep::SysctlConfAll { side, .. }
            | CondStep::SysctlGlobal { side, .. }
            | CondStep::NeighPin { side, .. }
            | CondStep::NeighFlush { side } => *side,
        }
    }
}

/// The per-case conditioning steps for `case_id`. Always begins with the
/// unconditional DUT neigh-flush prefix; at most one case-keyed family follows
/// (the ids are disjoint). `tester_ip4`/`tester_mac` resolve the AUTOCONF pin.
pub fn plan(case_id: &str, tester_ip4: &str, tester_mac: &str) -> Vec<CondStep> {
    use CondStep::*;
    use Side::{Dut, Tester};
    use SysctlTable::{Conf, Neigh};

    let id = case_id.to_uppercase();

    // Unconditional prefix (smoke-test.sh): cold the DUT neigh cache so a
    // cold-cache ARP_07..15 run as a non-first case in the bucket re-emits its
    // Request. neigh flush skips PERMANENT, so bring-up pins survive.
    let mut steps = vec![NeighFlush { side: Dut }];

    // ARP_38 — RFC 826 §2.3 step-4 target-ip check (ARP): Linux `arp_accept=1`
    // (set at bring-up for ARP_05/06) bypasses it; disable so the DUT drops the
    // off-target Reply and emits its own Request.
    if id == "ARP_38" {
        steps.push(SysctlIface { side: Dut, table: Conf, leaf: "arp_accept", on: "0", off: "1" });
        steps.push(SysctlConfAll { side: Dut, leaf: "arp_accept", on: "0", off: "1" });
    }
    // ARP_39/40 — suppress the TESTER kernel's own ARP Reply so the DUT learns
    // from the tester-injected frame, not the tester veth MAC. Tester-side.
    else if id == "ARP_39" || id == "ARP_40" {
        steps.push(SysctlIface { side: Tester, table: Conf, leaf: "arp_ignore", on: "8", off: "0" });
    }
    // IPv4 AUTOCONF cluster — pin <tester_ip> PERMANENT on the DUT so its
    // UT-confirmation reply path does not kernel-ARP-resolve the tester. Undone
    // explicitly: a leaked PERMANENT tester entry would suppress the cold-cache
    // ARP in a follow-up ARP_07..15 on the same worker.
    else if id.starts_with("IPV4_AUTOCONF_ADDRESS_SELECTION_")
        || id.starts_with("IPV4_AUTOCONF_CONFLICT_")
        || id.starts_with("IPV4_AUTOCONF_ANNOUNCING_")
        || id.starts_with("IPV4_AUTOCONF_LINKLOCAL_PACKETS_")
        || id.starts_with("IPV4_AUTOCONF_NETWORK_PARTITIONS_")
    {
        steps.push(NeighPin { side: Dut, ip: tester_ip4.to_string(), mac: tester_mac.to_string(), undo: true });
    }
    // DHCPv4 CM_05/_06 — pre-pin the Option-3 synthetic gateway → tester-injected
    // MAC. No restore: the pinned IP is not the tester ip, so a leaked PERMANENT
    // entry is harmless to the cold-cache ARP cases (bash leaves it unrestored).
    else if id == "DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_05" || id == "DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_06"
    {
        steps.push(NeighPin {
            side: Dut,
            ip: wire::DHCPV4_SERVER1_IP4.to_string(),
            mac: wire::ARP_TESTER_MAC.to_string(),
            undo: false,
        });
    }
    // ARP_48/49 — compress the DUT neigh expiry timers so the cache walks
    // REACHABLE→STALE→DELAY→PROBE inside the window. delay_first_probe_time
    // restores to setup-netns.sh's value (shared `netns::DELAY_FIRST_PROBE_SECS`),
    // NOT the kernel default 5 — ARP_03/05's absence window needs that dwell.
    else if id == "ARP_48" || id == "ARP_49" {
        steps.push(SysctlIface { side: Dut, table: Neigh, leaf: "base_reachable_time_ms", on: "500", off: "30000" });
        steps.push(SysctlIface { side: Dut, table: Neigh, leaf: "delay_first_probe_time", on: "1", off: netns::DELAY_FIRST_PROBE_SECS });
        steps.push(SysctlIface { side: Dut, table: Neigh, leaf: "gc_stale_time", on: "1", off: "60" });
    }
    // IP reassembly timer compression. ICMPv4_TYPE_04 → 3 s; REASSEMBLY_10/11/12
    // → 2 s. FRAGMENTS_02/03/04 deliberately get NO toggle. Restore to default 30.
    else if id == "ICMPV4_TYPE_04" {
        steps.push(SysctlGlobal { side: Dut, key: "ipfrag_time", on: "3", off: "30" });
    } else if id == "IPV4_REASSEMBLY_10" || id == "IPV4_REASSEMBLY_11" || id == "IPV4_REASSEMBLY_12" {
        steps.push(SysctlGlobal { side: Dut, key: "ipfrag_time", on: "2", off: "30" });
    }
    // TCP_RETRANSMISSION_TO_05 — disable Linux's SYN linear-RTO optimisation so
    // exponential backoff (RFC 6298 §5 step 5.5, TCP) engages from retransmit 1.
    else if id == "TCP_RETRANSMISSION_TO_05" {
        steps.push(SysctlGlobal { side: Dut, key: "tcp_syn_linear_timeouts", on: "0", off: "4" });
    }
    // TCP_RETRANSMISSION_TO_04/_03 — disable RACK + TLP so data-segment RTO
    // follows the canonical doubling path, not the thin-stream rapid-retransmit.
    else if id == "TCP_RETRANSMISSION_TO_04" || id == "TCP_RETRANSMISSION_TO_03" {
        steps.push(SysctlGlobal { side: Dut, key: "tcp_early_retrans", on: "0", off: "3" });
        steps.push(SysctlGlobal { side: Dut, key: "tcp_recovery", on: "0", off: "1" });
    }

    steps
}

/// Log the per-case conditioning OMISSIONS for a topology that does not manage the
/// DUT network stack (external/ssh-remote), mirroring bash `run_case` so an affected
/// case's later behaviour stays explainable. Returns the number of skip lines (tests).
///
/// Only DUT-side steps are skipped (and thus logged) — TESTER-side steps (ARP_39/40
/// `arp_ignore`) bash applies on every topology and the orchestrator does too, so
/// they are NOT an omission. bash emits up to two lines, reproduced here:
///   1. the per-case DUT neigh FLUSH (smoke-test.sh) — logged for every
///      `ARP_*` / `IPV4_AUTOCONF_*` case (the cache-sensitive families); the flush
///      is a DUT-side step, always skipped on a non-DUT-managing topology;
///   2. the case-keyed DUT-side FAMILY toggles (the `log_conditioning_skip` in each
///      conditioning block, e.g. arp_accept for ARP_38).
///
/// The family text is DERIVED from `plan` (the single source for which knobs a case
/// touches) rather than duplicating bash's per-family prose — deriving keeps the
/// case→knob mapping single-homed.
pub fn log_dut_skips(
    w: u32,
    case_id: &str,
    topology: TopologyKind,
    tester_ip4: &str,
    tester_mac: &str,
    ut_arp_conditioned: bool,
) -> usize {
    let id = case_id.to_uppercase();
    let topology = topology.as_str();
    let steps = plan(case_id, tester_ip4, tester_mac);
    let mut logged = 0;
    // 1. flush omission — cache-sensitive families only (bash smoke-test.sh).
    //    The flush is a DUT-side step, so it is among the skipped steps.
    if id.starts_with("ARP_") || id.starts_with("IPV4_AUTOCONF_") {
        log_conditioning_skip(
            w,
            case_id,
            topology,
            "per-case DUT neigh cache flush — repeat runs against a persistent DUT may hit a warm ARP cache",
        );
        logged += 1;
    }
    // 2. DUT-side family omission — the case-keyed toggles past the flush prefix,
    //    excluding any TESTER-side step (which is applied, not skipped). For ARP_39/40
    //    the only extra step is the tester-side arp_ignore, so there is NO family line.
    //    ARP_48/49's neigh-timer family is suppressed when the topology UT-conditions
    //    the ARP cache (lwIP): it is conditioned via UT 0x17, not skipped — matching
    //    bash, which omits the skip line there (smoke-test.sh).
    let ut_conditioned_neigh = ut_arp_conditioned && (id == "ARP_48" || id == "ARP_49");
    let dut_family: Vec<CondStep> = if ut_conditioned_neigh {
        Vec::new()
    } else {
        steps.into_iter().skip(1).filter(|s| s.side() == Side::Dut).collect()
    };
    if !dut_family.is_empty() {
        log_conditioning_skip(w, case_id, topology, &describe_family(&dut_family));
        logged += 1;
    }
    logged
}

/// One bash `log_conditioning_skip` line (smoke-test.sh), verbatim format.
fn log_conditioning_skip(w: u32, case_id: &str, topology: &str, what: &str) {
    println!(
        "[w{w}] INFO {case_id}: DUT-stack conditioning not applied ({what}) — topology '{topology}' does not manage the DUT network stack"
    );
}

/// A short summary of the case-keyed conditioning steps (the knobs that were not
/// applied), derived from the semantic plan so the case→knob mapping is not
/// duplicated. Distinct knobs only, in plan order (ARP_38's two arp_accept steps
/// collapse to one entry).
fn describe_family(steps: &[CondStep]) -> String {
    let mut knobs: Vec<String> = Vec::new();
    for step in steps {
        let knob = match step {
            CondStep::SysctlIface { leaf, .. } | CondStep::SysctlConfAll { leaf, .. } => leaf.to_string(),
            CondStep::SysctlGlobal { key, .. } => key.to_string(),
            CondStep::NeighPin { ip, .. } => format!("neigh-pin {ip}"),
            CondStep::NeighFlush { .. } => continue, // never in steps[1..]
        };
        if !knobs.contains(&knob) {
            knobs.push(knob);
        }
    }
    knobs.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIP: &str = "172.16.0.1";
    const TMAC: &str = "aa:bb:cc:dd:ee:ff";

    /// Every plan starts with the unconditional DUT neigh-flush prefix.
    fn assert_flush_prefix(p: &[CondStep]) {
        assert!(matches!(p[0], CondStep::NeighFlush { side: Side::Dut }), "missing flush prefix");
    }

    #[test]
    fn no_conditioning_case_is_flush_only() {
        for id in ["ICMPv4_TYPE_08", "ARP_03", "SOMEIPSRV_FORMAT_01"] {
            let p = plan(id, TIP, TMAC);
            assert_eq!(p.len(), 1, "{id}");
            assert_flush_prefix(&p);
        }
    }

    #[test]
    fn arp_38_toggles_arp_accept_iface_then_all_dut() {
        let p = plan("ARP_38", TIP, TMAC);
        assert_flush_prefix(&p);
        assert_eq!(p.len(), 3);
        assert_eq!(
            p[1],
            CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Conf, leaf: "arp_accept", on: "0", off: "1" }
        );
        assert_eq!(p[2], CondStep::SysctlConfAll { side: Side::Dut, leaf: "arp_accept", on: "0", off: "1" });
    }

    #[test]
    fn arp_39_40_arp_ignore_is_tester_side() {
        for id in ["ARP_39", "ARP_40"] {
            let p = plan(id, TIP, TMAC);
            assert_eq!(p.len(), 2, "{id}");
            assert_eq!(
                p[1],
                CondStep::SysctlIface { side: Side::Tester, table: SysctlTable::Conf, leaf: "arp_ignore", on: "8", off: "0" },
                "{id}"
            );
        }
    }

    #[test]
    fn ipv4_autoconf_pins_tester_with_undo() {
        let p = plan("IPv4_AUTOCONF_CONFLICT_01", TIP, TMAC);
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[1],
            CondStep::NeighPin { side: Side::Dut, ip: TIP.to_string(), mac: TMAC.to_string(), undo: true }
        );
    }

    #[test]
    fn dhcpv4_gateway_pin_uses_wire_consts_and_does_not_undo() {
        for id in ["DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_05", "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_06"] {
            let p = plan(id, TIP, TMAC);
            assert_eq!(p.len(), 2, "{id}");
            assert_eq!(
                p[1],
                CondStep::NeighPin {
                    side: Side::Dut,
                    ip: wire::DHCPV4_SERVER1_IP4.to_string(),
                    mac: wire::ARP_TESTER_MAC.to_string(),
                    undo: false,
                },
                "{id}"
            );
            assert!(!p[1].has_restore(), "{id} gateway pin must not be undone");
        }
    }

    #[test]
    fn arp_48_49_neigh_timers_restore_delay_to_shared_const() {
        let p = plan("ARP_49", TIP, TMAC);
        assert_eq!(p.len(), 4);
        assert_eq!(
            p[1],
            CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Neigh, leaf: "base_reachable_time_ms", on: "500", off: "30000" }
        );
        // delay_first_probe_time restores to the SHARED netns bring-up value, not 5.
        assert_eq!(
            p[2],
            CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Neigh, leaf: "delay_first_probe_time", on: "1", off: netns::DELAY_FIRST_PROBE_SECS }
        );
        assert_eq!(netns::DELAY_FIRST_PROBE_SECS, "30");
        assert_eq!(
            p[3],
            CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Neigh, leaf: "gc_stale_time", on: "1", off: "60" }
        );
    }

    #[test]
    fn ipfrag_time_compression_per_family() {
        assert_eq!(
            plan("ICMPv4_TYPE_04", TIP, TMAC)[1],
            CondStep::SysctlGlobal { side: Side::Dut, key: "ipfrag_time", on: "3", off: "30" }
        );
        for id in ["IPv4_REASSEMBLY_10", "IPv4_REASSEMBLY_11", "IPv4_REASSEMBLY_12"] {
            assert_eq!(
                plan(id, TIP, TMAC)[1],
                CondStep::SysctlGlobal { side: Side::Dut, key: "ipfrag_time", on: "2", off: "30" },
                "{id}"
            );
        }
    }

    #[test]
    fn tcp_retransmission_rto_toggles() {
        assert_eq!(
            plan("TCP_RETRANSMISSION_TO_05", TIP, TMAC)[1],
            CondStep::SysctlGlobal { side: Side::Dut, key: "tcp_syn_linear_timeouts", on: "0", off: "4" }
        );
        for id in ["TCP_RETRANSMISSION_TO_04", "TCP_RETRANSMISSION_TO_03"] {
            let p = plan(id, TIP, TMAC);
            assert_eq!(p.len(), 3, "{id}");
            assert_eq!(p[1], CondStep::SysctlGlobal { side: Side::Dut, key: "tcp_early_retrans", on: "0", off: "3" }, "{id}");
            assert_eq!(p[2], CondStep::SysctlGlobal { side: Side::Dut, key: "tcp_recovery", on: "0", off: "1" }, "{id}");
        }
    }

    #[test]
    fn case_id_match_is_case_insensitive() {
        assert_eq!(plan("arp_38", TIP, TMAC).len(), 3);
        assert_eq!(plan("tcp_retransmission_to_04", TIP, TMAC).len(), 3);
        assert_eq!(plan("icmpv4_type_04", TIP, TMAC).len(), 2);
    }

    #[test]
    fn dut_skip_line_count_matches_bash_structure() {
        // Non-DUT-conditioning topology that is NOT UT-arp-conditioned (Linux
        // external/ssh-remote): ut_arp_conditioned = false.
        let f = false;
        // Non-ARP/AUTOCONF, flush-only → no flush line, no family line (bash silent).
        assert_eq!(log_dut_skips(0, "ICMPv4_TYPE_08", TopologyKind::External, TIP, TMAC, f), 0);
        assert_eq!(log_dut_skips(0, "SOMEIPSRV_FORMAT_01", TopologyKind::External, TIP, TMAC, f), 0);
        // ARP_*, flush-only (no keyed family) → flush line only (bash:912-917).
        assert_eq!(log_dut_skips(0, "ARP_03", TopologyKind::External, TIP, TMAC, f), 1);
        // ARP_39/40 — the only extra step is TESTER-side arp_ignore (applied, not
        // skipped), so the DUT-side skips are flush-only → 1 line, matching bash
        // (bash applies arp_ignore on every topology, smoke-test.sh). This
        // is the round-2 over-count regression guard.
        assert_eq!(log_dut_skips(0, "ARP_39", TopologyKind::External, TIP, TMAC, f), 1);
        assert_eq!(log_dut_skips(0, "ARP_40", TopologyKind::SshRemote, TIP, TMAC, f), 1);
        // ARP_* WITH a DUT-side keyed family → flush line + family line (912-917 + 943).
        assert_eq!(log_dut_skips(0, "ARP_38", TopologyKind::External, TIP, TMAC, f), 2);
        assert_eq!(log_dut_skips(0, "ARP_48", TopologyKind::External, TIP, TMAC, f), 2);
        // AUTOCONF (matches the flush gate AND carries the DUT-side tester pin) → 2.
        assert_eq!(log_dut_skips(0, "IPv4_AUTOCONF_CONFLICT_01", TopologyKind::External, TIP, TMAC, f), 2);
        // Non-ARP DUT family (ipfrag/tcp) → family line only (no flush gate match).
        assert_eq!(log_dut_skips(0, "ICMPv4_TYPE_04", TopologyKind::SshRemote, TIP, TMAC, f), 1);
        assert_eq!(log_dut_skips(0, "TCP_RETRANSMISSION_TO_04", TopologyKind::SshRemote, TIP, TMAC, f), 1);
    }

    #[test]
    fn ut_arp_conditioned_suppresses_arp_48_49_neigh_skip() {
        // lwip-tap: ARP_48/49 condition via UT 0x17, not host sysctls, so the
        // neigh-timer family skip is suppressed — flush line only (1), matching bash
        // (smoke-test.sh). Other families are unaffected.
        let t = true;
        assert_eq!(log_dut_skips(0, "ARP_48", TopologyKind::LwipTap, TIP, TMAC, t), 1);
        assert_eq!(log_dut_skips(0, "ARP_49", TopologyKind::LwipTap, TIP, TMAC, t), 1);
        // ARP_38 arp_accept has no UT equivalent → still flush + family = 2 lines.
        assert_eq!(log_dut_skips(0, "ARP_38", TopologyKind::LwipTap, TIP, TMAC, t), 2);
        // ARP_03 (flush only) unaffected → 1.
        assert_eq!(log_dut_skips(0, "ARP_03", TopologyKind::LwipTap, TIP, TMAC, t), 1);
    }

    #[test]
    fn describe_family_dedupes_and_names_knobs() {
        // ARP_38's two arp_accept steps collapse to one knob name.
        assert_eq!(describe_family(&plan("ARP_38", TIP, TMAC)[1..]), "arp_accept");
        assert_eq!(describe_family(&plan("ICMPv4_TYPE_04", TIP, TMAC)[1..]), "ipfrag_time");
        assert_eq!(
            describe_family(&plan("ARP_49", TIP, TMAC)[1..]),
            "base_reachable_time_ms/delay_first_probe_time/gc_stale_time"
        );
        assert_eq!(describe_family(&plan("IPv4_AUTOCONF_CONFLICT_01", TIP, TMAC)[1..]), format!("neigh-pin {TIP}"));
    }
}
