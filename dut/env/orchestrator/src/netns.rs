//! Native Rust port of `setup-netns.sh` + `cleanup.sh` — the ip/sysctl/ethtool/
//! neigh sequence that builds a TC8 tester/DUT veth-pair fixture. Replaces the
//! Stage-1 shell-out to those scripts (topology.rs).
//!
//! The bash originals remain the SSOT baseline (smoke-test.sh still sources them)
//! until the S8 CI cutover; this module is validated behaviour-equivalent by
//! parity-check.sh. Every step below cites the `setup-netns.sh` / `cleanup.sh`
//! line it mirrors so the two can be diffed by eye until parity covers all paths.
//!
//! `set -e` parity: a mandatory `ip`/`sysctl`/`ping`/`neigh` step that fails
//! aborts the bring-up (the helpers return `Err`); the offload-disable and the
//! pre-create teardown deletes are best-effort, matching bash's `|| true`.
//!
//! Coverage note: the single-pc orchestrator drives only the single-pair, no-VLAN
//! path, so parity-check.sh exercises that. The `SecondVeth` (USAGE_01
//! Topology-2 second pair) and `Vlan` (802.1Q OEM profile) branches are ported
//! faithfully but are not yet parity-exercised — they become reachable + gated
//! when S5 / USAGE_01 wire the Config fields and a parity case that drive them.
//! See [[project-smoke-rust-rewrite]].

use anyhow::{bail, Context, Result};
use std::process::Command;

use crate::wire;

/// SOME/IP-SD multicast route — `224.244.224.245` in the vsomeip default lives in
/// this block (setup-netns.sh MCAST_ROUTE default, line 39).
pub(crate) const MCAST_ROUTE: &str = "224.0.0.0/4";
/// DUT NUD delay-first-probe window, widened past the ARP_03/05 5 s listen window
/// (setup-netns.sh) so a STALE→DELAY→PROBE re-verification does not fire a
/// unicast Request inside the absence-check window. `pub(crate)` so the per-case
/// conditioning (ARP_48/49) restores `delay_first_probe_time` to THIS value, not
/// the kernel default — the two must agree, so they share one home.
pub(crate) const DELAY_FIRST_PROBE_SECS: &str = "30";

/// Optional second veth pair — USAGE_01 Topology 2 (setup-netns.sh).
/// A distinct broadcast domain (separate veth, not a macvlan) per RFC 2131 §3.6.
pub struct SecondVeth {
    pub veth_t2: String,
    pub veth_d2: String,
    /// CIDR.
    pub tester_ip2: String,
    /// CIDR.
    pub dut_ip2: String,
}

/// Optional IEEE 802.1Q VLAN profile — D2 OEM tagged traffic (setup-netns.sh).
/// When set, all L3 config (addresses/routes/sysctls) homes on the subinterface
/// so every tester<->DUT L3 frame is 802.1Q-tagged.
pub struct Vlan {
    pub id: u16,
    pub tester_vlan_if: String,
    pub dut_vlan_if: String,
}

/// Fully-resolved inputs for one netns fixture. The caller (topology.rs) is the
/// SSOT for worker-scoped names; this module is name-agnostic.
pub struct NetnsParams {
    pub tester_ns: String,
    pub dut_ns: String,
    pub veth_t: String,
    pub veth_d: String,
    /// CIDR, e.g. `172.16.0.1/24`.
    pub tester_ip: String,
    /// CIDR, e.g. `172.16.0.2/24`.
    pub dut_ip: String,
    pub second_veth: Option<SecondVeth>,
    pub vlan: Option<Vlan>,
}

/// Build the tester/DUT netns fixture. Idempotent: tears down any prior state
/// first. Mirrors `setup-netns.sh` top to bottom.
pub fn setup(p: &NetnsParams) -> Result<()> {
    // Single source of truth for "which interface carries L3" (setup-netns.sh):
    // the bare veth, or the VLAN subinterface when 802.1Q is enabled. Every
    // addr/route/sysctl/neigh op below references these, so toggling the VLAN
    // leaves the no-VLAN path byte-identical.
    let (tester_l3if, dut_l3if) = match &p.vlan {
        Some(v) => (v.tester_vlan_if.as_str(), v.dut_vlan_if.as_str()),
        None => (p.veth_t.as_str(), p.veth_d.as_str()),
    };

    // --- Tear down previous state (setup-netns.sh). netns delete cascades
    //     to its veth peer; the bare `ip link del` catches a veth left orphaned in
    //     the root ns by a crashed prior setup. All best-effort. ---
    del_netns(&p.dut_ns);
    del_netns(&p.tester_ns);
    del_link(&p.veth_t);
    if let Some(s) = &p.second_veth {
        del_link(&s.veth_t2);
    }

    // --- netns + primary veth pair (setup-netns.sh) ---
    ip(&["netns", "add", &p.tester_ns])?;
    ip(&["netns", "add", &p.dut_ns])?;
    ip(&["link", "add", &p.veth_t, "type", "veth", "peer", "name", &p.veth_d])?;
    ip(&["link", "set", &p.veth_t, "netns", &p.tester_ns])?;
    ip(&["link", "set", &p.veth_d, "netns", &p.dut_ns])?;
    ip(&["-n", &p.tester_ns, "link", "set", "lo", "up"])?;
    ip(&["-n", &p.dut_ns, "link", "set", "lo", "up"])?;
    ip(&["-n", &p.tester_ns, "link", "set", &p.veth_t, "up"])?;
    ip(&["-n", &p.dut_ns, "link", "set", &p.veth_d, "up"])?;

    // --- Opt-in 802.1Q: stack a VLAN subif on each veth, repoint L3 onto it
    //     (setup-netns.sh). netns teardown cascades to subifs, no extra
    //     cleanup needed. ---
    if let Some(v) = &p.vlan {
        let id = v.id.to_string();
        ip(&["-n", &p.tester_ns, "link", "add", "link", &p.veth_t,
            "name", &v.tester_vlan_if, "type", "vlan", "id", &id])?;
        ip(&["-n", &p.dut_ns, "link", "add", "link", &p.veth_d,
            "name", &v.dut_vlan_if, "type", "vlan", "id", &id])?;
        ip(&["-n", &p.tester_ns, "link", "set", &v.tester_vlan_if, "up"])?;
        ip(&["-n", &p.dut_ns, "link", "set", &v.dut_vlan_if, "up"])?;
    }

    // --- Addresses: primary + the two UI_07/_08 aliases (setup-netns.sh).
    //     The alias bare IPs are the harness's SSOT (wire); netns derives the /24
    //     it configures, the same way the primary CIDRs are built from cfg. ---
    let dut_alias = format!("{}/24", wire::DUT_ALIAS_IP);
    let tester_alias = format!("{}/24", wire::TESTER_ALIAS_IP);
    ip(&["-n", &p.tester_ns, "addr", "add", &p.tester_ip, "dev", tester_l3if])?;
    ip(&["-n", &p.dut_ns, "addr", "add", &p.dut_ip, "dev", dut_l3if])?;
    ip(&["-n", &p.dut_ns, "addr", "add", &dut_alias, "dev", dut_l3if])?;
    ip(&["-n", &p.tester_ns, "addr", "add", &tester_alias, "dev", tester_l3if])?;

    // --- Disable veth TX checksum offload (setup-netns.sh) — best-effort
    //     (bash `|| true`). veth reports CHECKSUM_PARTIAL on TX, so without this
    //     the captured L4 checksum carries only the pseudo-header sum and
    //     TCP_CHECKSUM_03's `tcp_checksum_valid()` would see a bad value. ---
    ethtool_tx_off(&p.tester_ns, &p.veth_t);
    ethtool_tx_off(&p.dut_ns, &p.veth_d);

    // --- DUT gratuitous-ARP learning for ARP_05/06 (setup-netns.sh) ---
    sysctl(&p.dut_ns, &format!("net.ipv4.conf.{dut_l3if}.arp_accept=1"))?;
    sysctl(&p.dut_ns, "net.ipv4.conf.all.arp_accept=1")?;

    // --- Widen the DUT NUD delay-first-probe window (setup-netns.sh).
    //     `default.*` does not exist in a fresh netns, so only the per-iface key
    //     matters. ---
    sysctl(&p.dut_ns,
        &format!("net.ipv4.neigh.{dut_l3if}.delay_first_probe_time={DELAY_FIRST_PROBE_SECS}"))?;

    // --- Suppress tester-side unicast NUD_PROBE so a STALE re-validation does not
    //     fire an outbound ARP during an absence-check window (setup-netns.sh). ---
    sysctl(&p.tester_ns, &format!("net.ipv4.neigh.{tester_l3if}.ucast_solicit=0"))?;

    // --- SOME/IP-SD multicast route (setup-netns.sh) ---
    ip(&["-n", &p.tester_ns, "route", "add", MCAST_ROUTE, "dev", tester_l3if])?;
    ip(&["-n", &p.dut_ns, "route", "add", MCAST_ROUTE, "dev", dut_l3if])?;

    // --- USAGE_01 second veth pair, structurally identical to the first
    //     (setup-netns.sh) ---
    if let Some(s) = &p.second_veth {
        ip(&["link", "add", &s.veth_t2, "type", "veth", "peer", "name", &s.veth_d2])?;
        ip(&["link", "set", &s.veth_t2, "netns", &p.tester_ns])?;
        ip(&["link", "set", &s.veth_d2, "netns", &p.dut_ns])?;
        ip(&["-n", &p.tester_ns, "link", "set", &s.veth_t2, "up"])?;
        ip(&["-n", &p.dut_ns, "link", "set", &s.veth_d2, "up"])?;
        ip(&["-n", &p.tester_ns, "addr", "add", &s.tester_ip2, "dev", &s.veth_t2])?;
        ip(&["-n", &p.dut_ns, "addr", "add", &s.dut_ip2, "dev", &s.veth_d2])?;
        ethtool_tx_off(&p.tester_ns, &s.veth_t2);
        ethtool_tx_off(&p.dut_ns, &s.veth_d2);
        sysctl(&p.dut_ns, &format!("net.ipv4.conf.{}.arp_accept=1", s.veth_d2))?;
        sysctl(&p.dut_ns,
            &format!("net.ipv4.neigh.{}.delay_first_probe_time={DELAY_FIRST_PROBE_SECS}", s.veth_d2))?;
        sysctl(&p.tester_ns, &format!("net.ipv4.neigh.{}.ucast_solicit=0", s.veth_t2))?;
    }

    // --- Reachability sanity check (setup-netns.sh) ---
    ping(&p.tester_ns, &p.dut_ip)?;
    if let Some(s) = &p.second_veth {
        ping(&p.tester_ns, &s.dut_ip2)?;
    }

    // --- The sanity ping populated the DUT neigh table via RFC 826 §2.3; flush it
    //     once here so ARP_07..15 (DUT emits a Request on cache miss) see a cold
    //     cache. The tester cache is intentionally left populated (setup-netns.sh). ---
    ip(&["-n", &p.dut_ns, "neigh", "flush", "dev", dut_l3if])?;

    Ok(())
}

/// Remove the tester/DUT netns (cleanup.sh). Idempotent + best-effort: a netns
/// delete cascades to its veth peers, and deleting an absent netns is a harmless
/// no-op here (cleanup.sh swallows it with `|| true`). The startup stale-GC and
/// `setup()`'s idempotent re-create both rely on teardown never hard-failing.
pub fn teardown(tester_ns: &str, dut_ns: &str) {
    del_netns(dut_ns);
    del_netns(tester_ns);
}

/// Run `ip ARGS`, bailing with the captured stderr on a non-zero exit. Used for
/// every mandatory step (bash runs these without `|| true` under `set -e`).
/// `pub(crate)` so topology.rs's per-case conditioning reuses one checked runner.
pub(crate) fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("spawning `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `ip netns exec NS sysctl -wq KEY=VALUE` (mandatory — bash uses no `|| true`).
fn sysctl(ns: &str, kv: &str) -> Result<()> {
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "sysctl", "-wq", kv])
        .output()
        .with_context(|| format!("spawning sysctl `{kv}` in {ns}"))?;
    if !out.status.success() {
        bail!(
            "sysctl `{kv}` in {ns} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `ip netns exec NS ping -c1 -W1 IP` — strips any CIDR suffix (bash `${IP%/*}`).
fn ping(ns: &str, cidr: &str) -> Result<()> {
    let ip_only = cidr.split('/').next().unwrap_or(cidr);
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "ping", "-c", "1", "-W", "1", ip_only])
        .output()
        .with_context(|| format!("spawning ping {ns} -> {ip_only}"))?;
    if !out.status.success() {
        bail!("reachability ping {ns} -> {ip_only} failed ({})", out.status);
    }
    Ok(())
}

/// Best-effort `ip netns exec NS ethtool -K DEV tx off` (bash `... 2>&1 || true`):
/// veth TX offload-disable is advisory; a missing ethtool must not abort bring-up.
fn ethtool_tx_off(ns: &str, dev: &str) {
    ip_quiet(&["netns", "exec", ns, "ethtool", "-K", dev, "tx", "off"]);
}

/// Best-effort `ip netns delete NS` (bash `... 2>/dev/null || true`).
fn del_netns(ns: &str) {
    ip_quiet(&["netns", "delete", ns]);
}

/// Best-effort `ip link del DEV` (bash `... 2>/dev/null || true`).
fn del_link(dev: &str) {
    ip_quiet(&["link", "del", dev]);
}

/// Fire-and-forget `ip ARGS`, discarding output and ignoring the exit status (the
/// bash `... 2>/dev/null || true` idiom). `pub(crate)` so the fixtures reuse the one
/// `ip`-quiet helper instead of re-declaring it.
pub(crate) fn ip_quiet(args: &[&str]) {
    crate::proc::run_quiet(Command::new("ip").args(args));
}
