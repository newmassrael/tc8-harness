//! Per-worker netns-pair tester transport — the wire fixture a topology owns when
//! both ends of the link live on this host. It stands up the `tc8-tester-<w>` /
//! `tc8-dut-<w>` namespaces joined by a veth pair (optionally a second pair for TC8
//! Topology 2), runs the harness inside the tester namespace, and renders per-case
//! kernel conditioning to `ip netns exec` / `ip -n` on either side.
//!
//! This is the sibling of [`super::HostTester`], and the two exist for the same
//! reason: a topology is a pairing of a TESTER TRANSPORT (where the harness runs and
//! what wire it sees) with a DUT LIFECYCLE (how the DUT gets onto that wire). Host-NIC
//! topologies compose `HostTester`; netns topologies compose this. Neither knows
//! anything about the DUT beyond [`NetnsPair::dut_netns`] — the placement a DUT
//! lifecycle needs in order to put a DUT on this wire.
//!
//! Owning BOTH namespaces is what separates this transport from `HostTester`, and it
//! is why the conditioning renderer here handles DUT-side steps that the host
//! transport refuses: the DUT's kernel stack is ours, so `condition_case` applies
//! every step rather than skipping and logging the DUT-side half.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::conditioning::{self, CondDir, CondStep, Side};
use crate::config::Config;
use crate::netns::{self, NetnsParams, SecondVeth};
use crate::wire;

use super::{
    harness_link, kill_by_marker, netns_dut, netns_tester, symlink_force, which, Conditioning,
    Topology, WorkerCtx,
};

/// The per-worker netns-pair wire fixture: two namespaces joined by a veth pair,
/// with the harness running in the tester half.
pub(crate) struct NetnsPair<'a> {
    cfg: &'a Config,
    /// Provision the Topology-2 second veth pair (DIface-1 / TIface-1) per worker,
    /// so `tester_iface_secondary` returns it and USAGE_01 runs instead of skipping.
    /// The composing topology sets this iff the schedule contains a
    /// `requires_secondary_iface` case — bash's sticky `NEED_SECOND_VETH`, so the
    /// common single-pair run pays nothing.
    secondary_iface: bool,
}

impl<'a> NetnsPair<'a> {
    pub(crate) fn new(cfg: &'a Config, secondary_iface: bool) -> Self {
        NetnsPair { cfg, secondary_iface }
    }

    /// The namespace a DUT must run in to sit on this worker's wire. This is the
    /// ENTIRE interface between the transport and whatever DUT lifecycle is composed
    /// with it: the transport does not care how the DUT gets there, and the lifecycle
    /// does not care how the wire was built.
    pub(crate) fn dut_netns(&self, w: u32) -> String {
        netns_dut(w)
    }

    /// Tools this transport invokes directly (S3 port of setup-netns.sh). `ip` /
    /// `sysctl` / `ping` are mandatory — bash setup-netns.sh runs them without
    /// `|| true` under `set -e`. `ethtool` is best-effort there (offload-disable is
    /// advisory), so it is intentionally not a hard preflight requirement.
    pub(crate) fn preflight(&self) -> Result<()> {
        for tool in ["ip", "sysctl", "ping"] {
            if which(tool).is_none() {
                bail!("preflight: '{tool}' not found on PATH");
            }
        }
        Ok(())
    }

    /// Build this worker's netns fixture and capture its kernel-assigned identity.
    ///
    /// The netns pair is destroyed + recreated on every bring-up, which wipes any
    /// leftover iptables `tc8-stimulus` rule — so unlike bash's common_bring_up_worker
    /// (smoke-test.sh) no explicit chain flush is needed here. A persistent topology
    /// (external/ssh-remote) that reuses a netns WILL need that flush ported alongside it.
    pub(crate) fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        let cfg = self.cfg;
        fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
        fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;

        // The Topology-2 second veth pair (DIface-1 / TIface-1, 172.17.0.0/24 from
        // wire.def — the same source bash's setup-netns.sh SECOND_VETH path reads) is
        // provisioned only when the schedule needs it (self.secondary_iface). vlan
        // stays None (no 802.1Q on a netns pair). netns::setup implements both.
        let second_veth = self.secondary_iface.then(|| SecondVeth {
            veth_t2: veth_tester2(w),
            veth_d2: veth_dut2(w),
            tester_ip2: format!("{}/24", wire::TESTER_IP_2),
            dut_ip2: format!("{}/24", wire::DUT_IP_2),
        });
        netns::setup(&NetnsParams {
            tester_ns: netns_tester(w),
            dut_ns: netns_dut(w),
            veth_t: veth_tester(w),
            veth_d: veth_dut(w),
            tester_ip: format!("{}/24", cfg.tester_ip4),
            dut_ip: format!("{}/24", cfg.dut_ip4),
            second_veth,
            vlan: None,
        })
        .with_context(|| format!("bringing up netns for worker {w}"))?;

        // Worker-unique argv[0] so a teardown pkill is scoped to this worker. The DUT's
        // own marker belongs to the DUT lifecycle, not here.
        symlink_force(&cfg.harness, &harness_link(&cfg.vsomeip_base, w))?;

        let dut_mac = veth_mac(&netns_dut(w), &veth_dut(w))?;
        let tester_mac = veth_mac(&netns_tester(w), &veth_tester(w))?;

        // Neigh pins mirror single-pc.conf: pin <DUT_IP, dut_mac> on the tester
        // side (keeps the ARP cold-cache premise) and <HOST2_IP, tester_mac>
        // on the DUT side (Host-2 emulation for UDP_FIELDS_04/05).
        ip_neigh_replace(&netns_tester(w), &cfg.dut_ip4, &dut_mac, &veth_tester(w))?;
        ip_neigh_replace(&netns_dut(w), wire::HOST2_IP, &tester_mac, &veth_dut(w))?;

        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    /// The tester-side capture/injection interface — a bare veth (not a VLAN subif)
    /// so libpcap sees any 802.1Q tag intact.
    pub(crate) fn tester_iface(&self, w: u32) -> String {
        veth_tester(w)
    }

    /// The second tester veth (TIface-1) — `Some` only when `bring_up_worker`
    /// provisioned the pair. When `None`, dispatch SKIPs USAGE_01 (the schedule has
    /// no Topology-2 case, so the pair was never brought up).
    pub(crate) fn tester_iface_secondary(&self, w: u32) -> Option<String> {
        self.secondary_iface.then(|| veth_tester2(w))
    }

    /// Spawn the harness inside this worker's tester namespace.
    pub(crate) fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        let log = fs::File::create(hlog).context("creating harness log")?;
        let err = log.try_clone()?;
        Command::new("ip")
            .args(["netns", "exec", &netns_tester(w)])
            .arg(harness_link(&self.cfg.vsomeip_base, w))
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning harness via ip netns exec")
    }

    /// Reap this worker's harness by its symlink marker.
    pub(crate) fn kill_harness(&self, w: u32) {
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
    }

    /// Apply EVERY step of this case's conditioning plan — both sides, because this
    /// transport owns both kernel stacks. (The host transport applies only the
    /// tester-side steps and logs the DUT-side omission; that asymmetry is the whole
    /// content of bash's TOPOLOGY_DUT_CONDITIONING bit.)
    ///
    /// The guard is built incrementally and a step's restore is recorded only AFTER
    /// its apply succeeds, so a mid-sequence failure (the `?`) drops `cond` and
    /// reverts exactly the steps already applied. bash gets this for free from
    /// `set -e` + the EXIT-trap netns destroy.
    pub(crate) fn condition_case<'t>(
        &self,
        topo: &'t dyn Topology,
        w: u32,
        case_id: &str,
        tester_mac: &str,
    ) -> Result<Conditioning<'t>> {
        let steps = conditioning::plan(case_id, &self.cfg.tester_ip4, tester_mac);
        let mut cond = Conditioning::empty(topo, w);
        for step in steps {
            self.exec_cond_step(w, &step, CondDir::Apply)
                .with_context(|| format!("conditioning {case_id} (worker {w})"))?;
            if step.has_restore() {
                cond.record_restore(step);
            }
        }
        Ok(cond)
    }

    /// Render+run one semantic conditioning step in `dir` against this worker's
    /// namespaces. `None` = a no-op direction (a flush or a no-undo pin has no restore).
    pub(crate) fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        match render_cond_step(w, step, dir) {
            Some(argv) => {
                let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                netns::ip(&refs)
            }
            None => Ok(()),
        }
    }
}

// --- Worker-scoped veth names ------------------------------------------------
// The netns + symlink names shared with `teardown_worker` stay in the parent module;
// the veth devices belong to this transport, which is what creates them.
fn veth_tester(w: u32) -> String {
    format!("veth-tester-{w}")
}
fn veth_dut(w: u32) -> String {
    format!("veth-dut-{w}")
}
// Topology-2 second pair (TIface-1 / DIface-1), worker-scoped like the first pair
// so parallel workers never contend. Provisioned only when secondary_iface is set.
fn veth_tester2(w: u32) -> String {
    format!("veth-tester2-{w}")
}
fn veth_dut2(w: u32) -> String {
    format!("veth-dut2-{w}")
}

// --- conditioning rendering --------------------------------------------------
// Bind the semantic `conditioning::plan` steps to the netns transport for one
// worker. Kept pure (no I/O) so the rendering is unit-tested directly, separate
// from the case→toggle policy.

/// The (namespace, L3 interface) a logical `Side` resolves to on worker `w`.
fn side_ns_iface(w: u32, side: Side) -> (String, String) {
    match side {
        Side::Dut => (netns_dut(w), veth_dut(w)),
        Side::Tester => (netns_tester(w), veth_tester(w)),
    }
}

/// `ip netns exec NS sysctl -qw KEY=VALUE` argv.
fn sysctl_argv(ns: String, kv: String) -> Vec<String> {
    vec!["netns".into(), "exec".into(), ns, "sysctl".into(), "-qw".into(), kv]
}

/// Render one semantic step to an `ip` argv for `dir`, or `None` when the
/// direction is a no-op (a flush or a no-undo pin has no restore action).
fn render_cond_step(w: u32, step: &CondStep, dir: CondDir) -> Option<Vec<String>> {
    match step {
        CondStep::SysctlIface { side, table, leaf, on, off } => {
            let (ns, iface) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.{}.{iface}.{leaf}={val}", table.as_str())))
        }
        CondStep::SysctlConfAll { side, leaf, on, off } => {
            let (ns, _) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.conf.all.{leaf}={val}")))
        }
        CondStep::SysctlGlobal { side, key, on, off } => {
            let (ns, _) = side_ns_iface(w, *side);
            let val = match dir { CondDir::Apply => on, CondDir::Restore => off };
            Some(sysctl_argv(ns, format!("net.ipv4.{key}={val}")))
        }
        CondStep::NeighPin { side, ip, mac, undo } => {
            let (ns, iface) = side_ns_iface(w, *side);
            match dir {
                CondDir::Apply => Some(vec![
                    "-n".into(), ns, "neigh".into(), "replace".into(), ip.clone(),
                    "lladdr".into(), mac.clone(), "dev".into(), iface, "nud".into(), "permanent".into(),
                ]),
                CondDir::Restore if *undo => Some(vec![
                    "-n".into(), ns, "neigh".into(), "del".into(), ip.clone(), "dev".into(), iface,
                ]),
                CondDir::Restore => None,
            }
        }
        CondStep::NeighFlush { side } => match dir {
            CondDir::Apply => {
                let (ns, iface) = side_ns_iface(w, *side);
                Some(vec!["-n".into(), ns, "neigh".into(), "flush".into(), "dev".into(), iface])
            }
            CondDir::Restore => None,
        },
    }
}

// --- netns MAC read + neigh pin (bring-up) -----------------------------------

/// `ip -n NS link show DEV | awk '/link\/ether/ {print $2}'` in Rust.
fn veth_mac(ns: &str, dev: &str) -> Result<String> {
    let out = Command::new("ip")
        .args(["-n", ns, "link", "show", dev])
        .output()
        .with_context(|| format!("ip -n {ns} link show {dev}"))?;
    if !out.status.success() {
        bail!("ip -n {ns} link show {dev} failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("link/ether ") {
            if let Some(mac) = rest.split_whitespace().next() {
                return Ok(mac.to_string());
            }
        }
    }
    bail!("no link/ether for {dev} in {ns}")
}

fn ip_neigh_replace(ns: &str, ip: &str, mac: &str, dev: &str) -> Result<()> {
    let st = Command::new("ip")
        .args(["-n", ns, "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", dev])
        .status()
        .with_context(|| format!("ip -n {ns} neigh replace {ip}"))?;
    if !st.success() {
        bail!("ip -n {ns} neigh replace {ip} failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditioning::SysctlTable;

    fn vs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn renders_iface_sysctl_both_directions_dut_ns() {
        let step = CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Conf, leaf: "arp_accept", on: "0", off: "1" };
        assert_eq!(
            render_cond_step(0, &step, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.conf.veth-dut-0.arp_accept=0"])
        );
        assert_eq!(
            render_cond_step(0, &step, CondDir::Restore).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.conf.veth-dut-0.arp_accept=1"])
        );
    }

    #[test]
    fn renders_tester_side_step_in_tester_ns() {
        let step = CondStep::SysctlIface { side: Side::Tester, table: SysctlTable::Conf, leaf: "arp_ignore", on: "8", off: "0" };
        assert_eq!(
            render_cond_step(1, &step, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-tester-1", "sysctl", "-qw", "net.ipv4.conf.veth-tester-1.arp_ignore=8"])
        );
    }

    #[test]
    fn renders_neigh_table_and_global_sysctl() {
        let neigh = CondStep::SysctlIface { side: Side::Dut, table: SysctlTable::Neigh, leaf: "gc_stale_time", on: "1", off: "60" };
        assert_eq!(
            render_cond_step(0, &neigh, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.neigh.veth-dut-0.gc_stale_time=1"])
        );
        let global = CondStep::SysctlGlobal { side: Side::Dut, key: "ipfrag_time", on: "3", off: "30" };
        assert_eq!(
            render_cond_step(0, &global, CondDir::Apply).unwrap(),
            vs(&["netns", "exec", "tc8-dut-0", "sysctl", "-qw", "net.ipv4.ipfrag_time=3"])
        );
    }

    #[test]
    fn renders_neigh_pin_replace_and_del_and_no_undo() {
        let pin = CondStep::NeighPin { side: Side::Dut, ip: "172.16.0.1".into(), mac: "aa:bb:cc".into(), undo: true };
        assert_eq!(
            render_cond_step(0, &pin, CondDir::Apply).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "replace", "172.16.0.1", "lladdr", "aa:bb:cc", "dev", "veth-dut-0", "nud", "permanent"])
        );
        assert_eq!(
            render_cond_step(0, &pin, CondDir::Restore).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "del", "172.16.0.1", "dev", "veth-dut-0"])
        );
        let no_undo = CondStep::NeighPin { side: Side::Dut, ip: "172.16.0.10".into(), mac: "aa:bb:cc".into(), undo: false };
        assert!(render_cond_step(0, &no_undo, CondDir::Restore).is_none());
    }

    #[test]
    fn renders_flush_apply_only() {
        let flush = CondStep::NeighFlush { side: Side::Dut };
        assert_eq!(
            render_cond_step(0, &flush, CondDir::Apply).unwrap(),
            vs(&["-n", "tc8-dut-0", "neigh", "flush", "dev", "veth-dut-0"])
        );
        assert!(render_cond_step(0, &flush, CondDir::Restore).is_none());
    }
}
