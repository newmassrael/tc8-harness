//! single-pc topology — tester + reference tc8-dut in per-worker netns pairs on
//! this host. The cheap default: no worker cap, a fresh DUT per case, negative
//! self-validation, and per-case kernel conditioning, all rendered to `ip netns
//! exec` / `ip -n` in the worker's namespaces. Sibling of `host` (external /
//! ssh-remote) and `lwip_tap`; the shared worker-scoped names (`netns_*`/`dut_link`/
//! `harness_link`) + `teardown_worker` live in the parent `topology` module.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::conditioning::{self, CondDir, CondStep, Side};
use crate::config::Config;
use crate::netns::{self, NetnsParams};
use crate::wire;

use super::{
    dut_link, harness_link, kill_by_marker, netns_dut, netns_tester, symlink_force,
    teardown_worker, which, Conditioning, Topology, WorkerCtx, VSOMEIP_RT_LOCK,
    VSOMEIP_RT_SOCK_PREFIX,
};

/// single-pc: tester + reference tc8-dut in per-worker netns pairs on this host.
pub struct SinglePc<'a> {
    cfg: &'a Config,
}

impl<'a> SinglePc<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        SinglePc { cfg }
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

    fn preflight(&self) -> Result<()> {
        let cfg = self.cfg;
        if !cfg.dut_bin.is_file() {
            bail!("preflight: tc8-dut binary missing: {}", cfg.dut_bin.display());
        }
        if !cfg.vsomeip_cfg.is_file() {
            bail!("preflight: vsomeip.json missing: {}", cfg.vsomeip_cfg.display());
        }
        // Tools the netns module (S3 port) invokes directly. `ip`/`sysctl`/`ping`
        // are mandatory — bash setup-netns.sh runs them without `|| true` under
        // `set -e`. `ethtool` is best-effort there (offload-disable is advisory),
        // so it is intentionally not a hard preflight requirement.
        for tool in ["ip", "sysctl", "ping"] {
            if which(tool).is_none() {
                bail!("preflight: '{tool}' not found on PATH");
            }
        }
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        let cfg = self.cfg;
        fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
        fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;

        // Build the netns fixture natively (S3 port of setup-netns.sh).
        // single-pc destroys + recreates the netns pair each bring-up, which
        // wipes any leftover iptables `tc8-stimulus` rule — so unlike bash's
        // common_bring_up_worker (smoke-test.sh) no explicit chain flush is
        // needed here. A persistent topology (external/ssh-remote) that reuses a
        // netns WILL need that flush ported alongside it.
        //
        // second_veth / vlan are None: the single-pc orchestrator drives the
        // single-pair, no-VLAN path. netns::setup implements both optional
        // branches (full setup-netns.sh port); S5 / USAGE_01 wire the Config
        // fields + a parity case that drive them.
        netns::setup(&NetnsParams {
            tester_ns: netns_tester(w),
            dut_ns: netns_dut(w),
            veth_t: veth_tester(w),
            veth_d: veth_dut(w),
            tester_ip: format!("{}/24", cfg.tester_ip4),
            dut_ip: format!("{}/24", cfg.dut_ip4),
            second_veth: None,
            vlan: None,
        })
        .with_context(|| format!("bringing up netns for worker {w}"))?;

        // Worker-unique argv[0] so a teardown pkill is scoped to this worker.
        symlink_force(&cfg.dut_bin, &dut_link(&cfg.vsomeip_base, w))?;
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

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        teardown_worker(&self.cfg.vsomeip_base, w);
        Ok(())
    }

    fn tester_iface(&self, w: u32) -> String {
        // Bare veth (not a VLAN subif) so libpcap sees any 802.1Q tag intact.
        veth_tester(w)
    }

    fn tester_iface_secondary(&self, _w: u32) -> Option<String> {
        // The single-pc netns bring-up does not yet provision the Topology-2 second
        // veth pair (netns::setup is called with second_veth: None), so no secondary
        // iface is available and USAGE_01 SKIPs here. Wiring the second pair (and
        // running USAGE_01) is deferred; this is a noted gap, not a silent
        // wrong-pass — bash single-pc runs USAGE_01 via NEED_SECOND_VETH.
        None
    }

    fn condition_case(&self, w: u32, case_id: &str, ctx: &WorkerCtx) -> Result<Conditioning<'_>> {
        let steps = conditioning::plan(case_id, &self.cfg.tester_ip4, &ctx.tester_mac);
        // Build the guard incrementally and record a step's restore only AFTER its
        // apply succeeds, so a mid-sequence failure (the `?`) drops `cond` and
        // reverts exactly the steps already applied. bash gets this for free from
        // `set -e` + the EXIT-trap netns destroy.
        let mut cond = Conditioning::empty(self, w);
        for step in steps {
            self.exec_cond_step(w, &step, CondDir::Apply)
                .with_context(|| format!("conditioning {case_id} (worker {w})"))?;
            if step.has_restore() {
                cond.record_restore(step);
            }
        }
        Ok(cond)
    }

    fn exec_cond_step(&self, w: u32, step: &CondStep, dir: CondDir) -> Result<()> {
        // single-pc renders every step to `ip netns exec` / `ip -n` in the
        // worker's namespaces. `None` = a no-op direction (a flush or a no-undo
        // pin has no restore).
        match render_cond_step(w, step, dir) {
            Some(argv) => {
                let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
                netns::ip(&refs)
            }
            None => Ok(()),
        }
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
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

    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>> {
        let cfg = self.cfg;
        let log = fs::File::create(dlog).context("creating dut log")?;
        let err = log.try_clone()?;
        let base = cfg.vsomeip_base.join(w.to_string());
        // Per-case wipe of stale vsomeip UDS sockets + lock (smoke-test.sh) so
        // a leftover from the prior case in this worker's bucket cannot make the
        // fresh DUT's vsomeip routing init bind stale. Scoped to vsomeip-*/.lck —
        // never the worker symlinks kill_by_marker matches.
        wipe_vsomeip_runtime(&base);
        let child = Command::new("ip")
            .args(["netns", "exec", &netns_dut(w), "env"])
            .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
            .arg(format!("VSOMEIP_CONFIGURATION={}", cfg_path.display()))
            .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
            .arg(format!("VSOMEIP_BASE_PATH={}/", base.display()))
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
        kill_by_marker(&harness_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
}

// --- Worker-scoped veth names (single-pc owns the netns veth pairs; the netns +
// symlink names it shares with teardown_worker stay in the parent module) ------
fn veth_tester(w: u32) -> String {
    format!("veth-tester-{w}")
}
fn veth_dut(w: u32) -> String {
    format!("veth-dut-{w}")
}

// --- single-pc conditioning rendering ---------------------------------------
// Bind the semantic `conditioning::plan` steps to the netns transport for one
// worker. This is single-pc's renderer; S5 topologies (external/ssh-remote)
// render the same steps to host-exec / ssh / a logged skip. Kept pure (no I/O)
// so the rendering is unit-tested directly, separate from the case→toggle policy.

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

// --- netns MAC read + neigh pin (single-pc bring-up) ------------------------

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
