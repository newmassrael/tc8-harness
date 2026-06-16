//! Topology abstraction — the bash `source`+function-override profile contract
//! (single-pc.conf / external.conf / ssh-remote.conf) reimplemented as a Rust
//! trait. single-pc spawns per-worker netns pairs.
//!
//! Stage 1 shells out to the proven `setup-netns.sh` / `cleanup.sh`; the
//! ip/sysctl/neigh logic is ported to Rust in a later stage. stop_dut uses
//! `pkill -f` on the worker-unique symlink for smoke-test.sh parity; PGID-based
//! kill is a later hardening (the orchestrator's own cmdline never contains the
//! symlink path, so it is not self-matched).

use anyhow::{bail, Context, Result};
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::config::Config;

/// Per-worker identity captured at bring-up (kernel-assigned veth MACs).
pub struct WorkerCtx {
    pub dut_mac: String,
    #[allow(dead_code)] // wired into the link-local tester_neigh_pin in a later stage
    pub tester_mac: String,
}

/// The per-topology contract smoke-test.sh expresses as sourced bash functions.
pub trait Topology {
    fn preflight(&self) -> Result<()>;
    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx>;
    fn tear_down_worker(&self, w: u32) -> Result<()>;
    fn tester_iface(&self, w: u32) -> String;
    /// Spawn the harness backgrounded in the tester context; caller waits on it.
    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child>;
    /// Spawn a fresh DUT backgrounded; None for persistent (external) topologies.
    fn start_dut(&self, w: u32, dlog: &Path, cfg_path: &Path) -> Result<Option<Child>>;
    fn stop_dut(&self, w: u32) -> Result<()>;
}

/// single-pc: tester + reference tc8-dut in per-worker netns pairs on this host.
pub struct SinglePc<'a> {
    cfg: &'a Config,
}

impl<'a> SinglePc<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        SinglePc { cfg }
    }
    fn harness_link(&self, w: u32) -> PathBuf {
        self.cfg.vsomeip_base.join(format!("{w}/tc8-harness"))
    }
    fn dut_link(&self, w: u32) -> PathBuf {
        self.cfg.vsomeip_base.join(format!("{w}/tc8-dut"))
    }
}

impl Topology for SinglePc<'_> {
    fn preflight(&self) -> Result<()> {
        let cfg = self.cfg;
        if !cfg.dut_bin.is_file() {
            bail!("preflight: tc8-dut binary missing: {}", cfg.dut_bin.display());
        }
        if !cfg.vsomeip_cfg.is_file() {
            bail!("preflight: vsomeip.json missing: {}", cfg.vsomeip_cfg.display());
        }
        if which("ip").is_none() {
            bail!("preflight: 'ip' (iproute2) not found");
        }
        if !cfg.here.join("setup-netns.sh").is_file() {
            bail!("preflight: setup-netns.sh missing under {}", cfg.here.display());
        }
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<WorkerCtx> {
        let cfg = self.cfg;
        fs::create_dir_all(cfg.work_root.join(w.to_string()))?;
        fs::create_dir_all(cfg.vsomeip_base.join(w.to_string()))?;

        // Stage 1: reuse the proven bash netns setup (Rust port = later stage).
        let st = Command::new(cfg.here.join("setup-netns.sh"))
            .env("TESTER_NS", format!("tc8-tester-{w}"))
            .env("DUT_NS", format!("tc8-dut-{w}"))
            .env("VETH_T", format!("veth-tester-{w}"))
            .env("VETH_D", format!("veth-dut-{w}"))
            .env("TESTER_IP", format!("{}/24", cfg.tester_ip4))
            .env("DUT_IP", format!("{}/24", cfg.dut_ip4))
            .env("SECOND_VETH", "0")
            .stdout(Stdio::null())
            .status()
            .context("running setup-netns.sh")?;
        if !st.success() {
            bail!("setup-netns.sh failed for worker {w}");
        }

        // Worker-unique argv[0] so a teardown pkill is scoped to this worker.
        symlink_force(&cfg.dut_bin, &self.dut_link(w))?;
        symlink_force(&cfg.harness, &self.harness_link(w))?;

        let dut_mac = veth_mac(&format!("tc8-dut-{w}"), &format!("veth-dut-{w}"))?;
        let tester_mac = veth_mac(&format!("tc8-tester-{w}"), &format!("veth-tester-{w}"))?;

        // Neigh pins mirror single-pc.conf: pin <DUT_IP, dut_mac> on the tester
        // side (keeps the ARP cold-cache premise) and <172.16.0.3, tester_mac>
        // on the DUT side (Host-2 emulation for UDP_FIELDS_04/05).
        ip_neigh_replace(&format!("tc8-tester-{w}"), &cfg.dut_ip4, &dut_mac,
                         &format!("veth-tester-{w}"))?;
        ip_neigh_replace(&format!("tc8-dut-{w}"), "172.16.0.3", &tester_mac,
                         &format!("veth-dut-{w}"))?;

        Ok(WorkerCtx { dut_mac, tester_mac })
    }

    fn tear_down_worker(&self, w: u32) -> Result<()> {
        self.stop_dut(w).ok();
        let _ = Command::new(self.cfg.here.join("cleanup.sh"))
            .env("TESTER_NS", format!("tc8-tester-{w}"))
            .env("DUT_NS", format!("tc8-dut-{w}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        Ok(())
    }

    fn tester_iface(&self, w: u32) -> String {
        // Bare veth (not a VLAN subif) so libpcap sees any 802.1Q tag intact.
        format!("veth-tester-{w}")
    }

    fn run_harness(&self, w: u32, hlog: &Path, args: &[String]) -> Result<Child> {
        let log = fs::File::create(hlog).context("creating harness log")?;
        let err = log.try_clone()?;
        Command::new("ip")
            .args(["netns", "exec", &format!("tc8-tester-{w}")])
            .arg(self.harness_link(w))
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
        let child = Command::new("ip")
            .args(["netns", "exec", &format!("tc8-dut-{w}"), "env"])
            .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
            .arg(format!("VSOMEIP_CONFIGURATION={}", cfg_path.display()))
            .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
            .arg(format!("VSOMEIP_BASE_PATH={}/", base.display()))
            .arg(self.dut_link(w))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning tc8-dut via ip netns exec")?;
        Ok(Some(child))
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        let link = self.dut_link(w);
        let _ = Command::new("pkill")
            .args(["-KILL", "-f"])
            .arg(link.as_os_str())
            .status();
        Ok(())
    }
}

fn symlink_force(target: &Path, link: &Path) -> Result<()> {
    let _ = fs::remove_file(link);
    symlink(target, link)
        .with_context(|| format!("symlink {} -> {}", link.display(), target.display()))
}

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
        .args(["-n", ns, "neigh", "replace", ip, "lladdr", mac,
               "nud", "permanent", "dev", dev])
        .status()
        .with_context(|| format!("ip -n {ns} neigh replace {ip}"))?;
    if !st.success() {
        bail!("ip -n {ns} neigh replace {ip} failed");
    }
    Ok(())
}

fn which(prog: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(prog);
            if p.is_file() {
                Some(p)
            } else {
                None
            }
        })
    })
}
