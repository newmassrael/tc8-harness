//! Verification fixtures — orchestrator-owned host scaffolding that stands up a
//! DUT for the external / ssh-remote topologies, the typed Rust successors to the
//! bash `topology.d/examples/*.conf` fixtures.
//!
//! The bash example confs were imperative shell sourced by smoke-test.sh: they
//! provisioned host state (a netns DUT, or a netns + dedicated sshd) AND overrode
//! the per-case teardown hook. The orchestrator splits that — the declarative
//! site data lives in the `--topology-conf` TOML, and a `[fixture]` selector names
//! one of these provisioners, which the orchestrator stands up before the run and
//! tears down on every exit path (RAII Drop for normal/panic, the composed signal
//! handler for SIGINT/SIGTERM).
//!
//! The fixtures intentionally reuse the bash fixtures' fixed names (`tc8-extfix-*`,
//! `/tmp/tc8-sshfix`, port 2222) — they are not PID-scoped like the orchestrator's
//! own scratch, because parity runs the bash and Rust halves SEQUENTIALLY against
//! the same host state, and each provision teardown-firsts (idempotent reclaim,
//! the same contract `netns::setup` relies on). Reaping the DUT itself is the
//! TOPOLOGY's job (its `tear_down_worker` runs before this fixture teardown); the
//! ssh-remote fixture deliberately does not pkill the DUT by comm (it shares the
//! host PID namespace, so a `pkill -x tc8-dut` would be unscoped).

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use crate::config::Config;
use crate::netns;
use crate::site::FixtureSpec;

pub(crate) mod lwip_tap;
pub(crate) use lwip_tap::LwipTap;

// external (netns-dut) fixed names — mirror external-netns-fixture.conf.
const EXTFIX_NS: &str = "tc8-extfix-dut";
const EXTFIX_DIR: &str = "/tmp/tc8-extfix";
const EXTFIX_VETH_T: &str = "veth-extfix-t";
const EXTFIX_VETH_D: &str = "veth-extfix-d";

// ssh-remote (ssh-netns-dut) fixed names — mirror ssh-remote-netns-fixture.conf.
const SSHFIX_NS: &str = "tc8-sshfix-dut";
const SSHFIX_DIR: &str = "/tmp/tc8-sshfix";
const SSHFIX_VETH_T: &str = "veth-sshfix-t";
const SSHFIX_VETH_D: &str = "veth-sshfix-d";
const SSHFIX_PORT: &str = "2222";

// Shared wire layout — tester 172.16.0.1, DUT 172.16.0.2 on a /24, the SD mcast
// route both sides need. The verification TOML names these same values.
const FIX_TESTER_CIDR: &str = "172.16.0.1/24";
const FIX_DUT_CIDR: &str = "172.16.0.2/24";
const MCAST_ROUTE: &str = "224.0.0.0/4";
/// DUT boot settle before preflight probes it (external-netns-fixture.conf `sleep
/// 1.5`); the topology preflight ut-ping is the actual readiness gate.
const DUT_SETTLE: Duration = Duration::from_millis(1500);
/// sshd listen settle (ssh-remote-netns-fixture.conf `sleep 0.5`).
const SSHD_SETTLE: Duration = Duration::from_millis(500);

/// Which fixture a guard owns, so Drop and the signal path tear down the right one.
#[derive(Clone, Copy)]
enum FixtureKind {
    NetnsDut,
    SshNetnsDut,
}

/// RAII handle for a provisioned verification fixture. Drop tears the fixture down
/// (idempotent), so a normal return or a panic unwind cannot leak the netns / veth
/// / sshd / DUT. SIGINT/SIGTERM bypass Drop, so `main` also composes
/// [`teardown_by_kind`] into the signal handler.
pub struct FixtureGuard {
    kind: FixtureKind,
    /// netns-dut: the `ip netns exec` wrapper PID to reap (the real DUT is reaped
    /// by the path-scoped pkill in teardown, the wrapper by this `wait`).
    dut: Option<Child>,
    torn: bool,
}

impl FixtureGuard {
    fn teardown(&mut self) {
        if self.torn {
            return;
        }
        self.torn = true;
        match self.kind {
            FixtureKind::NetnsDut => {
                teardown_netns_dut();
                if let Some(mut c) = self.dut.take() {
                    let _ = c.wait();
                }
            }
            FixtureKind::SshNetnsDut => teardown_ssh_netns_dut(),
        }
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Provision the fixture named by `spec` (validated compatible with the topology
/// in [`crate::site::SiteConf::validate`]). Returns a guard whose Drop tears it down.
pub fn provision(spec: &FixtureSpec, cfg: &Config) -> Result<FixtureGuard> {
    // provision_* builds incrementally with `?` and the guard is only constructed on
    // success, so a mid-sequence failure would leave partial host state (netns/veth/
    // keys) with no guard to Drop. Reclaim it eagerly on error — the next run's
    // teardown-first would also reclaim it, but only for a matching topology, so do
    // not rely on that.
    match spec.kind.as_str() {
        "netns-dut" => {
            let dut = provision_netns_dut(cfg).inspect_err(|_| teardown_netns_dut())?;
            println!(
                "orchestrator: provisioned 'netns-dut' fixture (reference DUT in netns {EXTFIX_NS}, tester veth {EXTFIX_VETH_T})"
            );
            Ok(FixtureGuard { kind: FixtureKind::NetnsDut, dut: Some(dut), torn: false })
        }
        "ssh-netns-dut" => {
            provision_ssh_netns_dut().inspect_err(|_| teardown_ssh_netns_dut())?;
            println!(
                "orchestrator: provisioned 'ssh-netns-dut' fixture (sshd in netns {SSHFIX_NS} on port {SSHFIX_PORT})"
            );
            Ok(FixtureGuard { kind: FixtureKind::SshNetnsDut, dut: None, torn: false })
        }
        other => bail!("unknown fixture kind '{other}' (SiteConf::validate should have rejected it)"),
    }
}

/// Idempotent teardown by kind name — for the signal handler, which has no guard
/// to Drop. A no-op for an absent fixture.
pub fn teardown_by_kind(kind: &str) {
    match kind {
        "netns-dut" => teardown_netns_dut(),
        "ssh-netns-dut" => teardown_ssh_netns_dut(),
        "lwip-tap" => lwip_tap::signal_teardown(),
        _ => {}
    }
}

// --- external: reference tc8-dut in a netns, tester veth in the root ns --------

fn provision_netns_dut(cfg: &Config) -> Result<Child> {
    teardown_netns_dut(); // reclaim any leftover from a prior run (idempotent)
    fs::create_dir_all(EXTFIX_DIR).with_context(|| format!("mkdir {EXTFIX_DIR}"))?;

    netns::ip(&["netns", "add", EXTFIX_NS])?;
    netns::ip(&["link", "add", EXTFIX_VETH_T, "type", "veth", "peer", "name", EXTFIX_VETH_D])?;
    netns::ip(&["link", "set", EXTFIX_VETH_D, "netns", EXTFIX_NS])?;
    netns::ip(&["addr", "add", FIX_TESTER_CIDR, "dev", EXTFIX_VETH_T])?;
    netns::ip(&["link", "set", EXTFIX_VETH_T, "up"])?;
    netns::ip(&["-n", EXTFIX_NS, "addr", "add", FIX_DUT_CIDR, "dev", EXTFIX_VETH_D])?;
    netns::ip(&["-n", EXTFIX_NS, "link", "set", EXTFIX_VETH_D, "up"])?;
    netns::ip(&["-n", EXTFIX_NS, "link", "set", "lo", "up"])?;

    // Worker-unique-ish argv[0] so the teardown pkill is path-scoped (never a
    // host-wide `pkill -x tc8-dut`).
    let link = Path::new(EXTFIX_DIR).join("tc8-dut");
    let _ = fs::remove_file(&link);
    symlink(&cfg.dut_bin, &link)
        .with_context(|| format!("symlink {} -> {}", link.display(), cfg.dut_bin.display()))?;

    let dlog = Path::new(EXTFIX_DIR).join("dut.log");
    let log = fs::File::create(&dlog).with_context(|| format!("creating {}", dlog.display()))?;
    let err = log.try_clone()?;
    let child = Command::new("ip")
        .args(["netns", "exec", EXTFIX_NS, "env"])
        .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
        .arg(format!("VSOMEIP_CONFIGURATION={}", cfg.vsomeip_cfg.display()))
        .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
        .arg(format!("VSOMEIP_BASE_PATH={EXTFIX_DIR}/"))
        .arg(&link)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .context("spawning the netns-dut fixture DUT")?;
    sleep(DUT_SETTLE);
    Ok(child)
}

fn teardown_netns_dut() {
    pkill_path(&format!("{EXTFIX_DIR}/tc8-dut"));
    ip_quiet(&["netns", "del", EXTFIX_NS]);
    ip_quiet(&["link", "del", EXTFIX_VETH_T]);
    let _ = fs::remove_dir_all(EXTFIX_DIR);
}

// --- ssh-remote: dedicated sshd in a netns (fixture-local keys) -----------------

fn provision_ssh_netns_dut() -> Result<()> {
    teardown_ssh_netns_dut(); // reclaim any leftover (idempotent)
    fs::create_dir_all(SSHFIX_DIR).with_context(|| format!("mkdir {SSHFIX_DIR}"))?;

    let hostkey = format!("{SSHFIX_DIR}/hostkey");
    let client = format!("{SSHFIX_DIR}/client");
    keygen(&hostkey)?;
    keygen(&client)?;

    netns::ip(&["netns", "add", SSHFIX_NS])?;
    netns::ip(&["link", "add", SSHFIX_VETH_T, "type", "veth", "peer", "name", SSHFIX_VETH_D])?;
    netns::ip(&["link", "set", SSHFIX_VETH_D, "netns", SSHFIX_NS])?;
    netns::ip(&["addr", "add", FIX_TESTER_CIDR, "dev", SSHFIX_VETH_T])?;
    netns::ip(&["link", "set", SSHFIX_VETH_T, "up"])?;
    netns::ip(&["-n", SSHFIX_NS, "addr", "add", FIX_DUT_CIDR, "dev", SSHFIX_VETH_D])?;
    netns::ip(&["-n", SSHFIX_NS, "link", "set", SSHFIX_VETH_D, "up"])?;
    netns::ip(&["-n", SSHFIX_NS, "link", "set", "lo", "up"])?;

    // SOME/IP-SD multicast route (mirrors setup-netns.sh): tester side may already
    // carry one in the root ns (best-effort), DUT side is mandatory.
    ip_quiet(&["route", "add", MCAST_ROUTE, "dev", SSHFIX_VETH_T]);
    netns::ip(&["-n", SSHFIX_NS, "route", "add", MCAST_ROUTE, "dev", SSHFIX_VETH_D])?;

    fs::create_dir_all("/run/sshd").context("mkdir /run/sshd (sshd privilege-separation dir)")?;
    let pidfile = format!("{SSHFIX_DIR}/sshd.pid");
    let authkeys = format!("{client}.pub");
    let status = Command::new("ip")
        .args(["netns", "exec", SSHFIX_NS, "/usr/sbin/sshd"])
        .args(["-o", &format!("Port={SSHFIX_PORT}")])
        .args(["-o", "ListenAddress=172.16.0.2"])
        .args(["-o", &format!("HostKey={hostkey}")])
        .args(["-o", &format!("AuthorizedKeysFile={authkeys}")])
        .args(["-o", "PermitRootLogin=prohibit-password"])
        .args(["-o", "StrictModes=no"])
        .args(["-o", &format!("PidFile={pidfile}")])
        .status()
        .context("spawning sshd in the fixture netns")?;
    if !status.success() {
        bail!("sshd failed to start in the ssh-netns-dut fixture (is openssh-server installed?)");
    }
    sleep(SSHD_SETTLE);
    Ok(())
}

fn teardown_ssh_netns_dut() {
    // The remote DUT is reaped by the topology (SshRemote::tear_down_worker /
    // stop_dut and the composed signal handler) BEFORE this runs, so the fixture
    // only reclaims its own state — sshd (by exact pidfile PID, never `pkill -x
    // sshd` which would hit the host's system sshd), routes, netns, veth, dirs.
    kill_pidfile(&format!("{SSHFIX_DIR}/sshd.pid"));
    ip_quiet(&["route", "del", MCAST_ROUTE, "dev", SSHFIX_VETH_T]);
    ip_quiet(&["netns", "del", SSHFIX_NS]);
    ip_quiet(&["link", "del", SSHFIX_VETH_T]);
    let _ = fs::remove_dir_all(SSHFIX_DIR);
    // The per-worker remote vsomeip scratch SshRemote spawns the DUT under.
    for ent in fs::read_dir("/tmp").into_iter().flatten().flatten() {
        if let Some(name) = ent.file_name().to_str() {
            if name.starts_with("tc8-remote-vsomeip-") {
                let _ = fs::remove_dir_all(ent.path());
            }
        }
    }
}

// --- shared command helpers -----------------------------------------------------

/// `ssh-keygen -q -t ed25519 -N '' -f <path>` (overwrites a prior file). The
/// fixture's own keys; the user's ~/.ssh is never touched.
fn keygen(path: &str) -> Result<()> {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{path}.pub"));
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f", path])
        .status()
        .with_context(|| format!("ssh-keygen -f {path}"))?;
    if !status.success() {
        bail!("ssh-keygen failed for {path}");
    }
    Ok(())
}

/// SIGKILL every process whose argv contains `pattern` — only ever a fixture-owned
/// symlink path, so the match is scoped (never a bare comm name).
fn pkill_path(pattern: &str) {
    let _ = Command::new("pkill")
        .args(["-KILL", "-f", pattern])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// SIGKILL the exact PID recorded in `pidfile` (sshd) — never by comm name, which
/// would also kill the host's system sshd. Best-effort: a missing file is a no-op.
fn kill_pidfile(pidfile: &str) {
    if let Ok(s) = fs::read_to_string(pidfile) {
        let pid = s.trim();
        if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
            let _ = Command::new("kill")
                .args(["-KILL", pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Fire-and-forget `ip ARGS`, ignoring the exit status (the bash `2>/dev/null ||
/// true` idiom) — for the best-effort teardown deletes.
fn ip_quiet(args: &[&str]) {
    let _ = Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
