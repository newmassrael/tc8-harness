//! Static configuration — the bash globals from smoke-test.sh (paths, wire
//! IPs, scratch roots), env-overridable on the same keys. Resolved once at
//! startup. Mirrors smoke-test.sh lines 52-97 + init_expectation_defaults
//! (TESTER_IP4 / DUT_IP4).

use anyhow::{Context, Result};
use std::env;
use std::path::{Path, PathBuf};

/// DUT SOME/IP wire identity — derived from the DUT's own `vsomeip.json` (the
/// runtime config it boots from), so the orchestrator never re-hardcodes what
/// already has a single source of truth. Each field names its vsomeip.json
/// origin. The few values NOT present in vsomeip.json (SOME/IP-SD major/minor
/// version, the default subscribe eventgroup) and the harness-emitted constants
/// (tester MACs, ICMP echo id/seq) are single-homed in `wire` (generated from
/// tools/wire.def, cross-checked against the C++ stimulus headers) and consumed
/// in `dispatch::expect_args`. Values are kept as strings: they pass straight
/// through to the harness `--expect key=value` CLI, and vsomeip.json already
/// stores them in the exact `0x...`/decimal/dotted forms the harness expects.
pub struct DutIdentity {
    /// vsomeip `services[0].service`.
    pub service_id: String,
    /// vsomeip `services[0].instance`.
    pub instance_id: String,
    /// vsomeip `services[0].unreliable`.
    pub udp_port: String,
    /// vsomeip `services[0].reliable.port`.
    pub tcp_port: String,
    /// vsomeip `service-discovery.multicast`.
    pub sd_multicast_ip: String,
    /// vsomeip `service-discovery.ttl`.
    pub ttl: String,
    /// vsomeip `services[0].eventgroups[*].multicast.address`.
    pub mcast_ipv4: String,
    /// vsomeip `services[0].eventgroups[*].multicast.port`.
    pub mcast_port: String,
}

/// Resolved paths and wire constants for one orchestrator run.
pub struct Config {
    /// Repo root (TC8_ROOT or the cwd). Sudo preserves the cwd but strips the
    /// environment, so this is also how `${ROOT}` in a `--topology-conf` is
    /// expanded — from a value the orchestrator resolves itself, not an env var
    /// that would be empty under the NOPASSWD rules.
    pub root: PathBuf,
    pub harness: PathBuf,
    pub dut_bin: PathBuf,
    pub vsomeip_cfg: PathBuf,
    pub capi_cfg: PathBuf,
    /// /tmp/tc8-orch-workers.PID — per-worker sentinel/log scratch.
    pub work_root: PathBuf,
    /// /tmp/tc8-orch-vsomeip.PID — per-worker symlink + vsomeip socket base.
    pub vsomeip_base: PathBuf,
    pub tester_ip4: String,
    pub dut_ip4: String,
    /// DUT SOME/IP identity derived from vsomeip.json.
    pub identity: DutIdentity,
    /// Harness watchdog backstop (seconds). Single-homed in `wire::BACKSTOP_SEC`
    /// (generated from tools/wire.def), the same source bash's
    /// `HARNESS_BACKSTOP_SEC` reads via $TC8_WIRE_BACKSTOP_SEC.
    pub backstop_sec: u32,
}

fn env_path(key: &str, default: PathBuf) -> PathBuf {
    env::var(key).map(PathBuf::from).unwrap_or_else(|_| default)
}

/// Extract a string field, erroring with the JSON path on absence/type mismatch
/// (fail loud: a malformed vsomeip.json must not silently fall back to stale
/// defaults — that is exactly the drift this derivation removes).
fn jstr(v: &serde_json::Value, key: &str, path: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .with_context(|| format!("vsomeip.json: missing/non-string '{path}.{key}'"))
}

/// Derive the DUT wire identity from vsomeip.json.
fn parse_dut_identity(vsomeip_cfg: &Path) -> Result<DutIdentity> {
    let text = std::fs::read_to_string(vsomeip_cfg)
        .with_context(|| format!("reading vsomeip.json at {}", vsomeip_cfg.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing vsomeip.json at {}", vsomeip_cfg.display()))?;

    let svc = v
        .get("services")
        .and_then(|s| s.get(0))
        .context("vsomeip.json: services[0] missing")?;
    let sd = v
        .get("service-discovery")
        .context("vsomeip.json: service-discovery block missing")?;
    let reliable = svc
        .get("reliable")
        .context("vsomeip.json: services[0].reliable missing")?;

    // The threshold/multicast eventgroup (0x0008 for tc8-dut) carries the
    // notification multicast endpoint; pick whichever eventgroup declares one.
    let mcast = svc
        .get("eventgroups")
        .and_then(|e| e.as_array())
        .and_then(|egs| egs.iter().find_map(|eg| eg.get("multicast")))
        .context("vsomeip.json: no eventgroup with a multicast endpoint")?;

    Ok(DutIdentity {
        service_id: jstr(svc, "service", "services[0]")?,
        instance_id: jstr(svc, "instance", "services[0]")?,
        udp_port: jstr(svc, "unreliable", "services[0]")?,
        tcp_port: jstr(reliable, "port", "services[0].reliable")?,
        sd_multicast_ip: jstr(sd, "multicast", "service-discovery")?,
        ttl: jstr(sd, "ttl", "service-discovery")?,
        mcast_ipv4: jstr(mcast, "address", "services[0].eventgroups[*].multicast")?,
        mcast_port: jstr(mcast, "port", "services[0].eventgroups[*].multicast")?,
    })
}

impl Config {
    pub fn resolve() -> Result<Config> {
        // smoke-test.sh derives ROOT from its own location (readlink -f $0 →
        // dut/env → ../..). The orchestrator uses TC8_ROOT when set, else the
        // current directory (parity runs are launched from the repo root).
        let root = match env::var("TC8_ROOT") {
            Ok(r) => PathBuf::from(r),
            Err(_) => env::current_dir()
                .context("resolving repo root (set TC8_ROOT or run from the repo root)")?,
        };
        let vsomeip_cfg = env_path("VSOMEIP_CFG", root.join("dut/dut_service/vsomeip.json"));
        let identity = parse_dut_identity(&vsomeip_cfg)?;
        // PID-scoped scratch: a concurrent run gets a distinct /tmp prefix, so
        // worker symlinks / vsomeip UDS sockets never collide and the startup
        // stale-GC can key teardown on the owner PID. NOTE: the netns names
        // (tc8-tester-W / tc8-dut-W) are NOT PID-scoped — they are shared with
        // bash and reclaimed by `netns::setup`'s idempotent re-create (teardown-
        // first), the same contract bash's setup-netns.sh relies on. The
        // orchestrator and bash must therefore not drive the same netns
        // concurrently; the sequential parity protocol guarantees that (only the
        // /tmp scratch is concurrency-isolated).
        let pid = std::process::id();
        Ok(Config {
            harness: env_path("HARNESS", root.join("build/tc8-harness")),
            dut_bin: env_path("TC8_DUT_BIN", root.join("build/dut/dut_service/tc8-dut")),
            vsomeip_cfg,
            capi_cfg: env_path("CAPI_CFG", root.join("dut/dut_service/commonapi.ini")),
            work_root: PathBuf::from(format!("/tmp/tc8-orch-workers.{pid}")),
            vsomeip_base: PathBuf::from(format!("/tmp/tc8-orch-vsomeip.{pid}")),
            tester_ip4: env::var("TC8_TOPOLOGY_TESTER_IP")
                .unwrap_or_else(|_| crate::wire::TESTER_IP.into()),
            dut_ip4: env::var("TC8_TOPOLOGY_DUT_IP")
                .unwrap_or_else(|_| crate::wire::DUT_IP.into()),
            identity,
            backstop_sec: crate::wire::BACKSTOP_SEC,
            root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the two independent SOME/IP-identity parsers together: bash derives the
    /// identity via tools/dut_identity.py, the orchestrator via parse_dut_identity.
    /// Both read the same vsomeip.json so the VALUE cannot drift, but the field-
    /// mapping logic lives in two languages — this asserts they extract the same
    /// keys/values on the committed config, catching a structural (mapping) drift
    /// that runtime value-equality alone would not. Two independent drivers are
    /// deliberate (the strangler's "a passing case is real evidence, not a
    /// tautology"), so the fix for the duplication is this pin, NOT collapsing bash
    /// onto the Rust binary (which would break that independence).
    #[test]
    fn dut_identity_py_matches_rust_parser() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let vsomeip = root.join("dut/dut_service/vsomeip.json");
        let rust = parse_dut_identity(&vsomeip).expect("rust parse_dut_identity");
        let out = std::process::Command::new("python3")
            .arg(root.join("tools/dut_identity.py"))
            .arg(&vsomeip)
            .output()
            .expect("run dut_identity.py (python3 required)");
        assert!(
            out.status.success(),
            "dut_identity.py failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let py: std::collections::HashMap<String, String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect();
        let pairs = [
            ("service_id", &rust.service_id),
            ("instance_id", &rust.instance_id),
            ("udp_port", &rust.udp_port),
            ("tcp_port", &rust.tcp_port),
            ("sd_multicast_ip", &rust.sd_multicast_ip),
            ("ttl", &rust.ttl),
            ("mcast_ipv4", &rust.mcast_ipv4),
            ("mcast_port", &rust.mcast_port),
        ];
        for (key, rust_val) in pairs {
            assert_eq!(py.get(key), Some(rust_val), "parser drift on '{key}'");
        }
        // Neither parser invented or dropped a key.
        assert_eq!(py.len(), pairs.len(), "dut_identity.py emitted unexpected keys: {py:?}");
    }
}
