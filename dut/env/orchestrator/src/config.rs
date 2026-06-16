//! Static configuration — the bash globals from smoke-test.sh (paths, wire
//! IPs, scratch roots), env-overridable on the same keys. Resolved once at
//! startup. Mirrors smoke-test.sh lines 52-97 + init_expectation_defaults
//! (TESTER_IP4 / DUT_IP4).

use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;

/// Resolved paths and wire constants for one orchestrator run.
pub struct Config {
    /// dut/env — where setup-netns.sh / cleanup.sh live.
    pub here: PathBuf,
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
    /// Harness watchdog backstop (seconds) — smoke-test.sh HARNESS_BACKSTOP_SEC.
    pub backstop_sec: u32,
}

fn env_path(key: &str, default: PathBuf) -> PathBuf {
    env::var(key).map(PathBuf::from).unwrap_or(default)
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
        // PID-scoped scratch so a concurrent smoke-test.sh run (different PID,
        // different /tmp prefix) cannot collide — distinct prefix from bash's
        // tc8-workers/tc8-vsomeip keeps the two fully isolated for parity runs.
        let pid = std::process::id();
        Ok(Config {
            here: root.join("dut/env"),
            harness: env_path("HARNESS", root.join("build/tc8-harness")),
            dut_bin: env_path("TC8_DUT_BIN", root.join("build/dut/dut_service/tc8-dut")),
            vsomeip_cfg: env_path("VSOMEIP_CFG", root.join("dut/dut_service/vsomeip.json")),
            capi_cfg: env_path("CAPI_CFG", root.join("dut/dut_service/commonapi.ini")),
            work_root: PathBuf::from(format!("/tmp/tc8-orch-workers.{pid}")),
            vsomeip_base: PathBuf::from(format!("/tmp/tc8-orch-vsomeip.{pid}")),
            tester_ip4: env::var("TC8_TOPOLOGY_TESTER_IP").unwrap_or_else(|_| "172.16.0.1".into()),
            dut_ip4: env::var("TC8_TOPOLOGY_DUT_IP").unwrap_or_else(|_| "172.16.0.2".into()),
            backstop_sec: 240,
        })
    }
}
