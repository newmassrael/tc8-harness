//! `local-exec` DUT lifecycle — the reference tc8-dut exec'd directly into the
//! namespace the tester transport prepared. This is single-pc's historical DUT half,
//! and it stays the default: the cheapest DUT to stand up is one already on this
//! filesystem, and it is the only one that is OUR reference implementation and so can
//! be held to the deliberately wrong expectations the negative rows assert.
//!
//! It is now ONE lifecycle rather than the only one — a DUT that is a sibling
//! container, an already-running service, or a device that merely has to be TOLD to
//! start is a different lifecycle against the same transport.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use super::{DutLifecycle, DutPlacement};
use crate::config::Config;
use crate::topology::{
    dut_link, kill_by_marker, symlink_force, VSOMEIP_RT_LOCK, VSOMEIP_RT_SOCK_PREFIX,
};

/// The reference tc8-dut, exec'd per case into the transport's namespace.
pub(crate) struct LocalExec<'a> {
    cfg: &'a Config,
}

impl<'a> LocalExec<'a> {
    pub(crate) fn new(cfg: &'a Config) -> Self {
        LocalExec { cfg }
    }
}

impl DutLifecycle for LocalExec<'_> {
    fn name(&self) -> &'static str {
        "local-exec"
    }

    fn preflight(&self) -> Result<()> {
        let cfg = self.cfg;
        if !cfg.dut_bin.is_file() {
            anyhow::bail!("preflight: tc8-dut binary missing: {}", cfg.dut_bin.display());
        }
        if !cfg.vsomeip_cfg.is_file() {
            anyhow::bail!("preflight: vsomeip.json missing: {}", cfg.vsomeip_cfg.display());
        }
        Ok(())
    }

    fn bring_up_worker(&self, w: u32) -> Result<()> {
        // Worker-unique argv[0] so the per-case reap is scoped to this worker. Only
        // read at spawn time, so its position relative to the wire build is inert.
        symlink_force(&self.cfg.dut_bin, &dut_link(&self.cfg.vsomeip_base, w))
    }

    fn max_workers(&self) -> Option<u32> {
        // A DUT per worker costs one process in a namespace that already exists.
        None
    }

    fn spawns_per_case(&self) -> bool {
        true
    }

    fn supports_negative(&self) -> bool {
        // Our own reference implementation — the only DUT the curated negative rows
        // can be held against.
        true
    }

    fn start_dut(
        &self,
        w: u32,
        placement: &DutPlacement,
        dlog: &Path,
        cfg_path: &Path,
        extra_env: &[String],
    ) -> Result<Option<Child>> {
        let cfg = self.cfg;
        let ns = placement.require_netns(self.name())?;
        let log = fs::File::create(dlog).context("creating dut log")?;
        let err = log.try_clone()?;
        let base = cfg.vsomeip_base.join(w.to_string());
        // Per-case wipe of stale vsomeip UDS sockets + lock (smoke-test.sh) so
        // a leftover from the prior case in this worker's bucket cannot make the
        // fresh DUT's vsomeip routing init bind stale. Scoped to vsomeip-*/.lck —
        // never the worker symlinks kill_by_marker matches.
        wipe_vsomeip_runtime(&base);
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", ns, "env"])
            .arg(format!("COMMONAPI_CONFIG={}", cfg.capi_cfg.display()))
            .arg(format!("VSOMEIP_CONFIGURATION={}", cfg_path.display()))
            .arg("VSOMEIP_APPLICATION_NAME=tc8-dut")
            .arg(format!("VSOMEIP_BASE_PATH={}/", base.display()));
        // Per-case DUT flavor env (CASE_VSOMEIP_VARIANT): TC8_DUT_* the DUT app reads
        // to offer a 2nd instance/service or run as a client. Empty for the common
        // case; goes in the `env KEY=VAL ...` list before the binary.
        for kv in extra_env {
            cmd.arg(kv);
        }
        let child = cmd
            .arg(dut_link(&cfg.vsomeip_base, w))
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .context("spawning tc8-dut via ip netns exec")?;
        Ok(Some(child))
    }

    fn stop_dut(&self, w: u32) -> Result<()> {
        // argv[0] is this worker's unique symlink path, so `-f` hits exactly this
        // run's DUT (reap-selector matrix, `topology` mod docs).
        kill_by_marker(&dut_link(&self.cfg.vsomeip_base, w));
        Ok(())
    }
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
