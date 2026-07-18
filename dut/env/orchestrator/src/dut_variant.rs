//! Per-case DUT vsomeip flavor — the orchestrator's consumer of the harness's
//! `--list-vsomeip-variants` (the SSOT: `inventory_overrides.json`'s seventh axis).
//! A handful of SOME/IP cases need the reference tc8-dut launched with an alternate
//! vsomeip config (a 2nd instance/service) and/or `TC8_DUT_*` env the DUT app reads
//! to offer that instance/service or run as a client. The harness never launches
//! the DUT, so it only PARSES and EXPOSES the flavor; this module reads that ONE
//! source so bash `smoke-test.sh` and the orchestrator can never drift.

use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

use crate::config::Config;

/// A case's DUT flavor: an alternate vsomeip config basename (a sibling of the base
/// cfg) or `None` to keep the base; plus the extra `KEY=VALUE` env the DUT app reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DutVariant {
    pub cfg_basename: Option<String>,
    pub env: Vec<String>,
}

static CACHE: OnceLock<HashMap<String, DutVariant>> = OnceLock::new();

/// Load the flavor table ONCE from the harness's `--list-vsomeip-variants`. Call
/// before running cases (main.rs) — NEVER on the `--print-expect` path, which must
/// stay harness-free (build-test's identity job does not build the harness).
/// Idempotent: a second call is a no-op.
pub fn init(cfg: &Config) -> Result<()> {
    let out = Command::new(&cfg.harness)
        .args(["test", "--list-vsomeip-variants"])
        .output()
        .with_context(|| {
            format!("running {} test --list-vsomeip-variants", cfg.harness.display())
        })?;
    if !out.status.success() {
        bail!(
            "{} test --list-vsomeip-variants exited {}: {}",
            cfg.harness.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text =
        String::from_utf8(out.stdout).context("--list-vsomeip-variants output not UTF-8")?;
    let _ = CACHE.set(parse(&text)?);
    Ok(())
}

/// Look up a case's DUT flavor (case-insensitive). `None` for the common
/// non-variant case, or if `init` was never called (no flavor is then applied).
pub fn resolve(case_id: &str) -> Option<&'static DutVariant> {
    CACHE.get()?.get(&case_id.to_ascii_uppercase())
}

/// Parse `CASE|cfg|env1,env2` lines (the harness `--list-vsomeip-variants` grammar).
/// An empty cfg field = keep the base config; an empty env field = no extra env.
fn parse(text: &str) -> Result<HashMap<String, DutVariant>> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() != 3 {
            bail!("--list-vsomeip-variants produced a malformed row: {line:?}");
        }
        let cfg_basename = if parts[1].is_empty() {
            None
        } else {
            Some(parts[1].to_string())
        };
        let env: Vec<String> = if parts[2].is_empty() {
            Vec::new()
        } else {
            parts[2].split(',').map(str::to_string).collect()
        };
        map.insert(parts[0].to_ascii_uppercase(), DutVariant { cfg_basename, env });
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_and_client_flavors() {
        let m = parse(
            "SOMEIPSRV_RPC_14|vsomeip-multi-instance.json|TC8_DUT_INSTANCE_2=1\n\
             SOMEIP_ETS_082||TC8_DUT_CLIENT_MODE=1,TC8_DUT_CLIENT_MODE_UDP=1\n",
        )
        .unwrap();
        let mi = &m["SOMEIPSRV_RPC_14"];
        assert_eq!(mi.cfg_basename.as_deref(), Some("vsomeip-multi-instance.json"));
        assert_eq!(mi.env, ["TC8_DUT_INSTANCE_2=1"]);
        let udp = &m["SOMEIP_ETS_082"];
        assert_eq!(udp.cfg_basename, None);
        assert_eq!(udp.env, ["TC8_DUT_CLIENT_MODE=1", "TC8_DUT_CLIENT_MODE_UDP=1"]);
    }

    #[test]
    fn rejects_malformed_row() {
        assert!(parse("SOMEIPSRV_RPC_14|vsomeip-multi-instance.json").is_err());
    }

    #[test]
    fn empty_input_is_empty_map() {
        assert!(parse("\n  \n").unwrap().is_empty());
    }
}
