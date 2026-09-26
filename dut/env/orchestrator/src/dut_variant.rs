//! Per-case DUT vsomeip flavor — the orchestrator's consumer of the harness's
//! `--list-vsomeip-variants` (the SSOT: `inventory_overrides.json`'s seventh axis).
//! A handful of SOME/IP cases need the reference tc8-dut launched with an alternate
//! vsomeip config (a 2nd instance/service) and/or `TC8_DUT_*` env the DUT app reads
//! to offer that instance/service or run as a client. The harness never launches
//! the DUT, so it only PARSES and EXPOSES the flavor; this module reads that ONE
//! source so bash `smoke-test.sh` and the orchestrator can never drift.

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

use crate::case_token;
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
    let out = cfg
        .harness_test()
        .arg("--list-vsomeip-variants")
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

/// Look up the DUT flavor of a SCHEDULED token (case-insensitive). `Ok(None)` for
/// the common non-variant case, or if `init` was never called (no flavor is then
/// applied). See `lookup` for the rule, and docs/tech-debt.md TD-17 for why a
/// refusal is an error rather than "no flavor".
pub fn resolve(token: &str) -> Result<Option<&'static DutVariant>> {
    match CACHE.get() {
        Some(table) => lookup(table, token),
        None => Ok(None),
    }
}

/// The table is keyed the way `--list-vsomeip-variants` prints it: bare for the
/// in-tree suite, `suite:ID` for any other, each row resolved by the harness from
/// that suite's OWN catalog (spec_inventory.h, "ONE CATALOG PER SUITE"). A token
/// resolves on the same pair:
///
/// - bare, or qualified with the default suite: the in-tree row. A bare token IS an
///   in-tree case — the listing prints every other suite's qualified — so stripping
///   the default qualifier is resolution, not a workaround.
/// - another suite, and that suite's own catalog declares a flavor: that row. A
///   row with empty cfg and env is a declared BASE DUT (the harness prints a row
///   per declaration, not per non-empty value), and resolves to no alternate
///   config and no extra env — the same DUT a non-variant case gets, but chosen.
/// - another suite with no row of its own, but the bare id holds an in-tree flavor:
///   REFUSED. The case may be a copy of the in-tree test that needs the second
///   service, shared port or second instance, or a different test that needs none;
///   nothing here can tell which, and guessing either way runs it against a DUT
///   that may not be the one it asserts about. A flavor must never travel to
///   another catalog by id coincidence, and silence must never stand in for one.
/// - another suite, nothing either way: legitimately no flavor.
fn lookup<'t>(table: &'t HashMap<String, DutVariant>, token: &str) -> Result<Option<&'t DutVariant>> {
    let upper = token.to_ascii_uppercase();
    let (suite, id) = case_token::split(&upper);
    match suite {
        None => Ok(table.get(id)),
        Some(s) if case_token::is_default_suite(s) => Ok(table.get(id)),
        Some(s) => {
            if let Some(own) = table.get(&upper) {
                return Ok(Some(own));
            }
            if table.contains_key(id) {
                bail!(
                    "{token}: the in-tree case {id} needs a DUT vsomeip flavor and suite \
                     '{s}' declares none of its own, so the DUT this case needs cannot be \
                     known; declare which DUT it needs under the overrides key \
                     \"{token}\" rather than inherit the in-tree one by id coincidence: \
                     the in-tree case's vsomeip_cfg / vsomeip_env to want that flavor, or \
                     both empty (\"vsomeip_cfg\": \"\", \"vsomeip_env\": []) for the base DUT. \
                     The entry applies only to a case the inventory holds, so pass suite \
                     '{s}''s own catalog with --inventory-extra as well"
                );
            }
            Ok(None)
        }
    }
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

    // TD-17: the table as a two-suite build prints it. SOMEIPSRV_RPC_14 carries an
    // in-tree flavor; demo declares its own for SOMEIPSRV_RPC_17 only.
    fn two_suite_table() -> HashMap<String, DutVariant> {
        parse(
            "SOMEIPSRV_RPC_14|vsomeip-multi-instance.json|TC8_DUT_INSTANCE_2=1\n\
             SOMEIPSRV_RPC_17|vsomeip-multi-instance.json|\n\
             demo:SOMEIPSRV_RPC_17||TC8_DUT_DEMO=1\n",
        )
        .unwrap()
    }

    #[test]
    fn default_suite_qualifier_resolves_the_in_tree_row() {
        let t = two_suite_table();
        let bare = lookup(&t, "SOMEIPSRV_RPC_14").unwrap().expect("bare hits");
        let qualified = lookup(&t, "tc8:someipsrv_rpc_14").unwrap().expect("tc8: strips");
        assert_eq!(bare, qualified);
        assert_eq!(bare.env, ["TC8_DUT_INSTANCE_2=1"]);
    }

    #[test]
    fn another_suite_refuses_rather_than_inherit_the_in_tree_flavor() {
        let t = two_suite_table();
        let err = lookup(&t, "demo:SOMEIPSRV_RPC_14").expect_err("must refuse, not fall back");
        let msg = format!("{err:#}");
        assert!(msg.contains("demo:SOMEIPSRV_RPC_14"), "{msg}");
        assert!(msg.contains("declares none of its own"), "{msg}");
        // The remedy needs both halves; naming only the overrides key sent a
        // consumer to a declaration nothing could see (TD-58).
        assert!(msg.contains("--inventory-extra"), "{msg}");
    }

    #[test]
    fn another_suite_uses_its_own_row_never_the_in_tree_one() {
        let t = two_suite_table();
        let own = lookup(&t, "Demo:someipsrv_rpc_17").unwrap().expect("own row");
        assert_eq!(own.cfg_basename, None);
        assert_eq!(own.env, ["TC8_DUT_DEMO=1"]);
    }

    // TD-39: the same-id case that WANTS the base DUT declares it with an empty row
    // and runs, where without the declaration it is refused.
    #[test]
    fn another_suite_declaring_the_base_dut_is_not_refused() {
        let mut t = two_suite_table();
        assert!(lookup(&t, "demo:SOMEIPSRV_RPC_14").is_err(), "undeclared: refused");
        t.extend(parse("demo:SOMEIPSRV_RPC_14||\n").unwrap());
        let base = lookup(&t, "demo:SOMEIPSRV_RPC_14").unwrap().expect("declared row");
        assert_eq!(base.cfg_basename, None);
        assert!(base.env.is_empty());
    }

    #[test]
    fn another_suite_with_no_flavor_either_way_gets_none() {
        let t = two_suite_table();
        assert_eq!(lookup(&t, "demo:ARP_03").unwrap(), None);
        assert_eq!(lookup(&t, "ARP_03").unwrap(), None);
    }
}
