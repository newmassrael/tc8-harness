//! Site topology configuration — the TOML successor to the bash `--topology-conf`
//! sourced fragment (TC8_TOPOLOGY_* assignments). sudo's env_reset strips those
//! env vars under the orchestrator's NOPASSWD rules, so — exactly as bash did —
//! a CLI-passed file is the reliable channel for external / ssh-remote site data;
//! the orchestrator just parses typed TOML instead of `source`-ing arbitrary shell.
//!
//! Bash conflated three things in one sourced file: declarative site vars,
//! imperative host provisioning (stand up a netns/sshd DUT for verification), and
//! hook overrides. This module carries ONLY the declarative half. The provisioning
//! the example confs did is a typed `[fixture]` selector here, stood up + torn
//! down by the `fixtures` module — so a production deployment names a real DUT
//! (no `[fixture]`), while the in-tree verification runs name a fixture the
//! orchestrator owns end to end. There is deliberately no legacy bash-conf
//! compatibility: the strangler keeps smoke-test.sh as the SSOT (and the channel
//! OEM bash confs target) until the S8 cutover, so nothing drives the orchestrator
//! with a bash fragment yet.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

/// A verification fixture to provision around the run — orchestrator-owned host
/// scaffolding, the Rust equivalent of the bash example confs. Absent when the
/// topology drives a real, already-running external/remote DUT. The lwIP DUT is NOT
/// a fixture: it is the first-class `lwip-tap` topology (see [`LwipSpec`]).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    /// `netns-dut` (external) | `ssh-netns-dut` (ssh-remote).
    pub kind: String,
}

/// The `[lwip]` sub-table — config for the first-class `lwip-tap` topology (the lwIP
/// embedded stack DUT on a host tap). Every field is optional: the topology runs
/// zero-conf on the defaults (like single-pc), and an override conf supplies only
/// the standalone-UTM variant's binary / probe / process name. Distinct from
/// [`FixtureSpec`], which provisions a *verification* DUT for external/ssh-remote.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LwipSpec {
    /// The lwIP DUT binary (default `${ROOT}/build-lwip-dut/tc8-lwip-dut`).
    pub app: Option<String>,
    /// Readiness-probe backend — `opcode` (UT OpPing, default) or `testability`
    /// (AUTOSAR GET_VERSION, for the standalone UTM which has no opcode UT).
    pub ready_probe: Option<String>,
    /// DUT process name for the teardown pkill (default `tc8-lwip-dut`; the UTM
    /// variant sets `tc8-lwip-utm`).
    pub kill_name: Option<String>,
}

/// Declarative site config for the external / ssh-remote topologies. Every field
/// is optional at the TOML layer; [`SiteConf::validate`] enforces the per-topology
/// required set, enumerating every gap at once (bash contract-validation parity,
/// smoke-test.sh:379-400 + the per-profile preflight checks).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConf {
    // --- common to external + ssh-remote ---
    /// Tester capture/injection NIC facing the DUT.
    pub iface: Option<String>,
    /// DUT IPv4 on the wire.
    pub dut_ip: Option<String>,
    /// Tester IPv4 on the wire.
    pub tester_ip: Option<String>,
    /// DUT MAC; neigh-resolved from the preflight ping when unset.
    pub dut_mac: Option<String>,
    /// Optional second NIC for TC8 Topology 2 (DHCPv4_CLIENT_USAGE_01); checked
    /// for existence in preflight, consumed when Topology-2 dispatch lands.
    pub iface_secondary: Option<String>,
    /// Cold-cache probe-source steering: the source IP the preflight ICMP/UT
    /// probes use, so the warmed DUT ARP entry lands on an address no cold-cache
    /// ARP case references (external.conf TC8_TOPOLOGY_PREFLIGHT_SRC_IP).
    pub preflight_src_ip: Option<String>,
    /// Promote a failed Upper Tester preflight probe from WARNING to a hard FAIL
    /// (external.conf TC8_TOPOLOGY_REQUIRE_UT).
    #[serde(default)]
    pub require_ut: bool,
    // NOTE: bash also exposes TC8_TOPOLOGY_DUT_ALIAS_IP / TC8_TOPOLOGY_TESTER_ALIAS_IP
    // (UDP_USER_INTERFACE_07/08 against a real external DUT). They are deliberately
    // NOT fields yet: dispatch hardcodes the netns-default aliases (wire::*), and the
    // per-case --expect OVERRIDE layer that would consume site-supplied aliases lands
    // with the S6 override stage. `deny_unknown_fields` makes an OEM conf carrying
    // those keys fail LOUD (a clear rejection), not silently ignored — so this is a
    // tracked deferral, not a silent gap.

    // --- ssh-remote only ---
    /// user@host for the DUT machine.
    pub ssh_target: Option<String>,
    /// Extra ssh options, word-split (e.g. "-p 2222 -i /path/key").
    pub ssh_opts: Option<String>,
    /// tc8-dut path on the remote host.
    pub remote_dut_bin: Option<String>,
    /// vsomeip.json path on the remote host (per-case flavors resolve as siblings).
    pub remote_vsomeip_cfg: Option<String>,
    /// commonapi.ini path on the remote host.
    pub remote_capi_cfg: Option<String>,
    /// Optional command prefix on the remote side (lab fixtures, taskset, ...).
    pub remote_wrap: Option<String>,

    // --- verification fixture ---
    /// Stand up + tear down an orchestrator-owned verification DUT around the run
    /// (external/ssh-remote only). The lwIP DUT is the `lwip-tap` topology, not a
    /// fixture — its config lives in `[lwip]` below.
    pub fixture: Option<FixtureSpec>,

    // --- lwip-tap topology ---
    /// Optional overrides for the first-class `lwip-tap` topology (binary / readiness
    /// probe / kill name). Absent = run on the defaults. Valid only under
    /// `--topology lwip-tap`.
    pub lwip: Option<LwipSpec>,
}

impl SiteConf {
    /// Load + parse + env-expand + validate a `--topology-conf` TOML for `topology`.
    /// `root` is the orchestrator's resolved repo root, used to expand `${ROOT}`.
    pub fn load(path: &Path, topology: &str, root: &Path) -> Result<SiteConf> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading --topology-conf {}", path.display()))?;
        let mut conf: SiteConf = toml::from_str(&text)
            .with_context(|| format!("parsing --topology-conf {} as TOML", path.display()))?;
        conf.expand_all(root)?;
        conf.validate(topology)?;
        Ok(conf)
    }

    /// Expand `${VAR}` references in every string field. `${ROOT}` resolves to the
    /// orchestrator's repo root (available even under sudo's stripped environment,
    /// unlike a real env var) so the committed example confs stay portable; any
    /// other `${VAR}` resolves from the process environment. Applied before
    /// validation, so a required field that expands to empty still fails the
    /// required-field check.
    fn expand_all(&mut self, root: &Path) -> Result<()> {
        let fields: [&mut Option<String>; 12] = [
            &mut self.iface,
            &mut self.dut_ip,
            &mut self.tester_ip,
            &mut self.dut_mac,
            &mut self.iface_secondary,
            &mut self.preflight_src_ip,
            &mut self.ssh_target,
            &mut self.ssh_opts,
            &mut self.remote_dut_bin,
            &mut self.remote_vsomeip_cfg,
            &mut self.remote_capi_cfg,
            &mut self.remote_wrap,
        ];
        for v in fields.into_iter().flatten() {
            *v = expand_env(v, root)?;
        }
        // The lwip-tap topology's own string fields (`app` carries `${ROOT}`).
        if let Some(lw) = &mut self.lwip {
            for v in [&mut lw.app, &mut lw.ready_probe, &mut lw.kill_name].into_iter().flatten() {
                *v = expand_env(v, root)?;
            }
        }
        Ok(())
    }

    /// Enforce the per-topology required field set + fixture/topology compatibility.
    /// single-pc ignores most of this (it derives its IPs from defaults/env and
    /// provisions its own netns) — a topology-conf there is an optional IP override.
    fn validate(&self, topology: &str) -> Result<()> {
        let present = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
        let mut missing: Vec<&str> = Vec::new();
        match topology {
            "external" => {
                if !present(&self.iface) {
                    missing.push("iface");
                }
                if !present(&self.dut_ip) {
                    missing.push("dut_ip");
                }
                if !present(&self.tester_ip) {
                    missing.push("tester_ip");
                }
            }
            "ssh-remote" => {
                if !present(&self.iface) {
                    missing.push("iface");
                }
                if !present(&self.dut_ip) {
                    missing.push("dut_ip");
                }
                if !present(&self.tester_ip) {
                    missing.push("tester_ip");
                }
                if !present(&self.ssh_target) {
                    missing.push("ssh_target");
                }
                if !present(&self.remote_dut_bin) {
                    missing.push("remote_dut_bin");
                }
                if !present(&self.remote_vsomeip_cfg) {
                    missing.push("remote_vsomeip_cfg");
                }
                if !present(&self.remote_capi_cfg) {
                    missing.push("remote_capi_cfg");
                }
            }
            _ => {}
        }
        if !missing.is_empty() {
            bail!(
                "topology '{topology}' requires --topology-conf field(s): {} (sudo strips the environment, so they must come from the TOML file)",
                missing.join(", ")
            );
        }

        // A fixture provisions topology-specific host state, so it must match the
        // selected topology — sourcing the netns fixture under the wrong topology
        // built a "frankenstate" in bash (a documented 2026-06-11 leak); reject it
        // here before any host state is touched.
        if let Some(fx) = &self.fixture {
            let compatible = matches!(
                (topology, fx.kind.as_str()),
                ("external", "netns-dut") | ("ssh-remote", "ssh-netns-dut")
            );
            if !compatible {
                bail!(
                    "fixture kind '{}' is not valid for topology '{topology}' (netns-dut⇒external, ssh-netns-dut⇒ssh-remote)",
                    fx.kind
                );
            }
        }

        // `[lwip]` configures the lwip-tap topology; under any other topology it is a
        // misplaced section (the same frankenstate hazard, caught declaratively).
        if self.lwip.is_some() && topology != "lwip-tap" {
            bail!("[lwip] config is only valid for --topology lwip-tap (got '{topology}')");
        }
        Ok(())
    }

    /// A required field after validation: panics only on a contract bug (validate
    /// guarantees presence for the topology). Trims the `Option` for call sites
    /// that ran `validate` first.
    pub fn require(&self, field: &str) -> &str {
        let v = match field {
            "iface" => &self.iface,
            "dut_ip" => &self.dut_ip,
            "tester_ip" => &self.tester_ip,
            "ssh_target" => &self.ssh_target,
            "remote_dut_bin" => &self.remote_dut_bin,
            "remote_vsomeip_cfg" => &self.remote_vsomeip_cfg,
            "remote_capi_cfg" => &self.remote_capi_cfg,
            other => panic!("SiteConf::require: unknown field '{other}'"),
        };
        v.as_deref()
            .unwrap_or_else(|| panic!("SiteConf::require('{field}') called before validate, or on the wrong topology"))
    }
}

/// Expand `${VAR}` references. `${ROOT}` resolves to `root` (the orchestrator's
/// resolved repo root); any other `${VAR}` resolves from the process environment,
/// where an unset variable is a hard error — fail loud rather than substitute an
/// empty string that would silently mis-path a binary. A literal `$` not followed
/// by `{` passes through verbatim.
fn expand_env(s: &str, root: &Path) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .with_context(|| format!("unterminated '${{' in topology-conf value '{s}'"))?;
        let var = &after[..end];
        let val = if var == "ROOT" {
            root.to_string_lossy().into_owned()
        } else {
            std::env::var(var)
                .with_context(|| format!("topology-conf references unset env var ${{{var}}}"))?
        };
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_requires_core_triple_and_lists_every_gap() {
        let conf = SiteConf::default();
        let err = conf.validate("external").unwrap_err().to_string();
        assert!(err.contains("iface"), "{err}");
        assert!(err.contains("dut_ip"), "{err}");
        assert!(err.contains("tester_ip"), "{err}");
    }

    #[test]
    fn ssh_remote_requires_remote_fields() {
        let conf = SiteConf {
            iface: Some("eth0".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            ..SiteConf::default()
        };
        let err = conf.validate("ssh-remote").unwrap_err().to_string();
        assert!(err.contains("ssh_target"), "{err}");
        assert!(err.contains("remote_dut_bin"), "{err}");
        assert!(err.contains("remote_vsomeip_cfg"), "{err}");
        assert!(err.contains("remote_capi_cfg"), "{err}");
        // iface/dut_ip/tester_ip are present → not reported.
        assert!(!err.contains("iface,") && !err.contains(" iface"), "{err}");
    }

    #[test]
    fn external_triple_present_validates() {
        let conf = SiteConf {
            iface: Some("eth0".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            ..SiteConf::default()
        };
        assert!(conf.validate("external").is_ok());
    }

    #[test]
    fn fixture_topology_mismatch_rejected() {
        let conf = SiteConf {
            iface: Some("eth0".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            fixture: Some(FixtureSpec { kind: "ssh-netns-dut".into() }),
            ..SiteConf::default()
        };
        // ssh-netns-dut fixture under external → reject.
        assert!(conf.validate("external").is_err());
    }

    #[test]
    fn fixture_topology_match_accepted() {
        let conf = SiteConf {
            iface: Some("eth0".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            fixture: Some(FixtureSpec { kind: "netns-dut".into() }),
            ..SiteConf::default()
        };
        assert!(conf.validate("external").is_ok());
    }

    #[test]
    fn lwip_tap_topology_is_zero_conf_and_lwip_section_is_scoped() {
        // The lwip-tap topology hardcodes its wire identity, so it needs no fields.
        assert!(SiteConf::default().validate("lwip-tap").is_ok());
        // A [lwip] override validates under lwip-tap...
        let with_lwip = || SiteConf {
            lwip: Some(LwipSpec { kill_name: Some("tc8-lwip-utm".into()), ..LwipSpec::default() }),
            ..SiteConf::default()
        };
        assert!(with_lwip().validate("lwip-tap").is_ok());
        // ...and is rejected under any other topology (misplaced-section guard).
        assert!(with_lwip().validate("external").is_err());
        assert!(with_lwip().validate("single-pc").is_err());
    }

    #[test]
    fn parses_lwip_tap_toml_with_fields() {
        let toml = r#"
            [lwip]
            app = "${ROOT}/build-lwip-dut/tc8-lwip-utm"
            ready_probe = "testability"
            kill_name = "tc8-lwip-utm"
        "#;
        let mut conf: SiteConf = toml::from_str(toml).unwrap();
        conf.expand_all(Path::new("/repo")).unwrap();
        conf.validate("lwip-tap").unwrap();
        let lw = conf.lwip.unwrap();
        assert_eq!(lw.app.unwrap(), "/repo/build-lwip-dut/tc8-lwip-utm");
        assert_eq!(lw.ready_probe.unwrap(), "testability");
        assert_eq!(lw.kill_name.unwrap(), "tc8-lwip-utm");
    }

    #[test]
    fn env_expansion_substitutes_and_fails_loud() {
        let root = Path::new("/repo/root");
        // ${ROOT} resolves from the passed root, not the environment.
        assert_eq!(
            expand_env("${ROOT}/build/dut/tc8-dut", root).unwrap(),
            "/repo/root/build/dut/tc8-dut"
        );
        std::env::set_var("TC8_SITE_TEST_VAR", "/opt/tc8");
        assert_eq!(expand_env("${TC8_SITE_TEST_VAR}/x", root).unwrap(), "/opt/tc8/x");
        assert_eq!(expand_env("no-vars-here", root).unwrap(), "no-vars-here");
        // Unset (non-ROOT) var → error, never silent empty.
        assert!(expand_env("${TC8_DEFINITELY_UNSET_VAR_XYZ}", root).is_err());
        // Unterminated brace → error.
        assert!(expand_env("${OPEN", root).is_err());
        std::env::remove_var("TC8_SITE_TEST_VAR");
    }

    #[test]
    fn parses_full_ssh_remote_toml() {
        let toml = r#"
            iface = "veth-sshfix-t"
            dut_ip = "172.16.0.2"
            tester_ip = "172.16.0.1"
            ssh_target = "root@172.16.0.2"
            ssh_opts = "-p 2222"
            remote_dut_bin = "/build/tc8-dut"
            remote_vsomeip_cfg = "/cfg/vsomeip.json"
            remote_capi_cfg = "/cfg/commonapi.ini"

            [fixture]
            kind = "ssh-netns-dut"
        "#;
        let mut conf: SiteConf = toml::from_str(toml).unwrap();
        conf.expand_all(Path::new("/repo")).unwrap();
        conf.validate("ssh-remote").unwrap();
        assert_eq!(conf.require("ssh_target"), "root@172.16.0.2");
        assert_eq!(conf.fixture.unwrap().kind, "ssh-netns-dut");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = r#"
            iface = "eth0"
            typo_field = "oops"
        "#;
        assert!(toml::from_str::<SiteConf>(toml).is_err());
    }
}
