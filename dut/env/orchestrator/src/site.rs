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
//!
//! Two layers, parse-don't-validate: [`SiteConf`] is the permissive TOML boundary
//! (every field optional, `deny_unknown_fields`); [`SiteConf::resolve`] turns it
//! into a typed [`TopologyConf`] whose variant carries exactly the fields its
//! topology consumes. A wire IP under lwip-tap, or a required field absent under
//! external, is then unrepresentable rather than a runtime `require()` panic.

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

/// The raw `--topology-conf` TOML shape — the permissive deserialization boundary.
/// Every field is optional here; [`SiteConf::resolve`] enforces the per-topology
/// required set (enumerating every gap at once, bash contract-validation parity)
/// and moves the survivors into a typed [`TopologyConf`]. Nothing downstream sees
/// this raw form — they consume the resolved variant, so there is no `require()`
/// accessor and no stringly-typed field lookup to panic.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteConf {
    // --- common to external + ssh-remote ---
    /// Tester capture/injection NIC facing the DUT.
    iface: Option<String>,
    /// DUT IPv4 on the wire.
    dut_ip: Option<String>,
    /// Tester IPv4 on the wire.
    tester_ip: Option<String>,
    /// DUT MAC; neigh-resolved from the preflight ping when unset.
    dut_mac: Option<String>,
    /// Optional second NIC for TC8 Topology 2 (DHCPv4_CLIENT_USAGE_01); checked
    /// for existence in preflight, consumed when Topology-2 dispatch lands.
    iface_secondary: Option<String>,
    /// Cold-cache probe-source steering: the source IP the preflight ICMP/UT
    /// probes use, so the warmed DUT ARP entry lands on an address no cold-cache
    /// ARP case references (external.conf TC8_TOPOLOGY_PREFLIGHT_SRC_IP).
    preflight_src_ip: Option<String>,
    /// Promote a failed Upper Tester preflight probe from WARNING to a hard FAIL
    /// (external.conf TC8_TOPOLOGY_REQUIRE_UT).
    #[serde(default)]
    require_ut: bool,
    // NOTE: bash also exposes TC8_TOPOLOGY_DUT_ALIAS_IP / TC8_TOPOLOGY_TESTER_ALIAS_IP
    // (UDP_USER_INTERFACE_07/08 against a real external DUT). They are deliberately
    // NOT fields yet: dispatch hardcodes the netns-default aliases (wire::*), and the
    // per-case --expect OVERRIDE layer that would consume site-supplied aliases lands
    // with the S6 override stage. `deny_unknown_fields` makes an OEM conf carrying
    // those keys fail LOUD (a clear rejection), not silently ignored — so this is a
    // tracked deferral, not a silent gap.

    // --- ssh-remote only ---
    /// user@host for the DUT machine.
    ssh_target: Option<String>,
    /// Extra ssh options, word-split (e.g. "-p 2222 -i /path/key").
    ssh_opts: Option<String>,
    /// tc8-dut path on the remote host.
    remote_dut_bin: Option<String>,
    /// vsomeip.json path on the remote host (per-case flavors resolve as siblings).
    remote_vsomeip_cfg: Option<String>,
    /// commonapi.ini path on the remote host.
    remote_capi_cfg: Option<String>,
    /// Optional command prefix on the remote side (lab fixtures, taskset, ...).
    remote_wrap: Option<String>,

    // --- verification fixture (external/ssh-remote only) ---
    /// Stand up + tear down an orchestrator-owned verification DUT around the run.
    /// The lwIP DUT is the `lwip-tap` topology, not a fixture — its config lives in
    /// `[lwip]` below.
    fixture: Option<FixtureSpec>,

    // --- lwip-tap topology ---
    /// Optional overrides for the first-class `lwip-tap` topology (binary / readiness
    /// probe / kill name). Absent = run on the defaults. Valid only under
    /// `--topology lwip-tap`.
    lwip: Option<LwipSpec>,
}

/// Host-NIC wire identity common to the external and ssh-remote topologies. The
/// required triple (iface/dut_ip/tester_ip) is a plain `String` — present by
/// construction, since `resolve` only builds a `WireSite` after proving presence.
#[derive(Debug)]
pub struct WireSite {
    pub iface: String,
    pub dut_ip: String,
    pub tester_ip: String,
    /// DUT MAC; neigh-resolved from the preflight ping when `None`.
    pub dut_mac: Option<String>,
    /// Secondary tester NIC (TC8 Topology 2); empty-normalized to `None`.
    pub iface_secondary: Option<String>,
    /// Verification fixture to provision (kind compatibility already checked).
    pub fixture: Option<FixtureSpec>,
}

/// Resolved config for `--topology external` — a persistent DUT on a host NIC.
#[derive(Debug)]
pub struct ExternalSite {
    pub wire: WireSite,
    /// Cold-cache probe-source steering for the preflight (empty-normalized).
    pub preflight_src_ip: Option<String>,
    /// Make a failed Upper Tester preflight probe fatal rather than a WARNING.
    pub require_ut: bool,
}

/// Resolved config for `--topology ssh-remote` — the tester here, a per-case
/// reference DUT spawned over SSH on a second host. All remote paths present by
/// construction.
#[derive(Debug)]
pub struct SshSite {
    pub wire: WireSite,
    pub ssh_target: String,
    pub ssh_opts: Option<String>,
    pub remote_dut_bin: String,
    pub remote_vsomeip_cfg: String,
    pub remote_capi_cfg: String,
    pub remote_wrap: Option<String>,
}

/// The validated, typed site configuration. Each variant carries exactly the
/// fields its topology consumes, so an absent required field (external/ssh-remote)
/// or a wire IP under a wire-fixed topology (single-pc/lwip-tap) is unrepresentable
/// rather than a runtime `require()` panic or a silently-inert flat-struct field.
#[derive(Debug)]
pub enum TopologyConf {
    /// single-pc derives its wire identity from defaults and provisions its own
    /// netns; a conf may only override the tester/DUT IPs.
    SinglePc {
        tester_ip: Option<String>,
        dut_ip: Option<String>,
    },
    External(ExternalSite),
    SshRemote(SshSite),
    /// lwip-tap is wire-fixed (tap address + DUT IP are consts), so it carries no
    /// wire triple — only the `[lwip]` overrides and an optional secondary NIC for
    /// an OEM Topology-2-on-tap conf (none in-tree, but honored if configured).
    LwipTap {
        lwip: LwipSpec,
        iface_secondary: Option<String>,
    },
}

impl TopologyConf {
    /// Load + parse + env-expand + resolve a `--topology-conf` TOML for `topology`.
    /// `conf_path` is `None` when no `--topology-conf` was passed: single-pc and
    /// lwip-tap run zero-conf on their defaults, every other topology requires one
    /// (its iface / wire IPs / remote paths live there, and sudo strips the env).
    /// `root` expands `${ROOT}`.
    pub fn load(conf_path: Option<&Path>, topology: &str, root: &Path) -> Result<TopologyConf> {
        let raw = match conf_path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading --topology-conf {}", path.display()))?;
                let mut conf: SiteConf = toml::from_str(&text)
                    .with_context(|| format!("parsing --topology-conf {} as TOML", path.display()))?;
                conf.expand_all(root)?;
                conf
            }
            None => {
                if !matches!(topology, "single-pc" | "lwip-tap") {
                    bail!("--topology {topology} requires --topology-conf (iface/dut_ip/tester_ip live there; sudo strips the environment)");
                }
                SiteConf::default()
            }
        };
        raw.resolve(topology)
    }
}

impl SiteConf {
    /// Expand `${VAR}` references in every string field. `${ROOT}` resolves to the
    /// orchestrator's repo root (available even under sudo's stripped environment,
    /// unlike a real env var) so the committed example confs stay portable; any
    /// other `${VAR}` resolves from the process environment. Applied before
    /// resolution, so a required field that expands to empty still fails the
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

    /// Resolve the raw TOML into the typed [`TopologyConf`] for `topology`,
    /// enforcing the per-topology required set + fixture/topology compatibility and
    /// moving each surviving field into the variant that consumes it. Consumes self:
    /// nothing downstream sees the raw form. Empty strings (e.g. a `${VAR}` that
    /// expanded to "") normalize to absent here, so the consumers no longer carry
    /// scattered `.filter(|s| !s.is_empty())` guards.
    fn resolve(self, topology: &str) -> Result<TopologyConf> {
        let SiteConf {
            iface,
            dut_ip,
            tester_ip,
            dut_mac,
            iface_secondary,
            preflight_src_ip,
            require_ut,
            ssh_target,
            ssh_opts,
            remote_dut_bin,
            remote_vsomeip_cfg,
            remote_capi_cfg,
            remote_wrap,
            fixture,
            lwip,
        } = self;
        let ne = |o: Option<String>| o.filter(|s| !s.is_empty());
        let iface = ne(iface);
        let dut_ip = ne(dut_ip);
        let tester_ip = ne(tester_ip);
        let dut_mac = ne(dut_mac);
        let iface_secondary = ne(iface_secondary);
        let preflight_src_ip = ne(preflight_src_ip);
        let ssh_target = ne(ssh_target);
        let ssh_opts = ne(ssh_opts);
        let remote_dut_bin = ne(remote_dut_bin);
        let remote_vsomeip_cfg = ne(remote_vsomeip_cfg);
        let remote_capi_cfg = ne(remote_capi_cfg);
        let remote_wrap = ne(remote_wrap);

        // Every topology-conf field, paired with whether it was set. Each arm below
        // declares the fields it consumes; reject_unless_allowed bails on any set
        // field that arm does not consume — so a misplaced-but-known key (remote_*
        // under single-pc, require_ut under ssh-remote) fails LOUD rather than being
        // silently dropped, the field-level completion of the fixture/[lwip] guards.
        // (fixture/lwip have their own dedicated guards with kind-specific messages.)
        let all_fields: [(&str, bool); 13] = [
            ("iface", iface.is_some()),
            ("dut_ip", dut_ip.is_some()),
            ("tester_ip", tester_ip.is_some()),
            ("dut_mac", dut_mac.is_some()),
            ("iface_secondary", iface_secondary.is_some()),
            ("preflight_src_ip", preflight_src_ip.is_some()),
            ("require_ut", require_ut),
            ("ssh_target", ssh_target.is_some()),
            ("ssh_opts", ssh_opts.is_some()),
            ("remote_dut_bin", remote_dut_bin.is_some()),
            ("remote_vsomeip_cfg", remote_vsomeip_cfg.is_some()),
            ("remote_capi_cfg", remote_capi_cfg.is_some()),
            ("remote_wrap", remote_wrap.is_some()),
        ];

        // `[lwip]` configures the lwip-tap topology; under any other it is a
        // misplaced section — the same frankenstate hazard bash hit (a documented
        // 2026-06-11 cross-topology leak), caught declaratively before host setup.
        if lwip.is_some() && topology != "lwip-tap" {
            bail!("[lwip] config is only valid for --topology lwip-tap (got '{topology}')");
        }

        match topology {
            "single-pc" => {
                reject_fixture(&fixture, topology)?;
                reject_unless_allowed(topology, &all_fields, &["tester_ip", "dut_ip"])?;
                Ok(TopologyConf::SinglePc { tester_ip, dut_ip })
            }
            "lwip-tap" => {
                reject_fixture(&fixture, topology)?;
                reject_unless_allowed(topology, &all_fields, &["iface_secondary"])?;
                Ok(TopologyConf::LwipTap {
                    lwip: lwip.unwrap_or_default(),
                    iface_secondary,
                })
            }
            "external" => {
                reject_unless_allowed(
                    topology,
                    &all_fields,
                    &["iface", "dut_ip", "tester_ip", "dut_mac", "iface_secondary",
                      "preflight_src_ip", "require_ut"],
                )?;
                let mut missing: Vec<&str> = Vec::new();
                if iface.is_none() {
                    missing.push("iface");
                }
                if dut_ip.is_none() {
                    missing.push("dut_ip");
                }
                if tester_ip.is_none() {
                    missing.push("tester_ip");
                }
                bail_missing(topology, missing)?;
                let fixture = check_fixture(fixture, topology)?;
                Ok(TopologyConf::External(ExternalSite {
                    wire: WireSite {
                        iface: iface.unwrap(),
                        dut_ip: dut_ip.unwrap(),
                        tester_ip: tester_ip.unwrap(),
                        dut_mac,
                        iface_secondary,
                        fixture,
                    },
                    preflight_src_ip,
                    require_ut,
                }))
            }
            "ssh-remote" => {
                reject_unless_allowed(
                    topology,
                    &all_fields,
                    &["iface", "dut_ip", "tester_ip", "dut_mac", "iface_secondary",
                      "ssh_target", "ssh_opts", "remote_dut_bin", "remote_vsomeip_cfg",
                      "remote_capi_cfg", "remote_wrap"],
                )?;
                let mut missing: Vec<&str> = Vec::new();
                if iface.is_none() {
                    missing.push("iface");
                }
                if dut_ip.is_none() {
                    missing.push("dut_ip");
                }
                if tester_ip.is_none() {
                    missing.push("tester_ip");
                }
                if ssh_target.is_none() {
                    missing.push("ssh_target");
                }
                if remote_dut_bin.is_none() {
                    missing.push("remote_dut_bin");
                }
                if remote_vsomeip_cfg.is_none() {
                    missing.push("remote_vsomeip_cfg");
                }
                if remote_capi_cfg.is_none() {
                    missing.push("remote_capi_cfg");
                }
                bail_missing(topology, missing)?;
                let fixture = check_fixture(fixture, topology)?;
                Ok(TopologyConf::SshRemote(SshSite {
                    wire: WireSite {
                        iface: iface.unwrap(),
                        dut_ip: dut_ip.unwrap(),
                        tester_ip: tester_ip.unwrap(),
                        dut_mac,
                        iface_secondary,
                        fixture,
                    },
                    ssh_target: ssh_target.unwrap(),
                    ssh_opts,
                    remote_dut_bin: remote_dut_bin.unwrap(),
                    remote_vsomeip_cfg: remote_vsomeip_cfg.unwrap(),
                    remote_capi_cfg: remote_capi_cfg.unwrap(),
                    remote_wrap,
                }))
            }
            other => bail!("unknown topology '{other}'"),
        }
    }
}

/// Bail listing every missing required field at once (one actionable error, not a
/// fix-one-rerun loop) — bash contract-validation parity.
fn bail_missing(topology: &str, missing: Vec<&str>) -> Result<()> {
    if !missing.is_empty() {
        bail!(
            "topology '{topology}' requires --topology-conf field(s): {} (sudo strips the environment, so they must come from the TOML file)",
            missing.join(", ")
        );
    }
    Ok(())
}

/// A fixture provisions topology-specific host state, so it must match the selected
/// topology (external⇒netns-dut, ssh-remote⇒ssh-netns-dut). Sourcing the wrong one
/// built a "frankenstate" in bash (a documented 2026-06-11 leak); reject it here
/// before any host state is touched.
fn check_fixture(fixture: Option<FixtureSpec>, topology: &str) -> Result<Option<FixtureSpec>> {
    if let Some(fx) = &fixture {
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
    Ok(fixture)
}

/// single-pc / lwip-tap own no verification fixture (they self-provision or run
/// zero-conf), so a `[fixture]` block there is misplaced — reject it loudly rather
/// than silently ignore.
fn reject_fixture(fixture: &Option<FixtureSpec>, topology: &str) -> Result<()> {
    if let Some(fx) = fixture {
        bail!(
            "fixture kind '{}' is not valid for topology '{topology}' (fixtures are external/ssh-remote only)",
            fx.kind
        );
    }
    Ok(())
}

/// Reject any field set in the conf that `topology` does not consume — so a
/// misplaced-but-known key fails loud instead of being silently dropped by
/// resolve. `all` is every field paired with whether it was set; `allowed` names
/// the ones this topology consumes.
fn reject_unless_allowed(topology: &str, all: &[(&str, bool)], allowed: &[&str]) -> Result<()> {
    let foreign: Vec<&str> = all
        .iter()
        .filter(|(name, set)| *set && !allowed.contains(name))
        .map(|(name, _)| *name)
        .collect();
    if !foreign.is_empty() {
        bail!(
            "topology '{topology}' does not accept --topology-conf field(s): {} (they belong to a different topology)",
            foreign.join(", ")
        );
    }
    Ok(())
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

    fn external_triple() -> SiteConf {
        SiteConf {
            iface: Some("eth0".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            ..SiteConf::default()
        }
    }

    #[test]
    fn external_requires_core_triple_and_lists_every_gap() {
        let err = SiteConf::default().resolve("external").unwrap_err().to_string();
        assert!(err.contains("iface"), "{err}");
        assert!(err.contains("dut_ip"), "{err}");
        assert!(err.contains("tester_ip"), "{err}");
    }

    #[test]
    fn ssh_remote_requires_remote_fields() {
        let err = external_triple().resolve("ssh-remote").unwrap_err().to_string();
        assert!(err.contains("ssh_target"), "{err}");
        assert!(err.contains("remote_dut_bin"), "{err}");
        assert!(err.contains("remote_vsomeip_cfg"), "{err}");
        assert!(err.contains("remote_capi_cfg"), "{err}");
        // iface/dut_ip/tester_ip are present → not reported.
        assert!(!err.contains(" iface"), "{err}");
    }

    #[test]
    fn external_triple_present_resolves() {
        match external_triple().resolve("external").unwrap() {
            TopologyConf::External(e) => {
                assert_eq!(e.wire.iface, "eth0");
                assert_eq!(e.wire.dut_ip, "172.16.0.2");
                assert_eq!(e.wire.tester_ip, "172.16.0.1");
                assert!(!e.require_ut);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn fixture_topology_mismatch_rejected() {
        let conf = SiteConf {
            fixture: Some(FixtureSpec { kind: "ssh-netns-dut".into() }),
            ..external_triple()
        };
        // ssh-netns-dut fixture under external → reject.
        assert!(conf.resolve("external").is_err());
    }

    #[test]
    fn fixture_topology_match_accepted() {
        let conf = SiteConf {
            fixture: Some(FixtureSpec { kind: "netns-dut".into() }),
            ..external_triple()
        };
        assert!(matches!(conf.resolve("external"), Ok(TopologyConf::External(_))));
    }

    #[test]
    fn lwip_tap_is_zero_conf_and_lwip_section_is_scoped() {
        // The lwip-tap topology hardcodes its wire identity, so it needs no fields.
        assert!(matches!(
            SiteConf::default().resolve("lwip-tap"),
            Ok(TopologyConf::LwipTap { .. })
        ));
        let with_lwip = || SiteConf {
            lwip: Some(LwipSpec { kill_name: Some("tc8-lwip-utm".into()), ..LwipSpec::default() }),
            ..SiteConf::default()
        };
        assert!(with_lwip().resolve("lwip-tap").is_ok());
        // ...and is rejected under any other topology (misplaced-section guard).
        assert!(with_lwip().resolve("external").is_err());
        assert!(with_lwip().resolve("single-pc").is_err());
    }

    #[test]
    fn lwip_tap_rejects_a_wire_ip() {
        // A dut_ip in a lwip-tap conf is foreign to the wire-fixed topology: the
        // LwipTap variant has no field to hold it (so it cannot override the
        // wire-fixed default — the former silent-override bug), AND resolve now
        // rejects it loudly rather than silently dropping it.
        let conf = SiteConf { dut_ip: Some("10.0.0.9".into()), ..SiteConf::default() };
        assert!(conf.resolve("lwip-tap").unwrap_err().to_string().contains("dut_ip"));
    }

    #[test]
    fn single_pc_carries_optional_ip_overrides() {
        let conf = SiteConf {
            tester_ip: Some("10.0.0.1".into()),
            dut_ip: Some("10.0.0.2".into()),
            ..SiteConf::default()
        };
        match conf.resolve("single-pc").unwrap() {
            TopologyConf::SinglePc { tester_ip, dut_ip } => {
                assert_eq!(tester_ip.as_deref(), Some("10.0.0.1"));
                assert_eq!(dut_ip.as_deref(), Some("10.0.0.2"));
            }
            other => panic!("expected SinglePc, got {other:?}"),
        }
    }

    #[test]
    fn fixture_under_single_pc_or_lwip_tap_rejected() {
        let with_fx = || SiteConf {
            fixture: Some(FixtureSpec { kind: "netns-dut".into() }),
            ..SiteConf::default()
        };
        assert!(with_fx().resolve("single-pc").is_err());
        assert!(with_fx().resolve("lwip-tap").is_err());
    }

    #[test]
    fn unknown_topology_rejected() {
        assert!(SiteConf::default().resolve("bogus").is_err());
    }

    #[test]
    fn misplaced_field_fails_loud() {
        // A known key for a DIFFERENT topology is rejected, not silently dropped.
        let spc = SiteConf {
            remote_dut_bin: Some("/x".into()),
            tester_ip: Some("10.0.0.1".into()),
            ..SiteConf::default()
        };
        assert!(spc.resolve("single-pc").unwrap_err().to_string().contains("remote_dut_bin"));

        let ext = SiteConf { ssh_target: Some("root@h".into()), ..external_triple() };
        assert!(ext.resolve("external").unwrap_err().to_string().contains("ssh_target"));

        let ssh = SiteConf {
            require_ut: true,
            ssh_target: Some("root@h".into()),
            remote_dut_bin: Some("/x".into()),
            remote_vsomeip_cfg: Some("/v".into()),
            remote_capi_cfg: Some("/c".into()),
            ..external_triple()
        };
        assert!(ssh.resolve("ssh-remote").unwrap_err().to_string().contains("require_ut"));
    }

    #[test]
    fn empty_string_normalizes_to_absent() {
        // An expanded-to-empty required field fails the required check (not silently
        // accepted), and an empty optional drops out.
        let conf = SiteConf {
            iface: Some("".into()),
            dut_ip: Some("172.16.0.2".into()),
            tester_ip: Some("172.16.0.1".into()),
            ..SiteConf::default()
        };
        assert!(conf.resolve("external").unwrap_err().to_string().contains("iface"));
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
        match conf.resolve("lwip-tap").unwrap() {
            TopologyConf::LwipTap { lwip: lw, iface_secondary } => {
                assert_eq!(lw.app.unwrap(), "/repo/build-lwip-dut/tc8-lwip-utm");
                assert_eq!(lw.ready_probe.unwrap(), "testability");
                assert_eq!(lw.kill_name.unwrap(), "tc8-lwip-utm");
                assert!(iface_secondary.is_none());
            }
            other => panic!("expected LwipTap, got {other:?}"),
        }
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
        match conf.resolve("ssh-remote").unwrap() {
            TopologyConf::SshRemote(s) => {
                assert_eq!(s.ssh_target, "root@172.16.0.2");
                assert_eq!(s.ssh_opts.as_deref(), Some("-p 2222"));
                assert_eq!(s.remote_dut_bin, "/build/tc8-dut");
                assert_eq!(s.wire.fixture.unwrap().kind, "ssh-netns-dut");
            }
            other => panic!("expected SshRemote, got {other:?}"),
        }
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
