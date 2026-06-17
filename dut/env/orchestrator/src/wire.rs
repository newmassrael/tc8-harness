//! Single home for the wire/fixture constants the orchestrator hardcodes whose
//! ultimate source of truth lives OUTSIDE this crate — the C++ stimulus builders,
//! `udp_pilot_common.h`, the DHCPv4 endpoint header, `ets.fidl`, and
//! smoke-test.sh's `init_expectation_defaults`. They cannot yet be read from Rust
//! at build time, so they are mirrored here.
//!
//! Why one module: each of these values is referenced from more than one place in
//! the crate (the `--expect` builder in `dispatch`, the per-case conditioning pins
//! in `conditioning`, the netns address setup in `netns`). Homing them here makes
//! the crate single-source: a retune of the C++ constant updates exactly one Rust
//! line, and there is no second `const` under a different name to drift out of
//! sync. This module is also the natural generation target for the tracked
//! cross-language wire-constant manifest — when that lands, it generates this file
//! from the same source the C++ reads, the way `verdict_taxonomy.gen.rs` is
//! generated from `verdict_taxonomy.def`.
//!
//! Each constant names its external SSOT. Drift here silently turns a positive
//! test into a false pass, so these MUST be updated together with their source.

// --- Tester-injected ARP MACs — src/stimulus/arp_builder.h ------------------
/// `kTesterInjectedMac` — the sender MAC the harness injects in ARP stimulus, and
/// the lladdr the DHCPv4 CM_05/_06 synthetic-gateway pin binds to.
pub const ARP_TESTER_MAC: &str = "02:00:00:00:00:A1";
/// `kTesterInjectedMac2` — Group C cache-merge cases (ARP_32..35).
pub const ARP_TESTER_MAC2: &str = "02:00:00:00:00:A2";
/// `kTesterInjectedMac3` — Group D Response-learning case ARP_40.
pub const ARP_TESTER_MAC3: &str = "02:00:00:00:00:A3";

// --- ICMP echo identity — src/stimulus/icmpv4_builder.h ---------------------
/// `kIcmpEchoId`.
pub const ICMP_ECHO_ID: &str = "0x1234";
/// `kIcmpEchoSeq`.
pub const ICMP_ECHO_SEQ: &str = "0x5678";

// --- UDP UI_07/_08 alias fixture IPs — src/sce_integration/udp_pilot_common.h
// Bare addresses (the value SCXML asserts). `netns` derives the `/24` CIDR it
// configures from these, the same way bring-up derives the primary CIDRs.
/// `kDutAliasIp4Be` — DUT-side source-IP alias (UI_07).
pub const DUT_ALIAS_IP: &str = "172.16.0.5";
/// `kTesterAliasIp4Be` — tester-side destination-IP alias (UI_08).
pub const TESTER_ALIAS_IP: &str = "172.16.0.4";

// --- DHCPv4 synthetic server/gateway — src/sce_integration/dhcpv4_default_endpoints.h
/// `kDefaultServerIdBe` — the Option-3 router the CM_05/_06 conditioning pins.
pub const DHCPV4_SERVER1_IP4: &str = "172.16.0.10";

// --- SOME/IP-SD version + default subscribe target --------------------------
/// SD major version — SSOT: `dut/ets/ets.fidl` `version { major 1 minor 0 }`.
pub const SD_MAJOR_VERSION: &str = "1";
/// SD minor version — same SSOT.
pub const SD_MINOR_VERSION: &str = "0";
/// The UNCONFIGURED subscribe target (NOT a deployed eventgroup) several
/// SOMEIPSRV/ETS cases Nack-echo. SSOT: smoke-test.sh `init_expectation_defaults`
/// `eventgroup_id=0x0001`. Do NOT "correct" to a deployed eventgroup — that
/// breaks the Nack-echo baseline.
pub const SD_DEFAULT_EVENTGROUP: &str = "0x0001";
