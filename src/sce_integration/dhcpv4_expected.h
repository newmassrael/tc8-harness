#pragma once

#include <array>
#include <cstdint>

#include "dhcpv4_default_endpoints.h"
#include "dhcpv4_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying topology-pinned DUT identity
// supplied via CLI `--expect dhcpv4.<key>=<value>`. Matching SCXML
// declaration:
//
//   <sce:context id="expected" cpp:type="tc8::Dhcpv4Expected"
//                cpp:include="sce_integration/dhcpv4_expected.h"/>
//
// PROTOCOL_01/02, SUMMARY_04, CONSTRUCTING_MESSAGES_01/03 all read
// `dut_iface_mac` from their SCXML guards as
//
//   cond="cpp:captured.chaddr_matches_dut_mac(expected.dut_iface_mac)"
//
// to filter DUT-emitted DISCOVER from any ambient DHCP traffic the BPF
// `udp port 67/68` filter would otherwise pass through. Default zero
// MAC never matches a real wire frame, so a case landing here with
// the expectation unset falls into its `fail_*` sink — the failure
// reason plus the CLI banner lets the operator notice the missing
// configuration without another layer of validation plumbing.
struct Dhcpv4Expected {
    std::array<std::uint8_t, 6> dut_iface_mac{};

    // §4.7 tester-side server emulation identity / yiaddr — pinned to
    // the same `kDefault*Be` constants the server stimulus builder
    // (`dhcpv4_server_stimulus.h::scheduleDhcpReplyOnStateEntry`)
    // injects on `Listening_for_request` entry. Lifecycle cases that
    // observe the DUT's REQUEST against echoed Option 54 (Server
    // Identifier, ALLOCATING_03) or Option 50 (Requested IP Address,
    // REQUEST_02) compare via these expectations rather than via raw
    // SCXML literals — keeps the per-case .scxml decoupled from the
    // dev-netns IP plan and ready for future CLI override (OEM-lab
    // topology with a real DHCP-relay configuration).
    std::uint32_t server_id_be  = ::tc8::sce::dhcpv4::kDefaultServerIdBe;
    std::uint32_t offered_ip_be = ::tc8::sce::dhcpv4::kDefaultOfferedIpBe;
    // §4.7.6.1 SUMMARY_02: the captured REQUEST's Option 54 must
    // identify the SECOND tester server emul (matched-xid OFFER) — not
    // the first (mismatched-xid). Distinct value from `server_id_be`
    // so the SCXML pass guard reads which server the DUT selected.
    std::uint32_t second_server_id_be = ::tc8::sce::dhcpv4::kSecondServerIdBe;
};

inline void applyTestConfig(Dhcpv4Expected &e, const TestConfig &cfg) {
    e.dut_iface_mac = cfg.dhcpv4.dut_iface_mac;
    // server_id_be / offered_ip_be retain the constexpr defaults until
    // CLI plumbing (`--expect dhcpv4.server_id_be=...`) lands.
}

}  // namespace tc8
