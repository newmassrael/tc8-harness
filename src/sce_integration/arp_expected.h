#pragma once

#include <array>
#include <cstdint>

#include "arp_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying topology-pinned identity supplied via
// CLI `--expect arp.<key>=<value>`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::ArpExpected"
//                cpp:include="sce_integration/arp_expected.h"/>
//
// ARP_13/14/15 read these from their SCXML guards, e.g.
//
//   cond="cpp:captured.sender_proto_ip == expected.dut_iface_ip"
//
// Default 0 is never a valid topology endpoint, so a case landing here
// with expectations unset will fall into its `fail_*` sink — the failure
// reason plus the CLI banner lets the operator notice the missing
// configuration without another layer of validation plumbing.
//
// ARP_07..12 don't read expected values (they compare against RFC 826
// constants directly in their SCXML), but still declare this context so
// the SCE codegen emits a uniform two-arg state-machine constructor. The
// trade-off matches the §5.1 SOMEIPSRV split (FORMAT_01..13 also declare
// the unused expected context).
struct ArpExpected {
    std::array<std::uint8_t, 6> dut_iface_mac{};
    std::uint32_t dut_iface_ip = 0;  // network byte order
    std::uint32_t tester_ip = 0;     // network byte order
    // §4.2.4.1 ARP_04/06 cross-protocol guards compare this against the
    // observed UDP frame's Ethernet destination to confirm DUT honoured
    // the ARP entry the tester pre-populated. See `ArpExpectations`.
    std::array<std::uint8_t, 6> tester_mac{};
    // §4.2.4.2 Phase 3b Group C (ARP_32/33/34/35): second tester MAC.
    // After a MAC1 → MAC2 double ARP injection DUT's next UDP egress
    // `eth_dst` should match this value, proving the RFC 826 "merge"
    // step overwrote the first entry.
    std::array<std::uint8_t, 6> tester_mac2{};
    // §4.2.4.2 Phase 3c Group D (ARP_40): tester injects a Response
    // with sender_hw = MAC3 (distinct from MAC1/MAC2 for unambiguous
    // attribution); DUT UDP egress eth_dst must equal this value.
    std::array<std::uint8_t, 6> tester_mac3{};
    // §4.5.6.2 ADDRESS_SELECTION_16 (RFC 3927 §2.5): tester LL the
    // claim-condition Request is sent FROM; the DUT's Reply MUST
    // carry this value as `target_proto_ip`. NBO. Defaulted in
    // `ArpExpectations` and copied through `applyTestConfig`.
    std::uint32_t tester_linklocal_ip = 0;
};

inline void applyTestConfig(ArpExpected &e, const TestConfig &cfg) {
    e.dut_iface_mac = cfg.arp.dut_iface_mac;
    e.dut_iface_ip = cfg.arp.dut_iface_ip;
    e.tester_ip = cfg.arp.tester_ip;
    e.tester_mac = cfg.arp.tester_mac;
    e.tester_mac2 = cfg.arp.tester_mac2;
    e.tester_mac3 = cfg.arp.tester_mac3;
    e.tester_linklocal_ip = cfg.arp.tester_linklocal_ip;
}

}  // namespace tc8
