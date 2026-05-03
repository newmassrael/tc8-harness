#pragma once

#include <array>
#include <cstdint>

namespace tc8 {

// Flat DTO for the expected values a TC8 §4.7 DHCPv4 client case
// compares observed fields against. Carries only the topology-pinned
// DUT identity that anchors the "is this DUT-emitted DISCOVER?" filter
// in every passive-observation case (PROTOCOL_01/02, SUMMARY_04,
// CONSTRUCTING_MESSAGES_01/03).
//
// Supplied via `--expect dhcpv4.<key>=<value>` (see
// `cli/expect_parser.cpp`). The CLI driver populates
// `dhcpv4.dut_iface_mac` from the same MAC the topology pins for ARP /
// IPv4 SCXML guards — `smoke-test.sh` derives both from one veth-end
// MAC so a single source of truth covers all protocol families.
//
// Mirror of `Ipv4Expectations` / `ArpExpectations`: lives in its own
// header so `test_config.h` can aggregate it without pulling in the
// full `Dhcpv4Expected` Named Context layout.
struct Dhcpv4Expectations {
    // DUT-side `chaddr` value the BOOTP body is expected to carry —
    // RFC 2131 §2 fixes htype=1 / hlen=6 for Ethernet, so the first
    // 6 bytes of the 16-byte chaddr region match the DUT's iface MAC.
    // Used by SCXML guards as the predicate "this DISCOVER originated
    // from the DUT" without trusting the lossy `eth_src` (which a
    // misbehaving switch could rewrite).
    std::array<std::uint8_t, 6> dut_iface_mac{};
};

}  // namespace tc8
