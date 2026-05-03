#pragma once

#include <cstdint>

namespace tc8 {

// Flat DTO for the expected values a TC8 §4.4 IPv4 header case compares
// observed fields against. Carries only the topology-pinned IPv4
// identity (tester + DUT iface IP), both supplied by the operator via
// `--expect ipv4.<key>=<value>` (see `cli/expect_parser.cpp`).
//
// No `expected_version` / `expected_ttl` knob: §4.4.4.4 VERSION and
// §4.4.4.3 TTL fix the DUT-side literal by spec (version = 4, TTL >= 1),
// so the SCXML guard references the literal directly. Adding a CLI
// override here would invent a drift surface the spec does not.
//
// Mirror of `Icmpv4Expectations` / `ArpExpectations`: lives in its own
// header so `test_config.h` can aggregate it without pulling in the
// full `Ipv4Expected` Named Context layout.
struct Ipv4Expectations {
    std::uint32_t tester_ip    = 0;  // network byte order
    std::uint32_t dut_iface_ip = 0;  // network byte order
};

}  // namespace tc8
