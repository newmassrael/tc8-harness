#pragma once

#include <cstdint>

#include "ipv4_expectations.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying topology-pinned identity supplied
// via CLI `--expect ipv4.<key>=<value>`. Matching SCXML declaration:
//   <sce:context id="expected" cpp:type="tc8::Ipv4Expected"
//                cpp:include="sce_integration/ipv4_expected.h"/>
//
// §4.4 pilot cases read `expected.dut_iface_ip` from the dispatch-side
// filter (drop tester-originated IPv4 packets) and, for HEADER_03,
// from the SCXML guard asserting the DUT's reply source address. The
// `tester_ip` field is carried for symmetry with the ICMPv4/ARP Named
// Contexts and so future §4.4.4.6 / §4.4.4.2 cases that need a
// symmetric assertion on the tester side have the value already wired.
struct Ipv4Expected {
    std::uint32_t tester_ip    = 0;  // network byte order
    std::uint32_t dut_iface_ip = 0;  // network byte order
};

inline void applyTestConfig(Ipv4Expected &e, const TestConfig &cfg) {
    e.tester_ip    = cfg.ipv4.tester_ip;
    e.dut_iface_ip = cfg.ipv4.dut_iface_ip;
}

}  // namespace tc8
