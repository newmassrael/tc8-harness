#pragma once

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
// Inherits every field from the Ipv4Expectations DTO (data-only base), so the
// fields are declared once and the DTO and this Named Context cannot drift —
// the same idiom SomeIpExpected and the captured contexts use. Add a new
// `--expect ipv4.` field to Ipv4Expectations (plus the expect_parser.cpp key
// table); applyTestConfig copies the whole base in one assignment.
struct Ipv4Expected : Ipv4Expectations {};

inline void applyTestConfig(Ipv4Expected &e, const TestConfig &cfg) {
    static_cast<Ipv4Expectations &>(e) = cfg.ipv4;
}

}  // namespace tc8
