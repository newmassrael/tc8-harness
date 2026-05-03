#pragma once

#include "arp_expected.h"
#include "dhcpv4_expected.h"
#include "test_config.h"

namespace tc8 {

// Cross-protocol Expected context paired with `ArpAndDhcpv4Captured`.
// Composition mirror of the captured side — SCXML guards reach
// topology identity via `expected.arp.dut_iface_mac` /
// `expected.dhcpv4.dut_iface_mac`. Both fields carry the same MAC by
// construction (single iface) but the field names match each
// sub-context's existing convention so the Captured-side helper
// predicates accept them without renaming.
//
// First consumer: §4.5.6.1 IPV4_AUTOCONF_INTRO_01.
struct ArpAndDhcpv4Expected {
    ArpExpected     arp{};
    Dhcpv4Expected  dhcpv4{};
};

inline void applyTestConfig(ArpAndDhcpv4Expected &e, const TestConfig &cfg) {
    applyTestConfig(e.arp, cfg);
    applyTestConfig(e.dhcpv4, cfg);
}

}  // namespace tc8
