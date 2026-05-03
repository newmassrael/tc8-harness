#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_03_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection03SM =
    ::SCE::Generated::ipv4_autoconf_address_selection_03::ipv4_autoconf_address_selection_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection03SM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection03SM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ADDRESS_SELECTION_03";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "DUT emits the ARP Probe with Ethernet destination = broadcast "
        "(RFC 3927 §2.2.1, MUST)";

    // Single-step stimulus: kick the tc8-dut LL state machine via
    // OpStartLLAutoconf with the fast envelope. tc8-dut emits one
    // DHCPDISCOVER (covering the spec precondition step "DUT: Sends
    // DHCPDISCOVER Message") then enters PROBE phase per RFC 3927
    // §2.2.1. SCXML matches on the FIRST emitted Probe.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_probe_not_broadcast:
                return "fail:dut_arp_probe_not_eth_broadcast";
            case State::Fail_timeout:
                return "fail:no_arp_probe_after_ll_start";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection03SM,
                  ipv4_autoconf_address_selection_03)
