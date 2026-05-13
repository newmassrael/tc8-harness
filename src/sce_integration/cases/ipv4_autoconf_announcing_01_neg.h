#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing01NegSM =
    ::SCE::Generated::ipv4_autoconf_announcing_01_neg::ipv4_autoconf_announcing_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing01NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing01NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_01_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "Self-validation of _01: tc8-dut AnnounceEthDstUnicast "
        "fault-injection drives Announce eth_dst to DUT iface MAC "
        "(RFC 3927 §2.4 / §2.5 last MUST)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.arp.dut_real_mac,
            ::tc8::ut::kFlavorAnnounceEthDstUnicast);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_compliant_emit:
                return "fail:dut_emitted_compliant_announce_despite_eth_dst_unicast_flavor";
            case State::Fail_no_announce_after_probes:
                return "fail:no_arp_announce_after_probes";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing01NegSM,
                  ipv4_autoconf_announcing_01_neg)
