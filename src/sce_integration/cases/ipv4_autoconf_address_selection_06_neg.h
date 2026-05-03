#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_address_selection_06_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAddressSelection06NegSM =
    ::SCE::Generated::ipv4_autoconf_address_selection_06_neg::ipv4_autoconf_address_selection_06_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAddressSelection06NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAddressSelection06NegSM> {
    static constexpr std::string_view kCaseId =
        "IPV4_AUTOCONF_ADDRESS_SELECTION_06_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.2";
    static constexpr std::string_view kDescription =
        "Self-validation of _06: tc8-dut SenderIpNonzero fault-"
        "injection drives sender_proto_ip to DUT iface IP "
        "(RFC 3927 §2.1.1 MUST=0)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.arp.dut_real_mac,
            ::tc8::ut::kFlavorSenderIpNonzero);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_compliant_emit:
                return "fail:dut_emitted_compliant_probe_despite_sender_ip_nonzero_flavor";
            case State::Fail_timeout:
                return "fail:no_arp_probe_after_ll_start";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAddressSelection06NegSM,
                  ipv4_autoconf_address_selection_06_neg)
