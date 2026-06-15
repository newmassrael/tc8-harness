#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_ipv4_autoconf_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_autoconf_announcing_02_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4AutoconfAnnouncing02NegSM =
    ::SCE::Generated::ipv4_autoconf_announcing_02_neg::ipv4_autoconf_announcing_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4AutoconfAnnouncing02NegSM>
    : LinklocalAutoconfBase<cases::Ipv4AutoconfAnnouncing02NegSM> {
    static constexpr std::string_view kCaseId =
        "IPv4_AUTOCONF_ANNOUNCING_02_NEG";
    static constexpr std::string_view kSpecSection = "4.5.6.3";
    static constexpr std::string_view kDescription =
        "Self-validation of _02: tc8-dut AnnounceSenderTargetMismatch "
        "fault-injection drives sender_proto_ip != target_proto_ip "
        "in the Announce (RFC 3927 §2.4)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kFlavorAnnounceSenderTargetMismatch);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4AutoconfAnnouncing02NegSM,
                  ipv4_autoconf_announcing_02_neg)
