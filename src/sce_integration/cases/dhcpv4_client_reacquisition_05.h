#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_05_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition05SM =
    ::SCE::Generated::dhcpv4_client_reacquisition_05::dhcpv4_client_reacquisition_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition05SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition05SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_05";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "RENEWING retransmission interval = (T2 - T1) / 2 "
        "(RFC 2131 §4.4.5)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleRetxLeaseEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition05SM,
                  dhcpv4_client_reacquisition_05)
