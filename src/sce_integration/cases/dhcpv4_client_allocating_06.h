#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_06_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating06SM =
    ::SCE::Generated::dhcpv4_client_allocating_06::dhcpv4_client_allocating_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating06SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating06SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_06";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER is retransmitted on no DHCPOFFER (RFC 2131 §3.1, MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& /*scheduler*/) {
        // Pilot drives retry_count=2 — DUT emits DISCOVER#1, waits
        // 2 s with no OFFER, sleeps 1 s, emits DISCOVER#2. No tester
        // OFFER injection is registered.
        ::tc8::sce::dhcpv4::Dhcpv4StartConfig sc;
        sc.retry_count = 2;
        ::tc8::sce::dhcpv4::emitStartDhcpClient(cfg, iface, cfg.dut.mac, sc);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating06SM,
                  dhcpv4_client_allocating_06)
