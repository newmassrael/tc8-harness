#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_01_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation01NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_01_neg::dhcpv4_client_initialization_allocation_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation01NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation01NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of INITIALIZATION_ALLOCATION_01: the "
        "kDhcpFlavorNakRestartNoDelay timing mutant makes the harness-owned "
        "runLoop skip the RFC 2131 §4.4.1 random desync wait, so the "
        "NAK->DISCOVER interval collapses below the 1 s floor; a conformant "
        "client waits inside the [1, 11] s window.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Same fast envelope + [1000, 10000] ms desync window as the positive
        // plus the NakRestartNoDelay flavor byte: only the random wait is
        // faulted (the DISCOVER shape and the lifecycle stay conformant).
        ::tc8::sce::dhcpv4::Dhcpv4StartConfig sc;
        sc.nak_to_discover_min_ms = 1000;
        sc.nak_to_discover_max_ms = 10000;
        sc.flavor = ::tc8::ut::kDhcpFlavorNakRestartNoDelay;
        ::tc8::sce::dhcpv4::emitStartDhcpClient(cfg, iface, cfg.dut.mac, sc);
        ::tc8::sce::dhcpv4::scheduleRenewingNakSchedule<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation01NegSM,
                  dhcpv4_client_initialization_allocation_01_neg)
