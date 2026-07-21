#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_06_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation06NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_06_neg::dhcpv4_client_initialization_allocation_06_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation06NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation06NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_06_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_06: tc8-dut XORs the post-OFFER "
        "DHCPREQUEST's 'xid' (RFC 2131 §4.4.1 MUST echo the DISCOVER's xid) "
        "via the RequestXidMismatch firmware flavor. A conformant client "
        "(flavor None) echoes the xid, so the negative's fail_compliant "
        "branch is the live conformant-DUT outcome.";

    // Conformant DISCOVER (the flavor is gated to the SELECTING REQUEST so
    // the OFFER still matches DISCOVER.xid), DISCOVER snapshot on
    // Listening_for_request entry, tester OFFER, then the DUT emits the
    // xid-corrupted REQUEST the guard catches.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestXidMismatch);
        ::tc8::sce::dhcpv4::scheduleDiscoverSnapshotOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request), c);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation06NegSM,
                  dhcpv4_client_initialization_allocation_06_neg)
