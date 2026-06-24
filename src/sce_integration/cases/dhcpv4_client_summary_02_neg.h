#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_02_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary02NegSM =
    ::SCE::Generated::dhcpv4_client_summary_02_neg::dhcpv4_client_summary_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary02NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary02NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_SUMMARY_02_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SUMMARY_02: the kDhcpFlavorAcceptMismatchedXidOffer "
        "firmware flavor relaxes the OFFER xid gate so the client accepts "
        "SERVER-1's mismatched OFFER; a conformant client discards it and selects "
        "SERVER-2 (RFC 2131 §4.3.1)";
    static constexpr int kTopology = 3;

    // Same Topology 3 two-server schedule as the positive (SERVER-1 xid_offset=+1
    // sent first, SERVER-2 matched with kSecondServerIdBe) plus the
    // AcceptMismatchedXidOffer flavor: the relaxed xid gate makes the buggy client
    // accept SERVER-1's mismatched OFFER (the first one read off the socket) so its
    // REQUEST carries SERVER-1's Option 54 instead of SERVER-2's.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorAcceptMismatchedXidOffer);

        ::tc8::sce::dhcpv4::ServerEmulParams server1{};
        server1.xid_offset = 1;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, server1);

        ::tc8::sce::dhcpv4::ServerEmulParams server2{};
        server2.server_id_be = ::tc8::sce::dhcpv4::kSecondServerIdBe;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, server2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary02NegSM,
                  dhcpv4_client_summary_02_neg)
