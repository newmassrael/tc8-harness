#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_protocol_01_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientProtocol01NegSM =
    ::SCE::Generated::dhcpv4_client_protocol_01_neg::dhcpv4_client_protocol_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientProtocol01NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientProtocol01NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_PROTOCOL_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of PROTOCOL_01: tc8-dut's DHCP client emits a "
        "DHCPDISCOVER with a corrupted RFC 1497 magic cookie (RFC 2131 §3 "
        "MUST) via the DiscoverMagicCookieCorrupt firmware flavor. A "
        "conformant client (flavor None) emits the valid cookie, so the "
        "negative's fail_compliant branch is the live conformant-DUT "
        "outcome, not a harness artifact.";

    // Drive the ordinary DHCP client lifecycle with the magic-cookie
    // corruption flavor; the client emits one DISCOVER carrying the
    // mutated cookie (no OFFER is injected, so it stops after the single
    // DISCOVER). The corruption is a real firmware code path gated by the
    // flavor byte, so a conformant tc8-dut stays compliant.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDiscoverMagicCookieCorrupt);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientProtocol01NegSM,
                  dhcpv4_client_protocol_01_neg)
