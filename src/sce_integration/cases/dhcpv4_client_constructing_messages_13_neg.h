#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_client_constructing_messages_13.h"  // SSOT for kCm13* envelope
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_13_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages13NegSM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_13_neg::
        dhcpv4_client_constructing_messages_13_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.7.6.6 CONSTRUCTING_MESSAGES_13: DHCPDISCOVER
// retransmissions must use randomized exponential backoff (RFC 2131 §4.1).
// kDhcpFlavorRetxNoBackoff makes the harness-owned runLoop collapse the
// inter-DISCOVER wait to 0, so the first retransmission interval falls far
// below the [FirstRetx-1, FirstRetx+1] = [3,5] s range. The trait drives the
// same retx envelope the positive uses; only the schedule is faulted (the
// DISCOVER shape stays conformant). A conformant client (flavor None) keeps
// the backoff, so the negative's fail_compliant branch is the live
// conformant-DUT outcome. tc8-dut-only (the lwIP fixture carries no DHCP
// client).
template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages13NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages13NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_13_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of CONSTRUCTING_MESSAGES_13: the kDhcpFlavorRetxNoBackoff "
        "timing mutant collapses the DHCPDISCOVER retransmission interval below the "
        "RFC 2131 backoff range; a conformant client backs off.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Same retx envelope as the positive (cases::kCm13* SSOT) plus the
        // RetxNoBackoff flavor byte: only the schedule is faulted.
        ::tc8::sce::dhcpv4::Dhcpv4StartConfig sc;
        sc.retry_count = cases::kCm13RetryCount;
        sc.retry_interval_ms = 0U;
        sc.retx_first_ms = cases::kCm13RetxFirstMs;
        sc.retx_cap_ms = cases::kCm13RetxCapMs;
        sc.retx_jitter_ms = cases::kCm13RetxJitterMs;
        sc.flavor = ::tc8::ut::kDhcpFlavorRetxNoBackoff;
        ::tc8::sce::dhcpv4::emitStartDhcpClient(cfg, iface, cfg.dut.mac, sc);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages13NegSM,
                  dhcpv4_client_constructing_messages_13_neg)
