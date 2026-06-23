#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_client_constructing_messages_13.h"  // SSOT for kCm13* envelope
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_13_neg2_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages13Neg2SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_13_neg2::
        dhcpv4_client_constructing_messages_13_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation variant 2 of §4.7.6.6 CONSTRUCTING_MESSAGES_13 — proves the
// SECOND retransmission-interval fail-final reachable. Same kDhcpFlavorRetxNoBackoff
// timing mutant and retx envelope as _NEG; the divergence is purely SCXML-side
// (this variant observes the d2->d3 interval). tc8-dut-only.
template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages13Neg2SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages13Neg2SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_13_NEG2";
    static constexpr std::string_view kDescription =
        "Self-validation of CONSTRUCTING_MESSAGES_13 (2nd interval): the "
        "kDhcpFlavorRetxNoBackoff timing mutant collapses the second DHCPDISCOVER "
        "retransmission interval below the RFC 2131 backoff range; a conformant "
        "client backs off.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
            /*retry_count=*/cases::kCm13RetryCount,
            /*retry_interval_ms=*/0U,
            /*nak_to_discover_min_ms=*/0U,
            /*nak_to_discover_max_ms=*/0U,
            /*arp_probe_listen_ms=*/0U,
            /*decline_to_discover_min_ms=*/0U,
            /*decline_to_discover_max_ms=*/0U,
            /*retx_first_ms=*/cases::kCm13RetxFirstMs,
            /*retx_cap_ms=*/cases::kCm13RetxCapMs,
            /*retx_jitter_ms=*/cases::kCm13RetxJitterMs,
            /*iface_index=*/0U,
            /*apply_initial_wait=*/true,
            /*flavor=*/::tc8::ut::kDhcpFlavorRetxNoBackoff);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages13Neg2SM,
                  dhcpv4_client_constructing_messages_13_neg2)
