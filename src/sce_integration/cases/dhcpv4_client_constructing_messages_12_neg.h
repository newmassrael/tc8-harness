#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_client_constructing_messages_12.h"  // SSOT for kCm12* envelope
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_12_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages12NegSM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_12_neg::
        dhcpv4_client_constructing_messages_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.7.6.6 CONSTRUCTING_MESSAGES_12: the DHCPDISCOVER
// retransmission interval must not exceed the RFC 2131 §4.1 backoff cap.
// kDhcpFlavorRetxExceedCap makes the harness-owned runLoop skip the cap clamp,
// so the saturation interval doubles past the ceiling (2x the cap). The trait
// drives the same fast-envelope the positive uses (cases::kCm12* SSOT); only
// the schedule is faulted (the DISCOVER shape stays conformant). A conformant
// client (flavor None) clamps at the cap, so the negative's fail_compliant
// branch is the live conformant-DUT outcome. tc8-dut-only (the lwIP fixture
// carries no DHCP client).
template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages12NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages12NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_12_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of CONSTRUCTING_MESSAGES_12: the kDhcpFlavorRetxExceedCap "
        "timing mutant pushes the saturation DHCPDISCOVER retransmission interval "
        "past the RFC 2131 cap; a conformant client clamps at the cap.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Same fast-envelope as the positive (cases::kCm12* SSOT) plus the
        // RetxExceedCap flavor byte: only the cap enforcement is faulted.
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
            /*retry_count=*/cases::kCm12RetryCount,
            /*retry_interval_ms=*/0U,
            /*nak_to_discover_min_ms=*/0U,
            /*nak_to_discover_max_ms=*/0U,
            /*arp_probe_listen_ms=*/0U,
            /*decline_to_discover_min_ms=*/0U,
            /*decline_to_discover_max_ms=*/0U,
            /*retx_first_ms=*/cases::kCm12RetxFirstMs,
            /*retx_cap_ms=*/cases::kCm12RetxCapMs,
            /*retx_jitter_ms=*/cases::kCm12RetxJitterMs,
            /*iface_index=*/0U,
            /*apply_initial_wait=*/true,
            /*flavor=*/::tc8::ut::kDhcpFlavorRetxExceedCap);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages12NegSM,
                  dhcpv4_client_constructing_messages_12_neg)
