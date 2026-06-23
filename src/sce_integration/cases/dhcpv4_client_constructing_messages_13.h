#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_13_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages13SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_13::
        dhcpv4_client_constructing_messages_13;

// CONSTRUCTING_MESSAGES_13 retransmission envelope — the SSOT for the spec
// backoff parameters. The positive and its _neg / _neg2 self-validations all
// derive from these so the envelope cannot drift across the three traits, and
// the SCXML interval windows ([3,5] s, [7,9] s) are hand-derived from
// kCm13RetxFirstMs ± jitter and 2*kCm13RetxFirstMs ± jitter. retry_count=4
// gives the firmware budget for the 3 spec-asserted DISCOVERs plus one margin.
inline constexpr std::uint8_t  kCm13RetryCount   = 4U;
inline constexpr std::uint16_t kCm13RetxFirstMs  = 4000U;
inline constexpr std::uint16_t kCm13RetxCapMs    = 64000U;
inline constexpr std::uint16_t kCm13RetxJitterMs = 1000U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages13SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages13SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_13";
    static constexpr std::string_view kDescription =
        "DUT uses randomized exponential backoff for DHCPDISCOVER "
        "retransmissions: first interval = 4 ± 1 s, second = 8 ± 1 s "
        "(RFC 2131 §4.1, SHOULD).";
    // Spec defaults — no fast-envelope compression. The envelope is the
    // cases::kCm13* SSOT (shared with _neg / _neg2 so it cannot drift).
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
            /*retx_jitter_ms=*/cases::kCm13RetxJitterMs);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages13SM,
                  dhcpv4_client_constructing_messages_13)
