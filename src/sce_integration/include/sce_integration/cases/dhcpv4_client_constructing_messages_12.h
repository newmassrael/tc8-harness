#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_12_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages12SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_12::
        dhcpv4_client_constructing_messages_12;

// CONSTRUCTING_MESSAGES_12 fast-envelope backoff parameters — the SSOT shared
// with the _neg self-validation so the envelope cannot drift across the two
// traits. retry_count=8 gives the SCXML budget to observe the cap-doubling
// fixpoint at the 6th DISCOVER; cap=3200 ms is the harness-pinned saturation
// ceiling (real-spec 64 000 ms blows the smoke budget).
inline constexpr std::uint8_t  kCm12RetryCount   = 8U;
inline constexpr std::uint16_t kCm12RetxFirstMs  = 200U;
inline constexpr std::uint16_t kCm12RetxCapMs    = 3200U;
inline constexpr std::uint16_t kCm12RetxJitterMs = 100U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages12SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages12SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_12";
    static constexpr std::string_view kDescription =
        "DUT retransmits DHCPDISCOVER on doubling backoff capped at "
        "an upper bound (RFC 2131 §4.1, MUST). Fast-envelope cap = "
        "3200 ms; SCXML observes the cap-doubling fixpoint at the 6th "
        "DISCOVER.";
    // 3-arg stimulus: kick the lifecycle with retry_count=8 (enough for
    // SCXML to observe the cap interval at DISCOVER 6) and the fast-
    // envelope backoff knobs. Tester emits no OFFER, so the DUT runs
    // out the full retry budget on inter-DISCOVER waits.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::Dhcpv4StartConfig sc;
        sc.retry_count = cases::kCm12RetryCount;
        sc.retry_interval_ms = 0U;
        sc.retx_first_ms = cases::kCm12RetxFirstMs;
        sc.retx_cap_ms = cases::kCm12RetxCapMs;
        sc.retx_jitter_ms = cases::kCm12RetxJitterMs;
        ::tc8::sce::dhcpv4::emitStartDhcpClient(cfg, iface, cfg.dut.mac, sc);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages12SM,
                  dhcpv4_client_constructing_messages_12)
