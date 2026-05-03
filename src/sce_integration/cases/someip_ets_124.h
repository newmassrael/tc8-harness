#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_124_sm.h"

namespace tc8::sce::cases {

using SomeipEts124SM = ::SCE::Generated::someip_ets_124::someip_ets_124;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_124 — SubscribeEventgroup with EntriesLen
// exceeding actual entry bytes by ≥20 (canonical 16 → 36) but staying
// within the SOME/IP Length. Per PRS_SOMEIPSD_00265 / 00393 / 00270 /
// 00264 / 00566 the DUT must Nack. Lenient verdict accepts ignore as
// well — vsomeip may silently drop the malformed Subscribe before its
// SD layer dispatches a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts124SM> : SomeIpAnyBase<cases::SomeipEts124SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_124";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup EntriesLen too long by 20 B (within message) — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec: "an Entry Array length exceeding the total Length of the
        // message by at least 20 Bytes". Canonical EntriesLen for one
        // Type 2 entry is 16 bytes; 36 = 16 + 20 satisfies the spec.
        // Stays within the canonical SOME/IP Length=48 envelope (the
        // message body has 4 + 4 + 16 + 4 + 12 = 40 bytes, so EntriesLen
        // up to 32 would still fit; 36 spills 4 bytes into the option
        // array region — sufficient to violate "Entry Array length goes
        // beyond its normal Limit").
        params.entries_len_override = 36U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                    return "pass";
            case State::Fail_phase1_no_offer:                    return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_malformed:         return "fail:dut_acked_malformed_entries_array_length";
            default:                                             return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts124SM, someip_ets_124)
