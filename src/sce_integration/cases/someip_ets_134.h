#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_134_sm.h"

namespace tc8::sce::cases {

using SomeipEts134SM = ::SCE::Generated::someip_ets_134::someip_ets_134;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_134 — SubscribeEventgroup whose SOME/IP
// Length field is shortened by 12 bytes (48 → 36) AND OptionsLen is
// shortened by the same 12 bytes (12 → 0), so the declared options
// array would end before the IPv4 Endpoint option that is still
// physically on-wire. Per PRS_SOMEIPSD_00274 / 00393 / PRS_SOMEIP_00042
// the DUT must Nack or ignore. Lenient verdict accepts both because
// vsomeip's `udp_server_endpoint_impl` typically silent-drops on the
// truncated SOME/IP Length before its SD layer dispatches a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts134SM> : SomeIpAnyBase<cases::SomeipEts134SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_134";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup SOME/IP Length + OptionsLen both cut — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec wording (Var A): SOME/IP Length cut from 60→48 (Δ=12)
        // AND Options Array length cut by the same 12 bytes (24→12).
        // Our 1-option canonical Subscribe is 56 B (Length=48, OptionsLen=12),
        // so the equivalent Δ=12 cut produces Length=36 + OptionsLen=0
        // while one IPv4 Endpoint option remains physically on-wire.
        params.length_override = 36U;
        params.options_len_override = 0U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_phase1_no_offer:                return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_malformed:     return "fail:dut_acked_malformed_options_array_length";
            default:                                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts134SM, someip_ets_134)
