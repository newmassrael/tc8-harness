#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_113_sm.h"

namespace tc8::sce::cases {

using SomeipEts113SM = ::SCE::Generated::someip_ets_113::someip_ets_113;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_113 — SubscribeEventgroup with options array
// length = 0 (canonical 12). Per PRS_SOMEIPSD_00265 / 00393 the DUT must
// Nack. Lenient verdict accepts silent ignore. Lift of ETS_134 with
// options_len_override = 0 (matches _134's wire shape exactly except the
// SOME/IP Length stays canonical here so the Endpoint option body remains
// physically on-wire but is logically excluded from the options array).
template <>
struct TestCaseTraits<cases::SomeipEts113SM> : SomeIpAnyBase<cases::SomeipEts113SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_113";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with options array length=0 — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // OptionsLen field = 0 (canonical 12). Walker reads 0 options
        // → entry's option references (#Opt1=1) point past the (empty)
        // options array → entry invalid → Nack or ignore.
        params.options_len_override = 0U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                   return "pass";
            case State::Fail_phase1_no_offer:                   return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_zero_options:     return "fail:dut_acked_empty_options_array";
            default:                                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts113SM, someip_ets_113)
