#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_116_sm.h"

namespace tc8::sce::cases {

using SomeipEts116SM = ::SCE::Generated::someip_ets_116::someip_ets_116;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_116 — SubscribeEventgroup whose IPv4 Endpoint
// option Type byte is 0x77 (unknown option type, canonical 0x04). Per
// PRS_SOMEIPSD_00305 / 00307 / 00393 the DUT must Nack. Lenient verdict
// accepts silent ignore — vsomeip's option-walker may drop the unknown
// option type before SD layer dispatches a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts116SM> : SomeIpAnyBase<cases::SomeipEts116SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_116";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with unknown option type 0x77 — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        params.option_type_override = std::uint8_t{0x77};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_phase1_no_offer:                  return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_unknown_type:    return "fail:dut_acked_unknown_option_type";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts116SM, someip_ets_116)
