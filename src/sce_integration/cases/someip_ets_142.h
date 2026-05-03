#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_142_sm.h"

namespace tc8::sce::cases {

using SomeipEts142SM = ::SCE::Generated::someip_ets_142::someip_ets_142;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_142 — SubscribeEventgroup whose Major
// Version (0x09) does not match the DUT's declared 0x01. Per
// PRS_SOMEIPSD_00394 / 00393 the DUT must Nack. Lenient verdict
// accepts silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts142SM> : SomeIpAnyBase<cases::SomeipEts142SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_142";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with non-existing Major Version — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.target.major_version = 0x09;
        params.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_phase1_no_offer:                  return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_unknown_major:   return "fail:dut_acked_subscribe_for_unknown_major_version";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts142SM, someip_ets_142)
