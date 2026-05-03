#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_092_sm.h"

namespace tc8::sce::cases {

using SomeipEts092SM = ::SCE::Generated::someip_ets_092::someip_ets_092;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_092 — SD_Check_Reaction_to_a_Subscribe_with_ttl_0.
// Tester sends a unicast SubscribeEventgroup on eg 0x0002 with
// ttl == 0 (StopSubscribeEventgroup per SD §4.2). Per
// PRS_SOMEIPSD_00386 / 00387 / 00391 the DUT shall NOT respond.
// The phase 2 deadline is the pass terminal; any Type 0x07 entry
// on the subscribed eg within the listen window is a fail.
template <>
struct TestCaseTraits<cases::SomeipEts092SM> : SomeIpAnyBase<cases::SomeipEts092SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_092";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Subscribe ttl=0 (StopSubscribe) — DUT must not emit Ack/Nack";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        subscribe.ttl = 0;  // StopSubscribeEventgroup per SD §4.2
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                          return "pass";
            case State::Fail_phase1_no_offer_with_endpoint:            return "fail:no_offer_service_with_ipv4_endpoint_within_listen_window";
            case State::Fail_phase2_dut_responded_to_ttl_zero:         return "fail:dut_emitted_subscribe_response_for_ttl_zero_request";
            default:                                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts092SM, someip_ets_092)
