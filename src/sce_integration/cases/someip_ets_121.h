#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_121_sm.h"

namespace tc8::sce::cases {

using SomeipEts121SM = ::SCE::Generated::someip_ets_121::someip_ets_121;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_121 — SD_Initial_Events_after_SubscribeEventgroup.
// Tester subscribes to eventgroup 0x05 on SERVICE-ID-1; DUT must Ack
// the Subscribe and emit at least one initial event/field for that
// eventgroup (PRS_SOMEIPSD_00386/00391). Wire shape mirrors ETS_087 —
// both cases stimulate Subscribe(eg 0x05) and observe MSB-set
// Notification on SERVICE-ID-1; spec wording differs but the
// observable invariant is the same.
template <>
struct TestCaseTraits<cases::SomeipEts121SM> : SomeIpAnyBase<cases::SomeipEts121SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_121";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Subscribe to eventgroup 0x05 — DUT Ack + initial fields per PRS_SOMEIPSD_00386";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0005;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_phase1_no_offer_with_endpoint:         return "fail:no_offer_service_with_ipv4_endpoint_within_listen_window";
            case State::Fail_phase2_subscribe_nacked:               return "fail:subscribe_eventgroup_nacked_ttl_zero";
            case State::Fail_phase2_no_subscribe_ack:               return "fail:no_subscribe_ack_within_listen_window";
            case State::Fail_phase3_no_initial_event:               return "fail:no_initial_event_with_method_msb_within_listen_window";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts121SM, someip_ets_121)
