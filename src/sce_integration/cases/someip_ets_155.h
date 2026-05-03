#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_155_sm.h"

namespace tc8::sce::cases {

using SomeipEts155SM = ::SCE::Generated::someip_ets_155::someip_ets_155;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_155 — Subscribe / StopSubscribe / Subscribe
// chain on eg 0x0002. Per PRS_SOMEIPSD_00263 / 00386 the DUT shall Ack
// both Subscribes and silently accept the Stop. Stimulus paces the three
// SD emits ~1 s apart so vsomeip emits two distinct Acks rather than
// bundling them within one cyclic SD response window.
template <>
struct TestCaseTraits<cases::SomeipEts155SM> : SomeIpAnyBase<cases::SomeipEts155SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_155";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Subscribe → StopSubscribe → Subscribe — DUT Acks both subscribes";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // First Subscribe (Sub_1).
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0002;
        sub1.target.ttl = 3;
        sub1.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // StopSubscribe (ttl == 0 per SD §4.2).
        ::tc8::stimulus::SubscribeEventgroupParams stop{};
        stop.target.eventgroup_id = 0x0002;
        stop.target.ttl = 0;
        stop.session_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, stop);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Second Subscribe (Sub_2).
        ::tc8::stimulus::SubscribeEventgroupParams sub2{};
        sub2.target.eventgroup_id = 0x0002;
        sub2.target.ttl = 3;
        sub2.session_id = 0x0003;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                          return "pass";
            case State::Fail_phase1_no_offer:                          return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_first_ack:                      return "fail:no_first_subscribe_ack_within_listen_window";
            case State::Fail_phase3_no_second_ack:                     return "fail:no_second_subscribe_ack_after_stop_within_listen_window";
            default:                                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts155SM, someip_ets_155)
