#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_176_sm.h"

namespace tc8::sce::cases {

using SomeipEts176SM = ::SCE::Generated::someip_ets_176::someip_ets_176;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_176 — SubscribeEventgroup with extra payload
// bytes appended after the Options Array. Two phases per spec:
//   1. Extra payload bytes 0x30 0x30 0x3A 0x30 0x31 ARE counted by the
//      SOME/IP Length field — DUT should Ack.
//   2. Same extra bytes but NOT counted by the SOME/IP Length field —
//      DUT should still Ack.
// Per PRS_SOMEIPSD_00153 / 00273 the DUT shall ignore the trailing bytes.
template <>
struct TestCaseTraits<cases::SomeipEts176SM> : SomeIpAnyBase<cases::SomeipEts176SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_176";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with trailing payload (counted + uncounted) — DUT Acks both";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // Phase 1: trailing 5 bytes COUNTED by SOME/IP Length.
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0002;
        sub1.session_id = 0x0001;
        sub1.extra_trailing_payload = std::vector<std::uint8_t>{0x30, 0x30, 0x3A, 0x30, 0x31};
        sub1.extra_trailing_in_length = true;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Phase 2: trailing 5 bytes NOT counted by SOME/IP Length.
        ::tc8::stimulus::SubscribeEventgroupParams sub2{};
        sub2.target.eventgroup_id = 0x0002;
        sub2.session_id = 0x0002;
        sub2.extra_trailing_payload = std::vector<std::uint8_t>{0x30, 0x30, 0x3A, 0x30, 0x31};
        sub2.extra_trailing_in_length = false;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_phase1_no_offer:                       return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_first_ack:                   return "fail:no_first_subscribe_ack_within_listen_window";
            case State::Fail_phase3_no_second_ack:                  return "fail:no_second_subscribe_ack_within_listen_window";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts176SM, someip_ets_176)
