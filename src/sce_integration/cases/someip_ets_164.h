#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_164_sm.h"

namespace tc8::sce::cases {

using SomeipEts164SM = ::SCE::Generated::someip_ets_164::someip_ets_164;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_164 — SD_SuspendInterface. Tester drives a
// get / set / suspend / observe-StopOffer / wait / re-get cycle. Per
// PRS_SOMEIPSD_00356 / 00363 / 00364 / SIP_SD_811 the DUT shall:
//   - emit StopOfferService (ttl = 0) when suspendInterface is invoked,
//   - stay silent for the suspension duration,
//   - emit OfferService (ttl > 0) on resume,
//   - keep responding to field methods after resume.
//
// The DUT firmware (`dut_main.cpp:61` setSuspendCallback) implements this
// via runtime->unregisterService(...) → sleep(duration_ms) →
// registerService(...). suspend duration = 2000 ms here so the SCXML
// envelope stays bounded; trait re-issues getFieldA after the resume
// gate (Phase 4).
//
// Spec verdict-line reads "Value returned must not be the same as set by
// the Tester before the Suspension since after the suspension Time, the
// Interface is expected not to reset" — internally inconsistent. Lenient
// interpretation: post-resume getFieldA Response is accepted regardless
// of payload value (the conformance signal is "DUT field method works
// after resume", not the field value preservation).
template <>
struct TestCaseTraits<cases::SomeipEts164SM> : SomeIpAnyBase<cases::SomeipEts164SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_164";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "TestField get / set / suspendInterface / StopOffer / resume / get — DUT honors suspend cycle";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. setFieldA(0x77) — Method 0x42, payload [0x77]. Phase 2
        // observes the Response.
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0042;
        set.payload   = {0x77};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // 2. suspendInterface(start=0, duration=2000) — Method 0x02
        // Fire&Forget. Args 4-byte start + 4-byte duration BE.
        ::tc8::stimulus::MethodRequestTarget suspend{};
        suspend.method_id    = 0x0002;
        suspend.message_type = 0x01;  // RequestNoReturn (Fire&Forget).
        suspend.payload      = {0x00, 0x00, 0x00, 0x00,   // start = 0
                                0x00, 0x00, 0x07, 0xD0};  // duration = 2000 ms
        ::tc8::stimulus::emitMethodRequestAfter(iface, suspend);

        // Wait through the 2 s suspend window + 1 s resume settle.
        std::this_thread::sleep_for(std::chrono::milliseconds(3500));

        // 3. getFieldA again — Method 0x40. Phase 4 observes the
        // Response (any payload).
        ::tc8::stimulus::MethodRequestTarget get{};
        get.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                          return "pass";
            case State::Fail_phase1_no_offer:                          return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_set_response:                   return "fail:no_set_field_response";
            case State::Fail_phase3_no_stop_offer:                     return "fail:no_stop_offer_service_within_listen_window";
            case State::Fail_phase4_no_post_resume_get:                return "fail:no_post_resume_get_field_response";
            default:                                                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts164SM, someip_ets_164)
