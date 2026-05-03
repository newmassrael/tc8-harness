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

#include "someip_ets_167_sm.h"

namespace tc8::sce::cases {

using SomeipEts167SM = ::SCE::Generated::someip_ets_167::someip_ets_167;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_167 — TestFieldUINT8Array. Trigger DUT to
// send the field via getter (Method 0x28) + setter (Method 0x29). Per
// PRS_SOMEIPSD_00357 the DUT must echo the array value on get and set.
//
// Wire shape: 32-bit BE byte length prefix on both Request (set input) and
// Response (set output / get output) per ets.fdepl SomeIpArrayLengthWidth=4.
template <>
struct TestCaseTraits<cases::SomeipEts167SM> : SomeIpAnyBase<cases::SomeipEts167SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_167";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "TestFieldUINT8Array getter / setter / getter — DUT echoes set array";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getTestFieldUint8Array (Method 0x28) — empty Request payload.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x0028;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get1);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setTestFieldUint8Array (Method 0x29) — payload = 32-bit BE
        // length (4) + 4 bytes [0x11, 0x22, 0x33, 0x44].
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x0029;
        set.payload   = {0x00, 0x00, 0x00, 0x04,         // length 4 (BE)
                         0x11, 0x22, 0x33, 0x44};
        ::tc8::stimulus::emitMethodRequestAfter(iface, set);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getTestFieldUint8Array again — Response should echo the set
        // array (4 bytes 0x11..0x44 with the 4-byte length prefix).
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x0028;
        ::tc8::stimulus::emitMethodRequestAfter(iface, get2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                     return "pass";
            case State::Fail_phase1_no_offer:                     return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_initial_get:               return "fail:no_initial_get_array_response";
            case State::Fail_phase3_no_set_response:              return "fail:no_set_array_response";
            case State::Fail_phase4_no_post_set_get:              return "fail:no_post_set_get_array_response";
            default:                                              return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts167SM, someip_ets_167)
