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

#include "someip_ets_168_sm.h"

namespace tc8::sce::cases {

using SomeipEts168SM = ::SCE::Generated::someip_ets_168::someip_ets_168;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_168 — TestFieldUINT8Reliable. Trigger DUT to
// send the UInt8 field via getter (Method 0x2A) + setter (Method 0x2B)
// over TCP (SomeIpReliable=true). Per PRS_SOMEIPSD_00362 the DUT shall
// respond on the reliable transport with the current / set value.
//
// Reliable Method Request goes to the DUT's TCP unicast endpoint
// (SomeIpReliableUnicastPort = 30501). Tester opens a fresh SOCK_STREAM
// per emit via `emitMethodRequestTcpAfter`; vsomeip dispatches the
// Response on the same socket.
template <>
struct TestCaseTraits<cases::SomeipEts168SM> : SomeIpAnyBase<cases::SomeipEts168SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_168";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "TestFieldUINT8Reliable getter / setter / getter — DUT responds over TCP";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // 1. getTestFieldUint8Reliable (Method 0x2A) over TCP.
        ::tc8::stimulus::MethodRequestTarget get1{};
        get1.method_id = 0x002A;
        ::tc8::stimulus::MethodRequestDestination tcp_dest{};
        tcp_dest.port = 30501U;  // SomeIpReliableUnicastPort per ets.fdepl
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, get1,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 2. setTestFieldUint8Reliable(0x99) (Method 0x2B) over TCP.
        ::tc8::stimulus::MethodRequestTarget set{};
        set.method_id = 0x002B;
        set.payload   = {0x99};
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, set,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 3. getTestFieldUint8Reliable again — Response should echo 0x99.
        ::tc8::stimulus::MethodRequestTarget get2{};
        get2.method_id = 0x002A;
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, get2,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   tcp_dest);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_phase1_no_offer:                       return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_initial_get:                 return "fail:no_initial_get_reliable_response";
            case State::Fail_phase3_no_set_response:                return "fail:no_set_reliable_response";
            case State::Fail_phase4_no_post_set_get:                return "fail:no_post_set_get_reliable_response";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts168SM, someip_ets_168)
