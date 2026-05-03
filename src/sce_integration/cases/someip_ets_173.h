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

#include "someip_ets_173_sm.h"

namespace tc8::sce::cases {

using SomeipEts173SM = ::SCE::Generated::someip_ets_173::someip_ets_173;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_173 — Tester sends two unicast Subscribes
// each carrying TWO valid IPv4 Endpoint options but with DIFFERENT entry-
// to-options index/count configurations:
//   Phase 1: index1=0, index2=1, #Opt1=1, #Opt2=1 — entry references opt0
//            via run 1 + opt1 via run 2.
//   Phase 2: index1=0, index2=0, #Opt1=2, #Opt2=0 — entry references both
//            options via run 1.
// Per PRS_SOMEIPSD_00386 / 00387 / 00391 the DUT shall Ack both
// Subscribes regardless of how the entry partitions the option references.
template <>
struct TestCaseTraits<cases::SomeipEts173SM> : SomeIpAnyBase<cases::SomeipEts173SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_173";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Unicast SubscribeEventgroup with two endpoint-option index/count configurations — DUT Acks both";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // Two distinct-kind IPv4 Endpoint options (UDP + TCP) so the
        // walker treats them as canonical SOME/IP-SD multi-transport
        // Subscribe rather than rejecting "Multiple IPv4 endpoint options
        // of same kind" (vsomeip's `sdi::process_eventgroupentry` rejects
        // duplicate-kind references). Canonical first option (built by
        // emitSubscribeEventgroupRaw) is UDP; appended extra option is
        // TCP (l4proto=0x06) on the tester's reliable port (30501).
        const std::vector<std::uint8_t> tcp_body{
            0xAC, 0x10, 0x00, 0x03,  // 172.16.0.3 (tester)
            0x00,                     // reserved
            0x06,                     // l4proto = TCP
            0x77, 0x25,               // port = 30501 (BE)
            0x00                      // reserved tail (option body padding to 9 B)
        };

        // Phase 1: index1=0, index2=1, #Opt1=1, #Opt2=1.
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0002;
        sub1.session_id = 0x0001;
        sub1.index_first_options_override = std::uint8_t{0};
        sub1.index_second_options_override = std::uint8_t{1};
        sub1.num_options_first_override = std::uint8_t{1};
        sub1.num_options_second_override = std::uint8_t{1};
        sub1.extra_options.push_back({/*type=*/0x04, /*body=*/tcp_body, /*reserved=*/0});
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Phase 2: index1=0, index2=0, #Opt1=2, #Opt2=0.
        ::tc8::stimulus::SubscribeEventgroupParams sub2{};
        sub2.target.eventgroup_id = 0x0002;
        sub2.session_id = 0x0002;
        sub2.index_first_options_override = std::uint8_t{0};
        sub2.index_second_options_override = std::uint8_t{0};
        sub2.num_options_first_override = std::uint8_t{2};
        sub2.num_options_second_override = std::uint8_t{0};
        sub2.extra_options.push_back({/*type=*/0x04, /*body=*/tcp_body, /*reserved=*/0});
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

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts173SM, someip_ets_173)
