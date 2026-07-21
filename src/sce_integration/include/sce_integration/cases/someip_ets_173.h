#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

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
    static constexpr std::string_view kDescription =
        "Unicast SubscribeEventgroup with two endpoint-option index/count configurations — DUT Acks both";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // eg 0x0002 is mixed-reliability, so a Subscribe needs one UDP and one
        // TCP endpoint option AND a held connection to the TCP endpoint. Hold the
        // session; the two options are the tester UDP endpoint (option 0, filled
        // by subscribeParams) and this session's held TCP endpoint (option 1,
        // canonical via reliableEndpointOption). The two phases reference those
        // two options through DIFFERENT index/count configurations — the DUT must
        // Ack both regardless of how the entry partitions the option references.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        const ::tc8::stimulus::Ipv4Endpoint tcp_option = session->reliableEndpointOption();
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;

        // Phase 1: index1=0, index2=1, #Opt1=1, #Opt2=1 — opt0 (UDP) via run 1,
        // opt1 (TCP) via run 2.
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0002;
        sub1.session_id = 0x0001;
        sub1.second_endpoint = tcp_option;
        sub1.index_first_options_override = std::uint8_t{0};
        sub1.index_second_options_override = std::uint8_t{1};
        sub1.num_options_first_override = std::uint8_t{1};
        sub1.num_options_second_override = std::uint8_t{1};
        session->subscribeParams(sub1, sd_dest);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        // Phase 2: index1=0, index2=0, #Opt1=2, #Opt2=0 — both options via run 1.
        ::tc8::stimulus::SubscribeEventgroupParams sub2{};
        sub2.target.eventgroup_id = 0x0002;
        sub2.session_id = 0x0002;
        sub2.second_endpoint = tcp_option;
        sub2.index_first_options_override = std::uint8_t{0};
        sub2.index_second_options_override = std::uint8_t{0};
        sub2.num_options_first_override = std::uint8_t{2};
        sub2.num_options_second_override = std::uint8_t{0};
        session->subscribeParams(sub2, sd_dest);

        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts173SM, someip_ets_173)
