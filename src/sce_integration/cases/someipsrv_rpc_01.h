#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_01_sm.h"

namespace tc8::sce::cases {

using Rpc01SM = ::SCE::Generated::someipsrv_rpc_01::someipsrv_rpc_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.1 — single transport for all methods of SERVICE-ID-2.
// Stimulus: FindService for 0xF4E8 → wait for OfferService → Method
// Request to 0xF4E8 / METHOD-ID-1-SI-2 (0x08) on UDP port 30506
// (ets2.fdepl unreliable port).
template <>
struct TestCaseTraits<cases::Rpc01SM> : SomeIpAnyBase<cases::Rpc01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_01";
    static constexpr std::string_view kSpecSection = "5.1.5.7.1";
    static constexpr std::string_view kDescription =
        "Single UDP/TCP transport for all methods of SERVICE-ID-2";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::FindServiceTarget find{};
        find.service_id = ::tc8::someipsrv_si2::kServiceId;
        ::tc8::stimulus::emitFindServiceBoot(iface, find);

        ::tc8::stimulus::MethodRequestTarget target{};
        target.service_id = ::tc8::someipsrv_si2::kServiceId;
        target.method_id = ::tc8::someipsrv_si2::kMethodIdEcho;
        target.payload = {0x42};
        ::tc8::stimulus::MethodRequestDestination dest{};
        dest.port = 30506;  // SERVICE-ID-2 unreliable port (vsomeip-multi-service.json)
        ::tc8::stimulus::emitMethodRequestAfter(iface, target,
                                                ::tc8::stimulus::MethodRequestTiming{},
                                                dest);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_phase1_no_offer:
                return "fail:no_offer_service_for_service_id_2_within_listen_window";
            case State::Fail_phase2_no_response:
                return "fail:no_response_for_service_id_2_method_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc01SM, someipsrv_rpc_01)
