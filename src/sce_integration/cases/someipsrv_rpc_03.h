#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_03_sm.h"

namespace tc8::sce::cases {

using Rpc03SM = ::SCE::Generated::someipsrv_rpc_03::someipsrv_rpc_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.3 — Field getter is a request/response call with
// empty request payload and the field value in the response payload.
// Targets the fieldA getter (METHOD-ID-GET-SI-1 = 0x40, declared in
// dut/ets/ets.fdepl). Empty request payload is the natural default of
// MethodRequestTarget; CommonAPI's StubDefault stores the field's
// initial value (0) and serves the getter from there until a setter
// overwrites it.
template <>
struct TestCaseTraits<cases::Rpc03SM> : SomeIpAnyBase<cases::Rpc03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_03";
    static constexpr std::string_view kSpecSection = "5.1.5.7.3";
    static constexpr std::string_view kDescription =
        "Field getter — empty Request payload returns Response with field value";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0040;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_phase1_no_offer:       return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_response:    return "fail:no_getter_response_within_listen_window";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc03SM, someipsrv_rpc_03)
