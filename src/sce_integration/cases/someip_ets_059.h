#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_059_sm.h"

namespace tc8::sce::cases {

using SomeipEts059SM = ::SCE::Generated::someip_ets_059::someip_ets_059;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_059 — ResetInterface wrong Fire&Forget
// receives no Error back. Tester sends `resetInterface` (METHOD-ID-
// FIRE-FORGET-SI-1 = 0x0001) as Fire&Forget (msg_type 0x01) with
// interface_version = 0xFF (mismatched against the DUT's declared
// version 0x01). Per PRS_SOMEIP_00701 / 00170 / 00171 / 00189 the
// DUT shall NOT emit any response — neither a method response nor
// an error message — because Fire&Forget Requests do not warrant a
// reply even on header validation failure (the Forget half is
// load-bearing). Pass Criteria: "DUT doesn't answer and does not
// send an error message". The phase 2 deadline is the success
// terminal; any frame on method 0x0001 within the listen window is
// a fail.
template <>
struct TestCaseTraits<cases::SomeipEts059SM> : SomeIpAnyBase<cases::SomeipEts059SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_059";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "resetInterface Fire&Forget with wrong interface_version — DUT must stay silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id         = 0x0001;  // resetInterface (METHOD-ID-FIRE-FORGET-SI-1).
        target.message_type      = 0x01;    // RequestNoReturn (Fire&Forget) per SOME/IP §4.7.4.
        target.interface_version = 0xFF;    // Wrong version — DUT declares 0x01.
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                   return "pass";
            case State::Fail_phase1_no_offer:                   return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_responded_to_fire_forget:
                                                                return "fail:dut_emitted_response_to_wrong_interface_version_fire_forget";
            default:                                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts059SM, someip_ets_059)
