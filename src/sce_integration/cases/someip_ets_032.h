#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_032_sm.h"

namespace tc8::sce::cases {

using SomeipEts032SM = ::SCE::Generated::someip_ets_032::someip_ets_032;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_032 — echoUINT8ArrayMinSize happy-path.
// Tester sends a 4-element array (within the spec-defined 3..5 range)
// with 32-bit BE length prefix to METHOD-ID 0x0037. DUT echoes the
// array back. ETS_033 sends a too-short array on the same method ID.
template <>
struct TestCaseTraits<cases::SomeipEts032SM> : SomeIpAnyBase<cases::SomeipEts032SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_032";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8ArrayMinSize round-trip — 4-element array within 3..5 range";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0037;
        // CommonAPI UInt8[] with 32-bit BE length prefix:
        // [len_BE = 0x00000004] [0x10 0x11 0x12 0x13]. payload_len = 8.
        target.payload = {0x00, 0x00, 0x00, 0x04, 0x10, 0x11, 0x12, 0x13};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_array_echo_mismatch:   return "fail:echo_arraymin_response_did_not_match_request";
            case State::Fail_phase2_no_response:           return "fail:no_method_response_within_listen_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts032SM, someip_ets_032)
