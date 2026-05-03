#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_022_sm.h"

namespace tc8::sce::cases {

using SomeipEts022SM = ::SCE::Generated::someip_ets_022::someip_ets_022;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_022 — echoStaticUINT8Array round-trip.
// Tester sends 5 raw UInt8 bytes (no length prefix) to METHOD-ID
// 0x0036; DUT echoes the array back. Wire-format invariant per
// PRS_SOMEIP_00099/00100 — fixed-size arrays carry no length prefix
// (CommonAPI-SOMEIP achieves this with `SomeIpArrayLengthWidth = 0`
// + `SomeIpArrayMaxLength = 5`).
template <>
struct TestCaseTraits<cases::SomeipEts022SM> : SomeIpAnyBase<cases::SomeipEts022SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_022";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoStaticUINT8Array round-trip — 5-byte array without length prefix";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0036;
        // 5 raw UInt8 bytes, no length prefix. payload_len = 5.
        target.payload = {0x10, 0x11, 0x12, 0x13, 0x14};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                    return "pass";
            case State::Fail_phase1_no_offer:                    return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_static_array_echo_mismatch:  return "fail:echo_static_array_response_did_not_match_request";
            case State::Fail_phase2_no_response:                 return "fail:no_method_response_within_listen_window";
            default:                                             return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts022SM, someip_ets_022)
