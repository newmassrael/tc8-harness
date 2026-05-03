#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_051_sm.h"

namespace tc8::sce::cases {

using SomeipEts051SM = ::SCE::Generated::someip_ets_051::someip_ets_051;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_051 — DUT must reject (or silently ignore)
// an echoUTF8DYNAMIC Request whose SOME/IP Length header undershoots
// the actual UDP payload. Stimulus reuses the ETS_048 10-byte UTF-8
// baseline and sets `length_override = 0x0A` (claiming 10 bytes
// follow Length = 8 Request-ID-tail + 2 payload), while UDP carries
// 18. PRS_SOMEIP_00914 demands MALFORMED_MESSAGE; the lenient
// ETS_001/_002 pattern accepts Error Response, non-zero return_code,
// or silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts051SM> : SomeIpAnyBase<cases::SomeipEts051SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_051";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF8DYNAMIC length too short — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0015;
        target.payload = {
            0x00, 0x00, 0x00, 0x06,  // length prefix (BE)
            0xEF, 0xBB, 0xBF,        // UTF-8 BOM
            0x68,                    // 'h'
            0x69,                    // 'i'
            0x00,                    // trailing null terminator
        };
        target.length_override = 0x0Au;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_phase1_no_offer:                  return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_accepted_malformed:    return "fail:dut_returned_ok_response_for_undersized_length_field";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts051SM, someip_ets_051)
