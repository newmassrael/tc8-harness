#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_028_sm.h"

namespace tc8::sce::cases {

using SomeipEts028SM = ::SCE::Generated::someip_ets_028::someip_ets_028;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_028 — echoUINT8Array round-trip. Tester
// sends a 32-bit BE length prefix (=3) followed by 3 UInt8 elements
// (0x42 0x43 0x44) to METHOD-ID 0x0009. DUT echoes the array back on
// the wire; SCXML pins payload_len == 7 + each byte position so a
// CommonAPI deserialisation/serialisation regression cannot mask a
// genuine echo. Method ID 0x0009 / 32-bit length width per ets.fdepl.
template <>
struct TestCaseTraits<cases::SomeipEts028SM> : SomeIpAnyBase<cases::SomeipEts028SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_028";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8Array round-trip — DUT echoes the 3-element UInt8 array";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0009;
        // CommonAPI UInt8[] wire shape with 32-bit BE length prefix:
        // [len_BE = 3] [0x42 0x43 0x44]. Length self-computed to
        // 8 + 7 = 15 in the SOME/IP header.
        target.payload = {0x00, 0x00, 0x00, 0x03, 0x42, 0x43, 0x44};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_array_echo_mismatch:   return "fail:echo_array_response_did_not_match_request";
            case State::Fail_phase2_no_response:           return "fail:no_method_response_within_listen_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts028SM, someip_ets_028)
