#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_047_sm.h"

namespace tc8::sce::cases {

using SomeipEts047SM = ::SCE::Generated::someip_ets_047::someip_ets_047;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_047 — echoUTF16FIXED with one additional
// byte AFTER the 64-byte fixed frame. Tester sends 65 raw payload
// bytes: ETS_046 baseline (BOM + 'h' + 'i' + UTF-16 null + 56 B zero
// padding) plus a trailing 0xFF. ets.fdepl pins
// SomeIpStringLengthWidth = 0 + SomeIpStringLength = 64, so CommonAPI
// reads exactly 64 bytes of string content; the 65th byte sits past
// the fixed frame and is discarded. DUT echoes the canonical 64-byte
// frame (without the trailing odd byte) per spec Pass Criteria
// "DUT: returns method response message with odd number after the
// termination and without the additional byte".
template <>
struct TestCaseTraits<cases::SomeipEts047SM> : SomeIpAnyBase<cases::SomeipEts047SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_047";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16FIXED odd-after-termination — DUT discards 65th byte and echoes canonical 64-byte frame";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0014;
        // 65 raw bytes: ETS_046 64-byte fixed frame + 1 trailing odd byte.
        target.payload = std::vector<uint8_t>(65, 0x00);
        target.payload[0]  = 0xFE;  // BOM hi
        target.payload[1]  = 0xFF;  // BOM lo
        target.payload[2]  = 0x00;  // 'h' hi
        target.payload[3]  = 0x68;  // 'h' lo
        target.payload[4]  = 0x00;  // 'i' hi
        target.payload[5]  = 0x69;  // 'i' lo
        // [6..7]   = 00 00 (UTF-16 null terminator)
        // [8..63]  = 0     (zero padding to 64 B fixed frame)
        target.payload[64] = 0xFF;  // 65th byte — past the fixed frame
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                      return "pass";
            case State::Fail_phase1_no_offer:                      return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_utf16_fixed_echo_mismatch:     return "fail:echo_utf16_fixed_response_did_not_match_request";
            case State::Fail_phase2_no_response:                   return "fail:no_method_response_within_listen_window";
            default:                                               return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts047SM, someip_ets_047)
