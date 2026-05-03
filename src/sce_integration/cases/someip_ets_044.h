#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_044_sm.h"

namespace tc8::sce::cases {

using SomeipEts044SM = ::SCE::Generated::someip_ets_044::someip_ets_044;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_044 — echoUTF16DYNAMIC with odd byte
// AFTER termination. Tester sends a 13-byte payload whose 4-byte
// length prefix declares 9 bytes of UTF-16 BE string content, those
// 9 bytes being BOM + 'h' + 'i' + UTF-16 null + 1 trailing 0xFF.
// CommonAPI's InputStream walk-back loop
// (capicxx-someip-runtime InputStream.cpp:259-263) strips the
// trailing 0xFF until it finds the two consecutive zeros, exits at
// itsSize=8 (even), and parses "hi" cleanly. The DUT echo handler
// returns the C++ std::string("hi"), which CommonAPI re-serialises
// to the canonical ETS_039 wire shape (12 bytes, length prefix 8 +
// BOM + chars + null) — the trailing odd byte is dropped from the
// reply. Pass cond mirrors ETS_039.
template <>
struct TestCaseTraits<cases::SomeipEts044SM> : SomeIpAnyBase<cases::SomeipEts044SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_044";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC odd-after-termination — DUT walk-back strips trailing byte and echoes canonical \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0016;
        // Inner string length prefix declares 9 bytes; those 9 bytes are
        // BOM + 'h' + 'i' + null + 1 trailing odd byte. Walk-back strips
        // the odd byte, exits at itsSize=8, even -> parses cleanly.
        target.payload = {
            0x00, 0x00, 0x00, 0x09,  // length prefix (BE) — 9 bytes follow
            0xFE, 0xFF,              // BOM
            0x00, 0x68,              // 'h' UTF-16 BE
            0x00, 0x69,              // 'i' UTF-16 BE
            0x00, 0x00,              // UTF-16 null terminator
            0xFF,                    // trailing odd byte (walk-back strips)
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_phase1_no_offer:                return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_utf16_echo_mismatch:     return "fail:echo_utf16_response_did_not_match_request";
            case State::Fail_phase2_no_response:             return "fail:no_method_response_within_listen_window";
            default:                                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts044SM, someip_ets_044)
