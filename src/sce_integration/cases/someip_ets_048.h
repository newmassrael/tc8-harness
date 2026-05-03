#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_048_sm.h"

namespace tc8::sce::cases {

using SomeipEts048SM = ::SCE::Generated::someip_ets_048::someip_ets_048;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_048 — echoUTF8DYNAMIC round-trip. Tester
// sends a CommonAPI-SOMEIP UTF-8 dynamic string for ASCII "hi" to
// METHOD-ID 0x0015. The on-wire shape is `[len_BE Uint32][BOM EF BB BF]
// [char bytes][0x00]` = 10 bytes total. The trailing single null byte
// is mandatory per CommonAPI's InputStream UTF-8 path
// (capicxx-someip-runtime InputStream.cpp:251 — "if (data[itsSize - 1]
// != 0x00) errorOccurred_ = true"). ets.fdepl pins
// `SomeIpStringEncoding = utf8` + `SomeIpStringLengthWidth = 4`.
template <>
struct TestCaseTraits<cases::SomeipEts048SM> : SomeIpAnyBase<cases::SomeipEts048SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_048";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF8DYNAMIC round-trip — DUT echoes UTF-8 BOM-prefixed \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0015;
        // 32-bit BE byte length prefix (= BOM 3 + 'h' + 'i' + null = 6),
        // UTF-8 BOM, 'h', 'i', single trailing null.
        target.payload = {
            0x00, 0x00, 0x00, 0x06,  // length prefix (BE)
            0xEF, 0xBB, 0xBF,        // UTF-8 BOM
            0x68,                    // 'h'
            0x69,                    // 'i'
            0x00,                    // trailing null terminator
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_phase1_no_offer:                       return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_utf8_dynamic_echo_mismatch:     return "fail:echo_utf8_dynamic_response_did_not_match_request";
            case State::Fail_phase2_no_response:                    return "fail:no_method_response_within_listen_window";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts048SM, someip_ets_048)
