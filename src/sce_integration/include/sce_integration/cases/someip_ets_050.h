#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_050_sm.h"

namespace tc8::sce::cases {

using SomeipEts050SM = ::SCE::Generated::someip_ets_050::someip_ets_050;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_050 — UTF-8 mirror of ETS_041. First
// Request carries a valid 132-byte UTF-8 payload (string-length
// prefix 0x80 = 128 bytes follow, being EF BB BF BOM + 124 'H'
// chars + 1 B trailing null) and expects a canonical echo. Second
// Request reuses the same wire shape but corrupts the 4-byte
// string-length prefix to 0x02 — claims only 2 bytes follow, so
// CommonAPI's UTF-8 deserializer cannot find the trailing null
// within those 2 bytes -> errorOccurred_ -> Error Response
// (return_code 0x09 E_MALFORMED_MESSAGE).
template <>
struct TestCaseTraits<cases::SomeipEts050SM> : SomeIpAnyBase<cases::SomeipEts050SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_050";
    static constexpr std::string_view kDescription =
        "echoUTF8DYNAMIC two-step length-too-short — DUT echoes valid then rejects truncated";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        // 132-byte UTF-8 payload: 4 B length prefix + 128 B inner
        // (BOM EF BB BF + 124 'H' chars + 1 B trailing null).
        std::vector<std::uint8_t> wire(132, 0x00);
        // wire[0..3] inner string-length prefix — set per-request.
        wire[4] = 0xEF;  // UTF-8 BOM byte 0
        wire[5] = 0xBB;  // UTF-8 BOM byte 1
        wire[6] = 0xBF;  // UTF-8 BOM byte 2
        for (std::size_t i = 0; i < 124; ++i) {
            wire[7 + i] = 0x48;  // 'H'
        }
        wire[131] = 0x00;  // single trailing null

        // Step 1: valid string-length 0x80, session_id 0x0001.
        ::tc8::stimulus::SomeIpRpcMessage step1{};
        step1.method_id  = 0x0015;
        step1.session_id = 0x0001;
        step1.payload    = wire;
        step1.payload[0] = 0x00;
        step1.payload[1] = 0x00;
        step1.payload[2] = 0x00;
        step1.payload[3] = 0x80;
        ::tc8::stimulus::emitMethodRequestAfter(iface, step1, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Step 3: malformed string-length 0x02, session_id 0x0002.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        ::tc8::stimulus::SomeIpRpcMessage step3{};
        step3.method_id  = 0x0015;
        step3.session_id = 0x0002;
        step3.payload    = wire;
        step3.payload[0] = 0x00;
        step3.payload[1] = 0x00;
        step3.payload[2] = 0x00;
        step3.payload[3] = 0x02;
        ::tc8::stimulus::MethodRequestTiming step3_timing{};
        step3_timing.pre_emit_wait = std::chrono::milliseconds(0);
        ::tc8::stimulus::emitMethodRequestAfter(iface, step3, step3_timing, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts050SM, someip_ets_050)
