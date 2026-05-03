#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_041_sm.h"

namespace tc8::sce::cases {

using SomeipEts041SM = ::SCE::Generated::someip_ets_041::someip_ets_041;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_041 — echoUTF16DYNAMIC two-step
// length-too-short test. First Request carries a valid 132-byte
// UTF-16 BE payload (string-length prefix 0x80 = 128 bytes follow,
// being BOM + 62 'H' UTF-16 BE chars + UTF-16 null) and expects a
// canonical echo. Second Request reuses the same wire shape but
// corrupts the 4-byte string-length prefix to 0x02 — claims only
// 2 bytes follow, so CommonAPI's deserializer reads only the BOM
// (no UTF-16 null pair within the 2-byte window) -> errorOccurred_
// -> Error Response (msg_type 0x81 + return_code 0x09
// E_MALFORMED_MESSAGE) per PRS_SOMEIP_00372 + PRS_SOMEIP_00087.
//
// SOME/IP Length stays self-consistent (140 = 8 header tail + 132
// payload) so the frame reaches CommonAPI; only the inner
// string-length prefix lies. Two emits use explicit session_id
// pinning (0x0001 valid + 0x0002 malformed) so the SCXML can
// verdict each Response separately.
template <>
struct TestCaseTraits<cases::SomeipEts041SM> : SomeIpAnyBase<cases::SomeipEts041SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_041";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF16DYNAMIC two-step length-too-short — DUT echoes valid then rejects truncated";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        // 132-byte UTF-16 BE payload: 4 B length prefix + 128 B inner
        // (BOM 2 + 62 'H' chars at 2 B each + UTF-16 null 2). Used
        // verbatim as the wire for both Requests; only bytes [0..3]
        // (the inner string-length prefix) differ.
        std::vector<std::uint8_t> wire(132, 0x00);
        // Inner string-length prefix (set per-request below).
        // wire[0..3] filled at emit time.
        wire[4] = 0xFE;  // BOM hi
        wire[5] = 0xFF;  // BOM lo
        for (std::size_t i = 0; i < 62; ++i) {
            wire[6 + 2 * i]     = 0x00;
            wire[6 + 2 * i + 1] = 0x48;  // 'H'
        }
        wire[130] = 0x00;
        wire[131] = 0x00;

        // Step 1: valid string-length prefix 0x80 (128 bytes follow),
        // session_id 0x0001 -> DUT echoes the canonical 132-byte payload.
        ::tc8::stimulus::MethodRequestTarget step1{};
        step1.method_id  = 0x0016;
        step1.session_id = 0x0001;
        step1.payload    = wire;
        step1.payload[0] = 0x00;
        step1.payload[1] = 0x00;
        step1.payload[2] = 0x00;
        step1.payload[3] = 0x80;
        ::tc8::stimulus::emitMethodRequestAfter(iface, step1);

        // Step 3: same wire bytes but string-length prefix corrupted
        // to 0x02 (claims 2 bytes follow), session_id 0x0002 -> DUT
        // must reject (or silently ignore). Brief gap so the first
        // Response lands on pcap before the second Request perturbs
        // vsomeip's session-id state.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        ::tc8::stimulus::MethodRequestTarget step3{};
        step3.method_id  = 0x0016;
        step3.session_id = 0x0002;
        step3.payload    = wire;
        step3.payload[0] = 0x00;
        step3.payload[1] = 0x00;
        step3.payload[2] = 0x00;
        step3.payload[3] = 0x02;
        ::tc8::stimulus::MethodRequestTiming step3_timing{};
        step3_timing.pre_emit_wait = std::chrono::milliseconds(0);
        ::tc8::stimulus::emitMethodRequestAfter(iface, step3, step3_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_phase1_no_offer:                  return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_valid_echo:             return "fail:dut_did_not_echo_valid_first_request";
            case State::Fail_phase3_dut_accepted_malformed:    return "fail:dut_returned_ok_response_for_truncated_inner_string_length";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts041SM, someip_ets_041)
