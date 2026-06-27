#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_037_sm.h"

namespace tc8::sce::cases {

using SomeipEts037SM = ::SCE::Generated::someip_ets_037::someip_ets_037;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_037 — DUT must NOT tear down an
// established TCP reliable connection when a tester-side
// `resetInterface` (METHOD-ID-FIRE-FORGET-SI-1 = 0x0001, msg_type
// 0x01) is delivered over UDP. Stimulus shape:
//   1. emitFindServiceBoot — DUT enters OfferService cycle.
//   2. emitMethodRequestTcpAndHold — opens TCP socket, sends
//      echoUINT8RELIABLE Method Request (method_id 0x000A), dwells
//      1 s so the DUT can deliver the Response on the same
//      connection. Returns the connected fd to the trait.
//   3. emitMethodRequestAfter — fires a fire-and-forget
//      resetInterface UDP datagram (msg_type 0x01) at the DUT.
//   4. Sleep 5 s — observation window; if the DUT honors the reset
//      with a connection teardown, the kernel records the resulting
//      FIN as TCP_CLOSE_WAIT on the tester-side socket.
//   5. getTcpPeerStateAndClose — reads `getsockopt(TCP_INFO).
//      tcpi_state` and writes it to `captured.tcp_peer_state` for
//      the SCXML phase 3 verdict transition.
//
// Pass (phase 3): captured.tcp_peer_state == 1 (TCP_ESTABLISHED) —
// DUT did not emit FIN. Fail (phase 3): anything else (typically
// TCP_CLOSE_WAIT = 8) — DUT closed the connection.
template <>
struct TestCaseTraits<cases::SomeipEts037SM> : SomeIpAnyBase<cases::SomeipEts037SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_037";
    static constexpr std::string_view kDescription =
        "DUT must not close TCP reliable connection when service is stopped";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::MethodRequestTarget tcp_target{};
        tcp_target.method_id = 0x000A;  // echoUINT8RELIABLE
        tcp_target.payload = {0x42};
        const auto tcp_dest = ::tc8::sce::someipTcpMethodDest(cfg);
        const int fd = ::tc8::stimulus::emitMethodRequestTcpAndHold(
            iface, tcp_target, tcp_dest,
            std::chrono::milliseconds(500),    // pre-emit wait
            std::chrono::milliseconds(1000));  // dwell so DUT replies
        if (fd < 0) {
            // Connection or send failed — leave tcp_peer_state at 0;
            // SCXML phase 3 will trip fail_phase3_dut_emitted_fin so
            // the failure surfaces in the verdict instead of being
            // silently masked. Phase 2 would fail first if no
            // Response arrived.
            return;
        }

        ::tc8::stimulus::MethodRequestTarget reset_target{};
        reset_target.method_id = 0x0001;     // resetInterface (fire&forget).
        reset_target.message_type = 0x01;    // RequestNoReturn — no Response expected.
        ::tc8::stimulus::MethodRequestTiming reset_timing{};
        reset_timing.pre_emit_wait = std::chrono::milliseconds(0);
        ::tc8::stimulus::emitMethodRequestAfter(iface, reset_target, reset_timing, ::tc8::sce::someipUdpMethodDest(cfg));

        // Observation window — the spec failure shape is the DUT
        // emitting FIN on the held TCP connection in response to the
        // resetInterface stimulus. 2 s catches any reasonable teardown
        // latency (Linux kernel emits FIN within ms of socket close;
        // a vsomeip-side teardown also arrives well under a second)
        // without bloating total stimulus wall-time past the smoke-
        // test wait_budget envelope.
        std::this_thread::sleep_for(std::chrono::seconds(2));

        std::uint8_t tcp_state = 0;
        ::tc8::stimulus::getTcpPeerStateAndClose(fd, &tcp_state);
        c.tcp_peer_state = tcp_state;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts037SM, someip_ets_037)
