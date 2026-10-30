#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_call_receive_04_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_call_receive_04_it3_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive04It3SM =
    ::SCE::Generated::tcp_call_receive_04_it3::tcp_call_receive_04_it3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallReceive04It3SM>
    : TcpAnyBase<cases::TcpCallReceive04It3SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // shutdownTcpWr / receiveTcp), so it is not measurable on a backend without
    // ITcpControl. The half-close is part of ITcpControl, not a bit of its own.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_04_IT3";
    static constexpr std::string_view kDescription  =
        "Iteration 3 of TCP_CALL_RECEIVE_04: a RECEIVE call made while the DUT is in "
        "FIN-WAIT-2 is handed four queued 32 B segments joined into one 128 B stream";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = kTcpCallReceive04Phase3LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        auto& tcp = seamTcpControl(ctx.dut);

        // shutdown(WR) -> DUT FIN -> tester kernel auto-ACK (no AckDrop) -> DUT
        // FW1->FW2. The auto-ACK consumes the FIN sequence number so the tester
        // rcv_nxt advances past ISN_d + 1.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        const auto seq = queryTcpSeqRange(tester_fd);
        if (!seq.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        // Receive in FW2: ack = rcv_nxt (= ISN_d + 2, post-FIN) already acks the
        // DUT FIN - DUT.snd.una = rcv_nxt. The data segments are accepted
        // regardless of FIN-ack semantics; the DUT stays in FW2 across the
        // inject window.
        std::vector<std::uint8_t> expected_payload;
        const auto received = tcp.receiveTcp(
            open.conn->socket, cases::kCallReceive04PayloadLen, [&] {
                expected_payload = cases::injectCallReceive04Segments(
                    cfg, ctx.iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xE0U);
            });
        c.ut_received_payload_len = cases::gradeCallReceive04(received, expected_payload);

        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive04It3SM, tcp_call_receive_04_it3)
