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

#include "tcp_call_receive_04_it2_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive04It2SM =
    ::SCE::Generated::tcp_call_receive_04_it2::tcp_call_receive_04_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallReceive04It2SM>
    : TcpAnyBase<cases::TcpCallReceive04It2SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // shutdownTcpWr / receiveTcp), so it is not measurable on a backend without
    // ITcpControl. The half-close is part of ITcpControl, not a bit of its own.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_04_IT2";
    static constexpr std::string_view kDescription  =
        "Iteration 2 of TCP_CALL_RECEIVE_04: a RECEIVE call made while the DUT is in "
        "FIN-WAIT-1 is handed four queued 32 B segments joined into one 128 B stream";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = kTcpCallReceive04Phase2LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        // Suppress the tester kernel's auto-ACK so the DUT data-ACKs emitted
        // during the 4-segment inject are NOT coalesced into a pure ACK that
        // would advance the DUT FW1->FW2. The drop scope spans the inject loop
        // and the seam receive (which blocks until the bytes are drained) - the
        // critical window - then lifts at function return; the FW1 sibling
        // TCP_CLOSING_07 holds the same rule via a scheduled keepalive instead.
        TesterAutoAckDrop ack_drop(cfg);

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;
        // Snapshot tester snd_nxt / rcv_nxt BEFORE shutdown so the FIN's
        // seq-number consumption isn't reflected in rcv_nxt. The returned
        // rcv_nxt = ISN_d + 1 (post-handshake, no FIN processed yet) is exactly
        // the DUT's SND.UNA after FIN egress, so it doubles as the
        // spec-acceptable "doesn't ack FIN" ack value.
        const auto seq = queryTcpSeqRange(tester_fd);
        if (!seq.has_value()) return;

        auto& tcp = seamTcpControl(ctx.dut);

        // shutdown(WR) - DUT emits FIN, socket EST->FW1; the read side stays open
        // so the seam receive still drains the queued bytes.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Receive in FW1: ack = rcv_nxt (= ISN_d + 1 = SND.UNA). Acceptable per
        // RFC 793 §3.4 (in [snd.una, snd.nxt)) but does NOT ack the DUT FIN - the
        // DUT stays in FW1 across the data inject window.
        std::vector<std::uint8_t> expected_payload;
        const auto received = tcp.receiveTcp(
            open.conn->socket, cases::kCallReceive04PayloadLen, [&] {
                expected_payload = cases::injectCallReceive04Segments(
                    cfg, ctx.iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xD0U);
            });
        c.ut_received_payload_len = cases::gradeCallReceive04(received, expected_payload);

        // Tester fd intentionally leaked through case end - closing would either
        // emit FIN (drives DUT FW1->CLOSING) or silentlyCloseTesterFd would
        // dispose the kernel socket so a DUT FIN re-tx draws closed-port RST.
        // Same rationale as TCP_CLOSING_07.
        (void)tester_fd;
        (void)ack_drop;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive04It2SM, tcp_call_receive_04_it2)
