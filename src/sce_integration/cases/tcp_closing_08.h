#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_08_sm.h"

namespace tc8::sce::cases {

using TcpClosing08SM = ::SCE::Generated::tcp_closing_08::tcp_closing_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing08SM>
    : TcpAnyBase<cases::TcpClosing08SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_08";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-2 state MUST honour RECEIVE calls and ACK "
        "incoming data while remaining in FIN-WAIT-2 (RFC 793 §3.5 "
        "p38 Closing a Connection)";

    // 16-byte payload pattern. Distinct byte from sibling _03 (0xA5), _07
    // (0x69), _09 (0x5A) so a pcap reader can attribute a stray
    // segment to the correct case ID.
    static constexpr std::uint16_t kPayloadLen = 16U;

    // Single iteration, backend-agnostic (opcode UT or AUTOSAR testability).
    // Seam active-OPEN on +74 quad → snapshot tester snd_nxt / rcv_nxt → DUT
    // half-close (shutdownTcpWr → FIN, read side open) → the tester kernel
    // auto-ACKs the FIN (NO AckDrop) so the DUT advances FW1 → FW2 → seam
    // receive whose trigger raw-injects 16-byte data with ack=ISN_d+2 (acks
    // the DUT FIN, a benign duplicate since the kernel already acked) → the
    // DUT in FW2 drains the queued bytes back through the seam and emits a
    // pure data ACK → byte-match populates captured.ut_received_payload_len.
    // captured.expected_ack_num pre-set to the spec-conformant DUT ACK number
    // (ISN_t + 1 + kPayloadLen) so the SCXML guard checks the data ACK is for
    // our data, and the 3 s remain-in-FW2 absence asserts no DUT FIN/RST.
    //
    // Half-close (shutdownTcpWr) — not a full close (closeTcp): a full close
    // would drop the DUT socket so the subsequent receive returns nothing, and
    // Linux's tcp_data_queue would RST the incoming data because the user side
    // is closed — both breaking the "remain in FW2 / DUT receives proper data"
    // assertions. The FW1 sibling _07 is the half-close worked example.
    //
    // Tester fd intentionally left open so the kernel socket stays alive in CW
    // (after receiving the DUT FIN). Closing it via ::close would emit a tester
    // FIN → DUT FW2 → TIME-WAIT (breaks "remain in FW2"); silentlyCloseTesterFd
    // would dispose the socket so any DUT segment to the 4-tuple draws a
    // closed-port RST. The per-case harness process exits at case end, cleaning
    // the fd up. Unlike _07 there is no long-life AckDrop to hold alive, so no
    // IStimulusScheduler is taken.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 74U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        auto& tcp = seamTcpControl(dut);

        // Half-close: shutdown(SHUT_WR) → DUT emits FIN, socket EST→FW1. The
        // tester kernel's auto-ACK (NOT suppressed) acks the FIN and drives the
        // DUT FW1→FW2.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const std::vector<std::uint8_t> payload(kPayloadLen, 0x3CU);

        // Receive in FW2: the trigger raw-injects the 16-byte data segment with
        // ack=ISN_d+2 (post-FIN; a benign duplicate ack since the kernel
        // already acked), then the seam returns what the DUT received.
        const auto received = tcp.receiveTcp(
            open.conn->socket, kPayloadLen, [&] {
                ::tc8::stimulus::TcpSegmentSpec data{};
                data.src_port = remote_port;
                data.dst_port = local_port;
                data.seq_num  = seq_range->snd_nxt;          // ISN_t + 1
                data.ack_num  = seq_range->rcv_nxt + 1U;     // ISN_d + 2, acks DUT FIN
                data.flags    = ::tc8::stimulus::kTcpFlagAck
                              | ::tc8::stimulus::kTcpFlagPsh;
                data.payload  = payload;
                emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });
        if (received && *received == payload) {
            c.ut_received_payload_len = kPayloadLen;
        }

        // Spec-conformant DUT ack to our data: ack_num = tester snd_nxt
        // (ISN_t+1) + kPayloadLen. Same shape as _07.
        c.expected_ack_num = seq_range->snd_nxt + kPayloadLen;

        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing08SM, tcp_closing_08)
