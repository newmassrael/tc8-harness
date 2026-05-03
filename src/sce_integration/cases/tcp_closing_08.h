#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-2 state MUST honour RECEIVE calls and ACK "
        "incoming data while remaining in FIN-WAIT-2 (RFC 793 §3.5 "
        "p38 Closing a Connection)";

    // 16-byte payload pattern. Distinct byte from §_03 (0xA5), §_07
    // (0x69), §_09 (0x5A) so a pcap reader can attribute a stray
    // segment to the correct case ID.
    static constexpr std::uint16_t kPayloadLen = 16U;
    static constexpr std::uint16_t kUtRecvTimeoutMs = 2000U;

    // Single iteration. Active-OPEN handshake on +74 quad → snapshot
    // tester snd_nxt / rcv_nxt → UT shutdown(WR) → DUT FIN+ACK; tester
    // kernel auto-ACKs (NO AckDrop) → DUT transitions FW1 → FW2 → raw
    // inject 16 B PSH+ACK with ack=ISN_d+2 (acks DUT FIN, benign
    // duplicate since kernel already acked) → DUT in FW2 emits pure
    // ACK → UT receive drains data → byte-match → 3 s remain-in-FW2
    // absence asserts no DUT FIN/RST.
    //
    // Tester fd intentionally left open so the kernel socket stays
    // alive in CW (after receiving DUT FIN). Closing it via
    // silentlyCloseTesterFd would dispose the socket and any
    // subsequent DUT segment to the 4-tuple would draw closed-port
    // RST from tester kernel; closing via ::close would emit tester
    // FIN → DUT FW2→TIME-WAIT (breaks "remain in FW2"). Per-case
    // harness process exits at case end so the fd is cleaned up.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 74U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // shutdown(WR) — kernel emits FIN. Tester kernel's auto-ACK
        // (NOT suppressed) drives DUT FW1→FW2.
        sendShutdownTcpSocketWrRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        std::vector<std::uint8_t> payload(kPayloadLen, 0x3CU);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;          // ISN_t + 1
        // ack=ISN_d+2 (post-FIN). Kernel already acked so this is a
        // benign duplicate ack; DUT in FW2 has snd_una=ISN_d+2 so
        // tcp_ack treats it as a duplicate and processes the data
        // segment normally.
        data.ack_num  = seq_range->rcv_nxt + 1U;
        data.flags    = ::tc8::stimulus::kTcpFlagAck
                      | ::tc8::stimulus::kTcpFlagPsh;
        data.payload  = payload;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto bytes = queryReceivedBytesSync(
            cfg, /*req_id=*/3, /*socket_id=*/1,
            kPayloadLen, kUtRecvTimeoutMs);
        if (bytes.size() == payload.size()
            && std::equal(bytes.begin(), bytes.end(), payload.begin())) {
            c.ut_received_payload_len = kPayloadLen;
        }

        // Spec-conformant DUT ack to our data: ack_num = tester
        // snd_nxt (ISN_t+1) + kPayloadLen. Same shape as _07.
        c.expected_ack_num = seq_range->snd_nxt + kPayloadLen;

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_fin:            return "fail:no_dut_close_fin";
            case State::Fail_no_dut_data_ack:       return "fail:no_dut_ack_to_received_data_in_fw2";
            case State::Fail_dut_left_fw2:          return "fail:dut_emitted_fin_or_rst_in_fw2";
            case State::Fail_no_proper_data:        return "fail:dut_did_not_receive_proper_data_in_fw2";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing08SM, tcp_closing_08)
