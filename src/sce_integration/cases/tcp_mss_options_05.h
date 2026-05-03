#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_mss_options_05_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions05SM = ::SCE::Generated::tcp_mss_options_05::tcp_mss_options_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions05SM>
    : TcpAnyBase<cases::TcpMssOptions05SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "TCP MUST handle an illegal MSS option length in a SYN,ACK "
        "segment without crashing (RFC 1122 §4.2.2.5 p85). Iterations: "
        "ilen=0 and ilen=5.";

    // Drive one iteration of the spec procedure: active OPEN, capture
    // DUT SYN, raw-inject SYN+ACK carrying `bad_options` bytes, wait
    // for the DUT third-leg ACK to land on pcap, UT-close the socket.
    // The TesterAutoRstDrop scope spans the SYN-SENT period only —
    // after the DUT reaches ESTABLISHED via our injection, dropping
    // RST is no longer needed, and tearing the rule down before UT
    // close lets the tester kernel cleanly RST the orphaned 4-tuple
    // when tc8-dut emits FIN.
    static void runPhase(const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         std::uint8_t  open_req_id,
                         std::uint8_t  close_req_id,
                         std::uint8_t  socket_id,
                         std::uint16_t port_offset,
                         const std::vector<std::uint8_t> &bad_options) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  =
            static_cast<std::uint16_t>(kBasicsActiveLocalPort  + port_offset);
        const std::uint16_t remote_port =
            static_cast<std::uint16_t>(kBasicsActiveRemotePort + port_offset);

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        {
            TesterAutoRstDrop rst_drop(cfg);
            (void)rst_drop;

            sendOpenTcpSocketActiveRequest(
                cfg, iface, dut_mac,
                open_req_id, local_port,
                cfg.ipv4.tester_ip, remote_port);

            const auto syn = snippet.tryCapture(
                std::chrono::milliseconds(1000));
            if (syn.has_value()) {
                ::tc8::stimulus::TcpSegmentSpec synack{};
                synack.src_port = remote_port;
                synack.dst_port = local_port;
                synack.seq_num  = kTesterInitialSeq;
                synack.ack_num  = syn->seq_num + 1U;
                synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                                | ::tc8::stimulus::kTcpFlagAck;
                synack.options  = bad_options;
                emitTcpFrame(cfg, iface, dut_mac, synack,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }

            // 200 ms grace for the DUT TCB to process SYN+ACK and
            // emit the third-leg ACK on the wire (where SCXML
            // observes it).
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        sendCloseTcpSocketRequest(
            cfg, iface, dut_mac, close_req_id, socket_id);
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Iteration 1: ilen=0 (less than RFC 793 §3.1 MSS opsize=4).
        // Wire bytes [0x02 0x00] padded with NOP×2 → 4 B. Linux's
        // `tcp_parse_options` aborts further option parsing at
        // `opsize < 2` and proceeds with the rest of the SYN+ACK.
        runPhase(cfg, iface, cfg.arp.dut_real_mac,
                 /*open_req_id=*/1, /*close_req_id=*/2, /*socket_id=*/1,
                 kTcpMssOptions05Phase1LocalOffset,
                 std::vector<std::uint8_t>{0x02U, 0x00U, 0x01U, 0x01U});

        // Iteration 2: ilen=5 (more than actual). Wire bytes
        // [0x02 0x05 0xAA 0xBB 0xCC] — kind=2, length=5 (3 data
        // bytes, one more than the RFC encoding's 2). Builder pads
        // with NOP×3 → 8 B options region; Data Offset = 7. Linux
        // skips the option per `opsize > TCPOLEN_MSS` and continues.
        runPhase(cfg, iface, cfg.arp.dut_real_mac,
                 /*open_req_id=*/3, /*close_req_id=*/4, /*socket_id=*/2,
                 kTcpMssOptions05Phase2LocalOffset,
                 std::vector<std::uint8_t>{0x02U, 0x05U, 0xAAU, 0xBBU, 0xCCU});
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_timeout_phase1:    return "fail:no_dut_ack_to_synack_with_ilen0_mss";
            case State::Fail_timeout_phase2:    return "fail:no_dut_ack_to_synack_with_ilen5_mss";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions05SM, tcp_mss_options_05)
