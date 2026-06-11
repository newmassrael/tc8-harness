#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_02_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing02SM =
    ::SCE::Generated::tcp_flags_processing_02::tcp_flags_processing_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing02SM>
    : TcpAnyBase<cases::TcpFlagsProcessing02SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-RCVD / EST / FW1 / FW2 / CW MUST return to "
        "CLOSED state on RESET (RFC 793 §3.9 p70 Event Processing). "
        "5 spec iterations exercise wst ∈ {SYN-RCVD, EST, FW1, FW2, "
        "CW}; per phase a verify-probe ACK on the killed 4-tuple "
        "elicits DUT RST as wire-observable proof of CLOSED";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1SynRecv(cfg, iface);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        std::array<std::uint8_t, 6> dut_mac  = cfg.dut.mac;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase2Established(cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase3FinWait1(cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p4_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase4FinWait2(cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p5_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase5CloseWait(cfg_copy, iface_copy);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_p1_no_prelude_synack:         return "fail:no_dut_synack_phase1_syn_rcvd";
            case State::Fail_p1_no_verify_rst:             return "fail:dut_did_not_emit_rst_after_rst_in_syn_rcvd";
            case State::Fail_p2_no_handshake_ack:          return "fail:no_dut_handshake_ack_phase2_est";
            case State::Fail_p2_no_verify_rst:             return "fail:dut_did_not_emit_rst_after_rst_in_est";
            case State::Fail_p3_no_handshake_ack:          return "fail:no_dut_handshake_ack_phase3_fw1";
            case State::Fail_p3_no_dut_fin:                return "fail:no_dut_fin_phase3_fw1";
            case State::Fail_p3_no_verify_rst:             return "fail:dut_did_not_emit_rst_after_rst_in_fw1";
            case State::Fail_p4_no_handshake_ack:          return "fail:no_dut_handshake_ack_phase4_fw2";
            case State::Fail_p4_no_dut_fin:                return "fail:no_dut_fin_phase4_fw2";
            case State::Fail_p4_no_verify_rst:             return "fail:dut_did_not_emit_rst_after_rst_in_fw2";
            case State::Fail_p5_no_handshake_ack:          return "fail:no_dut_handshake_ack_phase5_cw";
            case State::Fail_p5_no_close_wait_ack:         return "fail:no_dut_close_wait_ack_phase5_cw";
            case State::Fail_p5_no_verify_rst:             return "fail:dut_did_not_emit_rst_after_rst_in_cw";
            default:                                       return "running";
        }
    }

private:
    // Spec-prescribed RST inject (RST+ACK with in-window seq).
    static void emitRst(const ::tc8::TestConfig& cfg,
                        std::string_view iface,
                        std::uint16_t src_port,
                        std::uint16_t dst_port,
                        std::uint32_t seq_value,
                        std::uint32_t ack_value) {
        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = src_port;
        rst.dst_port = dst_port;
        rst.seq_num  = seq_value;
        rst.ack_num  = ack_value;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst
                     | ::tc8::stimulus::kTcpFlagAck;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, rst,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    // Verify-probe ACK on the killed 4-tuple. If DUT honoured the
    // RST, the socket is gone and Linux's tcp_v4_send_reset (or
    // LISTEN's tcp_rcv_state_process return-1 path for phase 1)
    // emits a RST. seq/ack are arbitrary — Linux ignores them when
    // emitting RST(seq=incoming.ack) on no-socket / LISTEN-routed
    // paths.
    static void emitVerifyAck(const ::tc8::TestConfig& cfg,
                              std::string_view iface,
                              std::uint16_t src_port,
                              std::uint16_t dst_port,
                              std::uint32_t seq_value,
                              std::uint32_t ack_value) {
        ::tc8::stimulus::TcpSegmentSpec ack{};
        ack.src_port = src_port;
        ack.dst_port = dst_port;
        ack.seq_num  = seq_value;
        ack.ack_num  = ack_value;
        ack.flags    = ::tc8::stimulus::kTcpFlagAck;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, ack,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1SynRecv(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort = kBasicsListenPort + 12U;
        constexpr std::uint16_t kTesterPort = kBasicsTesterPort + 76U;

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/1, kListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSynAck(
            cfg, iface, kTesterPort);

        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = kTesterPort;
        syn.dst_port = kListenPort;
        syn.seq_num  = kTesterInitialSeq;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        const auto synack = snippet.tryCapture(
            std::chrono::milliseconds(500));
        if (!synack.has_value()) return;

        // Spec RST: seq = ISN_t + 1 (= req->rsk_rcv_nxt expected
        // next byte from tester after SYN consumed +1). ack =
        // ISN_d + 1 (acceptable). Linux's tcp_check_req drops the
        // req_sock for an in-seq RST.
        emitRst(cfg, iface, kTesterPort, kListenPort,
                kTesterInitialSeq + 1U, synack->seq_num + 1U);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Verify-probe ACK. Routes to LISTEN; tcp_rcv_state_process
        // returns 1 → DUT RST.
        emitVerifyAck(cfg, iface, kTesterPort, kListenPort,
                      kTesterInitialSeq + 5U,
                      synack->seq_num + 1U);
    }

    static void runPhase2Established(const ::tc8::TestConfig& cfg,
                                     std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 60U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 60U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/3, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        emitRst(cfg, iface, remote_port, local_port,
                seq_range->snd_nxt, seq_range->rcv_nxt);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        emitVerifyAck(cfg, iface, remote_port, local_port,
                      seq_range->snd_nxt + 5U, seq_range->rcv_nxt);
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase3FinWait1(const ::tc8::TestConfig& cfg,
                                  std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 61U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 61U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/5, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*close_req_id=*/6, /*socket_id=*/3);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        emitRst(cfg, iface, remote_port, local_port,
                seq_range->snd_nxt, seq_range->rcv_nxt);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        emitVerifyAck(cfg, iface, remote_port, local_port,
                      seq_range->snd_nxt + 5U, seq_range->rcv_nxt);
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase4FinWait2(const ::tc8::TestConfig& cfg,
                                  std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 62U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 62U;

        // Drive DUT to FW2 manually (driveTcpToTimeWaitFw2 goes
        // all the way to TW; we want to stop at FW2). Steps 1..3
        // match the helper through "tester kernel auto-ACK → DUT
        // FW2" but skip the shutdown(WR) that would advance to TW.
        // socket_id=4 — tc8-dut's next_tcp_socket_id_ allocation
        // advances on every OpOpenTcpSocket call (phase 1 passive
        // = 1, phase 2 active = 2, phase 3 active = 3, this phase
        // = 4).
        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/7, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*close_req_id=*/8, /*socket_id=*/4);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        emitRst(cfg, iface, remote_port, local_port,
                seq_range->snd_nxt, seq_range->rcv_nxt);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        emitVerifyAck(cfg, iface, remote_port, local_port,
                      seq_range->snd_nxt + 5U, seq_range->rcv_nxt);
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase5CloseWait(const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 63U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 63U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/9, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        emitRst(cfg, iface, remote_port, local_port,
                seq_range->snd_nxt, seq_range->rcv_nxt);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        emitVerifyAck(cfg, iface, remote_port, local_port,
                      seq_range->snd_nxt + 5U, seq_range->rcv_nxt);
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing02SM, tcp_flags_processing_02)
