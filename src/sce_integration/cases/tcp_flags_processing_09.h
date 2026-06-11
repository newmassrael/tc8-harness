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

#include "tcp_flags_processing_09_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09SM =
    ::SCE::Generated::tcp_flags_processing_09::tcp_flags_processing_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09SM>
    : TcpAnyBase<cases::TcpFlagsProcessing09SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT / CLOSING / LAST-ACK MUST not change "
        "state after receiving a FIN+ACK (RFC 793 §3.9 p75 Event "
        "Processing). 3 spec iterations exercise wst ∈ "
        "{CW with valid ack, CLOSING with invalid ack, LA with "
        "invalid ack}";

    // Phase 1 CW prelude is the SCXML's initial state, runs sync in
    // body. Phases 2..3 deferred via scheduleAfterStateEntry on
    // their handshake_ack states (multi-phase-absence pattern).
    //
    // Per-phase port quads dodge the §4.8 active-OPEN cluster
    // reservations (+0..+6, +20..+25, +30..+38, +40..+41,
    // +50..+56). _09 uses +57..+59.
    //
    // Each phase's "duplicate FIN+ACK" replays the original tester
    // FIN's seq (= snd_nxt - 1 from queryTcpSeqRange or = info
    // .tester_seq_post_fin - 1 from driveCloseToClosing). The
    // ack_num field per spec:
    //   Phase 1 CW:      valid (= rcv_nxt). DUT.snd_nxt unchanged
    //                    (no DUT FIN sent), so the ACK is a dup ACK.
    //   Phase 2 CLOSING: invalid (= info.tester_ack_post_fin - 1).
    //                    Does NOT acknowledge DUT FIN, so DUT stays
    //                    in CLOSING.
    //   Phase 3 LA:      invalid (= rcv_nxt - 1). Does NOT
    //                    acknowledge DUT FIN, so DUT stays in LA.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1CloseWait(cfg, iface);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        std::array<std::uint8_t, 6> dut_mac  = cfg.dut.mac;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase2Closing(cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase3LastAck(cfg_copy, iface_copy);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_p1_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase1_cw";
            case State::Fail_p1_no_close_wait_ack:           return "fail:no_dut_close_wait_ack_phase1_cw";
            case State::Fail_p1_unexpected_state_change:     return "fail:dut_state_changed_after_dup_fin_ack_in_cw";
            case State::Fail_p2_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase2_closing";
            case State::Fail_p2_no_dut_fin:                  return "fail:no_dut_fin_phase2_closing";
            case State::Fail_p2_no_closing_ack:              return "fail:no_dut_closing_ack_phase2_closing";
            case State::Fail_p2_unexpected_state_change:     return "fail:dut_emitted_rst_after_dup_fin_ack_in_closing";
            case State::Fail_p3_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase3_la";
            case State::Fail_p3_no_close_wait_ack:           return "fail:no_dut_close_wait_ack_phase3_la";
            case State::Fail_p3_no_dut_fin:                  return "fail:no_dut_fin_phase3_la";
            case State::Fail_p3_unexpected_state_change:     return "fail:dut_emitted_rst_after_dup_fin_ack_in_la";
            default:                                         return "running";
        }
    }

private:
    static void emitDupFinAck(const ::tc8::TestConfig& cfg,
                              std::string_view iface,
                              std::uint16_t src_port,
                              std::uint16_t dst_port,
                              std::uint32_t seq_value,
                              std::uint32_t ack_value) {
        ::tc8::stimulus::TcpSegmentSpec dup{};
        dup.src_port = src_port;
        dup.dst_port = dst_port;
        dup.seq_num  = seq_value;
        dup.ack_num  = ack_value;
        dup.flags    = ::tc8::stimulus::kTcpFlagFin
                     | ::tc8::stimulus::kTcpFlagAck;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, dup,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1CloseWait(const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 57U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 57U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            // Replay original tester FIN: seq = snd_nxt - 1 (the FIN
            // consumed +1 to advance snd_nxt; the original FIN's seq
            // was snd_nxt - 1). ack = valid (rcv_nxt = DUT's
            // post-handshake snd_nxt; DUT has not sent FIN since UT
            // did not call close).
            emitDupFinAck(cfg, iface, remote_port, local_port,
                          seq_range->snd_nxt - 1U,
                          seq_range->rcv_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase2Closing(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 58U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 58U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/3, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        const auto info = driveCloseToClosing(
            cfg, iface, cfg.dut.mac, tester_fd,
            /*close_req_id=*/4, /*socket_id=*/2,
            local_port, remote_port);
        if (info.ok) {
            // Replay the helper-injected FIN: seq = info
            // .tester_seq_post_fin - 1 (= seq->snd_nxt). ack =
            // info.tester_ack_post_fin - 1 (= rcv_nxt - 1 from
            // helper, "acceptable" but does NOT acknowledge DUT
            // FIN).
            emitDupFinAck(cfg, iface, remote_port, local_port,
                          info.tester_seq_post_fin - 1U,
                          info.tester_ack_post_fin - 1U);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase3LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 59U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 59U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/5, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*close_req_id=*/6, /*socket_id=*/3);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            // Replay original tester FIN: seq = snd_nxt - 1. ack =
            // rcv_nxt - 1 (acceptable per RFC 793 §3.4 but does NOT
            // acknowledge DUT FIN, so DUT stays in LA).
            emitDupFinAck(cfg, iface, remote_port, local_port,
                          seq_range->snd_nxt - 1U,
                          seq_range->rcv_nxt - 1U);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09SM, tcp_flags_processing_09)
